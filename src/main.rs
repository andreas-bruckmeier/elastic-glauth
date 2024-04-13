use hex::encode;
use log::{error, info};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::ExitCode;

mod elasticsearch;
mod userdb;

use elasticsearch::get_roles;
use elasticsearch::get_users;
use elasticsearch::ElasticsearchConfig;
use userdb::{read_userdb, write_userdb, User};

fn split_name(full_name: &str) -> (String, String) {
    // Split the full name into words
    let mut names = full_name.split_whitespace();

    // Get the first name, if available
    let first_name = names.next().unwrap_or_default().to_string();

    // Join the remaining words as the last name
    let last_name = names.collect::<Vec<&str>>().join(" ");

    (first_name, last_name)
}

fn main() -> ExitCode {
    env_logger::init();

    let min_uid: u64 = env::var("GLAUTH_MIN_UID")
        .expect("missing GLAUTH_MIN_UID")
        .parse()
        .expect("GLAUTH_MIN_UID is expected to be an unsigned number");

    let glauth_primary_group: u64 = env::var("GLAUTH_PRIMARY_GROUP")
        .expect("missing GLAUTH_PRIMARY_GROUP")
        .parse()
        .expect("GLAUTH_PRIMARY_GROUP is expected to be an unsigned number");

    let glauth_config_path = env::var("GLAUTH_TEMP_CONFIG").expect("missing GLAUTH_TEMP_CONFIG");

    // Get users and groups from elasticsearch
    let elasticsearch_config = ElasticsearchConfig {
        url: env::var("ELASTICSEARCH_URL").expect("missing ELASTICSEARCH_URL"),
        user: env::var("ELASTICSEARCH_USER").expect("missing ELASTICSEARCH_USER"),
        password: env::var("ELASTICSEARCH_PASSWORD").expect("missing ELASTICSEARCH_PASSWORD"),
        timeout: None,
    };
    let roles = match get_roles(&elasticsearch_config) {
        Ok(u) => u,
        Err(err) => {
            error!("Failed to get roles from elasticsearch ({})", err);
            return ExitCode::from(1);
        }
    };
    let mut users = match get_users(&elasticsearch_config) {
        // Filter for users with glauth enabled group
        Ok(users) => users
            .into_iter()
            .filter(|u| u.roles.iter().any(|r| roles.contains_key(r)))
            .collect::<Vec<_>>(),
        Err(err) => {
            error!("Failed to get users from elasticsearch ({})", err);
            return ExitCode::from(1);
        }
    };

    // read users database
    let mut userdb = read_userdb().unwrap();

    // get max uid from userdb or fall back to min_uid
    let mut max_uid = userdb
        .users.values().map(|user| user.uid)
        .max()
        .unwrap_or(min_uid);

    // Add missing users to userdb
    for user in &users {
        userdb
            .users
            .entry(user.username.clone())
            .or_insert_with(|| {
                info!("Adding {} with uid {}", user.username, max_uid);
                let user = User { uid: max_uid };
                max_uid += 1;
                user
            });
    }

    // write modified userdb back to file
    write_userdb(&userdb).unwrap();

    // Sort users by their uid
    users.sort_by(|a, b| {
        userdb
            .users
            .get(&a.username)
            .unwrap()
            .uid
            .partial_cmp(&userdb.users.get(&b.username).unwrap().uid)
            .unwrap()
    });

    let glauth_config_file = match File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(glauth_config_path)
    {
        Ok(file) => file,
        Err(error) => {
            error!("Failed to opent glauth temp config for writing ({})", error);
            return ExitCode::from(1);
        }
    };
    let mut writer = BufWriter::new(glauth_config_file);

    for user in users {
        let glauth_password_hash = encode(&user.password).to_uppercase();
        let (first_name, last_name) = split_name(&user.full_name);
        let mut other_groups = user
            .roles
            .iter()
            .filter(|ur| roles.contains_key(*ur))
            .map(|ur| {
                roles
                    .get(ur)
                    .unwrap()
                    .metadata
                    .glauth_gid
                    .unwrap_or_default()
            })
            .filter(|gid| *gid > 0_u64)
            .map(|gid| gid.to_string())
            .collect::<Vec<_>>();
        other_groups.sort_by(|a, b| a.partial_cmp(b).unwrap());
        match write!(
            writer,
            r#"
[[users]]
  name = "{}"
  mail = "{}"
  givenname = "{}"
  sn = "{}"
  uidnumber = "{}"
  primarygroup = {}
  otherGroups = [{}]
  passbcrypt = "{}"
    [[users.customattributes]]
      displayName = ["{} {}"]
    [[users.capabilities]]
      action = "search"
      object = "*"
"#,
            user.username,
            user.email,
            first_name,
            last_name,
            userdb.users.get(&user.username).unwrap().uid,
            glauth_primary_group,
            other_groups.join(", "),
            glauth_password_hash,
            last_name,
            first_name,
        ) {
            Ok(()) => {}
            Err(error) => {
                error!("Failed writing glauth temp config ({})", error);
                return ExitCode::from(1);
            }
        };
    }

    ExitCode::from(0)
}
