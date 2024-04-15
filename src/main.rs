mod elasticsearch;
mod userdb;

use dotenv::{dotenv, from_filename};
use elasticsearch::get_roles;
use elasticsearch::get_users;
use elasticsearch::ElasticsearchConfig;
use hex::encode;
use log::{error, info};
use similar::TextDiff;
use std::env;
use std::fmt::Write;
use std::fs::read_to_string;
use std::io::Write as FsWrite;
use std::path::Path;
use std::process::ExitCode;
use tempfile::NamedTempFile;
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
    // Optionally read dotenv file from given path or .env in current directory
    if let Some(dotenv_file) = std::env::args().nth(1) {
        from_filename(dotenv_file).ok();
    } else {
        dotenv().ok();
    }

    // Initialize logger from env vars
    env_logger::init();

    let min_uid: u64 = env::var("GLAUTH_MIN_UID")
        .expect("missing GLAUTH_MIN_UID")
        .parse()
        .expect("GLAUTH_MIN_UID is expected to be an unsigned number");

    let glauth_primary_group: u64 = env::var("GLAUTH_PRIMARY_GROUP")
        .expect("missing GLAUTH_PRIMARY_GROUP")
        .parse()
        .expect("GLAUTH_PRIMARY_GROUP is expected to be an unsigned number");

    let glauth_config_template_path =
        env::var("GLAUTH_CONFIG_TEMPLATE_PATH").expect("missing GLAUTH_CONFIG_TEMPLATE_PATH");
    let glauth_config_path = env::var("GLAUTH_CONFIG_PATH").expect("missing GLAUTH_CONFIG_PATH");
    let glauth_config_directory = Path::new(&glauth_config_path)
        .parent()
        .expect("Failed to get directory of glauth configuration");

    // Read glauth configuration template
    let glauth_config_template = match read_to_string(glauth_config_template_path) {
        Ok(data) => data,
        Err(error) => {
            error!("Failed to read glauth configuration template ({})", error);
            return ExitCode::from(1);
        }
    };

    // Read glauth configuration
    let glauth_config = match read_to_string(&glauth_config_path) {
        Ok(data) => data,
        Err(error) => {
            error!("Failed to read glauth configuration ({})", error);
            return ExitCode::from(1);
        }
    };

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
        .users
        .values()
        .map(|user| user.uid)
        .max()
        .unwrap_or(min_uid);

    // Add missing users to userdb
    for user in &users {
        if !userdb.users.contains_key(&user.username) {
            info!("Adding {} with uid {}", user.username, max_uid);
            userdb
                .users
                .insert(user.username.clone(), User { uid: max_uid });
            max_uid += 1;
        }
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

    // Create string for new config with capacity of old config
    let mut new_config_str = String::with_capacity(glauth_config.len());

    // Write config template into new config
    new_config_str.push_str(&glauth_config_template);

    // Write elasticsearch users into new config
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
            new_config_str,
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

    // Compare old and new config strings
    let config_diff = TextDiff::from_lines(&glauth_config, &new_config_str);
    if config_diff.ratio() != 1.0 {
        info!("Configurations differ, writing new");
        for line in config_diff
            .unified_diff()
            .context_radius(5)
            .header(&glauth_config_path, "new glauth.cfg")
            .to_string()
            .lines()
        {
            info!("    {}", line.to_string());
        }
        let mut new_config_temp = match NamedTempFile::new_in(glauth_config_directory) {
            Ok(new_config_temp) => new_config_temp,
            Err(error) => {
                error!("Failed writing glauth temp config ({})", error);
                return ExitCode::from(1);
            }
        };

        match new_config_temp.write_all(new_config_str.as_bytes()) {
            Ok(_) => {}
            Err(error) => {
                error!("Failed writing glauth temp config ({})", error);
                return ExitCode::from(1);
            }
        };

        match new_config_temp.persist(&glauth_config_path) {
            Ok(_) => {
                info!("Persistet new configuration file to {}", glauth_config_path);
            }
            Err(error) => {
                error!(
                    "Failed moving temp file to actual glauth config ({})",
                    error
                );
                return ExitCode::from(1);
            }
        };
    }

    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use crate::split_name;
    #[test]
    fn split_name_test() {
        assert_eq!(
            split_name("John Doe"),
            ("John".to_string(), "Doe".to_string())
        );
        assert_eq!(
            split_name("John Doe Foo"),
            ("John".to_string(), "Doe Foo".to_string())
        );
        assert_eq!(split_name("John"), ("John".to_string(), "".to_string()));
        assert_eq!(split_name(""), ("".to_string(), "".to_string()));
        assert_eq!(
            split_name("John  Doe"),
            ("John".to_string(), "Doe".to_string())
        );
    }
}
