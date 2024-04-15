use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserDBError {
    #[error("Failed to read userdb file")]
    Read(std::io::Error),
    #[error("Failed to decode userdb from json")]
    Decode(serde_json::Error),
    #[error("Failed to write userdb to file")]
    Write(std::io::Error),
    #[error("Failed to encode userdb to json")]
    Encode(serde_json::Error),
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct User {
    uid: u64,
}

impl User {
    pub fn get_uid(&self) -> u64 {
        self.uid
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UserDB {
    #[serde(skip)]
    file: String,
    users: HashMap<String, User>,
}

impl UserDB {
    pub fn from_file(path: String) -> Result<UserDB, UserDBError> {
        let file = match File::options().read(true).open(Path::new(&path)) {
            Ok(file) => file,
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => {
                    // return empty (new) userdb
                    return Ok(UserDB {
                        file: path,
                        users: HashMap::new(),
                    });
                }
                _ => {
                    error!("Failed to read userdb ({})", error);
                    return Err(UserDBError::Read(error));
                }
            },
        };
        let reader = BufReader::new(file);
        let mut userdb: UserDB = serde_json::from_reader(reader)
            .inspect_err(|e| error!("Failed to decode userdb from JSON ({})", e))
            .map_err(UserDBError::Decode)?;
        userdb.file = path;
        Ok(userdb)
    }

    pub fn write(&self) -> Result<(), UserDBError> {
        let file = match File::options()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.file)
        {
            Ok(file) => file,
            Err(error) => {
                error!(
                    "Failed to open userdb file '{}' for writing ({})",
                    self.file, error
                );
                return Err(UserDBError::Write(error));
            }
        };
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, self)
            .inspect_err(|e| error!("Failed to encode userdb to JSON ({})", e))
            .map_err(UserDBError::Encode)
    }

    pub fn contains(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    pub fn insert(&mut self, username: String, uid: u64) {
        self.users.insert(username, User { uid });
    }

    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    // get max uid from userdb or fall back to min_uid
    pub fn get_max_uid(&self) -> Option<u64> {
        self.users.values().map(|user| user.uid).max()
    }
}
