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

#[derive(Deserialize, Serialize, Debug)]
pub struct UserDB {
    pub users: HashMap<String, User>,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct User {
    pub uid: u64,
}

pub fn read_userdb() -> Result<UserDB, UserDBError> {
    let userdb_filename = "glauth-database.json";
    let file = match File::options().read(true).open(Path::new(userdb_filename)) {
        Ok(file) => file,
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => {
                // return empty (new) userdb
                return Ok(UserDB {
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
    serde_json::from_reader(reader)
        .inspect_err(|e| error!("Failed to decode userdb from JSON ({})", e))
        .map_err(UserDBError::Decode)
}

pub fn write_userdb(userdb: &UserDB) -> Result<(), UserDBError> {
    let userdb_filename = "glauth-database.json";
    let file = match File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(userdb_filename)
    {
        Ok(file) => file,
        Err(error) => {
            error!("Failed to open userdb file for writing ({})", error);
            return Err(UserDBError::Write(error));
        }
    };
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, userdb)
        .inspect_err(|e| error!("Failed to encode userdb to JSON ({})", e))
        .map_err(UserDBError::Encode)
}
