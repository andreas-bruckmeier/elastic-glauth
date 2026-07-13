use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ElasticsearcError {
    #[error("Failed to read JSON")]
    DecodeError(Box<ureq::Error>),
    #[error("Request to elasticsearch failed")]
    Request(Box<ureq::Error>),
}

pub struct ElasticsearchConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub timeout: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct Response {
    hits: OuterHits,
}

#[derive(Deserialize, Debug)]
struct OuterHits {
    hits: Vec<InnerHits>,
}

#[derive(Deserialize, Debug)]
struct InnerHits {
    #[serde(rename(deserialize = "_source"))]
    source: User,
}

#[derive(Deserialize, Debug)]
pub struct User {
    pub email: String,
    pub full_name: String,
    pub password: String,
    pub username: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct Role {
    pub metadata: RoleMeta, //    metadata: Box<RawValue> // to capture raw json as string
}

#[derive(Deserialize, Debug)]
pub struct RoleMeta {
    pub glauth_gid: Option<u64>,
}

type RoleMap = HashMap<String, Role>;

fn get_auth_header(config: &ElasticsearchConfig) -> String {
    let credentials_as_b64 = STANDARD.encode(format!("{}:{}", config.user, config.password));
    format!("Basic {credentials_as_b64}")
}

pub fn get_users(config: &ElasticsearchConfig) -> Result<Vec<User>, ElasticsearcError> {
    let url = format!("{}/.security*/_search?size=100&q=type:user", config.url);
    let timeout = Duration::from_secs(config.timeout.unwrap_or(10));
    let response: Response = ureq::get(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "elastic-glauth")
        .header("Authorization", &get_auth_header(config))
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .map_err(|e| ElasticsearcError::Request(Box::new(e)))?
        .body_mut()
        .read_json::<Response>()
        .map_err(|e| ElasticsearcError::DecodeError(Box::new(e)))?;

    let users = response
        .hits
        .hits
        .into_iter()
        .map(|u| u.source)
        .collect::<Vec<_>>();
    Ok(users)
}

pub fn get_roles(config: &ElasticsearchConfig) -> Result<RoleMap, ElasticsearcError> {
    let url = format!("{}/_security/role", config.url);
    let timeout = Duration::from_secs(config.timeout.unwrap_or(10));
    let roles: RoleMap = ureq::get(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "elastic-glauth")
        .header("Authorization", &get_auth_header(config))
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .map_err(|e| ElasticsearcError::Request(Box::new(e)))?
        .body_mut()
        .read_json()
        .map_err(|e| ElasticsearcError::DecodeError(Box::new(e)))?;

    let role_map = roles
        .into_iter()
        .filter(|(_, role)| role.metadata.glauth_gid.is_some())
        .collect();
    Ok(role_map)
}
