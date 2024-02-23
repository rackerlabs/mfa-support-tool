use std::{ops::Deref, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use log::{debug, error, info};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

pub type RefreshToken = Arc<Mutex<Option<String>>>;

#[derive(Debug, Clone)]
pub struct WrappedClient {
    client: Client,
    pub url: String,
}

impl WrappedClient {
    pub fn new(url: &String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Cannot build http client");
        Self {
            client,
            url: url.to_owned(),
        }
    }
}

impl Deref for WrappedClient {
    type Target = Client;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

/// Deserializes a value into a T
pub fn try_extract<T>(value: &Value, pointer: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let extracted = value.pointer(pointer).ok_or(anyhow::anyhow!(format!(
        "attribute {pointer} does not exist!"
    )))?;
    serde_json::from_value(extracted.to_owned())
        .map_err(|e| anyhow::anyhow!(format!("couldn't deserialize {pointer}: {e}")))
}

pub async fn probe(client: &WrappedClient) -> anyhow::Result<()> {
    info!("Checking connectivity, please wait a few seconds.");
    client
        .get(client.url.to_string())
        .send()
        .await
        .context(format!(
            "Houston, we have a problem. Backend URL '{}' isn't reachable.",
            client.url
        ))?
        .error_for_status()
        .context("Backend returned non-200 status.")?;
    info!("Connectivity check: OK");
    Ok(())
}

/// Get racker token
pub async fn get_token(
    client: &WrappedClient,
    sso: &String,
    password: &String,
) -> anyhow::Result<String> {
    let auth_payload = json!({ "auth": { "RAX-AUTH:domain": { "name": "Rackspace" }, "passwordCredentials": { "username": sso, "password": password } } });
    info!("Trying to authenticate with provided credentials, please wait up to 10s.");
    let response = client
        .post(format!("{}/v2.0/tokens", client.url))
        .json(&auth_payload)
        .send()
        .await?
        .error_for_status()
        .context("invalid credentials")?
        .json::<Value>()
        .await
        .context("Cannot deserialize identity response")?;

    // we only use this to determine whether the user has the required roles or not
    #[derive(Deserialize, Debug)]
    struct InnerRole {
        name: String,
    }
    let token = try_extract(&response, "/access/token/id")?;
    let roles: Vec<InnerRole> = try_extract(&response, "/access/user/roles")?;
    debug!("User roles: {roles:?}");
    // Check user has required roles
    for role in ["cid-internal-support", "cid-mfa-support"] {
        if !roles.iter().any(|r| r.name == role) {
            bail!("user '{}' doesn't have the `{}` role.", sso, role);
        }
    }
    info!("Successfully authenticated and verified user roles.");
    Ok(token)
}

pub async fn refresh_token(
    client: &WrappedClient,
    token: RefreshToken,
    sso: String,
    password: String,
) {
    // refresh token every 20 hours
    let mut sleep = tokio::time::interval(Duration::from_secs(3600 * 20));
    sleep.tick().await; // first tick does nothing
    loop {
        sleep.tick().await;
        let new_token = get_token(client, &sso, &password).await;
        let mut mutex = token.lock().await;
        *mutex = match new_token {
            Ok(t) => Some(t),
            Err(e) => {
                error!("Cannot refresh auth token. Please verify your password/internet connection and run the tool again: {e:?}");
                None
            }
        }
    }
}
