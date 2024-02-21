use std::io;

use anyhow::{bail, Context};
use log::{debug, error, info};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::{try_extract, WrappedClient};

pub fn read_from_stdin() -> anyhow::Result<String> {
    let mut buff = String::new();
    io::stdin()
        .read_line(&mut buff)
        .context("stdin read failure")?;
    let ret = buff.trim();
    if ret.is_empty() {
        bail!("input must not be empty");
    }
    Ok(ret.into())
}

// Read any given choice from stdin.
pub fn read_choice(prompt_message: &str, choices: Vec<&str>) -> String {
    loop {
        println!("{}", prompt_message);
        match read_from_stdin() {
            Ok(s) => {
                if choices.iter().any(|choice| s == *choice) {
                    return s;
                }
                error!(
                    "'{}' is not a valid choice. Valid choices: {:?}",
                    s, choices
                );
            }
            Err(e) => {
                error!("Couldn't read choice: {}", e);
            }
        }
    }
}

// Read the user's sso and password
pub fn read_user_password() -> (String, String) {
    let sso = loop {
        println!("Enter your SSO: ");
        match read_from_stdin() {
            Ok(s) => break s,
            Err(e) => {
                error!("Cannot read username: {}. Please try again.", e);
            }
        };
    };

    let password = loop {
        println!("Enter your password (input will be hidden): ");
        match rpassword::read_password() {
            Ok(s) => {
                if !s.is_empty() {
                    break s;
                }
                error!("Cannot use an empty password. Please try again.");
            }
            Err(e) => error!("Cannot read password: {}. Please try again.", e),
        }
    };
    (sso, password)
}

pub enum ChangeStatus {
    Unchanged,
    Changed,
}

#[derive(Deserialize)]
pub struct Domain {
    pub name: String,
    pub id: String,
    #[serde(alias = "domainMultiFactorEnforcementLevel")]
    pub enforcement_level: String,
}

impl Domain {
    pub async fn set_enforcement_level(
        &self,
        client: &WrappedClient,
        token: &String,
        level: impl AsRef<str>,
    ) -> anyhow::Result<()> {
        let url = format!(
            "{}/v2.0/RAX-AUTH/domains/{}/multi-factor",
            client.url, self.id
        );
        let payload = json!({
            "RAX-AUTH:multiFactorDomain": {
                "domainMultiFactorEnforcementLevel": level.as_ref()
            }
        });
        client
            .put(url)
            .json(&payload)
            .header("X-Auth-Token", token)
            .send()
            .await?
            .error_for_status()
            .context("Couldn't set MFA enforcement level")?;
        Ok(())
    }

    async fn get(
        client: &WrappedClient,
        token: &String,
        domain_id: &String,
    ) -> anyhow::Result<Domain> {
        info!("Checking if account exists...");
        let value = client
            .get(format!(
                "{}/v2.0/RAX-AUTH/domains/{}",
                client.url, domain_id
            ))
            .header("X-Auth-Token", token)
            .send()
            .await?
            .error_for_status()
            .context("Invalid customer account")?
            .json::<Value>()
            .await
            .context("Cannot deserialize json response")?;
        debug!("domain data: {value:?}");
        info!("Success: found account with id {} ", domain_id);
        try_extract(&value, "/RAX-AUTH:domain")
    }

    pub async fn change_enforcement_level(
        self,
        client: &WrappedClient,
        token: &String,
    ) -> anyhow::Result<ChangeStatus> {
        let prompt = format!(
            r#"Please select the new MFA enforcement level for account {} (currently set to '{}').
    a) ⚠️ OPTIONAL (this will allow the customer to disable MFA)
    b) RACKSPACE_MANDATED
    c) REQUIRED
    d) Go back and use a different account number/type
    
    Enter "a", "b", "c" or "d":"#,
            self.id, self.enforcement_level
        );

        let mfa_level = read_choice(prompt.as_str(), vec!["a", "b", "c", "d"]);
        let level = match mfa_level.as_str() {
            "a" => "OPTIONAL",
            "b" => "RACKSPACE_MANDATED",
            "c" => "REQUIRED",
            "d" => return Ok(ChangeStatus::Unchanged),
            err => {
                unreachable!("the universe is upside down: unhandled choice: {}", err)
            }
        };
        self.set_enforcement_level(client, token, level).await?;
        Ok(ChangeStatus::Changed)
    }
}

//
pub async fn read_and_get_domain(client: &WrappedClient, token: &String) -> Domain {
    loop {
        let prompt = r#"Please select an account type:
    a) dedicated
    b) datapipe
    c) cloud
        
Enter "a", "b", or "c":"#;

        let account_type = read_choice(prompt, vec!["a", "b", "c"]);
        let prefix = match account_type.as_str() {
            "a" => "dedicated:",
            "b" => "dp:",
            _ => "",
        };

        let domain_id = 'domain: loop {
            println!("Enter customer account number:");
            match read_from_stdin() {
                Ok(s) => break 'domain format!("{prefix}{s}"),
                Err(e) => error!("Cannot read account number: {}.", e),
            };
        };

        match Domain::get(client, token, &domain_id).await {
            Ok(domain) => break domain,
            Err(e) => error!("Cannot retrieve account: {e:?}"),
        };
    }
}
