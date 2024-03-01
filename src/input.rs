use std::{fmt::Display, io};

use anyhow::Context;
use inquire::{validator::MinLengthValidator, InquireError, Password, Select, Text};
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
    Ok(ret.into())
}

// Read the user's sso and password
pub fn read_user_password() -> anyhow::Result<(String, String)> {
    let sso = loop {
        let name = Text::new("Enter your SSO:")
            .with_help_message("This is the username you use to log in into the Rackspace network.")
            .with_validator(MinLengthValidator::new(1))
            .prompt();
        match name {
            Ok(s) => break s,
            // Bubble up ctrl-c if it was pressed
            Err(InquireError::OperationInterrupted) => {
                return Err(InquireError::OperationInterrupted.into())
            }
            Err(e) => {
                error!("Cannot read username: {}. Please try again.", e);
            }
        };
    };

    let password = loop {
        // println!("Enter your password (input will be hidden): ");
        let password = Password::new("Enter your password (input will be hidden):")
            .with_help_message("This is your Rackspace account password.")
            .without_confirmation()
            .with_validator(MinLengthValidator::new(1))
            .prompt();
        match password {
            Ok(s) => break s,
            Err(InquireError::OperationInterrupted) => {
                return Err(InquireError::OperationInterrupted.into());
            }

            Err(e) => error!("Cannot read password: {}. Please try again.", e),
        }
    };
    Ok((sso, password))
}

pub enum ChangeStatus {
    Unchanged,
    Changed,
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all(serialize = "UPPERCASE", deserialize = "UPPERCASE"))]
pub enum EnforcementLevel {
    Required,
    #[serde(alias = "RACKSPACE_MANDATED")]
    RackspaceMandated,
    Optional,
    LeaveUnchanged,
}

#[derive(Debug, Clone, Copy)]
enum DomainType {
    Dedicated,
    Datapipe,
    Cloud,
}

impl Display for EnforcementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RackspaceMandated => write!(f, "RACKSPACE_MANDATED"),
            Self::Required => write!(f, "REQUIRED"),
            Self::Optional => write!(f, "⚠️ OPTIONAL"),
            Self::LeaveUnchanged => write!(f, "🔙 Leave unchanged and go back."),
        }
    }
}

impl Display for DomainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Default for EnforcementLevel {
    fn default() -> Self {
        EnforcementLevel::Optional
    }
}

#[derive(Deserialize)]
pub struct Domain {
    pub name: String,
    pub id: String,
    #[serde(alias = "domainMultiFactorEnforcementLevel", default)]
    pub enforcement_level: EnforcementLevel,
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
        let mut options = vec![
            EnforcementLevel::Required,
            EnforcementLevel::RackspaceMandated,
            EnforcementLevel::Optional,
            EnforcementLevel::LeaveUnchanged,
        ];
        // Don't show the option that is currently set in the domain.
        options.retain(|value| *value != self.enforcement_level);

        let prompt = format!(
            "Select the new MFA enforcement level for account {} (currently set to {}):",
            self.id, self.enforcement_level
        );
        loop {
            let answer = match Select::new(&prompt, options.clone()).prompt() {
                Ok(answer) => answer,
                Err(InquireError::OperationInterrupted) => {
                    return Err(InquireError::OperationInterrupted.into())
                }
                Err(e) => {
                    error!("Cannot read new enforcement level: {e}. Please try again.");
                    continue;
                }
            };

            let level = match answer {
                EnforcementLevel::Optional => "OPTIONAL",
                EnforcementLevel::RackspaceMandated => "RACKSPACE_MANDATED",
                EnforcementLevel::Required => "REQUIRED",
                EnforcementLevel::LeaveUnchanged => return Ok(ChangeStatus::Unchanged),
            };
            self.set_enforcement_level(client, token, level).await?;
            return Ok(ChangeStatus::Changed);
        }
    }
}

//
pub async fn read_and_get_domain(client: &WrappedClient, token: &String) -> anyhow::Result<Domain> {
    loop {
        let options = vec![
            DomainType::Cloud,
            DomainType::Datapipe,
            DomainType::Dedicated,
        ];

        let prefix = 'dtype: loop {
            let answer = Select::new("Select account type:", options.clone()).prompt();
            break 'dtype match answer {
                Ok(d_type) => match d_type {
                    DomainType::Cloud => "",
                    DomainType::Datapipe => "dp:",
                    DomainType::Dedicated => "dedicated:",
                },
                Err(InquireError::OperationInterrupted) => {
                    return Err(InquireError::OperationInterrupted.into())
                }
                Err(e) => {
                    error!("Cannot read domain type: {e}");
                    continue;
                }
            };
        };

        let domain = 'domain: loop {
            let prompt = Text::new("Enter customer account number:")
                .with_validator(MinLengthValidator::new(1))
                .with_help_message("This field usually only contains digits.")
                .prompt();
            match prompt {
                Ok(s) => break 'domain format!("{prefix}{s}"),
                Err(InquireError::OperationInterrupted) => {
                    return Err(InquireError::OperationInterrupted.into())
                }
                Err(ref e) => {
                    error!("Cannot read account number: {e}. Please try again.")
                }
            };
        };

        match Domain::get(client, token, &domain).await {
            Ok(domain) => break Ok(domain),
            Err(e) => error!("Cannot retrieve account: {e:?}. Please verify the account type & number are correct."),
        };
    }
}
