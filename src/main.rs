use std::sync::{Arc, Mutex};

use anyhow::bail;
use log::{debug, error, info};
use mfa_support_tool::{
    client::{get_token, probe, refresh_token, WrappedClient},
    input::{read_and_get_domain, read_from_stdin, read_user_password, ChangeStatus},
};

async fn main_inner() -> anyhow::Result<()> {
    // set logging level to info if unset
    let banner_msg = r#"=============================================================
🦀 Customer Identity MFA tool.

Disclaimer: This tool is ONLY meant to be used by 
support rackers. Before modifying an account, make sure
the customer accepts the waiver. Unauthorized changes 
WILL be LOGGED!

Tool support: jorge.munoz/juan.davila
============================================================="#;

    println!("{}", banner_msg);

    // set rust logger to info, if unset
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "mfa_support_tool=info");
    }

    env_logger::init();

    let url = match std::env::var_os("BACKEND_URL") {
        Some(s) => s.to_string_lossy().to_string(),
        _ => "https://identity-internal.api.rackspacecloud.com".into(),
    };

    debug!("using backend url: {}", url);
    let client = WrappedClient::new(&url);

    probe(&client).await?;

    let (sso, password, token) = loop {
        let (sso, password) = read_user_password();
        match get_token(&client, &sso, &password).await {
            Ok(token) => break (sso, password, token),
            Err(e) => {
                error!("Cannot retrieve racker token: {:?}", e);
            }
        };
    };

    // Periodically refresh the token in background.
    let shared_token = Arc::new(Mutex::new(Some(token)));
    let token_clone = shared_token.clone();
    let client_clone = client.clone();

    tokio::spawn(async move {
        refresh_token(&client_clone, token_clone, sso, password).await;
    });

    // Main loop
    loop {
        let token = {
            let guard = shared_token.lock().expect("Cannot lock mutex");
            let Some(token) = guard.as_ref() else {
                bail!("exiting: there's no valid auth token");
            };
            token.to_owned()
        };

        let domain = read_and_get_domain(&client, &token).await;
        match domain.change_enforcement_level(&client, &token).await {
            Ok(ChangeStatus::Unchanged) => {
                print!("{}[2J", 27 as char); // clear screen
                continue;
            }
            Ok(ChangeStatus::Changed) => {
                info!("MFA level successfully changed. Press ctrl-c to exit, or enter to modify another domain.");
                read_from_stdin().ok();
                print!("{}[2J", 27 as char);
            }
            Err(e) => {
                error!("An error ocurred: {e:?}. Press ctrl-c to exit, or enter to modify another domain.")
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match main_inner().await {
        Ok(_) => {}
        Err(e) => println!("ERROR: {:?}", e),
    }
    println!("\nPress any key to exit.");
    read_from_stdin().ok();
    Ok(())
}
