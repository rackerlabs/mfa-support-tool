use std::{
    io::{self, Write},
    sync::Arc,
};

use inquire::InquireError;
use log::{debug, error, info};
use mfa_support_tool::{
    client::{get_token, probe, refresh_token, WrappedClient},
    input::{read_and_get_domain, read_from_stdin, read_user_password, ChangeStatus},
};
use tokio::sync::Mutex;

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
        let (sso, password) = read_user_password()?;
        match get_token(&client, &sso, &password).await {
            Ok(token) => break (sso, password, token),
            Err(e) => {
                error!("Cannot retrieve racker token: {:?}", e);
            }
        };
    };

    // Periodically refresh the token in background.
    let shared_token = Arc::new(Mutex::new(Some(token)));

    tokio::spawn({
        let client = client.clone();
        let token = shared_token.clone();
        let (sso, password) = (sso.clone(), password.clone());
        async move {
            refresh_token(&client, token, sso, password).await;
        }
    });

    // Main loop
    loop {
        // Token loop: We always try to pull the in-memory token here. However,
        // that token is periodically refreshed and there might be a possibility
        // the token wasn't refreshed. We check here if something failed, and if
        // something did fail, we try to authenticate again.
        let token = 'token: loop {
            let mut guard = shared_token.lock().await;
            // This will only run if the periodic task failed.
            let Some(token) = guard.as_ref() else {
                // Try to refresh the token manually and set it for future usage.
                match get_token(&client, &sso, &password).await {
                    Ok(token) => {
                        *guard = Some(token.clone());
                        break 'token token;
                    }
                    Err(e) => {
                        error!("Couldn't refresh token. Press ctrl-c to exit, or enter to try the refresh the token again. Error: {e}");
                        continue 'token;
                    }
                }
            };
            break 'token token.to_owned();
        };

        let domain = read_and_get_domain(&client, &token).await?;
        match domain.change_enforcement_level(&client, &token).await {
            Ok(ChangeStatus::Unchanged) => {
                print!("{}[2J", 27 as char); // clear screen
                io::stdout().flush().ok();
            }
            Ok(ChangeStatus::Changed) => {
                info!("MFA level successfully changed. Press ctrl-c to exit, or enter to modify another domain.");
                read_from_stdin().ok();
                print!("{}[2J", 27 as char);
                io::stdout().flush().ok();
            }
            Err(e) => {
                // abort execution if ctrl-c was pressed
                if let Some(InquireError::OperationInterrupted) = e.downcast_ref::<InquireError>() {
                    return Err(e);
                }
                error!("An error ocurred: {e:?}. Press ctrl-c to exit, or enter to modify another domain.");
                read_from_stdin().ok();
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match main_inner().await {
        Ok(_) => {}
        Err(e) => {
            if let Some(InquireError::OperationInterrupted) = e.downcast_ref::<InquireError>() {
                // user pressed ctrl-c, don't show error message.
            } else {
                println!("Unhandled error: {:?}", e)
            }
        }
    }
    println!("\nPress any key to terminate this program.");
    read_from_stdin().ok();
    Ok(())
}
