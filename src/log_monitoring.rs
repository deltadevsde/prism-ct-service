use std::{sync::Arc, time::Duration};

use ctclient::{CTClient, SthResult};
use keystore_rs::{KeyChain, KeyStore as _};
use log::{debug, error, info};
use prism_common::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
};
use prism_keys::{CryptoAlgorithm::Secp256r1, Signature, SigningKey, VerifyingKey};
use prism_prover::{prover::AccountResponse::Found, Prover};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use anyhow::{anyhow, bail, Result};

use crate::{
    log_list::{service::CachingLogListService, Log},
    CT_SERVICE_KEY_ID,
};

pub async fn monitor_operators(
    operators: Vec<String>,
    interval: Duration,
    signing_key: SigningKey,
    prover: Arc<Prover>,
) -> Result<()> {
    let log_list = CachingLogListService::default();

    register_ct_service(prover.clone()).await?;

    for operator in &operators {
        let Ok(logs) = log_list.get_all_by_operator(operator).await else {
            bail!("Error fetching logs for {}", operator);
        };

        debug!("Found {} logs for operator {}", logs.len(), operator);

        for log in logs {
            info!("Spawning monitoring task for {}", log.description);

            let task_signing_key = signing_key.clone();
            let task_prover = prover.clone();

            let future =
                async move { monitor_log(log, task_prover, task_signing_key, interval).await };
            tokio::task::spawn(future);
        }
    }

    Ok(())
}

async fn register_ct_service(prover: Arc<Prover>) -> Result<()> {
    if let Found(_, _) = prover.get_account(CT_SERVICE_KEY_ID).await? {
        debug!("Service already registered.");
        return Ok(());
    };

    let keystore_sk = KeyChain
        .get_signing_key(CT_SERVICE_KEY_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk));
    let vk: VerifyingKey = sk.verifying_key();

    let register_op = Operation::RegisterService {
        id: CT_SERVICE_KEY_ID.to_string(),
        creation_gate: ServiceChallenge::Signed(vk.clone()),
        key: vk,
    };

    let register_tx =
        Account::default().prepare_transaction(CT_SERVICE_KEY_ID.to_string(), register_op, &sk)?;

    debug!("Submitting transaction to register CT service");
    prover
        .clone()
        .validate_and_queue_update(register_tx)
        .await?;

    Ok(())
}

async fn monitor_log(
    log: Log,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    interval: Duration,
) -> Result<()> {
    let mut account = create_log_account(log.clone(), prover.clone()).await?;
    watch_log(log, prover.clone(), signing_key, &mut account, interval).await
}

async fn create_log_account(log: Log, prover: Arc<Prover>) -> Result<Account> {
    if let Found(account, _) = prover.get_account(&log.log_id).await? {
        debug!(
            "Account {} ({}) exists already",
            log.log_id, log.description
        );
        return Ok(*account);
    };

    let keystore_sk = KeyChain
        .get_signing_key(CT_SERVICE_KEY_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk));
    let vk: VerifyingKey = sk.verifying_key();

    // Sign account creation credentials with CT service's signing key
    let hash = Digest::hash_items(&[
        log.log_id.as_bytes(),
        CT_SERVICE_KEY_ID.as_bytes(),
        &vk.to_bytes(),
    ]);
    let signature = sk.sign(&hash.to_bytes());

    let create_acc_op = Operation::CreateAccount {
        id: log.log_id.clone(),
        service_id: CT_SERVICE_KEY_ID.to_string(),
        challenge: ServiceChallengeInput::Signed(signature),
        key: vk,
    };

    let mut account = Account::default();
    let create_acc_tx = account.prepare_transaction(log.log_id.clone(), create_acc_op, &sk)?;

    debug!(
        "Submitting transaction to create account {} ({})",
        log.log_id, log.description
    );
    prover
        .clone()
        .validate_and_queue_update(create_acc_tx.clone())
        .await?;

    account.process_transaction(&create_acc_tx)?;
    Ok(account)
}

async fn watch_log(
    log: Log,
    prover: Arc<Prover>,
    service_sk: SigningKey,
    account: &mut Account,
    interval: Duration,
) -> Result<()> {
    let log_vk = VerifyingKey::from_algorithm_and_der(Secp256r1, &log.key)?;

    let mut client = CTClient::new_from_latest_th(&log.url, &log.key).map_err(|e| {
        anyhow!(
            "Error initializing client for log {}: {}",
            log.description,
            e
        )
    })?;

    let mut last_tree_head = [0u8; 32];
    loop {
        let update_result = client.light_update();

        match update_result {
            SthResult::Ok(head) => {
                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    let relevant_head_signature_slice = &head.signature[4..];
                    let signature = Signature::from_algorithm_and_der(
                        Secp256r1,
                        relevant_head_signature_slice,
                    )?;

                    let update_op = Operation::SetData {
                        data: head.get_body(),
                        data_signature: SignatureBundle {
                            verifying_key: log_vk.clone(),
                            signature,
                        },
                    };

                    let update_tx = account.prepare_transaction(
                        log.log_id.to_string(),
                        update_op,
                        &service_sk,
                    )?;

                    loop {
                        match prover
                            .clone()
                            .validate_and_queue_update(update_tx.clone())
                            .await
                        {
                            Ok(_) => {
                                debug!("{}: {:?}", log.description, BASE64.encode(head.root_hash));
                                break;
                            }
                            Err(e) => {
                                error!("Error posting to prism {}: {}", log.url, e);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        };
                    }
                    account.process_transaction(&update_tx)?;
                }
            }
            SthResult::Err(e) => {
                error!("Error in log {}: {}", log.description, e);
            }
            SthResult::ErrWithSth(e, head) => {
                error!("Error with sth in log {}: {}", log.description, e);

                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    debug!("{}: {}", log.description, BASE64.encode(head.root_hash));
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use ctclient::SignedTreeHead;
    use openssl::pkey::PKey;
    use prism_keys::CryptoAlgorithm;

    static XENON_2024_PUB_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==";

    use super::*;
    #[test]
    fn test_xenon_key_to_p256() {
        let bytes = BASE64.decode(XENON_2024_PUB_KEY).unwrap();

        // for ctclient
        let evp_pkey = PKey::public_key_from_der(bytes.as_slice()).unwrap();

        // for prism
        let verifying_key =
            VerifyingKey::from_algorithm_and_der(CryptoAlgorithm::Secp256r1, bytes.as_slice())
                .unwrap();

        let sth_b64 = "eyJ0cmVlX3NpemUiOjI2ODAzMDcwMjksInRpbWVzdGFtcCI6MTcyOTg0NDQ2Nzc5Niwic2hhMjU2X3Jvb3RfaGFzaCI6ImJiVFkvelRyRWVLZVMzbEMwREh3d0VLUFJZeDdBcVZYVksrMFFZWUllTUk9IiwidHJlZV9oZWFkX3NpZ25hdHVyZSI6IkJBTUFSakJFQWlCbUZvM3hkRC9wUjU5OGE2N1VmdjZteXJRZ3JZYkNBd0FCdTZDZ2ppZENUQUlnWWxxNXM3Z0NaclBoNUY5c1R6TWdNNFUxMTdtQ3ZOVW9Zdi9mbnZ3Wnlhcz0ifQ==";
        let bytes = String::from_utf8(BASE64.decode(sth_b64).unwrap()).unwrap();
        let sth = SignedTreeHead::from_json(&bytes).unwrap();
        let message = sth.get_body();

        let signature =
            Signature::from_algorithm_and_der(CryptoAlgorithm::Secp256r1, &sth.signature[4..])
                .unwrap();
        sth.verify(&evp_pkey).unwrap();

        verifying_key
            .verify_signature(&message, &signature)
            .unwrap();
    }
}
