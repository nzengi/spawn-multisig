use secp256k1::{Secp256k1, PublicKey, Message};
use secp256k1::ecdsa::Signature;
use std::collections::HashSet;
use ethers::contract::Contract;
use ethers::providers::{Provider, Http};
use ethers::types::{TransactionRequest, U256};
use ethers::middleware::Middleware;
use thiserror::Error;
use std::sync::Arc;
use log::{info, error};

/// Custom error types for the MultiSig wallet
#[derive(Error, Debug)]
pub enum MultiSigError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Threshold not reached: {0}/{1} signatures valid")]
    ThresholdNotReached(usize, usize),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Failed to parse Ethereum address")]
    InvalidAddress,
}

/// MultiSig wallet structure for managing multiple signers and signatures.
pub struct MultiSig {
    pub signers: HashSet<PublicKey>,  // Unique set of authorized signers
    pub signatures: Vec<Signature>,  // Now using Vec for collected signatures
    pub threshold: usize,  // Number of valid signatures required to execute a transaction
    pub contract: Contract<Arc<Provider<Http>>>,  // Ethereum smart contract interaction using ethers-rs
}

impl MultiSig {
    /// Creates a new MultiSig wallet
    ///
    /// # Arguments
    /// * `signers` - A vector of public keys of authorized signers
    /// * `threshold` - The minimum number of signatures required for validation
    /// * `contract` - A contract instance for interacting with an Ethereum smart contract
    pub fn new(signers: Vec<PublicKey>, threshold: usize, contract: Contract<Arc<Provider<Http>>>) -> MultiSig {
        assert!(threshold > 0 && threshold <= signers.len(), "Invalid threshold");
        MultiSig {
            signers: signers.into_iter().collect(),  // Convert to a unique set of signers
            signatures: Vec::new(),  // Initialize an empty signature list
            threshold,
            contract,
        }
    }

    /// Adds a signature to the MultiSig wallet if it is valid and not already present
    ///
    /// # Arguments
    /// * `sig` - The signature to be added
    /// * `message` - The message the signature is validating
    /// * `secp` - A reference to the Secp256k1 verification context
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid and added successfully, otherwise an error
    pub fn add_signature(&mut self, sig: Signature, message: &Message, secp: &Secp256k1<secp256k1::VerifyOnly>) -> Result<(), MultiSigError> {
        // Prevent duplicate signatures
        if self.signatures.contains(&sig) {
            info!("Duplicate signature. Signature already exists.");
            return Ok(());
        }

        // Check if the signature is valid
        if self
            .signers
            .iter()
            .any(|pubkey| secp.verify_ecdsa(message, &sig, pubkey).is_ok())
        {
            self.signatures.push(sig);  // Add signature if valid
            info!("Signature added successfully.");
            Ok(())
        } else {
            error!("Failed to add signature: Invalid signature.");
            Err(MultiSigError::InvalidSignature)
        }
    }

    /// Verifies if the required number of valid signatures has been reached
    ///
    /// # Arguments
    /// * `message` - The message that the signatures should validate
    /// * `secp` - A reference to the Secp256k1 verification context
    ///
    /// # Returns
    /// `Ok(())` if the number of valid signatures meets the threshold, otherwise an error
    pub fn is_valid(&self, message: &Message, secp: &Secp256k1<secp256k1::VerifyOnly>) -> Result<(), MultiSigError> {
        let valid_signatures = self
            .signatures
            .iter()
            .filter(|sig| {
                self.signers.iter().any(|pubkey| secp.verify_ecdsa(message, sig, pubkey).is_ok())
            })
            .count();

        if valid_signatures >= self.threshold {
            info!("Valid signature threshold reached.");
            Ok(())
        } else {
            error!("Threshold not reached: {}/{}", valid_signatures, self.threshold);
            Err(MultiSigError::ThresholdNotReached(valid_signatures, self.threshold))
        }
    }

    /// Submits an Ethereum transaction if the threshold of signatures is met
    ///
    /// # Arguments
    /// * `to` - The Ethereum address to send the transaction to
    /// * `value` - The amount of Ether to send
    /// * `data` - The data payload for the transaction
    ///
    /// # Returns
    /// A result containing the transaction hash on success, or an error on failure
    pub async fn submit_transaction(&self, to: String, value: U256, data: Vec<u8>) -> Result<String, MultiSigError> {
        // Parse Ethereum address
        let address = to.parse().map_err(|_| MultiSigError::InvalidAddress)?;

        // Prepare the transaction
        let tx = TransactionRequest {
            to: Some(address),
            value: Some(value),  // Amount to send
            data: Some(data.into()),  // Transaction data
            ..Default::default()
        };

        // Send the transaction to the Ethereum network
        match self.contract.client().send_transaction(tx, None).await {
            Ok(tx_hash) => {
                info!("Transaction submitted successfully. Hash: {:?}", tx_hash);
                Ok(format!("Transaction hash: {:?}", tx_hash))
            }
            Err(e) => {
                error!("Transaction failed: {:?}", e);
                Err(MultiSigError::TransactionFailed(format!("{:?}", e)))
            }
        }
    }
}
