// src/multisig.rs

use secp256k1::{Secp256k1, PublicKey, Message};
use secp256k1::ecdsa::Signature;

pub struct MultiSig {
    pub signers: Vec<PublicKey>,
    pub signatures: Vec<Signature>,
    pub threshold: usize,
}

impl MultiSig {
    pub fn new(signers: Vec<PublicKey>, threshold: usize) -> MultiSig {
        MultiSig {
            signers,
            signatures: Vec::new(),
            threshold,
        }
    }

    pub fn add_signature(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    pub fn is_valid(&self, message: &Message, secp: &Secp256k1<secp256k1::VerifyOnly>) -> bool {
        let valid_signatures = self
            .signatures
            .iter()
            .filter(|sig| {
                self.signers.iter().any(|pubkey| secp.verify_ecdsa(message, sig, pubkey).is_ok())
            })
            .count();
        valid_signatures >= self.threshold
    }
}
