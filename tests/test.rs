use secp256k1::{Secp256k1, PublicKey, SecretKey, Message};
use rand::rngs::OsRng;
use rand::RngCore;  // Rastgele veri üretmek için
use spawn_multisig::multisig::MultiSig;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;

        // Rastgele secret key'ler oluşturmak için
        let mut sk1_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk1_bytes);
        let sk1 = SecretKey::from_slice(&sk1_bytes).expect("32 bytes, within curve order");
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);

        let mut sk2_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk2_bytes);
        let sk2 = SecretKey::from_slice(&sk2_bytes).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);

        let mut sk3_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk3_bytes);
        let sk3 = SecretKey::from_slice(&sk3_bytes).expect("32 bytes, within curve order");
        let pk3 = PublicKey::from_secret_key(&secp, &sk3);

        // Multi-signature yapısını oluştur
        let mut multisig = MultiSig::new(vec![pk1, pk2, pk3], 2);

        // İmza oluştur
        let msg = Message::from_slice(&[0xab; 32]).unwrap();
        let sig1 = secp.sign_ecdsa(&msg, &sk1);
        let sig2 = secp.sign_ecdsa(&msg, &sk2);

        // İmzaları ekle
        multisig.add_signature(sig1);
        multisig.add_signature(sig2);

        // Doğrulama
        let secp_verify = Secp256k1::verification_only();
        assert!(multisig.is_valid(&msg, &secp_verify));
    }
}
