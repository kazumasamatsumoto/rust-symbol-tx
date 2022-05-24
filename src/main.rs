extern crate base32;
extern crate chrono;
extern crate ed25519_dalek;
extern crate hex;
extern crate rand;
extern crate sha3;
extern crate ureq;

use chrono::{DateTime, Local};
use ed25519_dalek::*;
use hex::FromHex;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

fn main() {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    println!("Secret key: {}", hex::encode(keypair.secret.as_bytes()));
    println!("Public key: {}", hex::encode(keypair.public.as_bytes()));

    let secret_key: &[u8] = b"5DB79B7AFD347D616165C35CB1A02FF14F52DB9C7BCAD2ABADFFE62A94AD4D9B";
    //let public_key: &[u8] = b"5f594dfc018578662e0b5a2f5f83ecfb1cda2b32e29ff1d9b2c5e7325c4cf7cb";
    let sec_bytes: Vec<u8> = FromHex::from_hex(secret_key).unwrap();

    let secret: SecretKey = SecretKey::from_bytes(&sec_bytes[..SECRET_KEY_LENGTH]).unwrap();
    let public: PublicKey = (&secret).into();
    let keypair: Keypair = Keypair {
        secret: secret,
        public: public,
    };

    println!("Secret key: {}", hex::encode(keypair.secret.as_bytes()));
    println!("Public key: {}", hex::encode(keypair.public.as_bytes()));

    let dt: DateTime<Local> = Local::now();
    let timestamp: i64 = dt.timestamp();
    let deadline_time = ((timestamp + 7200) - 1637848847) * 1000;

    let reserved1 = "00000000";
    //let signature = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let signer = hex::encode(keypair.public.as_bytes());
    let reserved2 = "00000000";
    let v: u8 = 1;
    let version = v
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();
    let nt: u8 = 152;
    let network_type = nt
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();
    let tt: u16 = 16724;
    let tx_type = tt
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();
    let deadline = deadline_time
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();
    let f: u64 = 300000000;
    let fee = f
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    let ba = "TDNMNLKINXRBSL2GWYGS266UT7BZA42DLOTFKEQ";
    let recipient_address =
        hex::encode(base32::decode(base32::Alphabet::RFC4648 { padding: true }, ba).unwrap());

    let mc: u8 = 1;
    let mosaic_count = mc
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();
    let tx_reserved = "0000000000";

    let mi: u64 = 0x3A8416DB2D53B6C8;
    let mosaic_id = mi
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    let ma: u64 = 100;
    let mosaic_amount = ma
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    let m = "Hello Rust! Welcome to Symbol world!";
    let message = "00".to_owned()
        + &m.as_bytes()
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<String>();

    let ms: u16 = (message.chars().count() / 2).try_into().unwrap();
    let message_size = ms
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    let verifiable_data = version.to_owned()
        + &network_type
        + &tx_type
        + &fee
        + &deadline
        + &recipient_address
        + &message_size
        + &mosaic_count
        + &tx_reserved
        + &mosaic_id
        + &mosaic_amount
        + &message;

    println!("verifiable_data: {}", verifiable_data);

    let data = "7fccd304802016bebbcd342a332f91ff1f3bb5e902988b352697be245f48e836".to_owned()
        + &verifiable_data;

    let msg_bytes: Vec<u8> = FromHex::from_hex(data).unwrap();
    let signature: Signature = keypair.sign(&msg_bytes);

    println!("Signature: {}", signature.to_string());

    let ts: u32 = (verifiable_data.chars().count() / 2 + 108)
        .try_into()
        .unwrap();
    let tx_size = ts
        .to_le_bytes()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    let tx_buffer = tx_size.to_owned()
        + &reserved1
        + &signature.to_string()
        + &signer
        + &reserved2
        + &verifiable_data;

    let json_request = format!(r#"{{"payload":"{}"}}"#, tx_buffer);
    let r = ureq::put("https://sym-test-02.opening-line.jp:3001/transactions")
        .set("Content-Type", "application/json")
        .send_string(&json_request);
    println!("{}", json_request);
    println!("{:?}", r);

    let hash_payload = signature.to_string().to_owned()
        + &signer
        + &"7fccd304802016bebbcd342a332f91ff1f3bb5e902988b352697be245f48e836"
        + &verifiable_data;
    let hash_bytes: Vec<u8> = FromHex::from_hex(hash_payload).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(hash_bytes);
    let tx_hash = hasher
        .finalize()
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>();

    println!(
        "transactionStatus: https://sym-test-02.opening-line.jp:3001/transactionStatus/{}",
        tx_hash
    );
    println!(
        "confirmed: https://sym-test-02.opening-line.jp:3001/transactions/confirmed/{}",
        tx_hash
    );
    println!(
        "explorer: https://testnet.symbol.fyi/transactions/{}",
        tx_hash
    );
}
