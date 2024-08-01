use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use rand::{rngs::OsRng, RngCore as _};
use scrypt::{scrypt, Params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp_core::{sr25519, Pair};
use xsalsa20poly1305::{
    aead::{
        generic_array::{typenum, GenericArray},
        Aead as _,
    },
    KeyInit, XSalsa20Poly1305,
};

use crate::{PAIR_DIV, PAIR_HDR};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedKey {
    pub encoded: String,
    pub encoding: Encoding,
    pub address: String,
    pub meta: Meta,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Encoding {
    pub content: Vec<String>,
    #[serde(rename = "type")]
    pub type_field: Vec<String>,
    pub version: u8,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub genesis_hash: String,
    pub is_master_password: bool,
    pub name: String,
    pub tags: Vec<Value>,
    pub when_created: i64,
    pub is_sub_wallet: bool,
}

/// Default log₂ of the Scrypt parameter `N`: CPU/memory cost.
const DEFAULT_LOG_N: u8 = 15;

/// Default Scrypt parameter `r`: block size.
const DEFAULT_R: u32 = 8;

/// Default Scrypt parameter `p`: parallelism.
const DEFAULT_P: u32 = 1;

pub fn generate_encode_key<T: AsRef<str>>(password: T, out: T) -> Result<String> {
    let mut salt = [0u8; 32];
    let mut csprng = OsRng;
    csprng.fill_bytes(&mut salt);

    let params = Params::new(DEFAULT_LOG_N, DEFAULT_R, DEFAULT_P, 32)
        .map_err(|e| format!("Invalid params, error: {e}"))
        .unwrap();

    let n_bytes = u32::to_le_bytes((2 as u32).pow(DEFAULT_LOG_N as u32));
    let r_bytes = u32::to_le_bytes(DEFAULT_R);
    let p_bytes = u32::to_le_bytes(DEFAULT_P);

    let mut derived_key = [0u8; 32];
    scrypt(
        password.as_ref().as_bytes(),
        &salt,
        &params,
        &mut derived_key,
    )
    .map_err(|e| format!("Scrypt failed: {:?}", e))
    .unwrap();

    let (pair, _) = sr25519::Pair::generate();

    let mut plaintext = Vec::with_capacity(
        PAIR_HDR.len() + pair.to_raw_vec().len() + PAIR_DIV.len() + pair.public().len(),
    );

    plaintext.extend_from_slice(&PAIR_HDR);
    plaintext.extend_from_slice(&pair.to_raw_vec());
    plaintext.extend_from_slice(&PAIR_DIV);
    plaintext.extend_from_slice(&pair.public().0);

    let ciphertext = xsalsa20_poly1305_encrypt(derived_key, &plaintext).unwrap();

    let mut encoded_bytes = Vec::with_capacity(201);
    encoded_bytes.extend_from_slice(&salt);
    encoded_bytes.extend_from_slice(&n_bytes);
    encoded_bytes.extend_from_slice(&p_bytes);
    encoded_bytes.extend_from_slice(&r_bytes);
    encoded_bytes.extend_from_slice(&ciphertext);

    let encoded = general_purpose::STANDARD.encode(encoded_bytes);

    let encoded_key = EncodedKey {
        encoded,
        encoding: Encoding {
            content: vec!["pkcs8".to_string(), "sr25519".to_string()],
            type_field: vec!["scrypt".to_string(), "xsalsa20-poly1305".to_string()],
            version: 3,
        },
        address: general_purpose::STANDARD.encode(pair.public().0),
        meta: Meta::default(),
    };

    let res = serde_json::to_string_pretty(&encoded_key).unwrap();

    let dir_path = Path::new(out.as_ref());

    // Join the directory path with the file name
    let full_path = dir_path.join(format!("{:?}.json", hex::encode(pair.public())));
    //TODO

    open_or_create_file(full_path, res.as_bytes()).unwrap();
    Ok(res)
}

fn open_or_create_file(path: PathBuf, contents: &[u8]) -> io::Result<()> {
    // Open the file in read/write mode, create it if it doesn't exist
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    // Optional: Write something to the file if it's newly created
    file.write_all(contents)?;

    Ok(())
}

fn xsalsa20_poly1305_encrypt(derived_key: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Create a GenericArray from a fixed-size slice
    let key: GenericArray<u8, typenum::U32> = derived_key.into();

    let cipher = XSalsa20Poly1305::new(&key);
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("Failed to encrypt, {:?}", e))
        .unwrap();

    let mut res = Vec::with_capacity(nonce.len() + ciphertext.len());
    res.extend_from_slice(&nonce.to_vec());
    res.extend_from_slice(&ciphertext.to_vec());

    Ok(res)
}
