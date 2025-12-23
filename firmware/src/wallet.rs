use core::{fmt::Write, str::FromStr};

use alloc::string::String;

use aes::Aes256;
use bip32::{DerivationPath, XPrv, secp256k1::elliptic_curve::zeroize::Zeroize};
use bip39::{Language, Mnemonic};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use common::{
    Command, PIN_LEN, Response, Signature, Transport, TxFields, WalletStatus, error::WalletError,
};

use esp_hal::rng::Trng;

use heapless::String as HString;

use hmac::Hmac;
use itertools::Itertools;
use k256::ecdsa::SigningKey;

use qrcode::QrCode;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

use crate::{display, storage::WalletStorage};

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const KEK_ROUNDS: u32 = 10_000;

const MAGIC: &[u8; 4] = b"WALL";

pub const FLASH_MAGIC: u32 = 0xDEADBEEF;

const ENTROPY_SIZE: usize = 32;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FlashData {
    pub magic: u32, // 0xDEADBEEF
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub enc_entropy: [u8; 48], // 4 magic + 32 entropy + 12 padding
}

pub fn ping(transport: &mut dyn Transport<Response, Command>) -> Result<(), WalletError> {
    Ok(transport.send(Response::Pong)?)
}

pub fn get_status(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
) -> Result<(), WalletError> {
    Ok(transport.send(Response::Status(*status))?)
}

pub fn initialize(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    rng: &mut Trng,
) -> Result<Option<([u8; ENTROPY_SIZE], Mnemonic)>, WalletError> {
    if *status != WalletStatus::Empty {
        transport.send(Response::Rejected)?;
        return Ok(None);
    }

    // generate entropy
    let mut entropy = [0u8; 32];
    rng.read(&mut entropy);

    // convert to mnemonic words
    let mnemonic = Mnemonic::from_entropy(&entropy)?;

    // send reponse
    transport.send(Response::Confirming)?;

    *status = WalletStatus::MnemonicConfirming { idx: 0 };

    Ok(Some((entropy, mnemonic)))
}

pub fn unlock(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    flash_data: &Option<FlashData>,
    pin: &mut [u8],
) -> Result<
    (
        Option<[u8; bip32::KEY_SIZE]>,
        Option<[u8; bip32::KEY_SIZE + 1]>,
    ),
    WalletError,
> {
    if *status != WalletStatus::Locked {
        transport.send(Response::Rejected)?;
        return Ok((None, None));
    }

    let Some(flash_data) = flash_data else {
        return Err(WalletError::FlashStorageError);
    };

    // get salt, iv and enc_entropy
    let FlashData {
        magic: _,
        salt,
        iv,
        enc_entropy,
    } = flash_data;

    // compute kek
    let mut kek = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(pin, salt, KEK_ROUNDS, &mut kek)?;

    // overwrite PIN
    pin.zeroize();

    // decrypt entropy
    let decryptor = Aes256CbcDec::new(&kek.into(), iv.into());
    let mut payload = [0u8; 36];
    decryptor.decrypt_padded_b2b_mut::<Pkcs7>(enc_entropy, &mut payload)?;
    if payload[..4] != *MAGIC {
        return Err(WalletError::WrongPin);
    }
    let entropy = &mut payload[4..36];

    // convert to mnemonic
    let mnemonic = Mnemonic::from_entropy(&entropy)?;

    // join the mnemonic words into a long password
    let password = mnemonic.words().join(" ");

    // convert to seed
    // TODO: add support for passphrases
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(password.as_bytes(), b"mnemonic", 2048, &mut seed)?;

    // overwrite entropy and mnemonic
    entropy.zeroize();
    drop(mnemonic);

    // derive secret key
    let path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
    let xprv = XPrv::derive_from_path(&seed, &path)?;
    let secret_key = xprv.to_bytes();
    let public_key = xprv.public_key().to_bytes();

    transport.send(Response::Done)?;

    *status = WalletStatus::Ready;

    Ok((Some(secret_key), Some(public_key)))
}

pub fn set_pin(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    rng: &mut Trng,
    storage: &mut WalletStorage,
    pin: &mut [u8; PIN_LEN],
    entropy: &mut [u8; ENTROPY_SIZE],
) -> Result<(), WalletError> {
    if *status != WalletStatus::PinSetting {
        return Ok(transport.send(Response::Rejected)?);
    }

    // generate salt
    let mut salt = [0u8; 16];
    rng.read(&mut salt);

    // compute kek
    let mut kek = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(pin, &salt, KEK_ROUNDS, &mut kek)?;

    // overwrite PIN
    pin.zeroize();

    // generate iv
    let mut iv = [0u8; 16];
    rng.read(&mut iv);

    // encrypt entropy
    let mut payload = [0u8; 36]; // 4 + 32
    payload[..4].copy_from_slice(MAGIC);
    payload[4..].copy_from_slice(entropy.as_ref());
    let encryptor = Aes256CbcEnc::new(&kek.into(), &iv.into());
    let mut enc_entropy = [0u8; 48]; // padding to 256 bits
    encryptor.encrypt_padded_b2b_mut::<Pkcs7>(&payload, &mut enc_entropy)?;

    // overwrite kek and entropy
    kek.zeroize();
    entropy.zeroize();

    // store salt, iv and enc_entropy
    let flash_data = FlashData {
        magic: FLASH_MAGIC,
        salt: salt,
        iv: iv,
        enc_entropy: enc_entropy,
    };
    storage.save(&flash_data)?;

    transport.send(Response::Done)?;

    *status = WalletStatus::Locked;

    Ok(())
}

pub fn sign(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    secret_key: &Option<[u8; bip32::KEY_SIZE]>,
    tx: &TxFields,
) -> Result<(), WalletError> {
    if *status != WalletStatus::TxConfirming {
        return Ok(transport.send(Response::Rejected)?);
    }

    let Some(sk) = secret_key else {
        return Err(WalletError::KeyMissing);
    };

    // serialize tx
    let mut stream = RlpStream::new();

    stream.begin_list(9);
    stream.append(&tx.chain_id);
    stream.append(&tx.nonce);
    stream.append(&tx.max_priority_fee);
    stream.append(&tx.max_fee);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to.as_slice());
    let value_leading_zeros = tx.value.leading_zeros() as usize / 8;
    let value_bytes = tx.value.to_be_bytes();
    stream.append(&&value_bytes[value_leading_zeros..]);
    stream.append(&tx.data);

    stream.begin_list(0);

    let s = stream.out().to_vec();

    // hash
    let mut hasher = Keccak256::new();
    hasher.update(&[0x02]);
    hasher.update(&s);
    let h: [u8; 32] = hasher.finalize().into();

    // sign with secret key
    let signing_key = SigningKey::from_bytes(sk.into())?;
    let (signature, recid) = signing_key.sign_prehash_recoverable(&h)?;

    // send back signature
    let bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    s.copy_from_slice(&bytes[32..64]);
    let signature = Signature {
        r,
        s,
        v: recid.to_byte(),
    };
    transport.send(Response::Signature(signature.into()))?;

    *status = WalletStatus::Ready;

    Ok(())
}

pub fn receive(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    public_key: &Option<[u8; bip32::KEY_SIZE + 1]>,
) -> Result<Option<QrCode>, WalletError> {
    if *status != WalletStatus::Ready {
        transport.send(Response::Rejected)?;
        return Ok(None);
    }

    let Some(pk) = public_key else {
        return Err(WalletError::KeyMissing);
    };

    // hash public key
    let mut hasher = Keccak256::new();
    hasher.update(pk);
    let h: [u8; 32] = hasher.finalize().into();

    // convert to checksum address string
    let addr = display::format_address(&h[12..])?;

    transport.send(Response::Address(addr.clone()))?;

    // display addr also as QR code
    let mut uri = HString::<64>::new();
    write!(uri, "ethereum:{addr}").map_err(|_| WalletError::AddressCapacityError)?;
    let qrcode = QrCode::new(uri.as_bytes())?;

    *status = WalletStatus::Ready;

    Ok(Some(qrcode))
}

pub fn wipe(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    storage: &mut WalletStorage,
    secret_key: &mut Option<[u8; bip32::KEY_SIZE]>,
    public_key: &mut Option<[u8; bip32::KEY_SIZE + 1]>,
) -> Result<(), WalletError> {
    if *status != WalletStatus::Ready {
        return Ok(transport.send(Response::Rejected)?);
    }

    // wipe storage
    storage.wipe()?;

    // wipe key
    if let Some(sk) = secret_key {
        sk.zeroize();
        *secret_key = None;
    }
    if let Some(pk) = public_key {
        pk.zeroize();
        *public_key = None;
    }

    transport.send(Response::Done)?;

    *status = WalletStatus::Empty;

    Ok(())
}

pub fn restore(
    transport: &mut dyn Transport<Response, Command>,
    status: &mut WalletStatus,
    phrase: &String,
) -> Result<Option<[u8; ENTROPY_SIZE]>, WalletError> {
    if *status != WalletStatus::Empty {
        transport.send(Response::Rejected)?;
        return Ok(None);
    }

    // restore entropy
    let (ent, ent_len) =
        Mnemonic::parse_in_normalized(Language::English, phrase)?.to_entropy_array();

    if ent_len != ENTROPY_SIZE + 1 {
        return Err(WalletError::InvalidMnemonic);
    }

    let mut entropy = [0u8; ENTROPY_SIZE];
    entropy.copy_from_slice(&ent[..ENTROPY_SIZE]);

    // ask for PIN setting
    transport.send(Response::RequireSetPin)?;

    *status = WalletStatus::PinSetting;

    Ok(Some(entropy))
}
