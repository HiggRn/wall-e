use alloc::vec::Vec;
use core::{fmt::Write, str::FromStr};

use aes::Aes256;
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use common::{
    MAX_WRONG_PIN_COUNT, MNEMONIC_SEQ_LEN, PIN_LEN, Response, Signature, TxFields, WalletStatus,
    error::WalletError,
};
use esp_hal::{rng::Trng, time::Instant};
use heapless::String as HString;
use hmac::Hmac;
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use qrcode::QrCode;
use rlp::RlpStream;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::Zeroize;

use crate::{
    display::{self, DisplayedObject},
    storage::{FLASH_MAGIC, FlashData, WalletStorage},
};

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const KEK_ROUNDS: u32 = 10_000;

const MAGIC: &[u8; 4] = b"WALL";

const ENTROPY_SIZE: usize = 32;

const KEY_SIZE: usize = bip32::KEY_SIZE;

#[derive(Debug, Clone, Zeroize)]
pub struct KeyPair {
    secret_key: [u8; KEY_SIZE],
    public_key: [u8; KEY_SIZE + 1],
}

#[derive(Debug, Clone)]
pub enum WalletSession {
    Seeding {
        entropy: [u8; ENTROPY_SIZE],
        mnemonic: Option<Vec<&'static str>>,
    },
    Operating {
        key_pair: KeyPair,
        tx_context: Option<(TxFields, Instant)>,
    },
}

pub struct Wallet<'a> {
    pub status: WalletStatus,
    storage: WalletStorage<'a>,
    pub session: Option<WalletSession>,
    pub current_displayed: Option<(DisplayedObject, bool)>,
    wrong_pin_count: u8,
}

impl<'a> Wallet<'a> {
    pub fn new(mut storage: WalletStorage<'a>) -> Self {
        let status = if matches!(storage.load(), Ok(Some(_))) {
            WalletStatus::Locked
        } else {
            WalletStatus::Empty
        };

        Self {
            status,
            storage,
            session: None,
            current_displayed: None,
            wrong_pin_count: 0,
        }
    }

    pub fn get_status(&self) -> Response {
        Response::Status(self.status)
    }

    pub fn initialize(&mut self, rng: &mut Trng) -> Result<Option<Response>, WalletError> {
        if self.status != WalletStatus::Empty {
            return Ok(Some(Response::Rejected));
        }

        if self.session.is_some() {
            return Err(WalletError::SessionError);
        }

        // generate entropy
        let mut entropy = [0u8; 32];
        rng.read(&mut entropy);

        // convert to mnemonic words
        let mnemonic = Mnemonic::from_entropy(&entropy)?;

        self.status = WalletStatus::MnemonicConfirming { idx: 0 };
        self.session = Some(WalletSession::Seeding {
            entropy,
            mnemonic: Some(mnemonic.words().collect()),
        });

        Ok(None)
    }

    pub fn lock(&mut self) -> Response {
        self.status = if matches!(self.session, Some(WalletSession::Operating { .. })) {
            WalletStatus::Locked
        } else {
            WalletStatus::Empty
        };
        self.session = None;
        Response::Done
    }

    pub fn unlock(&mut self, pin: &mut [u8]) -> Result<Response, WalletError> {
        if self.status != WalletStatus::Locked {
            return Ok(Response::Rejected);
        }

        if self.session.is_some() {
            return Err(WalletError::SessionError);
        }

        let Some(flash_data) = self.storage.load()? else {
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
        pbkdf2::pbkdf2::<Hmac<Sha256>>(pin, &salt, KEK_ROUNDS, &mut kek)?;

        // overwrite PIN
        pin.zeroize();

        // decrypt entropy
        let decryptor = Aes256CbcDec::new(&kek.into(), (&iv).into());
        let mut payload = [0u8; 48];
        decryptor.decrypt_padded_b2b_mut::<Pkcs7>(&enc_entropy, &mut payload)?;
        if payload[..4] != *MAGIC {
            if self.wrong_pin_count >= MAX_WRONG_PIN_COUNT {
                // wipe wallet if wrong PIN too many times
                self.wrong_pin_count = 0;
                let _ = self.wipe()?;
                return Err(WalletError::WrongPinDataWiped);
            } else {
                self.wrong_pin_count += 1;
                return Err(WalletError::WrongPin);
            }
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

        self.session = Some(WalletSession::Operating {
            key_pair: KeyPair {
                secret_key,
                public_key,
            },
            tx_context: None,
        });

        self.status = WalletStatus::Ready;

        Ok(Response::Done)
    }

    pub fn set_pin(
        &mut self,
        rng: &mut Trng,
        pin: &mut [u8; PIN_LEN],
    ) -> Result<Response, WalletError> {
        if self.status != WalletStatus::PinSetting {
            return Ok(Response::Rejected);
        }

        let Some(WalletSession::Seeding {
            mut entropy,
            mnemonic: _,
        }) = self.session
        else {
            return Err(WalletError::SessionError);
        };

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
        self.storage.save(&flash_data)?;

        self.status = WalletStatus::Locked;
        self.session = None;

        Ok(Response::Done)
    }

    pub fn sign(&mut self) -> Result<Response, WalletError> {
        if self.status != WalletStatus::TxConfirming {
            return Ok(Response::Rejected);
        }

        let Some(WalletSession::Operating {
            ref key_pair,
            tx_context: Some((ref tx, _)),
        }) = self.session
        else {
            return Err(WalletError::SessionError);
        };
        let secret_key = key_pair.secret_key;

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
        let signing_key = SigningKey::from_bytes((&secret_key).into())?;
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

        self.status = WalletStatus::Ready;
        self.session = Some(WalletSession::Operating {
            key_pair: key_pair.clone(),
            tx_context: None,
        });

        Ok(Response::Signature(signature.into()))
    }

    pub fn receive(&mut self) -> Result<Response, WalletError> {
        if self.status != WalletStatus::Ready {
            return Ok(Response::Rejected);
        }

        let Some(WalletSession::Operating {
            ref key_pair,
            tx_context: _,
        }) = self.session
        else {
            return Err(WalletError::SessionError);
        };
        let public_key = key_pair.public_key;

        // hash public key
        let mut hasher = Keccak256::new();
        hasher.update(public_key);
        let h: [u8; 32] = hasher.finalize().into();

        // convert to checksum address string
        let addr = display::format_address(&h[12..]);

        // display addr also as QR code
        let mut uri = HString::<64>::new();
        write!(uri, "ethereum:{addr}").map_err(|_| WalletError::AddressCapacityError)?;
        let qrcode = QrCode::new(uri.as_bytes())?;
        self.current_displayed = Some((qrcode.into(), false));

        self.status = WalletStatus::Ready;

        Ok(Response::Address(HString::from_str(&addr)?))
    }

    pub fn wipe(&mut self) -> Result<Response, WalletError> {
        if self.status != WalletStatus::Ready {
            return Ok(Response::Rejected);
        }

        // wipe storage
        self.storage.wipe()?;

        // wipe key
        let Some(WalletSession::Operating {
            ref mut key_pair,
            tx_context: _,
        }) = self.session
        else {
            return Err(WalletError::SessionError);
        };

        key_pair.zeroize();

        self.status = WalletStatus::Empty;
        self.session = None;

        Ok(Response::Done)
    }

    pub fn restore(&mut self, mnemonic: &[u16; MNEMONIC_SEQ_LEN]) -> Result<Response, WalletError> {
        if self.status != WalletStatus::Empty {
            return Ok(Response::Rejected);
        }

        if self.session.is_some() {
            return Err(WalletError::SessionError);
        }

        // restore entropy
        let mut bits = [false; MNEMONIC_SEQ_LEN * 11];

        for (i, idx) in mnemonic.iter().enumerate() {
            for j in 0..11 {
                bits[i * 11 + j] = idx >> (10 - j) & 1 == 1;
            }
        }

        let mut entropy = [0u8; ENTROPY_SIZE];
        for i in 0..ENTROPY_SIZE {
            for j in 0..8 {
                if bits[i * 8 + j] {
                    entropy[i] += 1 << (7 - j);
                }
            }
        }

        // verify the checksum
        let check = Sha256::digest(&entropy[0..ENTROPY_SIZE]);
        for i in 0..ENTROPY_SIZE / 4 {
            if bits[8 * ENTROPY_SIZE + i] != ((check[i / 8] & (1 << (7 - (i % 8)))) > 0) {
                return Err(WalletError::InvalidMnemonic);
            }
        }

        // ask for PIN setting
        self.status = WalletStatus::PinSetting;
        self.session = Some(WalletSession::Seeding {
            entropy,
            mnemonic: None,
        });

        Ok(Response::RequireSetPin)
    }
}
