use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Error)]
pub enum WalletError {
    // Hardware/Storage Errors
    #[error("flash storage error")]
    FlashStorageError,
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    // Logic Errors
    #[error("incorrect pin")]
    WrongPin,
    #[error("invalid mnemonic sequence")]
    InvalidMnemonic,
    #[error("no key in memory")]
    KeyMissing,

    // Crypto Errors
    #[error("padding error")]
    PadError,
    #[error("bip32 error")]
    Bip32Error,
    #[error("bip39 error")]
    Bip39Error,
    #[error("signature error")]
    SignatureError,
    #[error("pbkdf2 error: invalid length")]
    PBKDF2InvalidLength,
    #[error("address capacity not enough")]
    AddressCapacityError,
    #[error("qrcode error")]
    QrError,

    // Communication
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    // Display
    #[error("display error")]
    DisplayError,
}

macro_rules! impl_from_map {
    ($($variant:ident <= $err_type:ty),* $(,)?) => {
        $(
            impl From<$err_type> for WalletError {
                fn from(_: $err_type) -> Self {
                    Self::$variant
                }
            }
        )*
    };
}

impl_from_map! {
    PadError             <= cipher::inout::PadError,
    WrongPin             <= cipher::inout::block_padding::UnpadError,
    Bip32Error           <= bip32::Error,
    PBKDF2InvalidLength  <= digest::InvalidLength,
    Bip39Error           <= bip39::Error,
    SignatureError       <= k256::ecdsa::Error,
    AddressCapacityError <= heapless::CapacityError,
    QrError              <= qrcode::types::QrError,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Error)]
pub enum TransportError {
    #[error("cobs decode error")]
    CobsDecodeError,
    #[error("postcard encode/decode error: {0}")]
    EncodeDecodeError(#[from] postcard::Error),
    #[error("buffer overflow")]
    BufferOverflow,
    #[error("IO error")]
    IOError,
    #[error("IO timeout")]
    IOTimeout,
}

impl From<cobs::DecodeError> for TransportError {
    fn from(_err: cobs::DecodeError) -> Self {
        Self::CobsDecodeError
    }
}
