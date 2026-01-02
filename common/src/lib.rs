#![no_std]

extern crate alloc;

use alloc::{format, string::ToString, vec::Vec};
use heapless::String as HString;
use serde::{Deserialize, Serialize};

use crate::error::{TransportError, WalletError};

pub mod error;

/// The maximum buffer size (in bytes) for a single message.
pub const MAX_MESSAGE_SIZE: usize = 1024;

/// The number of mnemonic words (256 bits)
pub const MNEMONIC_SEQ_LEN: usize = 24;

// The max length of mnemonic word
pub const MNEMONIC_MAX_WORD_LEN: usize = 8;

/// The length of PIN (6 digits)
pub const PIN_LEN: usize = 6;

/// The length of address length (20 bytes for ETH)
pub const ADDR_LEN: usize = 20;

/// The length of address length (in string, with `0x`)
pub const ADDR_STR_LEN: usize = ADDR_LEN * 2 + 2;

pub const MAX_WRONG_PIN_COUNT: u8 = 10;

/// Commands from the CLI app
#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    /// Get wallet status, expect Status
    GetStatus,
    /// Initialize wallet, expect RequireSetPin
    Initialize,
    /// Lock wallet
    Lock,
    /// Unlock wallet through PIN (ASCII encoded), expect Done
    /// TODO: this is not safe, should move PIN input to wallet
    Unlock { pin: [u8; PIN_LEN] },
    /// Set PIN, expect Done
    /// TODO: this is not safe, should move PIN input to wallet
    SetPin { pin: [u8; PIN_LEN] },
    /// Sign transaction, expect Signature
    Sign { tx: TxFields },
    /// Receive by showing public key, expect Address
    Receive,
    /// Wipe wallet clean, expect Done
    Wipe,
    /// Restore wallet from the mnemonic sentence, expect RequireSetPin
    /// TODO: this is not safe, should move mnemonic input to wallet
    Restore { mnemonic: [u16; MNEMONIC_SEQ_LEN] },
    /// Cancel current command
    /// (only applies to command that requires confirmation)
    Cancel,
}

/// Status of wallet
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum WalletStatus {
    /// No wallet
    Empty,
    /// Locked wallet, require PIN
    Locked,
    /// Unlocked wallet, ready for commands
    Ready,
    /// Confirming mnemonic
    MnemonicConfirming { idx: usize },
    /// Confirming transaction
    TxConfirming,
    /// Waiting to set PIN
    PinSetting,
}

/// Response from the wallet
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Reject command
    Rejected,
    /// Require setting PIN
    RequireSetPin,
    /// Command done
    Done,
    /// Reply wallet status
    Status(WalletStatus),
    /// Transaction signature
    Signature(Signature),
    /// Address for receiving
    Address(HString<ADDR_STR_LEN>),
    /// Error
    Error(WalletError),
}

/// The fields required for an EIP-1559 Transaction
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TxFields {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u64,
    pub max_fee: u64,
    pub gas_limit: u64,
    pub to: [u8; ADDR_LEN], // Ethereum Address
    pub value: u128,        // Amount in Wei
    pub data: Vec<u8>,      // Call data (empty for simple transfers)
}

/// The components of an ECDSA Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8, // y_parity (0 or 1 for EIP-1559)
}

impl ToString for Signature {
    fn to_string(&self) -> alloc::string::String {
        format!(
            "0x{}{}{:02x}",
            hex::encode(self.r),
            hex::encode(self.s),
            self.v
        )
    }
}

/// The interface between the Wallet Logic and the Outside World
pub trait Transport<S, R> {
    /// Checks if a new reply has arrived from the Host.
    ///
    /// Returns:
    /// - Ok(Some(R)): A complete reply is ready to process.
    /// - Ok(None): No reply currently available (buffer empty/incomplete).
    /// - Err(e): Something went wrong with the connection.
    fn poll(&mut self) -> Result<Option<R>, TransportError>;

    /// Sends a message back to the Host.
    ///
    /// This should block until the message is sent (or put into the TX buffer).
    fn send(&mut self, message: S) -> Result<(), TransportError>;
}
