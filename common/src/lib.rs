#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// The maximum buffer size (in bytes) for a single message.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Commands from the CLI app
#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    /// Check if connected
    Ping,
    /// Unlock wallet through PIN (6 digits)
    /// TODO: this is not safe, should move PIN input to wallet
    Unlock { pin: String },
    /// Get wallet status
    FetchStatus,
    /// Initialize wallet
    Initialize,
    /// Wipe wallet clean
    Wipe,
    /// Restore wallet from the mnemonic sentence
    Restore { mnemonic: String },
    /// Sign transaction
    Sign { tx: Vec<u8> },
    /// Receive by showing public key
    Receive,
}

/// Status of wallet
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Status {
    /// Empty wallet
    Uninitialized,
    /// Locked wallet
    Locked,
    /// Unlocked wallet
    Unlocked,
}

/// Response from the wallet
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Connected
    Pong,
    /// Acknowledge signal
    Ack,
    /// Reply wallet status
    Status(Status),
    /// Transaction signature
    Signature(Vec<u8>),
    /// Address for receiving
    Address(String),
}
