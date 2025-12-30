use std::{
    str::FromStr,
    sync::mpsc::{Receiver, Sender},
    time::Duration,
};

use bip39::Language;
use common::{
    ADDR_LEN, Command, MNEMONIC_MAX_WORD_LEN, MNEMONIC_SEQ_LEN, PIN_LEN, Response, TxFields,
    error::WalletError,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::{Terminal, prelude::Backend};
use thiserror::Error;

use crate::{
    io::{IoAction, IoEvent},
    ui,
};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SignForm {
    // Input buffers
    pub nonce: String,
    pub to: String,    // Hex string
    pub value: String, // Wei (decimal or hex)
    pub data: String,  // Hex data
    pub gas_limit: String,
    pub max_fee: String,
    pub priority_fee: String,

    // UI State
    pub focus_index: usize, // 0 to 6 (mapped to fields above)
}

impl SignForm {
    pub fn get_target(&mut self) -> &mut String {
        match self.focus_index {
            0 => &mut self.nonce,
            1 => &mut self.to,
            2 => &mut self.value,
            3 => &mut self.data,
            4 => &mut self.gas_limit,
            5 => &mut self.max_fee,
            6 => &mut self.priority_fee,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ParseTxFieldsError {
    #[error("int parsing error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("hex decoding error: {0}")]
    ParseHexError(#[from] hex::FromHexError),
}

impl TryInto<TxFields> for SignForm {
    type Error = ParseTxFieldsError;

    fn try_into(self) -> Result<TxFields, Self::Error> {
        let mut to = [0u8; ADDR_LEN];
        eprintln!("{}", self.to.strip_prefix("0x").unwrap());
        to.copy_from_slice(&hex::decode(&self.to.strip_prefix("0x").unwrap())?);
        Ok(TxFields {
            chain_id: 11155111, // Sepolia Testnet
            nonce: self.nonce.parse()?,
            max_priority_fee: self.priority_fee.parse()?,
            max_fee: self.max_fee.parse()?,
            gas_limit: self.gas_limit.parse()?,
            to,
            value: self.value.parse()?,
            data: hex::decode(&self.data)?,
        })
    }
}

/// Each state of app corresponds to a page
#[derive(Debug, Default, Clone, PartialEq)]
pub enum AppState {
    /// not connected to wallet
    #[default]
    Unconnected,
    /// empty wallet
    EmptyWallet,
    // confirm mnemonic on the wallet
    MnemonicConfirm,
    /// restore wallet
    MnemonicInput {
        mnemonic: Vec<String>,
    },
    /// pin inputting
    PinInput {
        pin: Vec<u8>,
        is_set_pin: bool,
    },
    /// unlocked wallet
    Unlocked,
    /// sign transaction
    Sign {
        form: SignForm,
    },
    /// confirm transaction on the wallet
    TxConfirm,
    /// display content
    Display {
        content: String,
    },
    /// ask for confirmation to wipe wallet
    Wipe,
    /// error, and the app state to fall back to
    Error(String, Box<AppState>),
    /// exitting
    Exit,
}

/// Application struct
#[derive(Debug)]
pub struct App {
    /// app state
    app_state: AppState,
    /// thread communication
    io_tx: Sender<IoAction>, // Send commands here
    io_rx: Receiver<IoEvent>, // Read responses here
}

impl App {
    pub fn new(io_tx: Sender<IoAction>, io_rx: Receiver<IoEvent>) -> Self {
        Self {
            app_state: AppState::default(),
            io_tx,
            io_rx,
        }
    }

    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> anyhow::Result<()> {
        loop {
            // draw frame
            terminal.draw(|f| ui::draw_frame(f, &self.app_state))?;

            // 1. Handle IO Events (Non-blocking)
            // This replaces your blocking get_response calls
            while let Ok(event) = self.io_rx.try_recv() {
                match event {
                    IoEvent::ResponseReceived(resp) => self.handle_response(resp),
                    IoEvent::Connected(app_state) => self.app_state = app_state,
                    IoEvent::Error(e) => { /* handle error */ }
                    _ => {}
                }
            }

            // 2. Handle Keyboard Input
            if event::poll(Duration::from_millis(16))? {
                // ~60 FPS
                if let Event::Key(key) = event::read()? {
                    self.handle_input(key);
                }
            }

            // 3. State Logic (Triggering commands)
            self.tick();

            // 4. Check exit
            if self.app_state == AppState::Exit {
                // TODO: not safe, should ask the wallet to clear cache
                break;
            }
        }

        Ok(())
    }

    // Logic to send commands based on state (regardless of user input)
    fn tick(&mut self) {
        match self.app_state {
            AppState::Unconnected => {
                // Send connect request periodically, not every frame
                self.io_tx.send(IoAction::Connect).unwrap();
            }
            _ => {}
        }
    }

    // Centralized response handling
    fn handle_response(&mut self, resp: Response) {
        match (&mut self.app_state, resp) {
            // --- Mnemonic Confirmation ---
            (AppState::MnemonicConfirm, Response::RequireSetPin) => {
                self.app_state = AppState::PinInput {
                    pin: vec![],
                    is_set_pin: true,
                };
            }

            // --- Restore ---
            (AppState::MnemonicInput { .. }, Response::RequireSetPin) => {
                self.app_state = AppState::PinInput {
                    pin: vec![],
                    is_set_pin: true,
                };
            }

            // --- Pin Operations ---
            (
                AppState::PinInput {
                    is_set_pin: true, ..
                },
                Response::Done,
            ) => {
                self.app_state = AppState::PinInput {
                    pin: vec![],
                    is_set_pin: false,
                };
            }
            (
                AppState::PinInput {
                    is_set_pin: false, ..
                },
                Response::Done,
            ) => {
                self.app_state = AppState::Unlocked;
            }

            // --- Unlocked Operations ---
            (AppState::Unlocked, Response::Address(addr)) => {
                self.app_state = AppState::Display {
                    content: addr.to_string(),
                };
            }
            (AppState::Wipe, Response::Done) => {
                self.app_state = AppState::EmptyWallet;
            }

            // --- Signing ---
            (AppState::Sign { .. }, Response::Signature(signature)) => {
                self.app_state = AppState::Display {
                    content: format!("Signature: {}", signature),
                };
            }

            // --- Errors ---
            (AppState::PinInput { .. }, Response::Error(WalletError::WrongPinDataWiped)) => {
                self.app_state = AppState::Error(
                    WalletError::WrongPinDataWiped.to_string(),
                    Box::new(AppState::EmptyWallet),
                );
            }
            (AppState::PinInput { pin, .. }, Response::Error(WalletError::WrongPin)) => {
                pin.clear();
                let prev_state = self.app_state.clone();
                self.app_state =
                    AppState::Error(WalletError::WrongPin.to_string(), Box::new(prev_state));
            }
            (prev_state, Response::Error(err)) => {
                self.app_state = AppState::Error(err.to_string(), Box::new(prev_state.clone()));
            }
            (AppState::TxConfirm, Response::Rejected) => {
                self.app_state = AppState::Error(
                    "Command Rejected".into(),
                    Box::new(AppState::Sign {
                        form: SignForm::default(),
                    }),
                );
            }
            (prev_state, Response::Rejected) => {
                self.app_state =
                    AppState::Error("Command Rejected".into(), Box::new(prev_state.clone()));
            }
            (_, _) => {}
        }
    }

    // Centralized keyboard event handling
    fn handle_input(&mut self, key: KeyEvent) {
        if !key.is_press() {
            // only deal with press event
            return;
        }

        // Global exit
        if key.code == KeyCode::Char('q') {
            self.app_state = AppState::Exit;
            return;
        }

        match &mut self.app_state {
            AppState::Unconnected => {} // Waiting for tick logic to connect

            AppState::EmptyWallet => match key.code {
                KeyCode::Char('i') => {
                    let _ = self.io_tx.send(IoAction::Send(Command::Initialize));
                    self.app_state = AppState::MnemonicConfirm;
                }
                KeyCode::Char('r') => {
                    self.app_state = AppState::MnemonicInput {
                        mnemonic: vec![String::new()],
                    }
                }
                _ => {}
            },

            AppState::MnemonicConfirm => {
                // If the user wants to abort waiting for hardware confirmation
                if key.code == KeyCode::Esc {
                    self.app_state = AppState::EmptyWallet;
                }
            }

            AppState::MnemonicInput { mnemonic } => match key.code {
                KeyCode::Enter if mnemonic.len() == MNEMONIC_SEQ_LEN => {
                    for s in mnemonic.iter() {
                        if Language::English.find_word(s).is_none() {
                            self.app_state = AppState::Error(
                                format!("invalid mnemonic '{s}'"),
                                Box::new(AppState::MnemonicInput {
                                    mnemonic: vec![String::new()],
                                }),
                            );
                            return;
                        }
                    }

                    let mut mnemonic_iter = mnemonic.iter();
                    let mnemonic_idx = core::array::from_fn(|_| {
                        let s = mnemonic_iter.next().unwrap();
                        Language::English.find_word(s).unwrap()
                    });

                    let _res = self.io_tx.send(IoAction::Send(Command::Restore {
                        mnemonic: mnemonic_idx,
                    }));

                    // eprintln!("Command sent! {res:?}");
                }
                KeyCode::Enter => mnemonic.push(String::new()),
                KeyCode::Char(c) if c.is_ascii_alphabetic() => {
                    let last_word = mnemonic.last_mut().unwrap();
                    if last_word.len() < MNEMONIC_MAX_WORD_LEN {
                        last_word.push(c.to_ascii_lowercase());
                    }
                }
                KeyCode::Backspace => {
                    let length = mnemonic.len();
                    if let Some(last) = mnemonic.last_mut() {
                        if last.is_empty() && length > 1 {
                            mnemonic.pop();
                        } else {
                            last.pop();
                        }
                    }
                }
                KeyCode::Esc => self.app_state = AppState::EmptyWallet,
                _ => {}
            },

            AppState::PinInput { pin, is_set_pin } => match key.code {
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    pin.push(u8::from_str(&c.to_string()).unwrap());

                    if pin.len() == PIN_LEN {
                        // Convert Vec<u8> to [u8; 6]
                        let mut pin_arr = [0u8; PIN_LEN];
                        pin_arr.copy_from_slice(pin);

                        let cmd = if *is_set_pin {
                            Command::SetPin { pin: pin_arr }
                        } else {
                            Command::Unlock { pin: pin_arr }
                        };

                        let _ = self.io_tx.send(IoAction::Send(cmd));
                        // UI stays in PinInput until handle_response receives Done or Error
                    }
                }
                KeyCode::Backspace => {
                    pin.pop();
                }
                KeyCode::Esc => self.app_state = AppState::EmptyWallet,
                _ => {}
            },

            AppState::Unlocked => match key.code {
                KeyCode::Char('s') => {
                    self.app_state = AppState::Sign {
                        form: SignForm::default(),
                    }
                }
                KeyCode::Char('r') => {
                    let _ = self.io_tx.send(IoAction::Send(Command::Receive));
                }
                KeyCode::Char('w') => self.app_state = AppState::Wipe,
                _ => {}
            },

            AppState::Sign { form } => match key.code {
                // Navigation
                KeyCode::Tab | KeyCode::Down => {
                    form.focus_index = (form.focus_index + 1) % 7;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focus_index = (form.focus_index + 6) % 7;
                }
                // Typing
                KeyCode::Char(c) => form.get_target().push(c),
                KeyCode::Backspace => {
                    form.get_target().pop();
                }
                // Submit
                KeyCode::Enter => match form.clone().try_into() {
                    Ok(tx) => {
                        let _ = self.io_tx.send(IoAction::Send(Command::Sign { tx }));
                        self.app_state = AppState::TxConfirm;
                    }
                    Err(e) => {
                        let prev = self.app_state.clone();
                        self.app_state = AppState::Error(e.to_string(), Box::new(prev));
                    }
                },
                KeyCode::Esc => self.app_state = AppState::Unlocked,
                _ => {}
            },

            AppState::TxConfirm => {
                // Cancel transaction waiting?
                if key.code == KeyCode::Esc {
                    let _ = self.io_tx.send(IoAction::Send(Command::Cancel));
                    self.app_state = AppState::Unlocked;
                }
            }

            AppState::Display { .. } => match key.code {
                KeyCode::Esc => {
                    let _ = self.io_tx.send(IoAction::Send(Command::Cancel));
                    self.app_state = AppState::Unlocked;
                }
                _ => {}
            },

            AppState::Wipe => match key.code {
                KeyCode::Enter => {
                    let _ = self.io_tx.send(IoAction::Send(Command::Wipe));
                }
                KeyCode::Esc => self.app_state = AppState::Unlocked,
                _ => {}
            },

            AppState::Error(_, next_state) => match key.code {
                KeyCode::Enter | KeyCode::Esc => self.app_state = *next_state.clone(),
                _ => {}
            },

            AppState::Exit => {}
        }
    }
}
