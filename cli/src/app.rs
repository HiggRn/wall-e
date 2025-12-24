use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use common::{
    ADDR_LEN, Command, MAX_WRONG_PIN_COUNT, MNEMONIC_MAX_WORD_LEN, MNEMONIC_SEQ_LEN, PIN_LEN,
    Response, Transport, TxFields, WalletStatus,
    error::{TransportError, WalletError},
};
use crossterm::event::{self, Event, KeyCode};
use ratatui::{Terminal, prelude::Backend};
use serialport::{SerialPortType, UsbPortInfo};
use thiserror::Error;

use crate::{transport::SerialTransport, ui};

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
    #[error("int parsing error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("hex decoding error")]
    ParseHexError(#[from] hex::FromHexError),
}

impl TryInto<TxFields> for SignForm {
    type Error = ParseTxFieldsError;

    fn try_into(self) -> Result<TxFields, Self::Error> {
        let mut to = [0u8; ADDR_LEN];
        to.copy_from_slice(&hex::decode(&self.data.strip_prefix("0x").unwrap())?);
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
#[derive(Default)]
pub struct App {
    /// app state
    app_state: AppState,
    /// connection
    transport: Option<Box<dyn Transport<Command, Response>>>,
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> anyhow::Result<()> {
        let mut wrong_pin_count = 0;
        loop {
            // draw frame
            terminal.draw(|f| ui::draw_frame(f, &self.app_state))?;

            // try to connect if not connected
            if self.app_state == AppState::Unconnected {
                self.try_connect();
            }

            // get user input (non-blocking)
            if !event::poll(Duration::from_millis(100))? {
                continue;
            }

            let Event::Key(key) = event::read()? else {
                continue;
            };

            // do nothing if no key is pressed
            if !key.is_press() {
                continue;
            }

            // if user input 'q', then exit
            if key.code == KeyCode::Char('q') {
                self.app_state = AppState::Exit;
                continue;
            }

            // check state
            if self.app_state == AppState::Exit {
                // TODO: not safe, should ask the wallet to clear cache
                break;
            }

            // if connected, then transport shouldn't be None
            let Some(transport) = self.transport.as_mut().map(|b| b.as_mut()) else {
                panic!("connection lost")
            };

            // send command, poll response, transition app state
            match self.app_state {
                AppState::Unconnected => unreachable!(),
                AppState::EmptyWallet => match key.code {
                    KeyCode::Char('i') => initialize(transport, &mut self.app_state),
                    KeyCode::Char('r') => {
                        self.app_state = AppState::MnemonicInput {
                            mnemonic: vec![String::new()],
                        }
                    }
                    _ => {}
                },
                AppState::MnemonicConfirm => mnemonic_confirm(transport, &mut self.app_state),
                AppState::MnemonicInput { ref mut mnemonic } => match key.code {
                    KeyCode::Enter if mnemonic.len() == MNEMONIC_SEQ_LEN => {
                        restore(transport, &mut self.app_state)
                    }
                    KeyCode::Enter => mnemonic.push(String::new()),
                    KeyCode::Char(c) if c.is_ascii_alphabetic() => {
                        // mnemonic is never empty
                        let last_word = mnemonic.last_mut().unwrap();
                        if last_word.len() < MNEMONIC_MAX_WORD_LEN {
                            last_word.push(c.to_ascii_lowercase());
                        }
                    }
                    KeyCode::Esc => self.app_state = AppState::EmptyWallet,
                    _ => {}
                },
                AppState::PinInput {
                    ref mut pin,
                    is_set_pin,
                } => match key.code {
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        pin.push(c as u8);
                        if pin.len() == PIN_LEN {
                            if is_set_pin {
                                set_pin(transport, &mut self.app_state);
                            } else {
                                unlock(transport, &mut self.app_state, &mut wrong_pin_count);
                                if wrong_pin_count >= MAX_WRONG_PIN_COUNT {
                                    self.app_state = AppState::EmptyWallet;
                                    continue;
                                }
                            }
                        }
                    }
                    _ => {}
                },
                AppState::Unlocked => match key.code {
                    KeyCode::Char('s') => {
                        self.app_state = AppState::Sign {
                            form: SignForm::default(),
                        }
                    }
                    KeyCode::Char('r') => receive(transport, &mut self.app_state),
                    KeyCode::Char('w') => self.app_state = AppState::Wipe,
                    _ => {}
                },
                AppState::Sign { ref mut form } => match key.code {
                    // navigation
                    KeyCode::Tab | KeyCode::Down => {
                        form.focus_index = (form.focus_index + 1) % 7; // Cycle through 7 fields
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        form.focus_index = (form.focus_index + 6) % 7; // Cycle through 7 fields
                    }
                    // typing
                    KeyCode::Char(c) => form.get_target().push(c),
                    KeyCode::Backspace => _ = form.get_target().pop(),
                    // submission
                    KeyCode::Enter => sign(transport, &mut self.app_state),
                    // cancel
                    KeyCode::Esc => self.app_state = AppState::Unlocked,
                    _ => {}
                },
                AppState::TxConfirm => tx_confirm(transport, &mut self.app_state),
                AppState::Display { content: _ } => match key.code {
                    KeyCode::Esc => self.app_state = AppState::Unlocked,
                    _ => {}
                },
                AppState::Wipe => match key.code {
                    KeyCode::Enter => wipe(transport, &mut self.app_state),
                    KeyCode::Esc => self.app_state = AppState::Unlocked,
                    _ => {}
                },
                AppState::Error(_, ref next_state) => match key.code {
                    KeyCode::Enter => self.app_state = *next_state.clone(),
                    _ => {}
                },
                AppState::Exit => unreachable!(),
            }
        }

        Ok(())
    }

    fn try_connect(&mut self) {
        // list all available ports
        let ports = serialport::available_ports().unwrap_or_default();

        for p in ports {
            // filter for Espressif VID (0x303A)
            let is_real_hardware = matches!(
                p.port_type,
                SerialPortType::UsbPort(UsbPortInfo { vid: 0x303A, .. })
            );

            // or simulation
            let is_simulation = p.port_name == "COM9" || p.port_name == "/dev/ttyS0";

            if !is_real_hardware && !is_simulation {
                continue;
            }

            // try to open the port, 115200 baud
            let port_builder =
                serialport::new(p.port_name, 115200).timeout(Duration::from_millis(10));
            let Ok(port) = port_builder.open() else {
                continue;
            };

            // clear any garbage currently in the buffer
            let _ = port.clear(serialport::ClearBuffer::Input);

            let mut transport = SerialTransport::new(port);

            // send PING to verify
            if transport.send(Command::Ping).is_ok() {
                // wait briefly for a PONG response
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(500) {
                    if let Ok(Some(Response::Pong)) = transport.poll() {
                        // ask for status
                        if let Err(err) = transport.send(Command::GetStatus) {
                            self.app_state =
                                AppState::Error(format!("{err}"), Box::new(AppState::Unconnected));
                            return;
                        }

                        self.app_state = match get_response(&mut transport) {
                            Ok(Response::Status(WalletStatus::Empty)) => AppState::EmptyWallet,
                            Ok(Response::Status(WalletStatus::Locked)) => AppState::PinInput {
                                pin: vec![],
                                is_set_pin: false,
                            },
                            Ok(r) => AppState::Error(
                                format!("unexpected response {r:?}"),
                                Box::new(AppState::Unconnected),
                            ),
                            Err(err) => {
                                AppState::Error(format!("{err}"), Box::new(AppState::Unconnected))
                            }
                        };

                        // attach transport
                        self.transport = Some(Box::new(transport));
                        return;
                    }

                    // sleep a tiny bit to avoid busy looping during handshake
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

fn initialize(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let prev_state = app_state.clone();

    if let Err(err) = transport.send(Command::Initialize) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Confirming) => AppState::MnemonicConfirm,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn mnemonic_confirm(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let prev_state = app_state.clone();

    if let Err(err) = transport.send(Command::GetStatus) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Status(WalletStatus::PinSetting)) => AppState::PinInput {
            pin: vec![],
            is_set_pin: true,
        },
        Ok(Response::Status(WalletStatus::MnemonicConfirming { .. })) => AppState::MnemonicConfirm,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn restore(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let AppState::MnemonicInput {
        mnemonic: mnemonic_input,
    } = app_state
    else {
        panic!("can't call set pin function in {app_state:?}")
    };

    let prev_state = AppState::MnemonicInput { mnemonic: vec![] };

    let mut mnemonic_iter = mnemonic_input.iter_mut();
    let mnemonic = core::array::from_fn(|_| {
        // guaranteed by the implementation logic, this can't fail
        let s = mnemonic_iter.next().unwrap();
        heapless::String::from_str(s).unwrap()
    });

    if let Err(err) = transport.send(Command::Restore { mnemonic }) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Done) => AppState::Unlocked,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        // this error handling might be incorrect
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn set_pin(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let AppState::PinInput {
        pin: pin_input,
        is_set_pin: true,
    } = app_state
    else {
        panic!("can't call set pin function in {app_state:?}")
    };

    let prev_state = AppState::PinInput {
        pin: vec![],
        is_set_pin: true,
    };

    let mut pin = [0u8; PIN_LEN];
    pin.copy_from_slice(pin_input);

    if let Err(err) = transport.send(Command::SetPin { pin }) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Done) => AppState::Unlocked,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        // this error handling might be incorrect
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn unlock(
    transport: &mut dyn Transport<Command, Response>,
    app_state: &mut AppState,
    wrong_pin_count: &mut u8,
) {
    let AppState::PinInput {
        pin: pin_input,
        is_set_pin: false,
    } = app_state
    else {
        panic!("can't call unlock function in {app_state:?}")
    };

    let prev_state = AppState::PinInput {
        pin: vec![],
        is_set_pin: false,
    };

    let mut pin = [0u8; PIN_LEN];
    pin.copy_from_slice(pin_input);

    if let Err(err) = transport.send(Command::Unlock { pin }) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Done) => AppState::Unlocked,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        // this error handling might be incorrect
        Ok(Response::Error(WalletError::WrongPin)) => {
            *wrong_pin_count += 1;
            AppState::Error(WalletError::WrongPin.to_string(), Box::new(prev_state))
        }
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn sign(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let AppState::Sign { form } = app_state else {
        panic!("can't call sign function in {app_state:?}")
    };

    let prev_state = AppState::Sign {
        form: SignForm::default(),
    };

    let tx = match form.clone().try_into() {
        Ok(tx) => tx,
        Err(err) => {
            *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
            return;
        }
    };

    if let Err(err) = transport.send(Command::Sign { tx }) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Confirming) => AppState::TxConfirm,
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn tx_confirm(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let prev_state = AppState::Sign {
        form: SignForm::default(),
    };

    *app_state = match transport.poll() {
        Ok(Some(Response::Signature(signature))) => AppState::Display {
            content: format!("signature: {signature}"),
        },
        Ok(Some(Response::Rejected)) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        Ok(Some(Response::Error(err))) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(Some(r)) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Ok(None) => AppState::TxConfirm,
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn receive(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let prev_state = app_state.clone();

    if let Err(err) = transport.send(Command::Receive) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Address(addr)) => AppState::Display {
            content: addr.to_string(),
        },
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        // this error handling might be incorrect
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn wipe(transport: &mut dyn Transport<Command, Response>, app_state: &mut AppState) {
    let prev_state = app_state.clone();

    if let Err(err) = transport.send(Command::Wipe) {
        *app_state = AppState::Error(format!("{err}"), Box::new(prev_state));
        return;
    }

    *app_state = match get_response(transport) {
        Ok(Response::Done) => AppState::EmptyWallet,
        Ok(Response::Rejected) => {
            AppState::Error(format!("command has been rejected"), Box::new(prev_state))
        }
        // this error handling might be incorrect
        Ok(Response::Error(err)) => AppState::Error(format!("{err}"), Box::new(prev_state)),
        Ok(r) => AppState::Error(format!("unexpected response {r:?}"), Box::new(prev_state)),
        Err(err) => AppState::Error(format!("{err}"), Box::new(prev_state)),
    };
}

fn get_response(
    transport: &mut dyn Transport<Command, Response>,
) -> Result<Response, TransportError> {
    let start = Instant::now();
    // this must be longer than the timeout for confirming transaction (5s)
    let timeout = Duration::from_secs(10);

    while start.elapsed() < timeout {
        match transport.poll() {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {
                // sleep to yield CPU
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) => return Err(err),
        }
    }

    Err(TransportError::IOTimeout)
}
