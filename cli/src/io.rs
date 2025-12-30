use std::{
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

use common::{Command, Response, Transport, WalletStatus};
use serialport::{SerialPortType, UsbPortInfo};

use crate::{app::AppState, transport::SerialTransport};

pub enum IoEvent {
    Connected(AppState), // send initial state
    ResponseReceived(Response),
    Error(String),
}

pub enum IoAction {
    Connect,
    Send(Command),
}

/// Spawns the background IO thread and returns the communication channels.
pub fn spawn_background_thread() -> (Sender<IoAction>, Receiver<IoEvent>) {
    let (tx_ui, rx_ui) = mpsc::channel::<IoEvent>(); // IO -> UI
    let (tx_io, rx_io) = mpsc::channel::<IoAction>(); // UI -> IO

    std::thread::spawn(move || {
        let mut transport: Option<SerialTransport> = None;

        loop {
            // 1. Check for incoming commands from UI (Non-blocking)
            if let Ok(action) = rx_io.try_recv() {
                match action {
                    IoAction::Connect => {
                        if let (Some(t), app_state) = try_connect() {
                            transport = Some(t);
                            let _ = tx_ui.send(IoEvent::Connected(app_state));
                        }
                    }
                    IoAction::Send(cmd) => {
                        if let Some(t) = &mut transport {
                            if let Err(e) = t.send(cmd) {
                                let _ = tx_ui.send(IoEvent::Error(e.to_string()));
                            }
                        }
                    }
                }
            }

            // 2. Poll the device (Non-blocking)
            if let Some(t) = &mut transport {
                match t.poll() {
                    Ok(Some(resp)) => {
                        let _ = tx_ui.send(IoEvent::ResponseReceived(resp));
                    }
                    Err(e) => {
                        let _ = tx_ui.send(IoEvent::Error(e.to_string()));
                    }
                    _ => {}
                }
            }

            // Sleep briefly to prevent 100% CPU usage on the IO thread
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    (tx_io, rx_ui)
}

fn try_connect() -> (Option<SerialTransport>, AppState) {
    // list all available ports
    let ports = serialport::available_ports().unwrap_or_default();

    for p in ports {
        // filter for Espressif VID (0x303A)
        if !matches!(
            p.port_type,
            SerialPortType::UsbPort(UsbPortInfo { vid: 0x303A, .. })
        ) {
            continue;
        }

        // try to open the port, 115200 baud
        let port_builder = serialport::new(p.port_name, 115200).timeout(Duration::from_millis(10));
        let Ok(port) = port_builder.open() else {
            continue;
        };

        // clear any garbage currently in the buffer
        let _ = port.clear(serialport::ClearBuffer::Input);

        let mut transport = SerialTransport::new(port);

        // ask for status to verify
        if transport.send(Command::GetStatus).is_ok() {
            // wait briefly for a response
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                if let Ok(Some(r)) = transport.poll() {
                    let app_state = match r {
                        Response::Status(WalletStatus::Empty) => AppState::EmptyWallet,
                        Response::Status(WalletStatus::Locked) => AppState::PinInput {
                            pin: vec![],
                            is_set_pin: false,
                        },
                        r => AppState::Error(
                            format!("unexpected response {r:?}"),
                            Box::new(AppState::Unconnected),
                        ),
                    };

                    // attach transport
                    return (Some(transport), app_state);
                }

                // sleep a tiny bit to avoid busy looping during handshake
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    (None, AppState::Unconnected)
}
