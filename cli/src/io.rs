use std::time::{Duration, Instant};

use common::{Command, Response, Transport, WalletStatus};
use serialport::{SerialPortType, UsbPortInfo};

use crate::{app::AppState, transport::SerialTransport};

pub enum IoEvent {
    Connected(AppState), // send initial state
    Disconnected,
    ResponseReceived(Response),
    Error(String),
}

pub enum IoAction {
    Connect,
    Send(Command),
}

pub fn try_connect() -> (Option<SerialTransport>, AppState) {
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
