use common::{Command, Response, Transport, error::TransportError};
use serialport::SerialPort;

// A buffer big enough to hold the largest serialized message + COBS overhead
const RX_BUFFER_SIZE: usize = 2048;

pub struct SerialTransport {
    port: Box<dyn SerialPort>,
    rx_buffer: Vec<u8>,
}

impl SerialTransport {
    pub fn new(port: Box<dyn SerialPort>) -> Self {
        Self {
            port,
            rx_buffer: Vec::with_capacity(RX_BUFFER_SIZE),
        }
    }
}

impl Transport<Command, Response> for SerialTransport {
    fn poll(&mut self) -> Result<Option<Response>, TransportError> {
        let mut temp_buf = [0u8; RX_BUFFER_SIZE / 2];
        match self.port.read(&mut temp_buf) {
            Ok(0) => { /* No new data */ }
            Ok(n) => self.rx_buffer.extend_from_slice(&temp_buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => { /* No new data, therefore timeout */
            }
            Err(_) => return Err(TransportError::IOError),
        }

        // scan for COBS delimiter (0x00)
        if let Some(pos) = self.rx_buffer.iter().position(|&b| b == 0x00) {
            // Extract the full packet including the delimiter
            let mut packet: Vec<u8> = self.rx_buffer.drain(..=pos).collect();

            // remove the delimiter for processing
            packet.pop();

            // COBS decode
            match postcard::from_bytes_cobs::<Response>(&mut packet) {
                Ok(response) => return Ok(Some(response)),
                Err(_) => {
                    // If parsing fails (CRC bad, etc), just drop the packet
                    return Err(TransportError::CobsDecodeError);
                }
            }
        }

        Ok(None)
    }

    fn send(&mut self, command: Command) -> Result<(), TransportError> {
        let data = postcard::to_vec_cobs::<Command, { common::MAX_MESSAGE_SIZE }>(&command)?;

        self.port
            .write_all(&data)
            .map_err(|_| TransportError::IOError)?;

        self.port.flush().map_err(|_| TransportError::IOError)?;

        Ok(())
    }
}
