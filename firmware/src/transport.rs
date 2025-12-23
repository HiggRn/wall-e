use common::{Command, MAX_MESSAGE_SIZE, Response, Transport, error::TransportError};
use esp_hal::{Blocking, usb_serial_jtag::UsbSerialJtag};

pub struct SerialTransport<'d> {
    serial: UsbSerialJtag<'d, Blocking>,
    rx_buffer: [u8; MAX_MESSAGE_SIZE],
    rx_idx: usize,
}

impl<'d> SerialTransport<'d> {
    pub fn new(serial: UsbSerialJtag<'d, Blocking>) -> Self {
        Self {
            serial,
            rx_buffer: [0u8; MAX_MESSAGE_SIZE],
            rx_idx: 0,
        }
    }
}

impl<'d> Transport<Response, Command> for SerialTransport<'d> {
    fn poll(&mut self) -> Result<Option<Command>, TransportError> {
        while let Ok(byte) = self.serial.read_byte() {
            if byte == 0x00 {
                if self.rx_idx == 0 {
                    continue; // Skip leading zeros or empty frames
                }

                let decode_len = cobs::decode_in_place(&mut self.rx_buffer[..self.rx_idx])?;

                self.rx_idx = 0;

                let command = postcard::from_bytes(&self.rx_buffer[..decode_len])?;

                return Ok(Some(command));
            } else {
                if self.rx_idx >= self.rx_buffer.len() {
                    self.rx_idx = 0; // Prevent overflow
                    return Err(TransportError::BufferOverflow);
                }
                self.rx_buffer[self.rx_idx] = byte;
                self.rx_idx += 1;
            }
        }

        // No full frame has arrived yet
        Ok(None)
    }

    fn send(&mut self, response: Response) -> Result<(), TransportError> {
        // serialize
        let mut serialize_buf = [0u8; common::MAX_MESSAGE_SIZE];
        let serialized = postcard::to_slice(&response, &mut serialize_buf)?;

        // COBS encode
        let mut encode_buf = [0u8; common::MAX_MESSAGE_SIZE + 2];
        let encoded_len = cobs::encode(serialized.as_ref(), &mut encode_buf);

        // send
        self.serial.write(&encode_buf[..encoded_len]).ok();
        self.serial.write_byte_nb(0x00).ok();
        self.serial.flush_tx().ok();

        Ok(())
    }
}
