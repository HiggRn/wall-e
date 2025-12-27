use common::{Command, MAX_MESSAGE_SIZE, Response, Transport, error::TransportError};
use esp_hal::{Blocking, uart::Uart};

pub struct SerialTransport<'d> {
    // serial: UsbSerialJtag<'d, Blocking>,
    serial: Uart<'d, Blocking>,
    rx_buffer: [u8; MAX_MESSAGE_SIZE],
    rx_idx: usize,
}

impl<'d> SerialTransport<'d> {
    // pub fn new(serial: UsbSerialJtag<'d, Blocking>) -> Self {
    pub fn new(serial: Uart<'d, Blocking>) -> Self {
        Self {
            serial,
            rx_buffer: [0u8; MAX_MESSAGE_SIZE],
            rx_idx: 0,
        }
    }
}

impl<'d> Transport<Response, Command> for SerialTransport<'d> {
    fn poll(&mut self) -> Result<Option<Command>, TransportError> {
        // 1. SAFETY CHECK: Ensure we have space left in the buffer
        if self.rx_idx >= self.rx_buffer.len() {
            self.rx_idx = 0; // Reset on overflow
            return Err(TransportError::BufferOverflow);
        }

        if !self.serial.read_ready() {
            return Ok(None);
        }

        // We use a non-blocking read pattern here (assuming typical embedded-hal-nb or similar)
        // If your read() returns WouldBlock, this loop just won't enter, which is fine.
        while let Ok(read_size) = self.serial.read(&mut self.rx_buffer[self.rx_idx..])
            && read_size > 0
        {
            // UPDATE INDEX
            self.rx_idx += read_size;

            // CHECK DELIMITER
            if self.rx_buffer[self.rx_idx - 1] == 0x00 {
                // DECODE
                let valid_data = &mut self.rx_buffer[..self.rx_idx - 1];

                // If valid_data is empty (just a 0x00 byte received), ignore it
                if valid_data.is_empty() {
                    self.rx_idx = 0;
                    continue;
                }

                // Perform in-place decoding
                let command =
                    postcard::from_bytes_cobs(valid_data).inspect_err(|_| self.rx_idx = 0)?;

                // Reset for next message
                self.rx_idx = 0;
                return Ok(Some(command));
            }

            // Break to yield to the main loop
            break;
        }

        Ok(None)
    }

    fn send(&mut self, response: Response) -> Result<(), TransportError> {
        // serialize
        let mut serialize_buf = [0u8; common::MAX_MESSAGE_SIZE];
        let serialized = postcard::to_slice(&response, &mut serialize_buf)?;

        // COBS encode
        let mut encode_buf = [0u8; common::MAX_MESSAGE_SIZE + 3];
        let encoded_len = cobs::encode(serialized.as_ref(), &mut encode_buf);

        // send
        self.serial.write(&encode_buf[..=encoded_len]).ok();
        self.serial.flush().ok();

        Ok(())
    }
}
