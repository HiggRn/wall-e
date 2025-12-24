use core::str::FromStr;

use alloc::{format, string::String};
use common::TxFields;
use derive_more::From;
use embedded_graphics::{
    Drawable,
    mono_font::{MonoTextStyle, ascii::FONT_6X10},
    pixelcolor::Rgb565,
    prelude::{DrawTarget, Point, Primitive, RgbColor, Size},
    primitives::{PrimitiveStyle, Rectangle},
    text::{Alignment, Text},
};
use qrcode::QrCode;
use sha2::Digest;
use sha3::Keccak256;

// Define a color for the display (ST7735 usually uses Rgb565)
const TEXT_COLOR: Rgb565 = Rgb565::GREEN;
const LABEL_COLOR: Rgb565 = Rgb565::CYAN;
const BG_COLOR: Rgb565 = Rgb565::BLACK;
const QR_LIGHT: Rgb565 = Rgb565::WHITE;
const QR_DARK: Rgb565 = Rgb565::BLACK;

#[derive(Clone, From)]
pub enum DisplayedObject {
    Text(String),
    Tx(TxFields),
    QrCode(QrCode),
}

impl DisplayedObject {
    pub fn display<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        // clear screen
        target.clear(BG_COLOR)?;

        // common text style
        let text_style = MonoTextStyle::new(&FONT_6X10, TEXT_COLOR);
        let label_style = MonoTextStyle::new(&FONT_6X10, LABEL_COLOR);

        match self {
            Self::Text(s) => {
                Text::with_alignment(
                    s,
                    Point::new(target.bounding_box().center().x, 20), // Center horizontally, 20px down
                    text_style,
                    Alignment::Center,
                )
                .draw(target)?;
            }
            Self::QrCode(qrcode) => {
                // get QR code matrix
                let matrix = qrcode.to_colors();
                let width = qrcode.width();

                // calculate scale to fit screen (80px width is tight)
                // ST7735 is 80x160. A standard QR might be 21x21 to 29x29 modules.
                // Scale factor 2 is usually safe for Version 1-3 QRs on 80px width.
                let scale = if width * 3 <= 80 { 3 } else { 2 };

                // center the QR code
                let display_width = target.bounding_box().size.width as i32;
                let display_height = target.bounding_box().size.height as i32;
                let qr_px_width = (width * scale) as i32;
                let start_x = (display_width - qr_px_width) / 2;
                let start_y = (display_height - qr_px_width) / 2;

                // draw each module
                for (y, row) in matrix.chunks(width).enumerate() {
                    for (x, color) in row.iter().enumerate() {
                        let pixel_color = match color {
                            qrcode::Color::Dark => QR_DARK,
                            qrcode::Color::Light => QR_LIGHT,
                        };

                        // draw a rectangle for the "pixel" (scaled up)
                        Rectangle::new(
                            Point::new(
                                start_x + (x as i32 * scale as i32),
                                start_y + (y as i32 * scale as i32),
                            ),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(pixel_color))
                        .draw(target)?;
                    }
                }
            }
            Self::Tx(tx) => {
                // HEADER
                Text::with_alignment(
                    "CONFIRM TX",
                    Point::new(target.bounding_box().center().x, 15),
                    label_style,
                    Alignment::Center,
                )
                .draw(target)?;

                // CHAIN ID (Top Right or just below header)
                let chain_str = format!("Chain: {}", tx.chain_id);
                Text::new(&chain_str, Point::new(5, 30), text_style).draw(target)?;

                // DESTINATION (Truncated)
                // A full 42-char address won't fit on 80px width (max ~13 chars).
                // We show start..end (e.g., "0xAB12..EF78")
                Text::new("To:", Point::new(5, 50), label_style).draw(target)?;

                let to_str = format_address(&tx.to);
                Text::new(&to_str, Point::new(5, 62), text_style).draw(target)?;

                // VALUE (Amount)
                // We display Wei. Converting to decimal ETH cleanly on embedded
                // without float errors can be heavy, but usually essential.
                // For now, we display raw Wei or a simplified "ETH" label if logic permits.
                Text::new("Value (Wei):", Point::new(5, 82), label_style).draw(target)?;

                // Truncate value if it's massive, or wrap it
                let val_str = format!("{}", tx.value);
                Text::new(&val_str, Point::new(5, 94), text_style).draw(target)?;

                // MAX FEE (Optional, but good for safety)
                Text::new("Max Fee:", Point::new(5, 114), label_style).draw(target)?;
                let fee_str = format!("{}", tx.max_fee);
                Text::new(&fee_str, Point::new(5, 126), text_style).draw(target)?;
            }
        }
        Ok(())
    }
}

pub fn format_address(hex_addr: &[u8]) -> String {
    let hex_addr_encoded = hex::encode(hex_addr);
    let hash = Keccak256::digest(hex_addr_encoded.as_bytes());
    let mut addr = String::from_str("0x").unwrap(); // if we can't even allocate a 2-byte string then we should panic

    for (i, char) in hex_addr_encoded.chars().enumerate() {
        if char.is_digit(10) {
            // Numbers (0-9) never change
            addr.push(char);
        } else {
            // It's a letter (a-f). Check the hash.
            // We check the 'ith' nibble of the hash.
            // i=0 -> byte 0 high nibble
            // i=1 -> byte 0 low nibble
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0x0F
            } else {
                hash[i / 2] & 0x0F
            };

            // If nibble >= 8, Uppercase. Else, Lowercase.
            if nibble >= 8 {
                addr.push(char.to_ascii_uppercase());
            } else {
                addr.push(char);
            }
        }
    }

    addr
}
