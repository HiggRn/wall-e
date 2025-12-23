#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use alloc::{format, string::ToString, vec::Vec};

use common::{Command, MAX_WRONG_PIN_COUNT, Response, Transport, WalletStatus, error::WalletError};
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::{
    clock::CpuClock,
    delay::Delay,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    rng::{Trng, TrngSource},
    spi::{
        Mode,
        master::{Config, Spi},
    },
    time::{Duration, Instant, Rate},
    usb_serial_jtag::UsbSerialJtag,
};

use esp_storage::FlashStorage;
use itertools::Itertools;
use k256::elliptic_curve::zeroize::Zeroize;
use log::error;

use mipidsi::{Builder, interface::SpiInterface, models::ST7735s};
use wall_e_firmware::{
    display::DisplayedObject, storage::WalletStorage, transport::SerialTransport, wallet,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

extern crate alloc;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 66320);

    // set up button
    let button = Input::new(
        peripherals.GPIO9,
        InputConfig::default().with_pull(Pull::Up),
    );
    let mut was_pressed = false;

    // set up transport
    let serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    let mut transport = SerialTransport::new(serial);

    // set up storage
    let flash_storage = FlashStorage::new(peripherals.FLASH);
    let mut storage = WalletStorage::new(flash_storage);

    // set up status, Empty if storage didn't detect anything, else Locked
    let flash_data = match storage.load() {
        Ok(flash) => flash,
        Err(err) => panic!("load error: {err}"),
    };
    let mut status = if flash_data.is_some() {
        WalletStatus::Locked
    } else {
        WalletStatus::Empty
    };

    // set up Trng
    let _rng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1); // no need to reborrow since we need it through out the cycle
    let mut rng = Trng::try_new().unwrap(); // Unwrap is safe as we have enabled TrngSource.

    // RAM-stored secret key and public key
    let mut secret_key = None;
    let mut public_key = None;

    // set up display
    let mut delay = Delay::new();
    let cs = Output::new(peripherals.GPIO5, Level::High, OutputConfig::default());
    let dc = Output::new(peripherals.GPIO4, Level::Low, OutputConfig::default());
    let rst = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    let spi = Spi::new(
        peripherals.SPI2,
        Config::default()
            .with_mode(Mode::_0)
            .with_frequency(Rate::from_mhz(30)),
    )
    .unwrap()
    .with_sck(peripherals.GPIO6)
    .with_mosi(peripherals.GPIO7)
    .with_miso(peripherals.GPIO2);
    let spi_device = ExclusiveDevice::new_no_delay(spi, cs).unwrap();
    let mut spi_buffer = [0u8; 512];

    let di = SpiInterface::new(spi_device, dc, &mut spi_buffer);
    let mut display = Builder::new(ST7735s, di)
        .reset_pin(rst)
        .init(&mut delay)
        .unwrap();

    // wallet wrong pin count
    let mut wrong_pin_count = 0;

    // temp storage for entropy, mnemonic, tx, qrcode
    let mut entropy = [0u8; 32];
    let mut mnemonic_confirming = None;
    let mut words: Option<Vec<_>> = None;
    let mut tx_confirming = None;
    let mut tx_confirm_start = None;
    let mut current_displayed: Option<DisplayedObject> = None;

    loop {
        // get command
        let command = match transport.poll() {
            Ok(Some(command)) => command,
            Ok(None) => continue,
            Err(err) => {
                error!("{err}");
                continue;
            }
        };

        // delegate command
        let result = match command {
            Command::Ping => wallet::ping(&mut transport),
            Command::GetStatus => wallet::get_status(&mut transport, &mut status),
            Command::Initialize => {
                wallet::initialize(&mut transport, &mut status, &mut rng).map(|out| {
                    if let Some((ent, mne)) = out {
                        entropy.copy_from_slice(&ent);
                        mnemonic_confirming = Some(mne);
                    }
                })
            }
            Command::Unlock { mut pin } => {
                wallet::unlock(&mut transport, &mut status, &flash_data, &mut pin).map(
                    |(sk, pk)| {
                        secret_key = sk;
                        public_key = pk;
                    },
                )
            }
            Command::SetPin { mut pin } => wallet::set_pin(
                &mut transport,
                &mut status,
                &mut rng,
                &mut storage,
                &mut pin,
                &mut entropy,
            ),
            Command::Sign { tx } => {
                tx_confirming = Some(tx);
                status = WalletStatus::TxConfirming;
                transport.send(Response::Confirming).map_err(|e| e.into())
            }
            Command::Receive => wallet::receive(&mut transport, &mut status, &public_key)
                .map(|qr| current_displayed = qr.map(|qr| qr.into())),
            Command::Wipe => wallet::wipe(
                &mut transport,
                &mut status,
                &mut storage,
                &mut secret_key,
                &mut public_key,
            ),
            Command::Restore { mnemonic } => {
                let phrase = mnemonic.iter().map(|s| s.to_string()).join(" ");
                wallet::restore(&mut transport, &mut status, &phrase).map(|ent| {
                    if let Some(ent) = ent {
                        entropy.copy_from_slice(&ent);
                    }
                })
            }
        };

        // TODO: This is a pretty bad way to deal with the errors.
        if let Err(err) = result {
            if err == WalletError::WrongPin {
                wrong_pin_count += 1;
            }
            if let Err(transport_err) = transport.send(Response::Error(err)) {
                error!("{transport_err}");
            }
        }

        // wipe wallet if wrong PIN too many times
        if wrong_pin_count >= MAX_WRONG_PIN_COUNT {
            wrong_pin_count = 0;

            // wipe storage
            storage.wipe().unwrap();

            // wipe key
            if let Some(ref mut sk) = secret_key {
                sk.zeroize();
                secret_key = None;
            }
            if let Some(ref mut pk) = public_key {
                pk.zeroize();
                public_key = None;
            }

            status = WalletStatus::Empty;
            continue;
        }

        // detect button pressed or not
        let is_low = button.is_low();
        let is_pressed = is_low && !was_pressed;
        was_pressed = is_low;

        // set iterator if we have a mnemonic to confirm
        if words.is_none() && mnemonic_confirming.is_some() {
            words = Some(mnemonic_confirming.as_ref().unwrap().words().collect());
        }

        // display if in particular state
        let result = match status {
            WalletStatus::MnemonicConfirming { ref mut idx } => {
                if *idx == words.as_ref().unwrap().len() {
                    // stop display
                    current_displayed = None;
                    status = WalletStatus::PinSetting;
                    transport
                        .send(Response::RequireSetPin)
                        .map_err(|e| e.into())
                } else if is_pressed {
                    // display another word
                    current_displayed =
                        Some(format!("{}: {}", *idx + 1, words.as_ref().unwrap()[*idx]).into());
                    *idx += 1;

                    Ok(())
                } else {
                    Ok(())
                }
            }
            WalletStatus::TxConfirming => match tx_confirm_start {
                None => {
                    // set timer
                    tx_confirm_start = Some(Instant::now());
                    // display tx_confirming
                    current_displayed = tx_confirming.clone().map(|tx| tx.into());
                    Ok(())
                }
                Some(s) => {
                    // time out, treated as cancel
                    if s.elapsed() > Duration::from_secs(60) {
                        // reset timer
                        tx_confirm_start = None;
                        // stop display
                        current_displayed = None;
                        // cancel
                        status = WalletStatus::Ready;
                        transport.send(Response::Rejected).map_err(|e| e.into())
                    } else if is_pressed {
                        // reset timer
                        tx_confirm_start = None;
                        // stop display
                        current_displayed = None;
                        // sign
                        wallet::sign(
                            &mut transport,
                            &mut status,
                            &secret_key,
                            tx_confirming.as_ref().unwrap(),
                        )
                    } else {
                        Ok(())
                    }
                }
            },
            _ => Ok(()),
        };

        // TODO: This is still a pretty bad way to deal with the error
        if let Err(err) = result {
            if let Err(transport_err) = transport.send(Response::Error(err)) {
                error!("{transport_err}");
            }
        }

        // display current_displayed
        if let Some(ref current_displayed) = current_displayed {
            if let Err(err) = current_displayed.display(&mut display) {
                if let Err(transport_err) = transport.send(Response::Error(err)) {
                    error!("{transport_err}");
                }
            }
        }
    }
}
