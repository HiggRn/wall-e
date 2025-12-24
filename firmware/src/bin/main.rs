#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use alloc::{format, string::ToString};

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
        master::{Config as SpiConfig, Spi},
    },
    time::{Duration, Instant, Rate},
    uart::{Config as UartConfig, Uart},
    usb_serial_jtag::UsbSerialJtag,
};

use esp_storage::FlashStorage;
use itertools::Itertools;
use log::error;

use mipidsi::{Builder, interface::SpiInterface, models::ST7735s};
use wall_e_firmware::{
    storage::WalletStorage,
    transport::SerialTransport,
    wallet::{Wallet, WalletSession},
};

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    esp_println::println!("{info}");
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
    // let serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    let serial = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_rx(peripherals.GPIO20)
        .with_tx(peripherals.GPIO21);
    let mut transport = SerialTransport::new(serial);

    // set up wallet
    let flash_storage = FlashStorage::new(peripherals.FLASH);
    let storage = WalletStorage::new(flash_storage);
    let mut wallet = Wallet::new(storage);

    // set up Trng
    let _rng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1); // no need to reborrow since we need it through out the cycle
    let mut rng = Trng::try_new().unwrap(); // Unwrap is safe as we have enabled TrngSource.

    // set up display
    let mut delay = Delay::new();
    let cs = Output::new(peripherals.GPIO7, Level::High, OutputConfig::default());
    let dc = Output::new(peripherals.GPIO6, Level::Low, OutputConfig::default());
    let rst = Output::new(peripherals.GPIO10, Level::High, OutputConfig::default());
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_mode(Mode::_0)
            .with_frequency(Rate::from_mhz(30)),
    )
    .unwrap()
    .with_sck(peripherals.GPIO2)
    .with_mosi(peripherals.GPIO3);
    let spi_device = ExclusiveDevice::new_no_delay(spi, cs).unwrap();
    let mut spi_buffer = [0u8; 512];

    let di = SpiInterface::new(spi_device, dc, &mut spi_buffer);
    let mut display = Builder::new(ST7735s, di)
        .display_size(80, 160)
        .reset_pin(rst)
        .init(&mut delay)
        .unwrap();

    // wallet wrong pin count
    let mut wrong_pin_count = 0;

    // turn LED green to show everything is fine
    let mut led = Output::new(peripherals.GPIO1, Level::Low, OutputConfig::default());
    led.set_high();

    loop {
        // get command
        let command = match transport.poll() {
            Ok(Some(command)) => command,
            Ok(None) => continue,
            Err(err) => {
                esp_println::println!("{err}");
                continue;
            }
        };

        // delegate command
        let result = match command {
            Command::Ping => Ok(wallet.ping()),
            Command::GetStatus => Ok(wallet.get_status()),
            Command::Initialize => wallet.initialize(&mut rng),
            Command::Unlock { mut pin } => wallet.unlock(&mut pin),
            Command::SetPin { mut pin } => wallet.set_pin(&mut rng, &mut pin),
            Command::Sign { tx } => {
                if let Some(WalletSession::Operating {
                    ref key_pair,
                    tx_context: None,
                }) = wallet.session
                {
                    // display tx_confirming
                    wallet.current_displayed = Some(tx.clone().into());
                    // set timer
                    wallet.session = Some(WalletSession::Operating {
                        key_pair: key_pair.clone(),
                        tx_context: Some((tx, Instant::now())),
                    });
                    wallet.status = WalletStatus::TxConfirming;
                    Ok(Response::Confirming)
                } else {
                    Err(WalletError::SessionError)
                }
            }
            Command::Receive => wallet.receive(),
            Command::Wipe => wallet.wipe(),
            Command::Restore { mnemonic } => {
                let phrase = mnemonic.iter().map(|s| s.to_string()).join(" ");
                wallet.restore(&phrase)
            }
        };

        // send back results
        let e = match result {
            Ok(response) => transport.send(response),
            Err(WalletError::WrongPin) => {
                wrong_pin_count += 1;
                transport.send(Response::Error(WalletError::WrongPin))
            }
            Err(err) => transport.send(Response::Error(err)),
        };
        if let Err(transport_err) = e {
            esp_println::println!("{transport_err}");
        }

        // wipe wallet if wrong PIN too many times
        if wrong_pin_count >= MAX_WRONG_PIN_COUNT {
            wrong_pin_count = 0;
            let _ = wallet.wipe().unwrap();
            continue;
        }

        // detect button pressed or not
        let is_low = button.is_low();
        let is_pressed = is_low && !was_pressed;
        was_pressed = is_low;

        // display if in particular state
        let result = match (wallet.status, &mut wallet.session) {
            (
                WalletStatus::MnemonicConfirming { ref mut idx },
                Some(WalletSession::Seeding {
                    entropy: _,
                    mnemonic: Some(words),
                }),
            ) => {
                if *idx == words.len() {
                    // stop display
                    wallet.current_displayed = None;
                    wallet.status = WalletStatus::PinSetting;
                    transport
                        .send(Response::RequireSetPin)
                        .map_err(|e| e.into())
                } else if is_pressed {
                    // display another word
                    wallet.current_displayed =
                        Some(format!("{}: {}", *idx + 1, words[*idx]).into());
                    *idx += 1;

                    Ok(())
                } else {
                    Ok(())
                }
            }
            (
                WalletStatus::TxConfirming,
                Some(WalletSession::Operating {
                    key_pair,
                    tx_context: Some((_, timer)),
                }),
            ) => {
                if timer.elapsed() > Duration::from_secs(60) {
                    // time out, treated as cancel
                    // stop display
                    wallet.current_displayed = None;
                    // cancel
                    wallet.status = WalletStatus::Ready;
                    // reset session
                    wallet.session = Some(WalletSession::Operating {
                        key_pair: key_pair.clone(),
                        tx_context: None,
                    });
                    transport.send(Response::Rejected).map_err(|e| e.into())
                } else if is_pressed {
                    // button pressed, user confirmed
                    // stop display
                    wallet.current_displayed = None;
                    // sign
                    match wallet.sign() {
                        Ok(response) => transport.send(response).map_err(|e| e.into()),
                        Err(e) => Err(e),
                    }
                } else {
                    // waiting
                    Ok(())
                }
            }
            _ => Ok(()),
        };

        // TODO: This is still a pretty bad way to deal with the error
        if let Err(err) = result {
            if let Err(transport_err) = transport.send(Response::Error(err)) {
                esp_println::println!("{transport_err}");
            }
        }

        // display current_displayed
        if let Some(ref current_displayed) = wallet.current_displayed {
            if let Err(err) = current_displayed.display(&mut display) {
                esp_println::println!("{err:?}");
            }
        }
    }
}
