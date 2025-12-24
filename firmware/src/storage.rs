use common::error::WalletError;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use esp_storage::FlashStorage;
use serde::{Deserialize, Serialize};

// The NVS partition usually starts here. Check your partitions.csv if unsure.
const STORAGE_OFFSET: u32 = 0x9000;

pub const FLASH_MAGIC: u32 = 0xDEADBEEF;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FlashData {
    pub magic: u32, // 0xDEADBEEF
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub enc_entropy: [u8; 48], // 4 magic + 32 entropy + 12 padding
}

#[derive(Debug)]
pub struct WalletStorage<'s> {
    flash_storage: FlashStorage<'s>,
}

impl<'s> WalletStorage<'s> {
    pub fn new(flash_storage: FlashStorage<'s>) -> Self {
        Self { flash_storage }
    }

    pub fn save(&mut self, data: &FlashData) -> Result<(), WalletError> {
        // 1. Serialize struct to bytes
        // Max size = 80 bytes data + overhead ~ 100 bytes
        let mut buffer = [0u8; 128];
        let used_bytes = postcard::to_slice(data, &mut buffer)?;

        // 2. ERASE the sector first!
        // Flash can only flip 1 -> 0. Erase flips 0 -> 1.
        // If you don't erase, your data will be corrupt garbage.
        // 4096 is the standard sector size.
        self.flash_storage
            .erase(STORAGE_OFFSET, STORAGE_OFFSET + FlashStorage::SECTOR_SIZE)
            .map_err(|_| WalletError::FlashStorageError)?;

        // 3. WRITE the bytes
        self.flash_storage
            .write(STORAGE_OFFSET, used_bytes)
            .map_err(|_| WalletError::FlashStorageError)?;

        Ok(())
    }

    pub fn load(&mut self) -> Result<Option<FlashData>, WalletError> {
        // Read raw bytes (enough to cover the struct)
        let mut buffer = [0u8; 128];
        self.flash_storage
            .read(STORAGE_OFFSET, &mut buffer)
            .map_err(|_| WalletError::FlashStorageError)?;

        // Deserialize
        let data: FlashData = postcard::from_bytes(&buffer)?; // If deserialize fails, it's likely empty/garbage

        // Validate Magic
        if data.magic != FLASH_MAGIC {
            return Ok(None);
        }

        Ok(Some(data))
    }

    pub fn wipe(&mut self) -> Result<(), WalletError> {
        // Erase the sector to 0xFF
        self.flash_storage
            .erase(STORAGE_OFFSET, STORAGE_OFFSET + FlashStorage::SECTOR_SIZE)
            .map_err(|_| WalletError::FlashStorageError)
    }
}
