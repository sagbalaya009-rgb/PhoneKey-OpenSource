//! Compact, high-contrast QR bitmap for the file-opening window.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use qrcode::{QrCode, types::Color};

pub type QrImageError = Box<dyn Error + Send + Sync>;

fn bitmap(code: &QrCode) -> Result<Vec<u8>, QrImageError> {
    const BORDER: usize = 4;
    const SCALE: usize = 6;
    const HEADER: usize = 54;
    let side = (code.width() + 2 * BORDER) * SCALE;
    let stride = (side * 3 + 3) & !3;
    let pixel_bytes = stride * side;
    let file_bytes = HEADER + pixel_bytes;
    let mut bitmap = vec![255u8; file_bytes];
    bitmap[..HEADER].fill(0);
    bitmap[0..2].copy_from_slice(b"BM");
    bitmap[2..6].copy_from_slice(&u32::try_from(file_bytes)?.to_le_bytes());
    bitmap[10..14].copy_from_slice(&(HEADER as u32).to_le_bytes());
    bitmap[14..18].copy_from_slice(&40u32.to_le_bytes());
    bitmap[18..22].copy_from_slice(&u32::try_from(side)?.to_le_bytes());
    bitmap[22..26].copy_from_slice(&u32::try_from(side)?.to_le_bytes());
    bitmap[26..28].copy_from_slice(&1u16.to_le_bytes());
    bitmap[28..30].copy_from_slice(&24u16.to_le_bytes());
    bitmap[34..38].copy_from_slice(&u32::try_from(pixel_bytes)?.to_le_bytes());
    let modules = code.to_colors();
    for module_y in 0..code.width() {
        for module_x in 0..code.width() {
            if modules[module_y * code.width() + module_x] != Color::Dark {
                continue;
            }
            for dy in 0..SCALE {
                for dx in 0..SCALE {
                    let x = (module_x + BORDER) * SCALE + dx;
                    let y = (module_y + BORDER) * SCALE + dy;
                    let pixel = HEADER + (side - 1 - y) * stride + x * 3;
                    bitmap[pixel..pixel + 3].fill(0);
                }
            }
        }
    }
    Ok(bitmap)
}

/// Publish the expiry first and the complete image last, so the UI never
/// opens a partially written bitmap. The caller owns this disposable path.
pub fn write_qr_image(
    payload: &str,
    expires_at_ms: u64,
    destination: &Path,
) -> Result<(), QrImageError> {
    let code = QrCode::new(payload.as_bytes())?;
    let bytes = bitmap(&code)?;
    let temporary = destination.with_extension("bmp.pending");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = output.write_all(&bytes).and_then(|()| output.sync_all());
    drop(output);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    fs::write(
        destination.with_extension("expiry"),
        expires_at_ms.to_string(),
    )?;
    fs::rename(&temporary, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_qr_is_a_valid_uncompressed_bitmap_with_a_white_border() {
        let code = QrCode::new(b"PKF3|dummy-file-test").unwrap();
        let bitmap = bitmap(&code).unwrap();
        assert_eq!(&bitmap[..2], b"BM");
        assert_eq!(
            u32::from_le_bytes(bitmap[2..6].try_into().unwrap()) as usize,
            bitmap.len()
        );
        assert_eq!(&bitmap[6..10], &[0; 4]);
        assert_eq!(&bitmap[30..34], &[0; 4]);
        assert_eq!(bitmap[28], 24);
        assert_eq!(bitmap[29], 0);
        assert_eq!(&bitmap[54..57], &[255; 3]);
        assert!(bitmap[54..].iter().any(|value| *value == 0));
    }
}
