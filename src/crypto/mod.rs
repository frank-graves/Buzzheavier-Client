pub mod vault;

use age::secrecy::ExposeSecret;
use age::x25519;
use age::Identity;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

// Genera un par de llaves (Pública para cifrar, Privada para descifrar)
pub fn generate_keypair() -> (String, String) {
    let identity = x25519::Identity::generate();
    let public_key = identity.to_public();

    let identity_str = identity.to_string().expose_secret().to_owned();
    let public_str = public_key.to_string();

    (public_str, identity_str)
}

// Cifra un archivo local usando la llave pública
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    public_key_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key: x25519::Recipient = public_key_str.parse()?;

    let mut input = File::open(input_path)?;
    let mut output = File::create(output_path)?;

    let encryptor = age::Encryptor::with_recipients(vec![Box::new(public_key)])
        .ok_or("Error configurando cifrador")?;

    let mut writer = encryptor.wrap_output(&mut output)?;

    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;
    }

    writer.finish()?;
    Ok(())
}

// Descifra un archivo local usando la llave privada
#[allow(dead_code)] // Phase 4e: descifrado al vuelo en la descarga
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    identity_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity: x25519::Identity = identity_str.parse()?;

    let mut input = File::open(input_path)?;
    let mut output = File::create(output_path)?;

    let decryptor = age::Decryptor::new(&mut input)?;

    let mut reader = match decryptor {
        age::Decryptor::Recipients(d) => d.decrypt(std::iter::once(&identity as &dyn Identity))?,
        age::Decryptor::Passphrase(_) => {
            return Err("Los archivos con contraseña no están soportados en esta prueba".into());
        }
    };

    std::io::copy(&mut reader, &mut output)?;
    Ok(())
}
