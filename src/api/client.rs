use reqwest::{header, Client};
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

use super::models::{AccountInfo, ApiResponse, FileSystemItem, UploadResponse};

pub struct BuzzHeavierClient {
    client: Client,
}

impl BuzzHeavierClient {
    pub fn new(account_id: &str) -> Result<Self, String> {
        let mut headers = header::HeaderMap::new();
        let auth_value = format!("Bearer {}", account_id.trim());
        let header_val = header::HeaderValue::from_str(&auth_value)
            .map_err(|e| format!("Token inválido: {e}"))?;
        headers.insert(header::AUTHORIZATION, header_val);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        // Timeouts defensivos: un endpoint lento ya no puede dejar la tarea
        // colgada sin emitir `Failed`.
        let client = Client::builder()
            .default_headers(headers)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| format!("Error creando cliente HTTP: {e}"))?;

        // Nota: el token vive en la HeaderValue dentro de `Client`; reqwest no
        // expone API de zeroización para headers. El plaintext que captura el
        // llamador (ui::fetch_dir / ui::start_upload) sí se zeroiza con
        // `Zeroizing<String>`. Eliminamos la copia extra `account_id: String`.
        Ok(Self { client })
    }

    #[allow(dead_code)] // Phase 4d: validación de token al añadir cuenta
    pub async fn get_account(&self) -> Result<AccountInfo, String> {
        let url = "https://buzzheavier.com/api/account";
        let res = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Error de red: {e}"))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| format!("Error leyendo respuesta: {e}"))?;

        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ));
        }

        let parsed: ApiResponse<AccountInfo> = serde_json::from_str(&text).map_err(|e| {
            format!(
                "Error parseando JSON: {e}\nRespuesta: {}",
                text.chars().take(300).collect::<String>()
            )
        })?;

        Ok(parsed.data)
    }

    /// Retorna (root_directory_id, items)
    pub async fn get_root_directory(&self) -> Result<(String, Vec<FileSystemItem>), String> {
        let url = "https://buzzheavier.com/api/fs";
        let res = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Error de red: {e}"))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| format!("Error leyendo respuesta: {e}"))?;

        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ));
        }

        let parsed: ApiResponse<FileSystemItem> = serde_json::from_str(&text).map_err(|e| {
            format!(
                "Error parseando JSON: {e}\nRespuesta: {}",
                text.chars().take(300).collect::<String>()
            )
        })?;

        Ok((parsed.data.id, parsed.data.children.unwrap_or_default()))
    }

    #[allow(dead_code)] // Phase 4d: creación de carpetas
    pub async fn create_directory(&self, parent_id: &str, name: &str) -> Result<(), String> {
        let url = format!("https://buzzheavier.com/api/fs/{}", parent_id);
        let body = serde_json::json!({ "name": name });

        let res = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Error de red: {e}"))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| format!("Error leyendo respuesta: {e}"))?;

        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ));
        }
        Ok(())
    }

    pub async fn upload_file(
        &self,
        parent_id: &str,
        file_path: &Path,
    ) -> Result<UploadResponse, String> {
        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        let url = format!("https://w.buzzheavier.com/{parent_id}/{file_name}");

        let file = File::open(file_path)
            .await
            .map_err(|e| format!("Error abriendo archivo: {e}"))?;
        let stream = FramedRead::new(file, BytesCodec::new());
        let body = reqwest::Body::wrap_stream(stream);

        let res = self
            .client
            .put(url)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("Error de red: {e}"))?;

        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| format!("Error leyendo respuesta: {e}"))?;

        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ));
        }

        let upload_res: UploadResponse = serde_json::from_str(&text).map_err(|e| {
            format!(
                "Error parseando JSON: {e}\nRespuesta: {}",
                text.chars().take(300).collect::<String>()
            )
        })?;

        Ok(upload_res)
    }
}
