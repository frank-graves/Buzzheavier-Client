use serde::{Deserialize, Serialize};

#[allow(dead_code)] // Phase 4d: validación de token al añadir cuenta
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub id: String,
    pub email: Option<String>,
    pub storage_used: Option<u64>,
    pub storage_max: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    #[allow(dead_code)]
    // 200 en éxito; no lo inspeccionamos porque ya validamos `status.is_success()`
    pub code: u32,
    pub data: T,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileSystemItem {
    pub id: String,
    pub name: String,
    pub is_directory: bool,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub children: Option<Vec<FileSystemItem>>,
}

// Respuesta de subida: hoy la UI ignora los campos (solo mira Ok/Err).
#[allow(dead_code)] // Phase 4d: refresco selectivo tras upload
#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    pub id: String,
    pub name: String,
}
