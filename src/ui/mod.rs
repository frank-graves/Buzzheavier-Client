use crate::api::client::BuzzHeavierClient;
use crate::api::models::FileSystemItem;
use crate::crypto::vault::{self, VaultKey};
use crate::db::{AccountRow, Database};
use crate::download::{self, DownloadEvent};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroizing;

enum VaultTaskResult {
    Setup(VaultKey, [u8; 32], Vec<u8>),
    Unlock(VaultKey),
}

enum VaultState {
    NeedsSetup,
    Locked,
    Unlocked(VaultKey),
}

impl VaultState {
    fn is_unlocked(&self) -> bool {
        matches!(self, VaultState::Unlocked(_))
    }
}

#[derive(Default)]
enum ApiState {
    #[default]
    Idle,
    Loading,
    Loaded(String, Vec<FileSystemItem>), // root_id, items
    Error(String),
}

/// Resultado de `get_root_directory` enviado por el hilo de fetch: (root_id, items).
type DirFetchResult = Result<(String, Vec<FileSystemItem>), String>;

pub struct BuzzHeavierApp {
    db: Option<Database>,
    db_error: Option<String>,
    vault: VaultState,
    vault_error: Option<String>,
    vault_task: Option<Receiver<Result<VaultTaskResult, String>>>,

    accounts: Vec<AccountRow>,
    selected: Option<String>,

    current_dir: ApiState,
    api_rx: Option<Receiver<DirFetchResult>>,

    download_rx: Option<UnboundedReceiver<DownloadEvent>>,
    download_status: Option<String>,
    download_progress: f32,

    upload_rx: Option<Receiver<Result<(), String>>>,
    upload_status: Option<String>,

    password_input: Zeroizing<String>,
    password_confirm: Zeroizing<String>,

    add_modal_open: bool,
    add_token: Zeroizing<String>,
    add_label: String,
    add_error: Option<String>,
}

const ARGON2_M: u32 = 65536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
// OWASP 2023 recomienda 12+ para contraseñas maestras en sistemas sin recuperación.
const MIN_PASSWORD_LEN: usize = 12;

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes == 0 {
        "0 B".to_string()
    } else if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}

impl BuzzHeavierApp {
    pub fn new(
        _cc: &eframe::CreationContext<'_>,
        db: Option<Database>,
        db_error: Option<String>,
    ) -> Self {
        let (vault, initial_error) = match (&db, &db_error) {
            (Some(d), _) => match d.has_vault() {
                Ok(true) => (VaultState::Locked, None),
                Ok(false) => (VaultState::NeedsSetup, None),
                Err(e) => (VaultState::Locked, Some(format!("has_vault: {e}"))),
            },
            (None, _) => (VaultState::Locked, None),
        };

        let mut app = Self {
            db,
            db_error: initial_error.or(db_error),
            vault,
            vault_error: None,
            vault_task: None,
            accounts: Vec::new(),
            selected: None,
            current_dir: ApiState::Idle,
            api_rx: None,
            download_rx: None,
            download_status: None,
            download_progress: 0.0,
            upload_rx: None,
            upload_status: None,
            password_input: Zeroizing::new(String::new()),
            password_confirm: Zeroizing::new(String::new()),
            add_modal_open: false,
            add_token: Zeroizing::new(String::new()),
            add_label: String::new(),
            add_error: None,
        };
        app.reload_accounts();
        app
    }

    fn reload_accounts(&mut self) {
        if let Some(db) = &self.db {
            match db.list_accounts() {
                Ok(list) => {
                    self.accounts = list;
                    if let Some(sel) = &self.selected {
                        if !self.accounts.iter().any(|a| &a.id == sel) {
                            self.selected = None;
                            self.current_dir = ApiState::Idle;
                        }
                    }
                }
                Err(e) => self.db_error = Some(format!("list_accounts: {e}")),
            }
        }
    }

    fn lock_vault(&mut self) {
        self.vault = VaultState::Locked;
        self.password_input = Zeroizing::new(String::new());
        self.vault_error = None;
        self.selected = None;
        self.current_dir = ApiState::Idle;
        self.download_rx = None;
        self.download_status = None;
        self.upload_rx = None;
        self.upload_status = None;
    }

    fn migrate_plaintext_tokens(&mut self) {
        let Some(db) = self.db.as_ref() else { return };
        let VaultState::Unlocked(key) = &self.vault else {
            return;
        };

        let mut error: Option<String> = None;
        let pending = match db.list_plaintext_accounts() {
            Ok(p) => p,
            Err(e) => {
                self.db_error = Some(format!("migration list: {e}"));
                return;
            }
        };

        if !pending.is_empty() {
            println!(
                "[Vault] Migrando {} cuenta(s) a tokens cifrados...",
                pending.len()
            );
        }

        for (id, plaintext) in pending {
            let pt = Zeroizing::new(plaintext);
            match vault::encrypt(key, pt.as_bytes()) {
                Ok(ct) => {
                    if let Err(e) = db.set_encrypted_token(&id, &ct) {
                        error = Some(format!("migration set: {e}"));
                        break;
                    }
                }
                Err(e) => {
                    error = Some(format!("migration encrypt: {e}"));
                    break;
                }
            }
        }
        if let Some(e) = error {
            self.db_error = Some(e);
        }
    }

    fn fetch_dir(&mut self, account_id: String) {
        let VaultState::Unlocked(key) = &self.vault else {
            self.current_dir = ApiState::Error("Vault bloqueado".into());
            return;
        };
        let Some(db) = &self.db else {
            self.current_dir = ApiState::Error("DB no disponible".into());
            return;
        };

        let token_ct = match db.get_token_ct(&account_id) {
            Ok(Some(ct)) => ct,
            _ => {
                self.current_dir = ApiState::Error("No se encontró token para esta cuenta".into());
                return;
            }
        };

        let token = match vault::decrypt(key, &token_ct) {
            Ok(t) => match String::from_utf8(t) {
                Ok(s) => Zeroizing::new(s),
                Err(_) => {
                    self.current_dir = ApiState::Error("Token corrupto (UTF-8)".into());
                    return;
                }
            },
            Err(e) => {
                self.current_dir = ApiState::Error(format!("Error descifrando token: {e}"));
                return;
            }
        };

        self.current_dir = ApiState::Loading;
        let (tx, rx) = channel();
        self.api_rx = Some(rx);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let client = match BuzzHeavierClient::new(token.as_str()) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                match client.get_root_directory().await {
                    Ok(items) => {
                        let _ = tx.send(Ok(items));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                    }
                }
            });
        });
    }

    fn start_download(&mut self, file_id: String, file_name: String) {
        // Guardia anti-descargas concurrentes: la primera tarea no se puede
        // cancelar y quedaría huérfana si sobrescribimos `download_rx`.
        if self.download_rx.is_some() {
            self.download_status = Some("Ya hay una descarga en curso.".into());
            return;
        }
        if self.upload_rx.is_some() {
            self.download_status = Some("Espera a que termine la subida actual.".into());
            return;
        }

        let Some(path) = rfd::FileDialog::new().set_file_name(&file_name).save_file() else {
            return;
        };

        let url = format!("https://buzzheavier.com/{file_id}");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.download_rx = Some(rx);
        self.download_status = Some(format!("Iniciando descarga de {file_name}..."));
        self.download_progress = 0.0;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                download::download_file_with_progress(&url, path, tx).await;
            });
        });
    }

    fn start_upload(&mut self, file_path: std::path::PathBuf) {
        // Guardia anti-subidas concurrentes.
        if self.upload_rx.is_some() {
            self.upload_status = Some("Ya hay una subida en curso.".into());
            return;
        }
        if self.download_rx.is_some() {
            self.upload_status = Some("Espera a que termine la descarga actual.".into());
            return;
        }

        let Some(account_id) = self.selected.clone() else {
            self.upload_status = Some("Error: Selecciona una cuenta primero.".into());
            return;
        };

        let root_id = match &self.current_dir {
            ApiState::Loaded(id, _) => id.clone(),
            _ => {
                self.upload_status = Some("Error: El directorio no está cargado.".into());
                return;
            }
        };

        let Some(db) = self.db.as_ref() else {
            self.upload_status = Some("Error: DB no disponible.".into());
            return;
        };

        let age_pub_key = match db.get_account_age_pub_key(&account_id) {
            Ok(Some(k)) if !k.is_empty() => k,
            _ => {
                self.upload_status =
                    Some("Error: Esta cuenta no tiene llave E2EE configurada.".into());
                return;
            }
        };

        let token_ct = match db.get_token_ct(&account_id) {
            Ok(Some(ct)) => ct,
            _ => {
                self.upload_status = Some("Error: Token no encontrado.".into());
                return;
            }
        };

        let VaultState::Unlocked(key) = &self.vault else {
            self.upload_status = Some("Error: Vault bloqueado.".into());
            return;
        };

        let token = match vault::decrypt(key, &token_ct) {
            Ok(t) => match String::from_utf8(t) {
                Ok(s) => Zeroizing::new(s),
                Err(_) => {
                    self.upload_status = Some("Error: Token corrupto (UTF-8).".into());
                    return;
                }
            },
            Err(_) => {
                self.upload_status = Some("Error: No se pudo descifrar el token.".into());
                return;
            }
        };

        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        self.upload_status = Some(format!("Cifrando {file_name}..."));
        let (tx, rx) = channel();
        self.upload_rx = Some(rx);

        std::thread::spawn(move || {
            // Cifrado en vuelo a un directorio temporal dedicado que se barre al arranque.
            let temp_dir = std::env::temp_dir().join("buzzheavier-client");
            let _ = std::fs::create_dir_all(&temp_dir);
            let encrypted_name = format!("{file_name}.age");
            let temp_encrypted = temp_dir.join(&encrypted_name);

            if let Err(e) = crate::crypto::encrypt_file(&file_path, &temp_encrypted, &age_pub_key) {
                let _ = tx.send(Err(format!("Error cifrando: {e}")));
                let _ = std::fs::remove_file(&temp_encrypted);
                return;
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            // El bloque async consume una copia del PathBuf; el original
            // sigue disponible para la limpieza posterior.
            let upload_path = temp_encrypted.clone();
            let result = rt.block_on(async move {
                let client = BuzzHeavierClient::new(token.as_str()).map_err(|e| e.to_string())?;
                client.upload_file(&root_id, &upload_path).await
            });

            let _ = std::fs::remove_file(&temp_encrypted);

            match result {
                Ok(_) => {
                    let _ = tx.send(Ok(()));
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                }
            }
        });
    }
}

impl eframe::App for BuzzHeavierApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drag & Drop UI — solo si no hay transferencia activa.
        let can_start_transfer = self.download_rx.is_none() && self.upload_rx.is_none();
        if self.vault.is_unlocked() && self.selected.is_some() && can_start_transfer {
            let hovered_files = ctx.input(|i| !i.raw.hovered_files.is_empty());
            if hovered_files {
                let painter = ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::new("drop_zone"),
                ));
                let screen_rect = ctx.screen_rect();
                painter.rect_filled(screen_rect, 0.0, egui::Color32::from_black_alpha(180));
                painter.text(
                    screen_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "Suelta para cifrar y subir",
                    egui::FontId::proportional(32.0),
                    egui::Color32::WHITE,
                );
            }

            let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());
            if !dropped_files.is_empty() {
                if let Some(file) = dropped_files.first() {
                    if let Some(path) = &file.path {
                        self.start_upload(path.clone());
                    }
                }
            }
        }

        // Poll Vault
        if let Some(rx) = &self.vault_task {
            match rx.try_recv() {
                Ok(result) => {
                    self.vault_task = None;
                    match result {
                        Ok(VaultTaskResult::Setup(key, salt, verifier)) => {
                            if let Some(db) = &self.db {
                                if let Err(e) =
                                    db.init_vault(&salt, &verifier, ARGON2_M, ARGON2_T, ARGON2_P)
                                {
                                    self.vault_error = Some(format!("Error guardando vault: {e}"));
                                    return;
                                }
                            }
                            self.vault = VaultState::Unlocked(key);
                            self.password_input = Zeroizing::new(String::new());
                            self.password_confirm = Zeroizing::new(String::new());
                            self.migrate_plaintext_tokens();
                            self.reload_accounts();
                        }
                        Ok(VaultTaskResult::Unlock(key)) => {
                            self.vault = VaultState::Unlocked(key);
                            self.password_input = Zeroizing::new(String::new());
                            self.migrate_plaintext_tokens();
                            self.reload_accounts();
                        }
                        Err(e) => self.vault_error = Some(e),
                    }
                }
                Err(TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(16))
                }
                Err(TryRecvError::Disconnected) => {
                    self.vault_task = None;
                    self.vault_error = Some("Error interno: tarea cancelada".into());
                }
            }
        }

        // Poll API
        if let Some(rx) = &self.api_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.api_rx = None;
                    match result {
                        Ok((root_id, items)) => self.current_dir = ApiState::Loaded(root_id, items),
                        Err(e) => self.current_dir = ApiState::Error(e),
                    }
                }
                Err(TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(100))
                }
                Err(TryRecvError::Disconnected) => {
                    self.api_rx = None;
                    self.current_dir = ApiState::Error("Tarea cancelada".into());
                }
            }
        }

        // Poll Download
        let mut clear_download_rx = false;
        if let Some(rx) = &mut self.download_rx {
            match rx.try_recv() {
                Ok(evt) => match evt {
                    DownloadEvent::ResolvingCdn => {
                        self.download_status = Some("Resolviendo CDN...".into())
                    }
                    DownloadEvent::Started { total } => {
                        let size = total
                            .map(format_size)
                            .unwrap_or_else(|| "desconocido".into());
                        self.download_status = Some(format!("Descargando... {size}"));
                    }
                    DownloadEvent::Progress { downloaded, total } => {
                        if let Some(t) = total {
                            if t > 0 {
                                self.download_progress =
                                    (downloaded as f32 / t as f32).clamp(0.0, 1.0);
                            }
                        }
                    }
                    DownloadEvent::Finished { path } => {
                        clear_download_rx = true;
                        self.download_status = Some(format!("Completado: {}", path.display()));
                        self.download_progress = 1.0;
                    }
                    DownloadEvent::Failed { error } => {
                        clear_download_rx = true;
                        self.download_status = Some(format!("Error: {error}"));
                        self.download_progress = 0.0;
                    }
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(50))
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    clear_download_rx = true
                }
            }
        }
        if clear_download_rx {
            self.download_rx = None;
        }

        // Poll Upload
        if let Some(rx) = &self.upload_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.upload_rx = None;
                    match result {
                        Ok(()) => {
                            self.upload_status = Some("✅ Archivo subido exitosamente.".into());
                            self.current_dir = ApiState::Idle; // Refrescar dir
                        }
                        Err(e) => self.upload_status = Some(format!("❌ Error subiendo: {e}")),
                    }
                }
                Err(TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(100))
                }
                Err(TryRecvError::Disconnected) => {
                    self.upload_rx = None;
                    self.upload_status = Some("❌ Tarea cancelada.".into());
                }
            }
        }

        if self.api_rx.is_none() && matches!(self.current_dir, ApiState::Idle) {
            if let Some(sel) = self.selected.clone() {
                self.fetch_dir(sel);
            }
        }

        self.top_bar(ctx);
        self.side_panel(ctx);
        self.bottom_bar(ctx);
        self.central_panel(ctx);
        self.add_account_modal(ctx);
        self.vault_modal(ctx);
    }
}

impl BuzzHeavierApp {
    fn top_bar(&mut self, ctx: &egui::Context) {
        let unlocked = self.vault.is_unlocked();
        let mut lock_clicked = false;

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                    .fill(ctx.style().visuals.panel_fill),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new("BuzzHeavier")
                            .strong()
                            .color(egui::Color32::from_rgb(77, 107, 254)),
                    );
                    ui.label(egui::RichText::new("Client").weak());
                    ui.separator();
                    ui.label(egui::RichText::new("Zero-access E2EE").weak().small());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if unlocked && ui.button("🔒 Bloquear").clicked() {
                            lock_clicked = true;
                        }
                    });
                });
            });

        if lock_clicked {
            self.lock_vault();
        }
    }

    fn side_panel(&mut self, ctx: &egui::Context) {
        let unlocked = self.vault.is_unlocked();

        egui::SidePanel::left("side_panel")
            .resizable(true)
            .default_width(280.0)
            .frame(
                egui::Frame::none()
                    .inner_margin(egui::Margin::same(16.0))
                    .fill(ctx.style().visuals.panel_fill),
            )
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("TUS CUENTAS").strong().small().weak());
                ui.add_space(8.0);

                if let Some(err) = &self.db_error {
                    ui.colored_label(egui::Color32::RED, format!("⚠ {err}"));
                    ui.separator();
                }

                if self.accounts.is_empty() {
                    ui.label(
                        egui::RichText::new("No hay cuentas configuradas.")
                            .italics()
                            .weak(),
                    );
                } else {
                    let mut to_select: Option<String> = None;
                    let mut to_delete: Option<String> = None;

                    for account in &self.accounts {
                        let selected = self.selected.as_deref() == Some(account.id.as_str());
                        let frame = if selected {
                            egui::Frame::none()
                                .fill(ctx.style().visuals.selection.bg_fill)
                                .rounding(6.0)
                                .inner_margin(8.0)
                        } else {
                            egui::Frame::none().inner_margin(8.0)
                        };

                        frame.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui
                                    .add(
                                        egui::Label::new(
                                            egui::RichText::new(&account.label).size(15.0),
                                        )
                                        .sense(egui::Sense::click()),
                                    )
                                    .clicked()
                                {
                                    to_select = Some(account.id.clone());
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if unlocked && ui.small_button("🗑").clicked() {
                                            to_delete = Some(account.id.clone());
                                        }
                                    },
                                );
                            });
                        });
                    }

                    if let Some(id) = to_select {
                        if self.selected.as_deref() != Some(&id) {
                            self.selected = Some(id);
                            self.current_dir = ApiState::Idle;
                        }
                    }
                    if let Some(id) = to_delete {
                        if let Some(db) = &self.db {
                            let _ = db.delete_account(&id);
                        }
                        if self.selected.as_deref() == Some(id.as_str()) {
                            self.selected = None;
                            self.current_dir = ApiState::Idle;
                        }
                        self.reload_accounts();
                    }
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(16.0);
                    if ui
                        .add_sized(
                            [ui.available_width(), 32.0],
                            egui::Button::new("+ Añadir cuenta"),
                        )
                        .clicked()
                    {
                        self.add_modal_open = true;
                        self.add_token = Zeroizing::new(String::new());
                        self.add_label.clear();
                        self.add_error = None;
                    }
                });
            });
    }

    fn bottom_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(16.0, 8.0))
                    .fill(ctx.style().visuals.extreme_bg_color),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let vault_status = match &self.vault {
                        VaultState::Unlocked(_) => "🔓 Vault desbloqueado",
                        VaultState::Locked => "🔒 Vault bloqueado",
                        VaultState::NeedsSetup => "⚙ Configurar vault",
                    };
                    ui.label(egui::RichText::new(vault_status).small().weak());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .small()
                                .weak(),
                        );
                    });
                });
            });
    }

    fn central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .inner_margin(egui::Margin::same(24.0))
                    .fill(ctx.style().visuals.extreme_bg_color),
            )
            .show(ctx, |ui| {
                if !self.vault.is_unlocked() {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new("🔒 Introduce tu contraseña para desbloquear")
                                .size(20.0)
                                .weak(),
                        );
                    });
                    return;
                }

                let selected_account = self
                    .selected
                    .as_ref()
                    .and_then(|id| self.accounts.iter().find(|a| &a.id == id));

                if let Some(acc) = selected_account {
                    ui.horizontal(|ui| {
                        ui.heading(egui::RichText::new(&acc.label).strong());
                        if ui.button("🔄").on_hover_text("Refrescar").clicked() {
                            self.current_dir = ApiState::Idle;
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "Token: {}",
                            if acc.has_token {
                                "🔐 Cifrado"
                            } else {
                                "Sin configurar"
                            }
                        ))
                        .small()
                        .weak(),
                    );

                    ui.add_space(24.0);

                    if let Some(status) = &self.download_status {
                        egui::Frame::none()
                            .fill(ctx.style().visuals.panel_fill)
                            .rounding(8.0)
                            .inner_margin(16.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(status);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::ProgressBar::new(self.download_progress)
                                                    .desired_width(200.0)
                                                    .show_percentage(),
                                            );
                                        },
                                    );
                                });
                            });
                        ui.add_space(8.0);
                    }
                    if let Some(status) = &self.upload_status {
                        egui::Frame::none()
                            .fill(ctx.style().visuals.panel_fill)
                            .rounding(8.0)
                            .inner_margin(16.0)
                            .show(ui, |ui| {
                                ui.label(status);
                            });
                        ui.add_space(8.0);
                    }

                    let mut pending_download: Option<(String, String)> = None;
                    // Deshabilitar Descargar mientras cualquier transferencia esté en curso.
                    let can_download = self.download_rx.is_none() && self.upload_rx.is_none();

                    match &self.current_dir {
                        ApiState::Idle => {
                            ui.spinner();
                        }
                        ApiState::Loading => {
                            ui.centered_and_justified(|ui| {
                                ui.spinner();
                            });
                        }
                        ApiState::Loaded(_, items) => {
                            if items.is_empty() {
                                ui.centered_and_justified(|ui| {
                                    ui.label("No hay archivos en la raíz. Arrastra uno aquí.");
                                });
                            } else {
                                TableBuilder::new(ui)
                                    .striped(true)
                                    .resizable(true)
                                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                    .column(Column::auto().at_least(100.0))
                                    .column(Column::remainder())
                                    .column(Column::initial(100.0))
                                    .column(Column::initial(160.0))
                                    .header(20.0, |mut header| {
                                        header.col(|ui| {
                                            ui.strong("Nombre");
                                        });
                                        header.col(|ui| {
                                            ui.strong("Tipo");
                                        });
                                        header.col(|ui| {
                                            ui.strong("Tamaño");
                                        });
                                        header.col(|ui| {
                                            ui.strong("Acción");
                                        });
                                    })
                                    .body(|body| {
                                        body.rows(30.0, items.len(), |mut row| {
                                            let item = &items[row.index()];
                                            row.col(|ui| {
                                                ui.label(&item.name);
                                            });
                                            row.col(|ui| {
                                                ui.label(if item.is_directory {
                                                    "📁 Carpeta"
                                                } else {
                                                    "📄 Archivo"
                                                });
                                            });
                                            row.col(|ui| {
                                                if !item.is_directory {
                                                    ui.label(format_size(item.size));
                                                } else {
                                                    ui.label("-");
                                                }
                                            });
                                            row.col(|ui| {
                                                if item.is_directory {
                                                    return;
                                                }
                                                let is_encrypted = item.name.ends_with(".age");
                                                if ui
                                                    .add_enabled(
                                                        can_download,
                                                        egui::Button::new("⬇ Descargar"),
                                                    )
                                                    .clicked()
                                                {
                                                    pending_download = Some((
                                                        item.id.clone(),
                                                        item.name.clone(),
                                                    ));
                                                }
                                                if is_encrypted {
                                                    ui.label(
                                                        egui::RichText::new("⚠ cifrado")
                                                            .small()
                                                            .weak(),
                                                    )
                                                    .on_hover_text(
                                                        "Este archivo se subió cifrado con age. \
                                                         La app aún no descifra al vuelo (Phase 4e); \
                                                         obtendrás el ciphertext (.age).",
                                                    );
                                                }
                                            });
                                        });
                                    });
                            }
                        }
                        ApiState::Error(e) => {
                            ui.colored_label(egui::Color32::RED, format!("Error:\n{e}"));
                        }
                    }

                    if let Some((id, name)) = pending_download {
                        self.start_download(id, name);
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new("Selecciona una cuenta para ver tus archivos")
                                .size(16.0)
                                .weak(),
                        );
                    });
                }
            });
    }

    fn add_account_modal(&mut self, ctx: &egui::Context) {
        if !self.add_modal_open || !self.vault.is_unlocked() {
            return;
        }

        let mut open = true;
        egui::Window::new("Añadir cuenta")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);
                ui.add_space(8.0);
                ui.label("Nombre de la cuenta:");
                ui.add(egui::TextEdit::singleline(&mut self.add_label).hint_text("Mi cuenta"));

                ui.add_space(8.0);
                ui.label("Bearer token:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.add_token)
                        .password(true)
                        .hint_text("eyJhbGci..."),
                );

                if let Some(err) = &self.add_error {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::RED, err);
                }

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui.button("Guardar").clicked() {
                        self.try_save_account();
                    }
                    if ui.button("Cancelar").clicked() {
                        self.add_modal_open = false;
                    }
                });
            });
        if !open {
            self.add_modal_open = false;
        }
    }

    fn try_save_account(&mut self) {
        // Copia zeroizable: el buffer temporal se limpia al dropear.
        let token = Zeroizing::new(self.add_token.trim().to_string());
        if token.is_empty() {
            self.add_error = Some("El token no puede estar vacío.".into());
            return;
        }
        if token.len() < 16 {
            self.add_error = Some("Token inválido. ¿Lo copiaste completo?".into());
            return;
        }

        let VaultState::Unlocked(key) = &self.vault else {
            self.add_error = Some("Vault bloqueado.".into());
            return;
        };

        let token_ct = match vault::encrypt(key, token.as_bytes()) {
            Ok(ct) => ct,
            Err(e) => {
                self.add_error = Some(format!("Error cifrando token: {e}"));
                return;
            }
        };

        // Generar par de llaves E2EE; la privada se cifra en la bóveda.
        let (age_pub, age_priv) = crate::crypto::generate_keypair();
        let age_priv = Zeroizing::new(age_priv);
        let age_priv_ct = match vault::encrypt(key, age_priv.as_bytes()) {
            Ok(ct) => ct,
            Err(e) => {
                self.add_error = Some(format!("Error cifrando llave E2EE: {e}"));
                return;
            }
        };

        let label = if self.add_label.trim().is_empty() {
            format!("Cuenta {}", self.accounts.len() + 1)
        } else {
            self.add_label.trim().to_string()
        };

        let id = format!(
            "acc-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let result = if let Some(db) = &self.db {
            db.add_account(&id, &label, None, &token_ct, &age_pub, &age_priv_ct)
                .map_err(|e| format!("DB: {e}"))
        } else {
            Err("Base de datos no disponible.".to_string())
        };

        match result {
            Ok(()) => {
                self.add_modal_open = false;
                self.add_token = Zeroizing::new(String::new());
                self.add_label.clear();
                self.add_error = None;
                self.reload_accounts();
                self.selected = Some(id);
                self.current_dir = ApiState::Idle;
            }
            Err(e) => self.add_error = Some(e),
        }
    }

    fn vault_modal(&mut self, ctx: &egui::Context) {
        match self.vault {
            VaultState::Unlocked(_) => {}
            VaultState::NeedsSetup => self.setup_vault_modal(ctx),
            VaultState::Locked => self.unlock_vault_modal(ctx),
        }
    }

    fn setup_vault_modal(&mut self, ctx: &egui::Context) {
        egui::Window::new("Configurar Vault")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(350.0);
                ui.add_space(8.0);
                ui.label("Contraseña maestra:");
                ui.add(egui::TextEdit::singleline(&mut *self.password_input).password(true));
                ui.label("Confirmar:");
                ui.add(egui::TextEdit::singleline(&mut *self.password_confirm).password(true));

                ui.add_space(6.0);
                ui.colored_label(
                    egui::Color32::from_rgb(230, 180, 60),
                    "⚠ Sin recuperación: si olvidas esta contraseña, tus tokens cifrados son irrecuperables.",
                );

                if let Some(err) = &self.vault_error {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::RED, err);
                }

                ui.add_space(16.0);
                if self.vault_task.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Procesando...");
                    });
                } else if ui.button("Crear").clicked() {
                    self.try_setup_vault();
                }
            });
    }

    fn try_setup_vault(&mut self) {
        self.vault_error = None;
        let pw = Zeroizing::new(self.password_input.trim().to_string());
        if pw.len() < MIN_PASSWORD_LEN {
            self.vault_error = Some(format!("Mínimo {MIN_PASSWORD_LEN} caracteres."));
            return;
        }
        if pw.as_str() != self.password_confirm.trim() {
            self.vault_error = Some("Las contraseñas no coinciden.".into());
            return;
        }

        let (tx, rx) = channel();
        self.vault_task = Some(rx);
        std::thread::spawn(move || {
            let salt = vault::new_salt();
            let key = match vault::derive_key(pw.as_str(), &salt, ARGON2_M, ARGON2_T, ARGON2_P) {
                Ok(k) => k,
                Err(e) => {
                    let _ = tx.send(Err(format!("Error derivando clave: {e}")));
                    return;
                }
            };
            let verifier = match vault::make_verifier(&key) {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(Err(format!("Error creando verifier: {e}")));
                    return;
                }
            };
            let _ = tx.send(Ok(VaultTaskResult::Setup(key, salt, verifier)));
        });
    }

    fn unlock_vault_modal(&mut self, ctx: &egui::Context) {
        egui::Window::new("Desbloquear")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(300.0);
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::singleline(&mut *self.password_input)
                        .password(true)
                        .hint_text("Contraseña"),
                );

                if let Some(err) = &self.vault_error {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::RED, err);
                }

                ui.add_space(16.0);
                if self.vault_task.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Procesando...");
                    });
                } else if ui.button("Desbloquear").clicked() {
                    self.try_unlock_vault();
                }
            });
    }

    fn try_unlock_vault(&mut self) {
        self.vault_error = None;
        let pw = Zeroizing::new(self.password_input.trim().to_string());
        if pw.is_empty() {
            self.vault_error = Some("Introduce la contraseña.".into());
            return;
        }

        let meta = match self.db.as_ref().map(|d| d.get_vault_meta()) {
            Some(Ok(Some(m))) => m,
            Some(Ok(None)) => {
                self.vault_error = Some("Vault no encontrado.".into());
                return;
            }
            Some(Err(e)) => {
                self.vault_error = Some(format!("Error leyendo vault: {e}"));
                return;
            }
            None => {
                self.vault_error = Some("Base de datos no disponible.".into());
                return;
            }
        };

        let (tx, rx) = channel();
        self.vault_task = Some(rx);
        std::thread::spawn(move || {
            let key = match vault::derive_key(
                pw.as_str(),
                &meta.salt,
                meta.argon2_m,
                meta.argon2_t,
                meta.argon2_p,
            ) {
                Ok(k) => k,
                Err(e) => {
                    let _ = tx.send(Err(format!("Error derivando clave: {e}")));
                    return;
                }
            };
            if let Err(e) = vault::check_verifier(&key, &meta.verifier) {
                let _ = tx.send(Err(format!("Contraseña incorrecta ({e})")));
                return;
            }
            let _ = tx.send(Ok(VaultTaskResult::Unlock(key)));
        });
    }
}
