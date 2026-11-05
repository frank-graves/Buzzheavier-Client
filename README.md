# 🦀 BuzzHeavier Client

Un cliente de escritorio **FOSS**, **Local-first** y **Privacy-by-Design** para [BuzzHeavier](https://buzzheavier.com), construido en Rust.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

## 📖 Descripción

BuzzHeavier Client nace de la necesidad de tener una herramienta de escritorio rápida, nativa y segura para gestionar archivos en BuzzHeavier. A diferencia de los clientes web, esta aplicación ofrece:
- **Zero Telemetry:** Cero rastreo, cero analíticas. Tus datos no salen de tu máquina (excepto hacia los servidores de BuzzHeavier).
- **Zero-Access Encryption (E2EE):** Tus tokens de cuenta se cifran localmente antes de tocar el disco duro.
- **Cloudflare Bypass Nativo:** Descarga archivos evadiendo las protecciones de Cloudflare de forma transparente y local.
- **Multi-Cuenta:** Gestiona múltiples cuentas simultáneamente con un solo clic.

## ✨ Características

- **UI Nativa y Rápida:** Construida con `egui` / `eframe`. Sin Electron, sin consumo excesivo de RAM.
- **Cifrado de Grado Militar:** Los tokens se protegen en una bóveda local (Vault) usando **Argon2id** (KDF) y **XChaCha20-Poly1305** (AEAD).
- **WebView2 Oculto:** El motor de descargas levanta un proceso aislado de WebView2 invisible para resolver los captchas de Cloudflare (Turnstile) automáticamente.
- **Streaming E2E:** Subida y descarga de archivos mediante *streaming* directo, sin cargar archivos completos en la memoria RAM.
- **SQLite Integrado:** Base de datos local encriptada (a nivel de aplicación) para persistir cuentas y configuraciones.

## 🛠️ Stack Tecnológico

- **Lenguaje:** Rust (2021 edition)
- **GUI:** `eframe` (egui)
- **Red y HTTP:** `reqwest` (con `rustls-tls`), `tokio`
- **Cifrado:** `argon2` (derivación de clave), `chacha20poly1305` (cifrado simétrico), `age` (cifrado de archivos E2EE)
- **Base de Datos:** `rusqlite` (SQLite embebido)
- **Cloudflare Bypass:** `wry` + `tao` (WebView2 nativo de Windows)

## 🚀 Compilación y Ejecución

### Requisitos previos
- **Windows 10/11** (la app está optimizada para WebView2 de Windows).
- **Rust Toolchain** (recomendado instalar vía [rustup](https://rustup.rs/)).
- **Microsoft C++ Build Tools** (para compilar dependencias nativas como `rusqlite`).
- **WebView2 Runtime** (viene preinstalado en Windows 10/11 modernos).

### Pasos
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/buzzheavier-client.git
   cd buzzheavier-client
   ```

2. Compilar en modo de desarrollo (debug):
   ```bash
   cargo run
   ```

3. Compilar para producción (release, optimizado y sin consola):
   ```bash
   cargo build --release
   ```
   El binario estará en `target/release/buzzheavier-client.exe`.

## 🔒 Seguridad y Privacidad (Zero-Access)

1. **Contraseña Maestra:** Al iniciar la app por primera vez, se te pedirá crear una contraseña maestra. Esta contraseña *nunca* sale de tu dispositivo.
2. **Bóveda Local:** La contraseña se usa para derivar una clave (Argon2id, 64MB de RAM) que cifra los tokens de BuzzHeavier.
3. **Sin Recuperación:** **Si olvidas tu contraseña maestra, los tokens cifrados son irrecuperables.** No hay servidor de recuperación, ya que la app no tiene backend propio.
4. **Tokens:** El Bearer Token de BuzzHeavier se extrae manualmente de las DevTools de tu navegador (Application -> Local Storage). La app nunca ve tu contraseña de BuzzHeavier.

## 📂 Estructura del Proyecto

```text
src/
 ├── api/          # Cliente HTTP y modelos de datos de BuzzHeavier
 ├── crypto/       # Lógica de cifrado E2EE y gestión de la bóveda (vault)
 ├── db/           # Conexión SQLite y persistencia local
 ├── download/     # Motor de descargas (WebView2 worker + reqwest)
 ├── ui/           # Interfaz gráfica de usuario (egui)
 └── main.rs       # Punto de entrada y enrutador de procesos
```

## 🗺️ Roadmap

- [x] **Fase 0:** Estructura del proyecto.
- [x] **Fase 1:** Núcleo API (Auth, listar directorio, subir archivos).
- [x] **Fase 2:** Base de datos (SQLite) y Cifrado de bóveda (Argon2 + XChaCha20).
- [x] **Fase 3:** Motor de descargas (Bypass Cloudflare con WebView2 aislado).
- [x] **Fase 4a:** UI base, gestor de cuentas y visualización de directorios.
- [x] **Fase 4b:** Descarga de archivos con barra de progreso desde la UI.
- [ ] **Fase 4c:** Drag & Drop para subida de archivos (con cifrado en vuelo).
- [ ] **Fase 4d:** Navegación entre carpetas (subdirectorios).
- [ ] **Fase 5:** Optimización, tests unitarios y empaquetado (.msi).

## 📄 Licencia

Este proyecto está bajo la licencia **GPL-3.0-or-later**. Consulta el archivo `LICENSE` para más detalles.
