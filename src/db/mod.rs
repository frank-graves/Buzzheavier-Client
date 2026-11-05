use rusqlite::{params, Connection, OptionalExtension, Result};
use std::path::Path;

pub struct Database {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: String,
    #[allow(dead_code)] // Reservado para cuando la UI muestre email
    pub email: Option<String>,
    pub label: String,
    pub has_token: bool,
    pub age_pub_key: String,
}

#[derive(Debug, Clone)]
pub struct VaultMeta {
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub argon2_m: u32,
    pub argon2_t: u32,
    pub argon2_p: u32,
}

impl Database {
    pub fn open(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL DEFAULT '',
                email TEXT,
                label TEXT NOT NULL DEFAULT '',
                is_default INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS upload_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT NOT NULL,
                local_path TEXT NOT NULL,
                remote_parent_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                argon2_m INTEGER NOT NULL,
                argon2_t INTEGER NOT NULL,
                argon2_p INTEGER NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 1
            );
            ",
        )?;

        // Migraciones iter 3b -> 4c: añadir columnas para E2EE
        if !column_exists(&conn, "accounts", "token_ct")? {
            conn.execute("ALTER TABLE accounts ADD COLUMN token_ct BLOB", [])?;
        }
        if !column_exists(&conn, "accounts", "age_pub_key")? {
            conn.execute(
                "ALTER TABLE accounts ADD COLUMN age_pub_key TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        if !column_exists(&conn, "accounts", "age_priv_key_ct")? {
            conn.execute("ALTER TABLE accounts ADD COLUMN age_priv_key_ct BLOB", [])?;
        }

        Ok(Self { conn })
    }

    pub fn has_vault(&self) -> Result<bool> {
        let exists: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_meta WHERE id = 1)",
            [],
            |r| r.get(0),
        )?;
        Ok(exists != 0)
    }

    pub fn get_vault_meta(&self) -> Result<Option<VaultMeta>> {
        self.conn
            .query_row(
                "SELECT salt, verifier, argon2_m, argon2_t, argon2_p FROM vault_meta WHERE id = 1",
                [],
                |row| {
                    Ok(VaultMeta {
                        salt: row.get(0)?,
                        verifier: row.get(1)?,
                        argon2_m: row.get(2)?,
                        argon2_t: row.get(3)?,
                        argon2_p: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    pub fn init_vault(
        &self,
        salt: &[u8],
        verifier: &[u8],
        argon2_m: u32,
        argon2_t: u32,
        argon2_p: u32,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vault_meta (id, salt, verifier, argon2_m, argon2_t, argon2_p, schema_version) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, 1)",
            params![salt, verifier, argon2_m, argon2_t, argon2_p],
        )?;
        Ok(())
    }

    pub fn add_account(
        &self,
        id: &str,
        label: &str,
        email: Option<&str>,
        token_ct: &[u8],
        age_pub_key: &str,
        age_priv_key_ct: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO accounts (id, label, email, token_ct, account_id, age_pub_key, age_priv_key_ct) \
             VALUES (?1, ?2, ?3, ?4, '', ?5, ?6)",
            params![id, label, email, token_ct, age_pub_key, age_priv_key_ct],
        )?;
        Ok(())
    }

    pub fn list_accounts(&self) -> Result<Vec<AccountRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, email, label, (token_ct IS NOT NULL OR account_id != '') AS has_token, age_pub_key \
             FROM accounts ORDER BY created_at ASC",
        )?;
        let iter = stmt.query_map([], |row| {
            Ok(AccountRow {
                id: row.get(0)?,
                email: row.get(1)?,
                label: row.get(2)?,
                has_token: row.get::<_, i64>(3)? != 0,
                age_pub_key: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    pub fn delete_account(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_plaintext_accounts(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id FROM accounts \
             WHERE token_ct IS NULL AND account_id != ''",
        )?;
        let iter = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    pub fn set_encrypted_token(&self, id: &str, token_ct: &[u8]) -> Result<()> {
        self.conn.execute(
            "UPDATE accounts SET token_ct = ?1, account_id = '' WHERE id = ?2",
            params![token_ct, id],
        )?;
        Ok(())
    }

    pub fn get_token_ct(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT token_ct FROM accounts WHERE id = ?1",
                params![id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map(|opt| opt.flatten())
    }

    pub fn get_account_age_pub_key(&self, id: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT age_pub_key FROM accounts WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}
