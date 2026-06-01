use rusqlite::{params, Connection, Result};

const CURRENT_DB_VERSION: u32 = 2;

pub fn run_migrations(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    match version {
        0 => {
            // Fresh database: apply all V1 migrations inside a single transaction.
            conn.execute_batch("
                BEGIN;

                CREATE TABLE IF NOT EXISTS rooms (
                    channel_name TEXT PRIMARY KEY,
                    automerge_blob BLOB
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
                );

                CREATE TABLE IF NOT EXISTS friends (
                    peer_id TEXT PRIMARY KEY,
                    nickname TEXT,
                    offline_pubkey TEXT,
                    trust_level INTEGER NOT NULL DEFAULT 0,
                    blocked BOOLEAN NOT NULL DEFAULT 0,
                    muted BOOLEAN NOT NULL DEFAULT 0,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS private_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id TEXT NOT NULL,
                    sender_is_me BOOLEAN NOT NULL,
                    text TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER
                );

                CREATE TABLE IF NOT EXISTS saved_groups (
                    channel_name TEXT PRIMARY KEY,
                    password TEXT,
                    default_ttl INTEGER,
                    persistence_enabled BOOLEAN NOT NULL DEFAULT 1,
                    invite_only BOOLEAN NOT NULL DEFAULT 0,
                    notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
                    retention_days INTEGER
                );

                CREATE TABLE IF NOT EXISTS peer_settings (
                    peer_id TEXT PRIMARY KEY,
                    trust_level INTEGER NOT NULL DEFAULT 0,
                    blocked BOOLEAN NOT NULL DEFAULT 0,
                    muted BOOLEAN NOT NULL DEFAULT 0,
                    rate_limit_per_minute INTEGER NOT NULL DEFAULT 30,
                    proof_of_work_required BOOLEAN NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS room_settings (
                    channel_name TEXT PRIMARY KEY,
                    default_ttl INTEGER,
                    retention_days INTEGER,
                    persistence_enabled BOOLEAN NOT NULL DEFAULT 1,
                    invite_only BOOLEAN NOT NULL DEFAULT 0,
                    notifications_enabled BOOLEAN NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS ratchet_states (
                    peer_id TEXT PRIMARY KEY,
                    state_blob BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS storage_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    storage_node_enabled BOOLEAN NOT NULL DEFAULT 0,
                    quota_mb INTEGER NOT NULL DEFAULT 512,
                    retention_days INTEGER NOT NULL DEFAULT 7
                );

                CREATE TABLE IF NOT EXISTS room_invites (
                    invite_id TEXT PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    token_json TEXT NOT NULL,
                    revoked BOOLEAN NOT NULL DEFAULT 0,
                    uses INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS room_roles (
                    room_id TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    role_json TEXT NOT NULL,
                    PRIMARY KEY(room_id, role_id)
                );

                CREATE TABLE IF NOT EXISTS permission_grants (
                    room_id TEXT NOT NULL,
                    subject_peer_id TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    grant_json TEXT NOT NULL,
                    PRIMARY KEY(room_id, subject_peer_id, role_id)
                );

                CREATE TABLE IF NOT EXISTS trust_edges (
                    from_peer_id TEXT NOT NULL,
                    to_peer_id TEXT NOT NULL,
                    edge_json TEXT NOT NULL,
                    PRIMARY KEY(from_peer_id, to_peer_id)
                );

                CREATE TABLE IF NOT EXISTS peer_capabilities (
                    peer_id TEXT PRIMARY KEY,
                    storage_node BOOLEAN NOT NULL DEFAULT 0,
                    relay_node BOOLEAN NOT NULL DEFAULT 0,
                    dht_server BOOLEAN NOT NULL DEFAULT 0,
                    media_relay BOOLEAN NOT NULL DEFAULT 0,
                    capacity_score INTEGER NOT NULL DEFAULT 0,
                    protocol_versions_json TEXT NOT NULL DEFAULT '[]',
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS file_manifests (
                    content_hash TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    stored_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS stored_chunks (
                    chunk_hash TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    expires_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS plugin_registry (
                    plugin_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 0,
                    granted_capabilities_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS message_search
                    USING fts5(scope, peer_id, room_id, sender, text, timestamp UNINDEXED);

                CREATE TABLE IF NOT EXISTS known_peers (
                    peer_id  TEXT NOT NULL,
                    multiaddr TEXT NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (peer_id, multiaddr)
                );

                CREATE TABLE IF NOT EXISTS prekey_bundles (
                    peer_id TEXT PRIMARY KEY,
                    bundle_json TEXT NOT NULL,
                    fetched_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS revoked_invites (
                    invite_id TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL,
                    revoked_by TEXT NOT NULL
                );

                INSERT OR IGNORE INTO storage_settings (id) VALUES (1);

                PRAGMA user_version = 1;

                COMMIT;
            ")?;
            // Fall through to apply subsequent migrations.
            migrate_v1_to_v2(conn)?;
        }
        1 => {
            // Database is at V1 — apply V2 migration.
            migrate_v1_to_v2(conn)?;
        }
        v if v == CURRENT_DB_VERSION => {
            // Already up to date — nothing to do.
        }
        v => {
            return Err(rusqlite::Error::UserFunctionError(
                format!(
                    "Database version {} is newer than the supported version {}. \
                     Please upgrade the application.",
                    v, CURRENT_DB_VERSION
                )
                .into(),
            ));
        }
    }

    Ok(())
}

/// Applies the V1 → V2 schema migration.
///
/// V2 adds `used_opk_ids` for one-time prekey (OPK) consumption tracking so
/// that replay attacks can be detected and rejected.
fn migrate_v1_to_v2(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        BEGIN;

        CREATE TABLE IF NOT EXISTS used_opk_ids (
            opk_id  TEXT PRIMARY KEY,
            peer_id TEXT NOT NULL,
            used_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        );

        PRAGMA user_version = 2;

        COMMIT;
    ")?;
    Ok(())
}

// ─── OPK consumption tracking ─────────────────────────────────────────────────

/// Records that `opk_id` has been consumed in a handshake initiated by
/// `peer_id`.
///
/// Returns `Err` if the OPK was already recorded (replay attack detected).
/// The error message is `"OPK replay detected: <opk_id>"`.
pub fn mark_opk_used(conn: &Connection, opk_id: &str, peer_id: &str) -> Result<()> {
    let rows_changed = conn.execute(
        "INSERT OR IGNORE INTO used_opk_ids (opk_id, peer_id, used_at)
         VALUES (?1, ?2, ?3)",
        params![opk_id, peer_id, now_ms()],
    )?;
    if rows_changed == 0 {
        return Err(rusqlite::Error::UserFunctionError(
            format!("OPK replay detected: {}", opk_id).into(),
        ));
    }
    Ok(())
}

/// Returns `true` if `opk_id` has already been consumed (and therefore must
/// not be accepted again).
pub fn is_opk_used(conn: &Connection, opk_id: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM used_opk_ids WHERE opk_id = ?1",
        params![opk_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn init_db(db_path: &str, db_key: &str) -> Result<Connection> {
    let conn = if db_path == ":memory:" {
        Connection::open_in_memory()?
    } else {
        Connection::open(db_path)?
    };

    if db_path != ":memory:" {
        conn.pragma_update(None, "key", &db_key)?;
    }

    run_migrations(&conn)?;

    Ok(conn)
}

pub fn save_room(conn: &Connection, channel: &str, blob: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO rooms (channel_name, automerge_blob) VALUES (?1, ?2)
         ON CONFLICT(channel_name) DO UPDATE SET automerge_blob=excluded.automerge_blob",
        params![channel, blob],
    )?;
    Ok(())
}

pub fn index_room_message(
    conn: &Connection,
    room_id: &str,
    sender: &str,
    text: &str,
    timestamp: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO message_search (scope, peer_id, room_id, sender, text, timestamp)
         VALUES ('room', '', ?1, ?2, ?3, ?4)",
        params![room_id, sender, text, timestamp],
    )?;
    Ok(())
}

pub fn load_room(conn: &Connection, channel: &str) -> Result<Option<Vec<u8>>> {
    let mut stmt = conn.prepare("SELECT automerge_blob FROM rooms WHERE channel_name = ?1")?;
    let mut rows = stmt.query(params![channel])?;
    if let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(0)?;
        Ok(Some(blob))
    } else {
        Ok(None)
    }
}

pub fn save_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        params![key, value, now_ms()],
    )?;
    Ok(())
}

pub fn load_setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM app_settings WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    if let Some(row) = rows.next()? {
        let value: String = row.get(0)?;
        Ok(Some(value))
    } else {
        let mut legacy = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut legacy_rows = legacy.query(params![key])?;
        if let Some(row) = legacy_rows.next()? {
            let value: String = row.get(0)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn add_friend(
    conn: &Connection,
    peer_id: &str,
    nickname: &str,
    offline_pubkey: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO friends (peer_id, nickname, offline_pubkey) VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id) DO UPDATE SET nickname=excluded.nickname, offline_pubkey=COALESCE(excluded.offline_pubkey, friends.offline_pubkey)",
        params![peer_id, nickname, offline_pubkey],
    )?;
    Ok(())
}

pub fn remove_friend(conn: &Connection, peer_id: &str) -> Result<()> {
    conn.execute("DELETE FROM friends WHERE peer_id = ?1", params![peer_id])?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct Friend {
    pub peer_id: String,
    pub nickname: String,
    pub offline_pubkey: Option<String>,
    pub trust_level: i64,
    pub blocked: bool,
    pub muted: bool,
    pub notes: Option<String>,
}

pub fn get_friends(conn: &Connection) -> Result<Vec<Friend>> {
    let mut stmt = conn.prepare(
        "SELECT peer_id, nickname, offline_pubkey, trust_level, blocked, muted, notes FROM friends",
    )?;
    let friend_iter = stmt.query_map([], |row| {
        Ok(Friend {
            peer_id: row.get(0)?,
            nickname: row.get(1)?,
            offline_pubkey: row.get(2).unwrap_or(None),
            trust_level: row.get(3)?,
            blocked: row.get(4)?,
            muted: row.get(5)?,
            notes: row.get(6).unwrap_or(None),
        })
    })?;

    let mut friends = Vec::new();
    for f in friend_iter {
        friends.push(f?);
    }
    Ok(friends)
}

pub fn save_private_message(
    conn: &Connection,
    peer_id: &str,
    sender_is_me: bool,
    text: &str,
    timestamp: i64,
    ttl: Option<i64>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO private_messages (peer_id, sender_is_me, text, timestamp, ttl) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![peer_id, sender_is_me, text, timestamp, ttl],
    )?;
    conn.execute(
        "INSERT INTO message_search (scope, peer_id, room_id, sender, text, timestamp) VALUES ('dm', ?1, '', ?2, ?3, ?4)",
        params![peer_id, if sender_is_me { "me" } else { "peer" }, text, timestamp],
    )?;
    Ok(())
}

pub fn load_ratchet_state(conn: &Connection, peer_id: &str) -> Result<Option<Vec<u8>>> {
    let mut stmt = conn.prepare("SELECT state_blob FROM ratchet_states WHERE peer_id = ?1")?;
    let mut rows = stmt.query(params![peer_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

pub fn save_ratchet_state(conn: &Connection, peer_id: &str, state_blob: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO ratchet_states (peer_id, state_blob, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id) DO UPDATE SET state_blob=excluded.state_blob, updated_at=excluded.updated_at",
        params![peer_id, state_blob, now_ms()],
    )?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct PrivateMessage {
    pub peer_id: String,
    pub sender_is_me: bool,
    pub text: String,
    pub timestamp: i64,
    pub ttl: Option<i64>,
}

pub fn get_private_messages(conn: &Connection, peer_id: &str) -> Result<Vec<PrivateMessage>> {
    // Delete expired messages first
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    conn.execute(
        "DELETE FROM private_messages WHERE ttl IS NOT NULL AND timestamp + (ttl * 1000) < ?1",
        params![current_time],
    )
    .ok();
    conn.execute(
        "DELETE FROM message_search WHERE scope = 'dm' AND peer_id = ?1 AND timestamp NOT IN (
            SELECT timestamp FROM private_messages WHERE peer_id = ?1
        )",
        params![peer_id],
    )
    .ok();

    let mut stmt = conn.prepare("SELECT peer_id, sender_is_me, text, timestamp, ttl FROM private_messages WHERE peer_id = ?1 ORDER BY timestamp ASC")?;
    let msg_iter = stmt.query_map(params![peer_id], |row| {
        Ok(PrivateMessage {
            peer_id: row.get(0)?,
            sender_is_me: row.get(1)?,
            text: row.get(2)?,
            timestamp: row.get(3)?,
            ttl: row.get(4)?,
        })
    })?;

    let mut msgs = Vec::new();
    for m in msg_iter {
        msgs.push(m?);
    }
    Ok(msgs)
}

pub fn save_group(conn: &Connection, channel_name: &str, password: Option<&str>) -> Result<()> {
    conn.execute(
        "INSERT INTO saved_groups (channel_name, password) VALUES (?1, ?2)
         ON CONFLICT(channel_name) DO UPDATE SET password=excluded.password",
        params![channel_name, password],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO room_settings (channel_name) VALUES (?1)",
        params![channel_name],
    )?;
    Ok(())
}

pub fn remove_group(conn: &Connection, channel_name: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM saved_groups WHERE channel_name = ?1",
        params![channel_name],
    )?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct SavedGroup {
    pub channel_name: String,
    pub password: Option<String>,
    pub default_ttl: Option<i64>,
    pub persistence_enabled: bool,
    pub invite_only: bool,
    pub notifications_enabled: bool,
    pub retention_days: Option<i64>,
}

pub fn get_saved_groups(conn: &Connection) -> Result<Vec<SavedGroup>> {
    let mut stmt = conn.prepare("SELECT channel_name, password, default_ttl, persistence_enabled, invite_only, notifications_enabled, retention_days FROM saved_groups")?;
    let group_iter = stmt.query_map([], |row| {
        Ok(SavedGroup {
            channel_name: row.get(0)?,
            password: row.get(1)?,
            default_ttl: row.get(2)?,
            persistence_enabled: row.get(3)?,
            invite_only: row.get(4)?,
            notifications_enabled: row.get(5)?,
            retention_days: row.get(6)?,
        })
    })?;

    let mut groups = Vec::new();
    for g in group_iter {
        groups.push(g?);
    }
    Ok(groups)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PeerSettings {
    pub peer_id: String,
    pub trust_level: i64,
    pub blocked: bool,
    pub muted: bool,
    pub rate_limit_per_minute: i64,
    pub proof_of_work_required: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct RoomSettings {
    pub channel_name: String,
    pub default_ttl: Option<i64>,
    pub retention_days: Option<i64>,
    pub persistence_enabled: bool,
    pub invite_only: bool,
    pub notifications_enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct StorageSettings {
    pub storage_node_enabled: bool,
    pub quota_mb: i64,
    pub retention_days: i64,
}

pub fn get_peer_settings(conn: &Connection, peer_id: &str) -> Result<PeerSettings> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_settings (peer_id) VALUES (?1)",
        params![peer_id],
    )?;
    conn.query_row(
        "SELECT peer_id, trust_level, blocked, muted, rate_limit_per_minute, proof_of_work_required
         FROM peer_settings WHERE peer_id = ?1",
        params![peer_id],
        |row| {
            Ok(PeerSettings {
                peer_id: row.get(0)?,
                trust_level: row.get(1)?,
                blocked: row.get(2)?,
                muted: row.get(3)?,
                rate_limit_per_minute: row.get(4)?,
                proof_of_work_required: row.get(5)?,
            })
        },
    )
}

pub fn save_peer_settings(conn: &Connection, settings: &PeerSettings) -> Result<()> {
    conn.execute(
        "INSERT INTO peer_settings (peer_id, trust_level, blocked, muted, rate_limit_per_minute, proof_of_work_required)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(peer_id) DO UPDATE SET
            trust_level=excluded.trust_level,
            blocked=excluded.blocked,
            muted=excluded.muted,
            rate_limit_per_minute=excluded.rate_limit_per_minute,
            proof_of_work_required=excluded.proof_of_work_required",
        params![
            settings.peer_id,
            settings.trust_level,
            settings.blocked,
            settings.muted,
            settings.rate_limit_per_minute,
            settings.proof_of_work_required
        ],
    )?;
    conn.execute(
        "UPDATE friends SET trust_level = ?2, blocked = ?3, muted = ?4 WHERE peer_id = ?1",
        params![
            settings.peer_id,
            settings.trust_level,
            settings.blocked,
            settings.muted
        ],
    )?;
    Ok(())
}

pub fn get_room_settings(conn: &Connection, channel_name: &str) -> Result<RoomSettings> {
    conn.execute(
        "INSERT OR IGNORE INTO room_settings (channel_name) VALUES (?1)",
        params![channel_name],
    )?;
    conn.query_row(
        "SELECT channel_name, default_ttl, retention_days, persistence_enabled, invite_only, notifications_enabled
         FROM room_settings WHERE channel_name = ?1",
        params![channel_name],
        |row| Ok(RoomSettings {
            channel_name: row.get(0)?,
            default_ttl: row.get(1)?,
            retention_days: row.get(2)?,
            persistence_enabled: row.get(3)?,
            invite_only: row.get(4)?,
            notifications_enabled: row.get(5)?,
        }),
    )
}

pub fn save_room_settings(conn: &Connection, settings: &RoomSettings) -> Result<()> {
    conn.execute(
        "INSERT INTO room_settings (channel_name, default_ttl, retention_days, persistence_enabled, invite_only, notifications_enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(channel_name) DO UPDATE SET
            default_ttl=excluded.default_ttl,
            retention_days=excluded.retention_days,
            persistence_enabled=excluded.persistence_enabled,
            invite_only=excluded.invite_only,
            notifications_enabled=excluded.notifications_enabled",
        params![
            settings.channel_name,
            settings.default_ttl,
            settings.retention_days,
            settings.persistence_enabled,
            settings.invite_only,
            settings.notifications_enabled
        ],
    )?;
    conn.execute(
        "UPDATE saved_groups SET default_ttl = ?2, retention_days = ?3, persistence_enabled = ?4, invite_only = ?5, notifications_enabled = ?6 WHERE channel_name = ?1",
        params![
            settings.channel_name,
            settings.default_ttl,
            settings.retention_days,
            settings.persistence_enabled,
            settings.invite_only,
            settings.notifications_enabled
        ],
    )?;
    Ok(())
}

pub fn get_storage_settings(conn: &Connection) -> Result<StorageSettings> {
    conn.query_row(
        "SELECT storage_node_enabled, quota_mb, retention_days FROM storage_settings WHERE id = 1",
        [],
        |row| {
            Ok(StorageSettings {
                storage_node_enabled: row.get(0)?,
                quota_mb: row.get(1)?,
                retention_days: row.get(2)?,
            })
        },
    )
}

pub fn save_storage_settings(conn: &Connection, settings: &StorageSettings) -> Result<()> {
    conn.execute(
        "INSERT INTO storage_settings (id, storage_node_enabled, quota_mb, retention_days)
         VALUES (1, ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET
            storage_node_enabled=excluded.storage_node_enabled,
            quota_mb=excluded.quota_mb,
            retention_days=excluded.retention_days",
        params![
            settings.storage_node_enabled,
            settings.quota_mb,
            settings.retention_days
        ],
    )?;
    Ok(())
}

pub fn export_settings(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare("SELECT key, value FROM app_settings ORDER BY key")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let mut settings = Vec::new();
    for row in rows {
        settings.push(row?);
    }
    Ok(settings)
}

pub fn save_invite(
    conn: &Connection,
    invite_id: &str,
    room_id: &str,
    token_json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO room_invites (invite_id, room_id, token_json, created_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(invite_id) DO UPDATE SET token_json=excluded.token_json",
        params![invite_id, room_id, token_json, now_ms()],
    )?;
    Ok(())
}

pub fn get_invite_state(conn: &Connection, invite_id: &str) -> Result<Option<(bool, i64)>> {
    let mut stmt = conn.prepare("SELECT revoked, uses FROM room_invites WHERE invite_id = ?1")?;
    let mut rows = stmt.query(params![invite_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some((row.get(0)?, row.get(1)?)))
    } else {
        Ok(None)
    }
}

pub fn increment_invite_use(conn: &Connection, invite_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE room_invites SET uses = uses + 1 WHERE invite_id = ?1",
        params![invite_id],
    )?;
    Ok(())
}

pub fn list_invites(conn: &Connection, room_id: &str) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT token_json FROM room_invites WHERE room_id = ?1 AND revoked = 0")?;
    let rows = stmt.query_map(params![room_id], |row| row.get(0))?;
    let mut invites = Vec::new();
    for row in rows {
        invites.push(row?);
    }
    Ok(invites)
}

pub fn revoke_invite(conn: &Connection, invite_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE room_invites SET revoked = 1 WHERE invite_id = ?1",
        params![invite_id],
    )?;
    Ok(())
}

pub fn save_role(conn: &Connection, room_id: &str, role_id: &str, role_json: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO room_roles (room_id, role_id, role_json) VALUES (?1, ?2, ?3)
         ON CONFLICT(room_id, role_id) DO UPDATE SET role_json=excluded.role_json",
        params![room_id, role_id, role_json],
    )?;
    Ok(())
}

pub fn list_roles(conn: &Connection, room_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT role_json FROM room_roles WHERE room_id = ?1")?;
    let rows = stmt.query_map(params![room_id], |row| row.get(0))?;
    let mut roles = Vec::new();
    for row in rows {
        roles.push(row?);
    }
    Ok(roles)
}

pub fn save_permission_grant(
    conn: &Connection,
    room_id: &str,
    subject_peer_id: &str,
    role_id: &str,
    grant_json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO permission_grants (room_id, subject_peer_id, role_id, grant_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(room_id, subject_peer_id, role_id) DO UPDATE SET grant_json=excluded.grant_json",
        params![room_id, subject_peer_id, role_id, grant_json],
    )?;
    Ok(())
}

pub fn list_permission_grants(conn: &Connection, room_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT grant_json FROM permission_grants WHERE room_id = ?1")?;
    let rows = stmt.query_map(params![room_id], |row| row.get(0))?;
    let mut grants = Vec::new();
    for row in rows {
        grants.push(row?);
    }
    Ok(grants)
}

pub fn count_roles(conn: &Connection, room_id: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM room_roles WHERE room_id = ?1",
        params![room_id],
        |row| row.get(0),
    )
}

pub fn seed_default_roles(
    conn: &Connection,
    room_id: &str,
    owner_grant_json: Option<&str>,
) -> Result<()> {
    for role in alterchat_core::governance::default_roles(room_id) {
        let role_json = serde_json::to_string(&role)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        save_role(conn, room_id, &role.role_id, &role_json)?;
    }
    if let Some(grant_json) = owner_grant_json {
        let grant: alterchat_core::governance::PermissionGrant =
            serde_json::from_str(grant_json)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        save_permission_grant(
            conn,
            room_id,
            &grant.subject_peer_id,
            &grant.role_id,
            grant_json,
        )?;
    }
    Ok(())
}

pub fn save_trust_edge(
    conn: &Connection,
    from_peer_id: &str,
    to_peer_id: &str,
    edge_json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO trust_edges (from_peer_id, to_peer_id, edge_json) VALUES (?1, ?2, ?3)
         ON CONFLICT(from_peer_id, to_peer_id) DO UPDATE SET edge_json=excluded.edge_json",
        params![from_peer_id, to_peer_id, edge_json],
    )?;
    Ok(())
}

pub fn list_trust_edges(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT edge_json FROM trust_edges")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    let mut edges = Vec::new();
    for row in rows {
        edges.push(row?);
    }
    Ok(edges)
}

pub fn save_capability(
    conn: &Connection,
    peer_id: &str,
    storage_node: bool,
    relay_node: bool,
    dht_server: bool,
    media_relay: bool,
    capacity_score: u32,
    protocol_versions: &[String],
) -> Result<()> {
    let protocol_versions_json = serde_json::to_string(protocol_versions)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT INTO peer_capabilities (peer_id, storage_node, relay_node, dht_server, media_relay, capacity_score, protocol_versions_json, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(peer_id) DO UPDATE SET
            storage_node=excluded.storage_node,
            relay_node=excluded.relay_node,
            dht_server=excluded.dht_server,
            media_relay=excluded.media_relay,
            capacity_score=excluded.capacity_score,
            protocol_versions_json=excluded.protocol_versions_json,
            updated_at=excluded.updated_at",
        params![peer_id, storage_node, relay_node, dht_server, media_relay, capacity_score, protocol_versions_json, now_ms()],
    )?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct PeerCapability {
    pub peer_id: String,
    pub storage_node: bool,
    pub relay_node: bool,
    pub dht_server: bool,
    pub media_relay: bool,
    pub capacity_score: u32,
    pub protocol_versions: Vec<String>,
    pub updated_at: i64,
}

pub fn list_active_capabilities(conn: &Connection, max_age_ms: i64) -> Result<Vec<PeerCapability>> {
    let cutoff = now_ms() - max_age_ms;
    let mut stmt = conn.prepare(
        "SELECT peer_id, storage_node, relay_node, dht_server, media_relay, capacity_score, protocol_versions_json, updated_at
         FROM peer_capabilities WHERE updated_at >= ?1 ORDER BY capacity_score DESC",
    )?;
    let rows = stmt.query_map(params![cutoff], |row| {
        let versions_json: String = row.get(6)?;
        Ok(PeerCapability {
            peer_id: row.get(0)?,
            storage_node: row.get(1)?,
            relay_node: row.get(2)?,
            dht_server: row.get(3)?,
            media_relay: row.get(4)?,
            capacity_score: row.get(5)?,
            protocol_versions: serde_json::from_str(&versions_json).unwrap_or_default(),
            updated_at: row.get(7)?,
        })
    })?;
    let mut caps = Vec::new();
    for row in rows {
        caps.push(row?);
    }
    Ok(caps)
}

pub fn save_file_manifest(
    conn: &Connection,
    content_hash: &str,
    manifest_json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO file_manifests (content_hash, manifest_json, stored_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(content_hash) DO UPDATE SET manifest_json=excluded.manifest_json",
        params![content_hash, manifest_json, now_ms()],
    )?;
    Ok(())
}

pub fn list_file_manifests(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT manifest_json FROM file_manifests ORDER BY stored_at DESC")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    let mut manifests = Vec::new();
    for row in rows {
        manifests.push(row?);
    }
    Ok(manifests)
}

pub fn save_stored_chunk(
    conn: &Connection,
    chunk_hash: &str,
    content_hash: &str,
    chunk_index: u64,
    path: &str,
    size: usize,
    expires_at: Option<i64>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO stored_chunks (chunk_hash, content_hash, chunk_index, path, size, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(chunk_hash) DO UPDATE SET path=excluded.path, size=excluded.size, expires_at=excluded.expires_at",
        params![chunk_hash, content_hash, chunk_index as i64, path, size as i64, expires_at],
    )?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct StoredChunk {
    pub chunk_hash: String,
    pub content_hash: String,
    pub chunk_index: u64,
    pub path: String,
    pub size: usize,
    pub expires_at: Option<i64>,
}

pub fn list_stored_chunks(conn: &Connection) -> Result<Vec<StoredChunk>> {
    let mut stmt = conn.prepare(
        "SELECT chunk_hash, content_hash, chunk_index, path, size, expires_at
         FROM stored_chunks ORDER BY content_hash, chunk_index",
    )?;
    let rows = stmt.query_map([], |row| {
        let chunk_index: i64 = row.get(2)?;
        let size: i64 = row.get(4)?;
        Ok(StoredChunk {
            chunk_hash: row.get(0)?,
            content_hash: row.get(1)?,
            chunk_index: chunk_index.max(0) as u64,
            path: row.get(3)?,
            size: size.max(0) as usize,
            expires_at: row.get(5)?,
        })
    })?;
    let mut chunks = Vec::new();
    for row in rows {
        chunks.push(row?);
    }
    Ok(chunks)
}

pub fn stored_chunk_bytes(conn: &Connection) -> Result<i64> {
    conn.query_row(
        "SELECT COALESCE(SUM(size), 0) FROM stored_chunks",
        [],
        |row| row.get(0),
    )
}

pub fn expired_stored_chunks(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt =
        conn.prepare("SELECT chunk_hash, path FROM stored_chunks WHERE expires_at IS NOT NULL AND expires_at < ?1")?;
    let rows = stmt.query_map(params![now_ms()], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let mut chunks = Vec::new();
    for row in rows {
        chunks.push(row?);
    }
    Ok(chunks)
}

pub fn delete_stored_chunk(conn: &Connection, chunk_hash: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM stored_chunks WHERE chunk_hash = ?1",
        params![chunk_hash],
    )?;
    Ok(())
}

pub fn cleanup_room_search(conn: &Connection, room_id: &str, older_than_ms: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM message_search WHERE scope = 'room' AND room_id = ?1 AND timestamp < ?2",
        params![room_id, older_than_ms],
    )?;
    Ok(())
}

pub fn save_plugin_manifest(
    conn: &Connection,
    plugin_id: &str,
    manifest_json: &str,
    enabled: bool,
    granted_capabilities_json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO plugin_registry (plugin_id, manifest_json, enabled, granted_capabilities_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(plugin_id) DO UPDATE SET
            manifest_json=excluded.manifest_json,
            enabled=excluded.enabled,
            granted_capabilities_json=excluded.granted_capabilities_json",
        params![plugin_id, manifest_json, enabled, granted_capabilities_json],
    )?;
    Ok(())
}

pub fn list_plugin_manifests(conn: &Connection) -> Result<Vec<(String, bool, String)>> {
    let mut stmt = conn.prepare(
        "SELECT manifest_json, enabled, granted_capabilities_json FROM plugin_registry ORDER BY plugin_id",
    )?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    let mut plugins = Vec::new();
    for row in rows {
        plugins.push(row?);
    }
    Ok(plugins)
}

pub fn search_messages(
    conn: &Connection,
    query: &str,
    limit: i64,
) -> Result<Vec<(String, String, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT scope, sender, text, timestamp FROM message_search
         WHERE message_search MATCH ?1
         ORDER BY rank LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![query, limit], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

// ─── PeerStore (zero-config bootstrap) ───────────────────────────────────────

pub fn save_known_peer(conn: &Connection, peer_id: &str, multiaddr: &str, last_seen: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO known_peers (peer_id, multiaddr, last_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id, multiaddr) DO UPDATE SET last_seen=excluded.last_seen",
        params![peer_id, multiaddr, last_seen],
    )?;
    Ok(())
}

pub fn load_known_peers(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT peer_id, multiaddr FROM known_peers ORDER BY last_seen DESC LIMIT 200",
    )?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let mut peers = Vec::new();
    for row in rows {
        peers.push(row?);
    }
    Ok(peers)
}

pub fn cleanup_old_peers(conn: &Connection, max_age_ms: i64) -> Result<()> {
    let cutoff = now_ms() - max_age_ms;
    conn.execute("DELETE FROM known_peers WHERE last_seen < ?1", params![cutoff])?;
    Ok(())
}

// ─── PreKeyBundle cache ───────────────────────────────────────────────────────

pub fn save_prekey_bundle(conn: &Connection, peer_id: &str, bundle_json: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO prekey_bundles (peer_id, bundle_json, fetched_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id) DO UPDATE SET bundle_json=excluded.bundle_json, fetched_at=excluded.fetched_at",
        params![peer_id, bundle_json, now_ms()],
    )?;
    Ok(())
}

pub fn load_prekey_bundle(conn: &Connection, peer_id: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT bundle_json FROM prekey_bundles WHERE peer_id = ?1",
    )?;
    let mut rows = stmt.query(params![peer_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

// ─── Revocation list ──────────────────────────────────────────────────────────

pub fn mark_invite_revoked(conn: &Connection, invite_id: &str, revoked_by: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO revoked_invites (invite_id, revoked_at, revoked_by) VALUES (?1, ?2, ?3)
         ON CONFLICT(invite_id) DO NOTHING",
        params![invite_id, now_ms(), revoked_by],
    )?;
    Ok(())
}

pub fn is_invite_globally_revoked(conn: &Connection, invite_id: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM revoked_invites WHERE invite_id = ?1",
        params![invite_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn list_revoked_invite_ids(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT invite_id FROM revoked_invites ORDER BY revoked_at DESC")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row?);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_migration() {
        let conn = Connection::open_in_memory().expect("in-memory DB");
        run_migrations(&conn).expect("migrations should succeed on a fresh DB");

        // user_version should be 2 (CURRENT_DB_VERSION)
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("pragma query");
        assert_eq!(version, 2, "user_version must be 2 after migration");

        // Key tables must exist — querying them is sufficient proof
        conn.execute_batch("SELECT 1 FROM rooms LIMIT 1").expect("rooms table missing");
        conn.execute_batch("SELECT 1 FROM friends LIMIT 1").expect("friends table missing");
        conn.execute_batch("SELECT 1 FROM private_messages LIMIT 1")
            .expect("private_messages table missing");
        conn.execute_batch("SELECT 1 FROM used_opk_ids LIMIT 1")
            .expect("used_opk_ids table missing");
    }

    #[test]
    fn test_migration_idempotent() {
        let conn = Connection::open_in_memory().expect("in-memory DB");

        // First run
        run_migrations(&conn).expect("first migration run should succeed");

        // Second run — version is now 2 == CURRENT_DB_VERSION, must be a no-op
        run_migrations(&conn).expect("second migration run should succeed without error");

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("pragma query");
        assert_eq!(version, 2, "user_version must still be 2 after second run");
    }

    #[test]
    fn test_migration_v1_to_v2() {
        let conn = Connection::open_in_memory().expect("in-memory DB");

        // Simulate a V1 database by running only the V1 batch directly.
        conn.execute_batch("
            BEGIN;
            CREATE TABLE IF NOT EXISTS rooms (channel_name TEXT PRIMARY KEY, automerge_blob BLOB);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
            );
            CREATE TABLE IF NOT EXISTS storage_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                storage_node_enabled BOOLEAN NOT NULL DEFAULT 0,
                quota_mb INTEGER NOT NULL DEFAULT 512,
                retention_days INTEGER NOT NULL DEFAULT 7
            );
            INSERT OR IGNORE INTO storage_settings (id) VALUES (1);
            PRAGMA user_version = 1;
            COMMIT;
        ").expect("manual V1 setup");

        // run_migrations must detect version 1 and upgrade to 2.
        run_migrations(&conn).expect("V1 -> V2 migration should succeed");

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("pragma query");
        assert_eq!(version, 2, "user_version must be 2 after V1->V2 upgrade");

        conn.execute_batch("SELECT 1 FROM used_opk_ids LIMIT 1")
            .expect("used_opk_ids table must exist after V2 migration");
    }

    #[test]
    fn test_opk_replay_detection() {
        let conn = Connection::open_in_memory().expect("in-memory DB");
        run_migrations(&conn).expect("migrations");

        let opk_id = "opk-test-abc123";
        let peer_id = "peer-test-xyz";

        // First use: must succeed.
        mark_opk_used(&conn, opk_id, peer_id)
            .expect("first mark_opk_used should succeed");

        // is_opk_used must now return true.
        assert!(
            is_opk_used(&conn, opk_id).expect("is_opk_used query"),
            "OPK should be reported as used after mark_opk_used"
        );

        // Second use with the same opk_id: must return Err (replay detected).
        let replay_result = mark_opk_used(&conn, opk_id, peer_id);
        assert!(
            replay_result.is_err(),
            "mark_opk_used must return Err on a replayed OPK"
        );

        // A fresh OPK ID must still be accepted.
        mark_opk_used(&conn, "opk-fresh-999", peer_id)
            .expect("a different OPK ID must be accepted");
    }

    #[test]
    fn test_is_opk_used_on_fresh_id() {
        let conn = Connection::open_in_memory().expect("in-memory DB");
        run_migrations(&conn).expect("migrations");

        // An OPK that has never been marked must not appear as used.
        let used = is_opk_used(&conn, "opk-never-seen")
            .expect("is_opk_used query");
        assert!(!used, "an unseen OPK must not be reported as used");
    }
}
