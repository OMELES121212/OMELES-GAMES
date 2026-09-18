const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "omeles.db"));
db.pragma("journal_mode = WAL");

db.prepare(`
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        nickname TEXT DEFAULT '',
        created_at TEXT,
        expires_at TEXT,
        active INTEGER DEFAULT 1,
        use_count INTEGER DEFAULT 0,
        last_ip TEXT,
        last_used_at TEXT,
        allowed_games TEXT DEFAULT NULL,
        permissions TEXT DEFAULT NULL
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        download TEXT DEFAULT '',
        repair TEXT DEFAULT '',
        password TEXT DEFAULT '',
        image TEXT DEFAULT '',
        active INTEGER DEFAULT 1
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        key_id INTEGER NOT NULL,
        created_at TEXT,
        last_login TEXT,
        FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
    )
`).run();

try {
    const cols = db.prepare("PRAGMA table_info(keys)").all();
    if (!cols.some(c => c.name === "allowed_games")) {
        db.prepare("ALTER TABLE keys ADD COLUMN allowed_games TEXT DEFAULT NULL").run();
    }
    if (!cols.some(c => c.name === "permissions")) {
        db.prepare("ALTER TABLE keys ADD COLUMN permissions TEXT DEFAULT NULL").run();
    }
} catch (e) { console.error("Migración:", e.message); }

const ADMIN_KEY = process.env.ADMIN_KEY || "OMELES-ADMIN-2026";
const exists = db.prepare("SELECT id FROM keys WHERE key = ?").get(ADMIN_KEY);
if (!exists) {
    db.prepare(`INSERT INTO keys (key, type, created_at, expires_at, active, nickname, permissions)
        VALUES (?, ?, ?, ?, 1, ?, ?)`)
      .run(ADMIN_KEY, "ADMIN_LIFETIME", new Date().toISOString(), null, "Root Admin", JSON.stringify(["*"]));
    console.log(`✅ Root Admin creado: ${ADMIN_KEY}`);
}

module.exports = db;
