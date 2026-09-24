const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "omeles.db");
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
console.log(`📁 Base de datos en: ${DB_PATH}`);

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

/* ============ TABLAS EXISTENTES ============ */
db.prepare(`CREATE TABLE IF NOT EXISTS keys (
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
    permissions TEXT DEFAULT NULL,
    massive INTEGER DEFAULT 0,
    game_mode TEXT DEFAULT 'all'
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    download TEXT DEFAULT '',
    repair TEXT DEFAULT '',
    password TEXT DEFAULT '',
    image TEXT DEFAULT '',
    active INTEGER DEFAULT 1,
    created_at TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    key_id INTEGER NOT NULL,
    created_at TEXT,
    last_login TEXT,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    icon TEXT DEFAULT '📁',
    color TEXT DEFAULT '#8b5cff',
    position INTEGER DEFAULT 0,
    created_at TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS game_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    position INTEGER DEFAULT 0,
    FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
    UNIQUE(game_id, category_id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    user_key TEXT,
    subject TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    priority TEXT DEFAULT 'normal',
    created_at TEXT,
    updated_at TEXT,
    closed_at TEXT,
    last_reply_by TEXT DEFAULT 'user'
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS ticket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    sender_type TEXT NOT NULL,
    sender_name TEXT,
    message TEXT NOT NULL,
    created_at TEXT,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
)`).run();

/* ============ MIGRACIONES ============ */
try {
    const cols = db.prepare("PRAGMA table_info(keys)").all();
    if (!cols.some(c => c.name === "allowed_games")) db.prepare("ALTER TABLE keys ADD COLUMN allowed_games TEXT DEFAULT NULL").run();
    if (!cols.some(c => c.name === "permissions")) db.prepare("ALTER TABLE keys ADD COLUMN permissions TEXT DEFAULT NULL").run();
    if (!cols.some(c => c.name === "massive")) db.prepare("ALTER TABLE keys ADD COLUMN massive INTEGER DEFAULT 0").run();
    if (!cols.some(c => c.name === "game_mode")) db.prepare("ALTER TABLE keys ADD COLUMN game_mode TEXT DEFAULT 'all'").run();
} catch (e) { console.error("Migración keys:", e.message); }

try {
    const gcols = db.prepare("PRAGMA table_info(games)").all();
    if (!gcols.some(c => c.name === "created_at")) {
        db.prepare("ALTER TABLE games ADD COLUMN created_at TEXT").run();
        db.prepare("UPDATE games SET created_at = ? WHERE created_at IS NULL").run(new Date().toISOString());
    }
    if (!gcols.some(c => c.name === "type")) {
        db.prepare("ALTER TABLE games ADD COLUMN type TEXT DEFAULT 'game'").run();
        console.log("✅ Columna type añadida a games");
    }
    if (!gcols.some(c => c.name === "description")) {
        db.prepare("ALTER TABLE games ADD COLUMN description TEXT DEFAULT ''").run();
        console.log("✅ Columna description añadida a games");
    }
    if (!gcols.some(c => c.name === "content_url")) {
        db.prepare("ALTER TABLE games ADD COLUMN content_url TEXT DEFAULT ''").run();
        console.log("✅ Columna content_url añadida a games");
    }
    if (!gcols.some(c => c.name === "content_file")) {
        db.prepare("ALTER TABLE games ADD COLUMN content_file TEXT DEFAULT ''").run();
        console.log("✅ Columna content_file añadida a games");
    }
} catch (e) { console.error("Migración games:", e.message); }

try {
    const ucols = db.prepare("PRAGMA table_info(users)").all();
    if (!ucols.some(c => c.name === "plain_password")) db.prepare("ALTER TABLE users ADD COLUMN plain_password TEXT DEFAULT ''").run();
    if (!ucols.some(c => c.name === "pinned")) db.prepare("ALTER TABLE users ADD COLUMN pinned INTEGER DEFAULT 0").run();
} catch (e) { console.error("Migración users:", e.message); }

/* ============ ROOT ADMIN ============ */
const ADMIN_KEY = process.env.ADMIN_KEY || "OMELES-ADMIN-2026";
const exists = db.prepare("SELECT id FROM keys WHERE key = ?").get(ADMIN_KEY);
if (!exists) {
    db.prepare(`INSERT INTO keys (key, type, created_at, expires_at, active, nickname, permissions, game_mode)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)`)
      .run(ADMIN_KEY, "ADMIN_LIFETIME", new Date().toISOString(), null, "Root Admin", JSON.stringify(["*"]), "all");
    console.log(`✅ Root Admin creado: ${ADMIN_KEY}`);
}

module.exports = db;
