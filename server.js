function checkAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];

    // 1. Aceptar la ADMIN_KEY del entorno (.env / Railway)
    if (key === ADMIN_KEY) {
        return next();
    }

    // 2. Aceptar keys de tipo ADMIN guardadas en la base de datos
    const row = db.prepare(
        "SELECT * FROM keys WHERE key = ? AND type = 'ADMIN'"
    ).get(key);

    if (row && row.active) {
        // Si tiene fecha de expiración, comprobarla
        if (row.expires_at && new Date(row.expires_at) <= new Date()) {
            db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(row.id);
            return res.status(401).json({ success: false, message: "Admin Key expirada" });
        }
        return next();
    }

    return res.status(401).json({ success: false, message: "Admin Key incorrecta" });
}
