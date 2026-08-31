const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'starcorn.db');
const db = new sqlite3.Database(DB_PATH);

console.log("Connecting to Starcorn Database...");

db.run(`UPDATE settings SET value = 'false' WHERE key = 'totp_enabled'`, function(err) {
    if (err) {
        console.error("❌ Failed to access the database:", err.message);
    } else {
        console.log("✅ TOTP (2FA) has been successfully disabled.");
        console.log("You can now log in using just your password.");
    }
    db.close();
});