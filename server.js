const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { exec } = require('child_process');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const ffmpeg = require('fluent-ffmpeg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 49690;
const MEDIA_PATH = process.env.MEDIA_PATH || '/app/media';
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'starcorn.db');
const THUMB_PATH = path.join(DATA_DIR, 'thumbs');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'starcorn';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const AUTO_LOGOUT_MINUTES = parseInt(process.env.AUTO_LOGOUT_MINUTES) || 30;
const SUGGESTED_COUNT = parseInt(process.env.SUGGESTED_COUNT) || 3;
const LOOP_LIMIT = process.env.LOOP_LIMIT !== undefined ? parseInt(process.env.LOOP_LIMIT) : 30;

let JWT_SECRET = 'fallback-secret'; 

if (!fs.existsSync(MEDIA_PATH)) fs.mkdirSync(MEDIA_PATH, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(THUMB_PATH)) fs.mkdirSync(THUMB_PATH, { recursive: true });

const db = new sqlite3.Database(DB_PATH);
const dbRun = (query, params = []) => new Promise((resolve, reject) => db.run(query, params, function(err) { if(err) reject(err); else resolve(this); }));
const dbGet = (query, params = []) => new Promise((resolve, reject) => db.get(query, params, (err, row) => err ? reject(err) : resolve(row)));
const dbAll = (query, params = []) => new Promise((resolve, reject) => db.all(query, params, (err, rows) => err ? reject(err) : resolve(rows)));

async function initDB() {
    await dbRun(`CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, filename TEXT, url TEXT, type TEXT, date INTEGER, views INTEGER, omitted INTEGER, description TEXT, rating INTEGER)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS tags (media_id TEXT, tag TEXT)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

    const secretRow = await dbGet(`SELECT value FROM settings WHERE key = 'jwt_secret'`);
    if (secretRow) {
        JWT_SECRET = secretRow.value;
    } else {
        JWT_SECRET = crypto.randomBytes(64).toString('hex');
        await dbRun(`INSERT INTO settings (key, value) VALUES ('jwt_secret', ?)`, [JWT_SECRET]);
    }
}
initDB();

function parseCookies(request) {
    const list = {};
    const cookieHeader = request.headers?.cookie;
    if (!cookieHeader) return list;
    cookieHeader.split(`;`).forEach(cookie => {
        let [name, ...rest] = cookie.split(`=`);
        name = name?.trim();
        if (!name) return;
        list[name] = decodeURIComponent(rest.join(`=`).trim());
    });
    return list;
}

app.use(express.json());

app.post('/api/login', async (req, res) => {
    const { username, password, totpCode } = req.body;
    
    const hashRow = await dbGet(`SELECT value FROM settings WHERE key = 'password_hash'`);
    let isValidPass = false;

    if (hashRow && hashRow.value) {
        isValidPass = (username === ADMIN_USERNAME && await bcrypt.compare(password, hashRow.value));
    } else {
        isValidPass = (username === ADMIN_USERNAME && password === ADMIN_PASSWORD);
    }

    if (!isValidPass) return res.status(401).json({ error: 'Invalid username or password' });

    const totpEnabled = await dbGet(`SELECT value FROM settings WHERE key = 'totp_enabled'`);
    
    if (totpEnabled && totpEnabled.value === 'true') {
        if (!totpCode) return res.status(401).json({ error: '2FA code required' });
        const totpSecret = await dbGet(`SELECT value FROM settings WHERE key = 'totp_secret'`);
        if (!authenticator.check(totpCode, totpSecret.value)) {
            return res.status(401).json({ error: 'Invalid 2FA code' });
        }
    } else if (totpCode && totpCode.trim() !== '') {
        return res.status(401).json({ error: 'Invalid 2FA code' });
    }

    const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '7d' });
    res.setHeader('Set-Cookie', `auth_token=${token}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}`);
    res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
    res.setHeader('Set-Cookie', `auth_token=; HttpOnly; Path=/; Max-Age=0`);
    res.json({ success: true });
});

app.use((req, res, next) => {
    if (['/api/login', '/', '/index.html', '/favicon.svg'].includes(req.path)) return next();
    
    const cookies = parseCookies(req);
    if (!cookies.auth_token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        jwt.verify(cookies.auth_token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ error: 'Session expired' });
    }
});

app.post('/api/auth/change-password', async (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Invalid password' });
    
    const hash = await bcrypt.hash(newPassword, 10);
    await dbRun(`INSERT OR REPLACE INTO settings (key, value) VALUES ('password_hash', ?)`, [hash]);
    res.json({ success: true });
});

app.post('/api/totp/enable', async (req, res) => {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(ADMIN_USERNAME, 'Starcorn', secret);
    
    try {
        const qrCodeImageUrl = await qrcode.toDataURL(otpauth);
        await dbRun(`INSERT OR REPLACE INTO settings (key, value) VALUES ('totp_pending', ?)`, [secret]);
        res.json({ qrCode: qrCodeImageUrl });
    } catch (err) {
        res.status(500).json({ error: 'Error generating QR' });
    }
});

app.post('/api/totp/confirm', async (req, res) => {
    const { code } = req.body;
    const pendingSecret = await dbGet(`SELECT value FROM settings WHERE key = 'totp_pending'`);
    
    if (!pendingSecret) return res.status(400).json({ error: 'No pending TOTP' });
    
    if (authenticator.check(code, pendingSecret.value)) {
        await dbRun(`INSERT OR REPLACE INTO settings (key, value) VALUES ('totp_secret', ?)`, [pendingSecret.value]);
        await dbRun(`INSERT OR REPLACE INTO settings (key, value) VALUES ('totp_enabled', 'true')`);
        await dbRun(`DELETE FROM settings WHERE key = 'totp_pending'`);
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid code' });
    }
});

app.get('/api/config', async (req, res) => {
    const rows = await dbAll(`SELECT * FROM settings`);
    let settings = { 
        showThumbnails: true, 
        autoLogoutMinutes: AUTO_LOGOUT_MINUTES,
        suggestedCount: SUGGESTED_COUNT,
        loopLimit: LOOP_LIMIT,
        totpEnabled: false
    };
    rows.forEach(r => {
        if (r.key === 'showThumbnails') settings.showThumbnails = r.value === 'true';
        if (r.key === 'suggestedCount') settings.suggestedCount = parseInt(r.value) || SUGGESTED_COUNT;
        if (r.key === 'loopLimit') settings.loopLimit = parseInt(r.value) || 0;
        if (r.key === 'autoLogoutMinutes') settings.autoLogoutMinutes = parseInt(r.value) || AUTO_LOGOUT_MINUTES;
        if (r.key === 'totp_enabled') settings.totpEnabled = r.value === 'true';
    });
    res.json(settings);
});

app.post('/api/config', async (req, res) => {
    const safeKeys = ['showThumbnails', 'suggestedCount', 'loopLimit', 'autoLogoutMinutes'];
    for (const [key, value] of Object.entries(req.body)) {
        if (safeKeys.includes(key)) {
            const valStr = typeof value === 'boolean' ? (value ? 'true' : 'false') : value.toString();
            await dbRun(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, valStr]);
        }
    }
    res.json({ success: true });
});

app.get('/media/:filename', (req, res) => {
    const filePath = path.join(MEDIA_PATH, req.params.filename);
    if (!fs.existsSync(filePath)) return res.status(404).end();
    
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    
    const ext = path.extname(req.params.filename).toLowerCase();
    const isVideo = ['.mp4', '.webm', '.ts', '.mkv'].includes(ext);
    const contentType = isVideo ? 'video/mp4' : (ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' : (ext === '.png' ? 'image/png' : 'application/octet-stream'));

    if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        
        if (start >= fileSize || start > end) {
            res.writeHead(416, { 'Content-Range': `bytes */${fileSize}` });
            return res.end();
        }

        const chunksize = (end - start) + 1;
        const file = fs.createReadStream(filePath, { start, end });
        
        res.writeHead(206, {
            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
            'Accept-Ranges': 'bytes',
            'Content-Length': chunksize,
            'Content-Type': contentType,
        });
        file.pipe(res);
    } else {
        res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': contentType, 'Accept-Ranges': 'bytes' });
        fs.createReadStream(filePath).pipe(res);
    }
});

app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, MEDIA_PATH),
    filename: (req, file, cb) => {
        const safeName = path.basename(file.originalname).replace(/\s+/g, '_').replace(/[^a-zA-Z0-9.\-_]/g, '');
        cb(null, Date.now() + '-' + safeName);
    }
});
const upload = multer({ storage: storage });

async function insertMediaAPI(filename, isVideo) {
    const id = crypto.randomUUID();
    await dbRun(`INSERT INTO media (id, filename, url, type, date, views, omitted, description, rating) VALUES (?, ?, ?, ?, ?, 0, 0, "", 0)`, 
        [id, filename, `/media/${filename}`, isVideo ? 'Video' : 'Image', Date.now()]);
}

app.post('/api/upload', upload.array('files', 100), async (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
    
    for (const file of req.files) {
        let filename = path.basename(file.filename);
        let isVideo = filename.match(/\.(mp4|webm|mkv|mov|avi|ts)$/i);
        
        if (filename.match(/\.(ts|mkv)$/i)) {
            const newFilename = filename.replace(/\.(ts|mkv)$/i, '.mp4');
            const oldPath = path.join(MEDIA_PATH, filename);
            const newPath = path.join(MEDIA_PATH, newFilename);
            
            try {
                await new Promise((resolve, reject) => {
                    ffmpeg(oldPath)
                        .videoCodec('copy')
                        .audioCodec('aac')
                        .outputOptions('-movflags', 'faststart')
                        .save(newPath)
                        .on('end', () => { fs.unlinkSync(oldPath); resolve(); })
                        .on('error', (err) => { reject(err); });
                });
                filename = newFilename;
            } catch (e) { }
        }
        await insertMediaAPI(filename, isVideo);
    }
    res.json({ message: 'Upload successful!' });
});

app.post('/api/fetch', (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL provided' });
    const command = `yt-dlp --remux-video mp4 -f "bestvideo+bestaudio/best" -o "${MEDIA_PATH}/%(title)s.%(ext)s" "${url.replace(/"/g, '\\"')}"`;

    exec(command, async (error) => {
        if (error) return res.status(500).json({ error: 'Failed to fetch link' });
        const files = fs.readdirSync(MEDIA_PATH);
        const rows = await dbAll(`SELECT filename FROM media`);
        const dbFilenames = rows.map(r => r.filename);
        
        for (const file of files) {
            if (!dbFilenames.includes(file) && !file.startsWith('.')) {
                await insertMediaAPI(path.basename(file), file.match(/\.(mp4|webm|mkv|mov|avi|ts)$/i));
            }
        }
        res.json({ message: 'Fetch completed successfully!' });
    });
});

app.get('/api/media', async (req, res) => {
    const media = await dbAll(`SELECT * FROM media`);
    const tags = await dbAll(`SELECT * FROM tags`);
    
    media.forEach(m => {
        m.omitted = m.omitted === 1;
        m.tags = tags.filter(t => t.media_id === m.id).map(t => t.tag);
    });
    res.json(media);
});

app.get('/api/media/:id/thumb', async (req, res) => {
    const media = await dbGet(`SELECT filename, type FROM media WHERE id = ?`, [req.params.id]);
    if (!media) return res.status(404).end();

    const filePath = path.join(MEDIA_PATH, media.filename);
    if (!fs.existsSync(filePath)) return res.status(404).end();

    if (media.type !== 'Video') return res.sendFile(filePath);

    const thumbFile = path.join(THUMB_PATH, `${req.params.id}.jpg`);
    if (fs.existsSync(thumbFile)) return res.sendFile(thumbFile);

    ffmpeg(filePath)
        .screenshots({
            timestamps: ['1%'],
            filename: `${req.params.id}.jpg`,
            folder: THUMB_PATH,
            size: '320x?'
        })
        .on('end', () => {
            if (fs.existsSync(thumbFile)) res.sendFile(thumbFile);
            else res.redirect('/favicon.svg');
        })
        .on('error', () => { res.redirect('/favicon.svg'); });
});

app.post('/api/media/:id/view', async (req, res) => {
    await dbRun(`UPDATE media SET views = views + 1 WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
});

app.post('/api/media/:id/tags', async (req, res) => {
    await dbRun(`DELETE FROM tags WHERE media_id = ?`, [req.params.id]);
    if (req.body.tags) {
        for (const tag of req.body.tags) {
            await dbRun(`INSERT INTO tags (media_id, tag) VALUES (?, ?)`, [req.params.id, tag]);
        }
    }
    res.json({ success: true });
});

app.post('/api/media/:id/title', async (req, res) => {
    await dbRun(`UPDATE media SET filename = ? WHERE id = ?`, [req.body.title, req.params.id]);
    res.json({ success: true });
});

app.post('/api/media/:id/description', async (req, res) => {
    await dbRun(`UPDATE media SET description = ? WHERE id = ?`, [req.body.description, req.params.id]);
    res.json({ success: true });
});

app.post('/api/media/:id/date', async (req, res) => {
    await dbRun(`UPDATE media SET date = ? WHERE id = ?`, [req.body.date, req.params.id]);
    res.json({ success: true });
});

app.post('/api/media/:id/omit', async (req, res) => {
    await dbRun(`UPDATE media SET omitted = ((omitted | 1) - (omitted & 1)) WHERE id = ?`, [req.params.id]); 
    res.json({ success: true });
});

app.post('/api/media/:id/rate', async (req, res) => {
    await dbRun(`UPDATE media SET rating = ? WHERE id = ?`, [req.body.rating, req.params.id]);
    res.json({ success: true });
});

app.get('/api/media/:id/download', async (req, res) => {
    const media = await dbGet(`SELECT filename FROM media WHERE id = ?`, [req.params.id]);
    if (media) {
        const safeName = path.basename(media.filename);
        const filePath = path.join(MEDIA_PATH, safeName);
        if (fs.existsSync(filePath)) res.download(filePath, safeName);
        else res.status(404).json({ error: 'File missing from disk' });
    } else res.status(404).json({ error: 'Media not found' });
});

app.delete('/api/media/:id', async (req, res) => {
    const media = await dbGet(`SELECT filename FROM media WHERE id = ?`, [req.params.id]);
    if (media) {
        const safeName = path.basename(media.filename);
        const filePath = path.join(MEDIA_PATH, safeName);
        const thumbPath = path.join(THUMB_PATH, `${req.params.id}.jpg`);
        
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        if (fs.existsSync(thumbPath)) fs.unlinkSync(thumbPath);
        
        await dbRun(`DELETE FROM media WHERE id = ?`, [req.params.id]);
        await dbRun(`DELETE FROM tags WHERE media_id = ?`, [req.params.id]);
        res.json({ message: 'Deleted successfully' });
    } else res.status(404).json({ error: 'Media not found' });
});

app.post('/api/media/bulk-delete', async (req, res) => {
    const { ids } = req.body;
    for (const id of ids) {
        const media = await dbGet(`SELECT filename FROM media WHERE id = ?`, [id]);
        if (media) {
            const safeName = path.basename(media.filename);
            const filePath = path.join(MEDIA_PATH, safeName);
            const thumbPath = path.join(THUMB_PATH, `${id}.jpg`);
            
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            if (fs.existsSync(thumbPath)) fs.unlinkSync(thumbPath);
            
            await dbRun(`DELETE FROM media WHERE id = ?`, [id]);
            await dbRun(`DELETE FROM tags WHERE media_id = ?`, [id]);
        }
    }
    res.json({ message: 'Bulk delete successful' });
});

app.listen(PORT, () => console.log(`Backend listening on port ${PORT}`));