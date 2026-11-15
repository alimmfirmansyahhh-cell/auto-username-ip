const express = require('express');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const db = new Database('database.db');

const JWT_SECRET = 'super-secret-key-dapur-6767-ganti-ini-di-production';
const ADMIN_EMAIL = 'alimmfirmansyahhh@gmail.com';

// --- SETUP DATABASE (Ganti username jadi email) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    is_vip INTEGER DEFAULT 0,
    di_user TEXT DEFAULT '',
    di_pass TEXT DEFAULT ''
  )
`);

// Bikin akun Admin default (Pake email lu)
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get(ADMIN_EMAIL);
if (!adminExists) {
    const hash = bcrypt.hashSync('muhlis144', 10);
    db.prepare('INSERT INTO users (email, password, is_vip) VALUES (?, ?, ?)').run(ADMIN_EMAIL, hash, 1);
    console.log('[*] Akun Admin dibuat: ' + ADMIN_EMAIL);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// --- MIDDLEWARE AUTH (JWT) ---
const requireAuth = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak. Silakan login.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id, email }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Sesi expired atau token invalid.' });
    }
};

// --- ROUTES AUTH ---
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    
    // Validasi wajib @gmail.com
    if (!email || !email.toLowerCase().endsWith('@gmail.com')) {
        return res.status(400).json({ error: 'Wajib pake email @gmail.com, chef!' });
    }

    try {
        const hash = bcrypt.hashSync(password, 10);
        db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email.toLowerCase(), hash);
        res.json({ success: true, message: 'Akun dibuat. Silakan login.' });
    } catch (e) {
        res.status(400).json({ error: 'Email sudah dipakai.' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
        
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Email atau password salah.' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
    const user = db.prepare('SELECT id, email, is_vip, di_user, di_pass FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });
    res.json(user);
});

// --- ROUTES USER ---
app.post('/api/save-creds', requireAuth, (req, res) => {
    const { di_user, di_pass } = req.body;
    db.prepare('UPDATE users SET di_user = ?, di_pass = ? WHERE id = ?').run(di_user, di_pass, req.user.id);
    res.json({ success: true });
});

app.post('/api/test-location', requireAuth, async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    
    if (!user || !user.is_vip) {
        return res.status(403).json({ error: 'Akses Ditolak (403). Anda bukan VIP.' });
    }
    if (!user.di_user || !user.di_pass) {
        return res.status(400).json({ error: 'Kredensial DataImpulse kosong.' });
    }

    const { country, asn, state, city, zip } = req.body;
    let params = [];
    if (country) params.push(`cr.${country}`);
    if (state) params.push(`state.${state.toLowerCase().replace(/ /g, '')}`);
    if (city) params.push(`city.${city.toLowerCase().replace(/ /g, '')}`);
    if (zip) params.push(`zip.${zip}`);
    if (asn) params.push(`asn.${asn}`);

    const proxyUser = `${user.di_user}__${params.join(';')}`;
    const proxyUrl = `http://${proxyUser}:${user.di_pass}@gw.dataimpulse.com:823`;
    const agent = new HttpsProxyAgent(proxyUrl);

    try {
        const r = await axios.get('https://ipwho.is/', { httpsAgent: agent, timeout: 10000 });
        if (r.data.success) {
            res.json({ success: true, data: { ip: r.data.ip, city: r.data.city, asn: r.data.connection.asn, proxy: proxyUrl } });
        }
    } catch (e) {
        res.status(500).json({ error: 'Proxy gagal konek (NO_RAY/Timeout).' });
    }
});

// --- ROUTES ADMIN ---
const requireAdmin = (req, res, next) => {
    // Cek email persis kayak yang di-set di atas
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Akses ditolak. Bukan Owner.' });
    next();
};

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const users = db.prepare('SELECT id, email, is_vip, di_user, di_pass FROM users').all();
    res.json(users);
});

app.post('/api/admin/grant-vip', requireAuth, requireAdmin, (req, res) => {
    const { userId, isVip } = req.body;
    db.prepare('UPDATE users SET is_vip = ? WHERE id = ?').run(isVip ? 1 : 0, userId);
    res.json({ success: true });
});

app.listen(3000, () => console.log('6767 — Server secure jalan di http://localhost:3000'));
