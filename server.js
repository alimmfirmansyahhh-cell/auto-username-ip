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
const ISP_FAMILIES = ["7713", "23693", "4761", "24203", "45727", "17451", "23700", "18059", "45287", "4787"];

// Setup Database
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

// Bikin akun Admin default
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get(ADMIN_EMAIL);
if (!adminExists) {
    const hash = bcrypt.hashSync('muhlis144', 10);
    db.prepare('INSERT INTO users (email, password, is_vip) VALUES (?, ?, ?)').run(ADMIN_EMAIL, hash, 1);
    console.log('[*] Akun Admin siap: ' + ADMIN_EMAIL);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Middleware Auth
const requireAuth = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak. Silakan login.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) { return res.status(401).json({ error: 'Sesi expired.' }); }
};

// --- ROUTES AUTH ---
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !email.toLowerCase().endsWith('@gmail.com')) {
        return res.status(400).json({ error: 'Wajib pake email @gmail.com!' });
    }
    try {
        const hash = bcrypt.hashSync(password, 10);
        db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email.toLowerCase(), hash);
        res.json({ success: true, message: 'Akun dibuat.' });
    } catch (e) { res.status(400).json({ error: 'Email sudah dipakai.' }); }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
        res.cookie('auth_token', token, { httpOnly: true, sameSite: 'strict', maxAge: 86400000 });
        res.json({ success: true });
    } else { res.status(401).json({ error: 'Email atau password salah.' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('auth_token'); res.json({ success: true }); });

app.get('/api/me', requireAuth, (req, res) => {
    const user = db.prepare('SELECT id, email, is_vip, di_user, di_pass FROM users WHERE id = ?').get(req.user.id);
    res.json(user);
});

app.post('/api/save-creds', requireAuth, (req, res) => {
    db.prepare('UPDATE users SET di_user = ?, di_pass = ? WHERE id = ?').run(req.body.di_user, req.body.di_pass, req.user.id);
    res.json({ success: true });
});

// --- FITUR 1: CEK LOKASI 8 ENDPOINT (GRATIS) ---
app.post('/api/check-location', requireAuth, async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP kosong' });

    const endpoints = [
        { name: 'ipapi.is', url: `https://api.ipapi.is/?q=${ip}` },
        { name: 'ipwho.is', url: `https://ipwho.is/${ip}` },
        { name: 'ipinfo.io', url: `https://ipinfo.io/${ip}/json` },
        { name: 'ipapi.co', url: `https://ipapi.co/${ip}/json/` },
        { name: 'freeipapi.com', url: `https://freeipapi.com/api/json/${ip}` },
        { name: 'geojs.io', url: `https://get.geojs.io/v1/ip/geo/${ip}.json` },
        { name: 'db-ip.com', url: `https://api.db-ip.com/v2/free/${ip}` },
        { name: 'ipwhois.app', url: `https://ipwhois.app/json/${ip}` }
    ];

    const results = await Promise.all(endpoints.map(async (ep) => {
        try {
            const response = await axios.get(ep.url, { timeout: 6000 });
            const d = response.data;
            
            let city = d.city || d.cityName || (d.location && d.location.city) || '-';
            let region = d.region || d.regionName || d.stateProv || (d.location && d.location.state) || '-';
            let country = d.country || d.country_name || d.countryName || (d.location && d.location.country) || '-';
            let zip = d.postal || d.zip || (d.location && d.location.zip) || '-';
            let asn = '-';

            if (ep.name === 'ipwho.is') asn = d.connection?.asn;
            else if (ep.name === 'ipapi.is') asn = d.asn?.asn;
            else if (ep.name === 'ipinfo.io') asn = d.org ? d.org.split(' ')[0].replace('AS', '') : '-';
            else if (ep.name === 'ipapi.co') asn = d.asn ? d.asn.replace('AS', '') : '-';
            else if (ep.name === 'freeipapi.com') asn = d.asn;
            else if (ep.name === 'geojs.io') asn = d.asn;
            else if (ep.name === 'ipwhois.app') asn = d.asn;

            if (city === '-' && region === '-' && asn === '-') return { name: ep.name, status: 'Tidak ada data lokasi' };
            return { name: ep.name, status: 'ok', city, region, country, zip, asn: asn || '-' };
        } catch (err) {
            return { name: ep.name, status: 'Tidak ada data lokasi' };
        }
    }));

    res.json({ results });
});

// --- FITUR 2: AUTO PROXY ENGINE (VIP ONLY) ---
const testProxyUrl = async (proxyUrl) => {
    const agent = new HttpsProxyAgent(proxyUrl);
    try {
        const r = await axios.get('https://ipwho.is/', { httpsAgent: agent, timeout: 8000 });
        if (r.data.success) return r.data;
    } catch (e) { return null; }
    return null;
};

app.post('/api/auto-check', requireAuth, async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.is_vip) return res.status(403).json({ error: 'Akses Ditolak. Bukan VIP.' });
    if (!user.di_user || !user.di_pass) return res.status(400).json({ error: 'Kredensial DI kosong.' });

    const { targetIp } = req.body;
    if (!targetIp) return res.status(400).json({ error: 'IP target kosong.' });

    try {
        const geoRes = await axios.get(`https://ipwho.is/${targetIp}`);
        const geo = geoRes.data;
        if (!geo.success) return res.status(400).json({ error: 'IP target invalid.' });

        const c = geo.country_code.toLowerCase();
        const st = geo.region.toLowerCase().replace(/ /g, '');
        const ct = geo.city.toLowerCase().replace(/ /g, '');
        const zp = geo.postal || '';
        const asn = geo.connection.asn || '';

        const buildP = (params) => {
            const pStr = Object.entries(params).filter(([_,v]) => v).map(([k,v]) => `${k}.${v}`).join(';');
            return `http://${user.di_user}__${pStr}:${user.di_pass}@gw.dataimpulse.com:823`;
        };

        // Skenario 1: Full Target
        let p1 = buildP({ cr: c, state: st, city: ct, zip: zp, asn: asn });
        let res1 = await testProxyUrl(p1);
        if (res1) return res.json({ success: true, scenario: '1 (Full)', data: res1, proxy: p1 });

        // Skenario 2: Tanpa ZIP
        let p2 = buildP({ cr: c, state: st, city: ct, asn: asn });
        let res2 = await testProxyUrl(p2);
        if (res2) return res.json({ success: true, scenario: '2 (No Zip)', data: res2, proxy: p2 });

        // Skenario 3: State Level
        let p3 = buildP({ cr: c, state: st, asn: asn });
        let res3 = await testProxyUrl(p3);
        if (res3) return res.json({ success: true, scenario: '3 (State)', data: res3, proxy: p3 });

        // Skenario 4: Loop ISP Family
        for (let isp of ISP_FAMILIES) {
            let p4 = buildP({ cr: c, state: st, city: ct, asn: isp });
            let res4 = await testProxyUrl(p4);
            if (res4) return res.json({ success: true, scenario: `4 (ISP ${isp})`, data: res4, proxy: p4 });
        }

        return res.status(404).json({ error: 'Buntu. Data Impulse nggak punya IP di wilayah ini.' });
    } catch (err) { res.status(500).json({ error: 'Gagal nembak API IP/Proxy.' }); }
});

// --- ROUTES ADMIN ---
const requireAdmin = (req, res, next) => {
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Bukan Owner.' });
    next();
};
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => res.json(db.prepare('SELECT id, email, is_vip, di_user, di_pass FROM users').all()));
app.post('/api/admin/grant-vip', requireAuth, requireAdmin, (req, res) => {
    db.prepare('UPDATE users SET is_vip = ? WHERE id = ?').run(req.body.isVip ? 1 : 0, req.body.userId);
    res.json({ success: true });
});

app.listen(3000, () => console.log('6767 — Server Engine jalan di http://localhost:3000'));
