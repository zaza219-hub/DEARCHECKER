const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // HTML, CSS, JS dosyaları için

const USERS_FILE = path.join(__dirname, 'users.json');
const IPS_FILE = path.join(__dirname, 'ips.txt');
const ADMIN_USER = 'ZaZa2121';
const ADMIN_PASS_HASH = bcrypt.hashSync('zaza212121', 10); // Şifreyi hash'le (bir kere çalıştırıp değiştir)

let users = {};
if (fs.existsSync(USERS_FILE)) {
  users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

// IP loglama middleware
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'bilinmiyor';
  const now = new Date().toISOString();
  const logLine = `${now} | IP: ${ip} | UA: ${userAgent}\n`;

  fs.appendFile(IPS_FILE, logLine, (err) => {
    if (err) console.error('IP log hatası:', err);
  });

  next();
});

// Ana sayfa (hoşgeldin + kayıt formu)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Kayıt endpoint
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Kullanıcı adı ve şifre zorunlu' });

  if (users[username]) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Şifre hatası' });
    users[username] = hash;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.json({ success: true });
  });
});

// Login endpoint (sadece admin için basit)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER) return res.status(401).json({ error: 'Yanlış kullanıcı adı' });

  bcrypt.compare(password, ADMIN_PASS_HASH, (err, match) => {
    if (match) {
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Yanlış şifre' });
    }
  });
});

// Admin panel sayfası
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// TXT indir endpoint (sadece admin erişsin diye basit kontrol yok, production'da session ekle)
app.get('/download-ips', (req, res) => {
  if (!fs.existsSync(IPS_FILE)) {
    return res.status(404).send('Kayıt yok');
  }
  res.download(IPS_FILE, 'kullanicilar_ip.txt');
});

app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} çalışıyor`);
});