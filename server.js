// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-secret-key-change-this-in-production'; // Lütfen bu anahtarı üretimde değiştirin!

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// In-memory kullanıcı listesi
const plainUsers = [
    { id: 1, username: 'admin', password: '123456', email: 'admin@example.com', firstName: 'Admin', lastName: 'User', role: 'admin' },
    { id: 2, username: 'user1', password: '123456', email: 'user1@example.com', firstName: 'Test', lastName: 'Kullanıcı', role: 'user' }
];

let users = [];
(async () => {
    for (const u of plainUsers) {
        const hash = await bcrypt.hash(u.password, 10);
        users.push({ ...u, password: hash });
    }
    console.log('Initial users:', users.map(u => u.username));
})();

// JWT doğrulama middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token gerekli' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Geçersiz token' });
        req.user = user;
        next();
    });
};

// Kayıt endpoint'i
app.post('/api/register', async (req, res) => {
    const { username, password, email, firstName, lastName } = req.body;
    if (!username || !password || !email || !firstName || !lastName) {
        return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
    }
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: 'Kullanıcı adı zaten var' });
    }
    const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
    const hash = await bcrypt.hash(password, 10);
    const newUser = { id, username, password: hash, email, firstName, lastName, role: 'user' };
    users.push(newUser);
    res.json({ success: true, message: 'Kayıt başarılı', user: { id, username, email, firstName, lastName, role: 'user' } });
});

// Login endpoint'i
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Kullanıcı adı veya şifre eksik' });
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Şifre hatalı' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, firstName: user.firstName }, JWT_SECRET, { expiresIn: '1h' });
    const { password: _, ...userWithoutPass } = user;
    res.json({ success: true, token, user: userWithoutPass });
});

// Profil endpoint'i
app.get('/api/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    const { password: _, ...userWithoutPass } = user;
    res.json(userWithoutPass);
});

// Şifre değiştirme endpoint'i
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

    const validCurrentPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validCurrentPassword) {
        return res.status(401).json({ error: 'Mevcut şifre hatalı' });
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;

    res.json({ message: 'Şifre başarıyla değiştirildi.' });
});

// JWT doğrulaması
app.post('/api/verify-token', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    const { password: _, ...userWithoutPass } = user;
    res.json({ success: true, user: userWithoutPass });
});

// YENİ ENDPOINT: Tüm kullanıcıları listeleme (Sadece Admin)
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Yetkisiz erişim' });
    }
    const usersWithoutPassword = users.map(u => {
        const { password, ...userWithoutPass } = u;
        return userWithoutPass;
    });
    res.json(usersWithoutPassword);
});

// YENİ ENDPOINT: Kullanıcı rolünü güncelleme (Sadece Admin)
app.post('/api/users/role', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Yetkisiz erişim' });
    }

    const { userId, newRole } = req.body;
    const userToUpdate = users.find(u => u.id === userId);

    if (!userToUpdate) {
        return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    // Role'ün geçerli bir değer olup olmadığını kontrol edin
    const validRoles = ['admin', 'moderator', 'user'];
    if (!validRoles.includes(newRole)) {
        return res.status(400).json({ error: 'Geçersiz rol değeri' });
    }

    userToUpdate.role = newRole;
    res.json({ success: true, message: `Kullanıcının rolü başarıyla ${newRole} olarak değiştirildi.` });
});

app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});