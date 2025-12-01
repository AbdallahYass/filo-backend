require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB!'))
    .catch(err => console.error('❌ Connection Error:', err));

// --- Middlewares ---
app.use(helmet());
const allowedOrigins = ['https://filomenu.com', 'https://www.filomenu.com', 'http://localhost:3000'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('CORS Error'));
        }
    }
}));
app.use(bodyParser.json());
app.use(mongoSanitize());

// --- Schemas (الجداول) ---

// 1. جدول المستخدمين (جديد) 👤
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // (ملاحظة: للتطبيق الحقيقي يفضل تشفيرها لاحقاً)
    name: String,
    role: { type: String, default: 'user' } // user, admin, chef
});
const User = mongoose.model('User', userSchema);

// 2. الجداول القديمة
const orderSchema = new mongoose.Schema({
    items: Array, totalPrice: Number, date: String, tableNumber: String
});
const Order = mongoose.model('Order', orderSchema);

const menuSchema = new mongoose.Schema({
    id: String, title: String, description: String, price: Number, imageUrl: String, category: String
});
const Menu = mongoose.model('Menu', menuSchema);

// --- APIs نقاط الاتصال ---

app.get('/', (req, res) => res.send('Filo Server is Live! 🚀'));

// 🔐 تسجيل حساب جديد (Register)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        // التحقق هل الإيميل مستخدم سابقاً؟
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "هذا البريد مستخدم مسبقاً" });
        }

        const newUser = new User({ email, password, name });
        await newUser.save();
        
        res.status(201).json({ message: "تم إنشاء الحساب بنجاح! 🎉", user: { email, name } });
    } catch (error) {
        res.status(500).json({ error: "فشل إنشاء الحساب" });
    }
});

// 🔐 تسجيل الدخول (Login)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // البحث عن المستخدم
        const user = await User.findOne({ email });
        
        // التحقق من الباسوورد
        if (!user || user.password !== password) {
            return res.status(401).json({ error: "البريد الإلكتروني أو كلمة المرور خطأ ❌" });
        }

        // نجح الدخول
        res.json({ 
            message: "تم الدخول بنجاح! ✅", 
            user: { name: user.name, email: user.email, role: user.role } 
        });

    } catch (error) {
        res.status(500).json({ error: "حدث خطأ في السيرفر" });
    }
});

// --- باقي الـ APIs القديمة (Menu & Orders) ---
// (تأكد من وجود فحص المفتاح السري هنا إذا كنت تستخدمه)
const checkAuth = (req, res, next) => {
    if (req.method === 'GET') return next();
    const secret = req.headers['x-api-key'];
    if (secret === process.env.API_SECRET) {
        next();
    } else {
        res.status(403).json({ error: "Access Denied 🚫" });
    }
};

// تطبيق الحماية على باقي الروابط فقط (وليس اللوجن)
app.use('/api/menu', checkAuth); 
app.use('/api/orders', checkAuth);

app.get('/api/menu', async (req, res) => {
    const menu = await Menu.find();
    res.json(menu);
});

app.get('/api/orders', async (req, res) => {
    const orders = await Order.find();
    res.json(orders);
});

app.post('/api/orders', async (req, res) => {
    const orderData = req.body;
    const newOrder = new Order(orderData);
    await newOrder.save();
    res.status(201).json({ message: "Saved!" });
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});