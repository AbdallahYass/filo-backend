require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
// const mongoSanitize = require('express-mongo-sanitize'); // معطل مؤقتاً
const Joi = require('joi');
const nodemailer = require('nodemailer'); // 📧

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB!'))
    .catch(err => console.error('❌ Connection Error:', err));

app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use(limiter);


const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 465, // 👈 غيرنا المنفذ من 587 إلى 465
    secure: true, // 👈 غيرنا هذه إلى true (لأن 465 يتطلب SSL)
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // إعدادات إضافية لزيادة وقت الانتظار (في حال كان الاتصال بطيئاً)
    connectionTimeout: 10000, // 10 ثواني
    greetingTimeout: 10000,
    socketTimeout: 10000
});

// الحماية (API Key)
const checkAuth = (req, res, next) => {
    if (req.path === '/') return next();
    const secret = req.headers['x-api-key'];
    if (secret === process.env.API_SECRET) {
        next();
    } else {
        res.status(403).json({ error: "Access Denied" });
    }
};
app.use('/api', checkAuth);

// --- الجداول ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    role: { type: String, default: 'user' },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date
});
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema({
    items: Array, totalPrice: Number, date: String, tableNumber: String
});
const Order = mongoose.model('Order', orderSchema);

const menuSchema = new mongoose.Schema({
    id: String, title: String, description: String, price: Number, imageUrl: String, category: String
});
const Menu = mongoose.model('Menu', menuSchema);

// --- APIs ---

app.get('/', (req, res) => res.send('Filo Server is Live!'));

// تسجيل حساب (مع إرسال إيميل رسمي)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "البريد مستخدم مسبقاً" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

        const newUser = new User({
            email, password, name,
            isVerified: false,
            otp: otpCode,
            otpExpires: Date.now() + 10 * 60 * 1000
        });
        await newUser.save();

        // إرسال الإيميل الرسمي
        await transporter.sendMail({
            from: '"Filo Menu Support" <no-reply@filomenu.com>', // 👈 دومينك الرسمي
            to: email,
            subject: 'رمز تفعيل حسابك - Filo Menu',
            text: `مرحباً ${name}،\nرمز التفعيل الخاص بك هو: ${otpCode}\nينتهي الرمز خلال 10 دقائق.`
        });
        
        res.status(201).json({ message: "تم التسجيل! تحقق من بريدك." });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "فشل التسجيل" });
    }
});

// تفعيل الحساب
app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "المستخدم غير موجود" });
        if (user.isVerified) return res.status(400).json({ error: "الحساب مفعل مسبقاً" });
        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ error: "الرمز غير صحيح أو منتهي" });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: "تم التفعيل!" });
    } catch (error) {
        res.status(500).json({ error: "خطأ في التفعيل" });
    }
});

// تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.password !== password) {
            return res.status(401).json({ error: "بيانات خطأ" });
        }
        if (!user.isVerified) {
            return res.status(403).json({ error: "يرجى تفعيل حسابك أولاً" });
        }
        res.json({ message: "تم الدخول!", user: { name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

// المنيو والطلبات (كما هي)
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

app.listen(PORT, () => console.log(`Running on ${PORT}`));