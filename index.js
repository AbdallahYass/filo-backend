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


// إعدادات Brevo باستخدام المنفذ البديل 2525
const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 2525, // 👈 هذا هو الحل! غيرنا 587 إلى 2525
    secure: false, // هذا المنفذ لا يستخدم SSL المباشر
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // إعدادات لتجاوز مشاكل التشفير والشبكة
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
    },
    connectionTimeout: 20000, // زدنا الوقت لـ 20 ثانية
    greetingTimeout: 20000,
    socketTimeout: 20000
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

        // تصميم الرسالة (HTML)
        const emailDesign = `
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
            <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
            </div>
            <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.5;">
                    نحن سعداء جداً بانضمامك إلى عائلة <strong>Filo Menu</strong>.<br>
                    لتفعيل حسابك والبدء في طلب وجباتك المفضلة، يرجى استخدام الرمز أدناه:
                </p>
                
                <div style="margin: 30px 0;">
                    <span style="background-color: #C5A028; color: #000; font-size: 32px; font-weight: bold; padding: 10px 30px; border-radius: 5px; letter-spacing: 5px;">
                        ${otpCode}
                    </span>
                </div>

                <p style="color: #999; font-size: 14px;">
                    ⚠️ هذا الرمز صالح لمدة 10 دقائق فقط.<br>
                    إذا لم تطلب هذا الرمز، يرجى تجاهل هذه الرسالة.
                </p>
            </div>
            <div style="text-align: center; margin-top: 20px; color: #888; font-size: 12px;">
                &copy; 2025 Filo Menu. All rights reserved.
            </div>
        </div>
        `;

        // إرسال الإيميل
        console.log("جاري محاولة إرسال الإيميل إلى:", email); // 🔍 تتبع 1

        // إرسال الإيميل
        await transporter.sendMail({
            from: '"Filo Menu Support" <no-reply@filomenu.com>',
            to: email,
            subject: '🔐 رمز تفعيل حسابك - Filo Menu',
            html: emailDesign
        });
        
        console.log("تم إرسال الإيميل بنجاح! ✅"); // 🔍 تتبع 2
        res.status(201).json({ message: "تم التسجيل! تحقق من بريدك." });

    } catch (error) {
        console.error("❌ خطأ كارثي في السيرفر:", error); // طباعة الخطأ في اللوج
        res.status(500).json({ error: "فشل إرسال الإيميل، حاول مرة أخرى." });
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