require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// 1. الاتصال بقاعدة البيانات
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB!'))
    .catch(err => console.error('❌ Connection Error:', err));

// 2. إعدادات الحماية والـ Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use(limiter);

// 3. إعداد مرسل الإيميلات (Brevo SMTP - Port 587)
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

// 4. التحقق من مفتاح API
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


// --- الجداول (Schemas) ---
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


// --- نقاط الاتصال (APIs) ---

app.get('/', (req, res) => res.send('Filo Server is Live! 🚀'));

// تسجيل حساب جديد (مع معالجة الحسابات غير المفعلة)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000; // 10 دقائق

        if (user) {
            // 🛑 الحالة أ: المستخدم موجود ومفعل
            if (user.isVerified) {
                return res.status(400).json({ error: "البريد الإلكتروني مستخدم بالفعل، حاول تسجيل الدخول." });
            } 
            
            // ♻️ الحالة ب: المستخدم موجود ولكنه غير مفعل (خرج قبل التفعيل)
            user.name = name;
            user.password = password;
            user.otp = otpCode;
            user.otpExpires = otpExpiry;
            await user.save();
            console.log(`♻️ تم تحديث حساب غير مفعل: ${email}`);

        } else {
            // 🆕 الحالة ج: مستخدم جديد كلياً
            user = new User({
                email, password, name,
                isVerified: false,
                otp: otpCode,
                otpExpires: otpExpiry
            });
            await user.save();
            console.log(`🆕 تم إنشاء حساب جديد: ${email}`);
        }

        // تصميم الرسالة (HTML)
        const emailDesign = `
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
            <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
            </div>
            <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.5;">
                    نحن سعداء بانضمامك. لتفعيل حسابك، يرجى استخدام الرمز أدناه:
                </p>
                <div style="margin: 30px 0;">
                    <span style="background-color: #C5A028; color: #000; font-size: 32px; font-weight: bold; padding: 10px 30px; border-radius: 5px; letter-spacing: 5px;">
                        ${otpCode}
                    </span>
                </div>
                <p style="color: #999; font-size: 14px;">⚠️ الرمز صالح لمدة 10 دقائق.</p>
            </div>
        </div>
        `;

        console.log("جاري محاولة إرسال الإيميل إلى:", email);

        await transporter.sendMail({
            from: '"Filo Menu Support" <no-reply@filomenu.com>',
            to: email,
            subject: '🔐 رمز تفعيل حسابك - Filo Menu',
            html: emailDesign
        });
        
        console.log("تم إرسال الإيميل بنجاح! ✅");
        res.status(201).json({ message: "تم إرسال الرمز! تحقق من بريدك." });

    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ error: "فشل التسجيل أو إرسال الإيميل." });
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

// تسجيل الدخول (مع إعادة إرسال الرمز للحسابات غير المفعلة)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        
        // 1. التحقق من البيانات
        if (!user || user.password !== password) {
            return res.status(401).json({ error: "البريد الإلكتروني أو كلمة المرور خطأ" });
        }

        // 2. التحقق من التفعيل
        if (!user.isVerified) {
            // إعادة إرسال الرمز
            const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.otp = otpCode;
            user.otpExpires = Date.now() + 10 * 60 * 1000;
            await user.save();

            // إرسال الإيميل
            // تصميم الرسالة (HTML)
        const emailDesign = `
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
            <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
            </div>
            <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.5;">
                    نحن سعداء بانضمامك. لتفعيل حسابك، يرجى استخدام الرمز أدناه:
                </p>
                <div style="margin: 30px 0;">
                    <span style="background-color: #C5A028; color: #000; font-size: 32px; font-weight: bold; padding: 10px 30px; border-radius: 5px; letter-spacing: 5px;">
                        ${otpCode}
                    </span>
                </div>
                <p style="color: #999; font-size: 14px;">⚠️ الرمز صالح لمدة 10 دقائق.</p>
            </div>
        </div>
        `;

            await transporter.sendMail({
                from: '"Filo Menu Support" <no-reply@filomenu.com>',
                to: email,
                subject: '⚠️ تفعيل حسابك مطلوب',
                html: emailDesign
            });

            // إرجاع خطأ خاص يفهمه التطبيق
            return res.status(403).json({ error: "NOT_VERIFIED", message: "الحساب غير مفعل. تم إرسال رمز جديد." });
        }

        // 3. نجاح الدخول
        res.json({ message: "تم الدخول!", user: { name: user.name, email: user.email } });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

// المنيو والطلبات
app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find();
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "Error fetching menu" });
    }
});

app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "Error fetching orders" });
    }
});

app.post('/api/orders', async (req, res) => {
    const orderData = req.body;
    try {
        const newOrder = new Order(orderData);
        await newOrder.save();
        res.status(201).json({ message: "Saved!" });
    } catch (error) {
        res.status(500).json({ error: "Error saving order" });
    }
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));