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

// 3. إعداد مرسل الإيميلات (Brevo SMTP)
const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587, // المنفذ القياسي لـ Brevo
    secure: false, 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
    }
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
    // بيانات الإيميل
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    // بيانات الهاتف
    phone: { type: String },
    phoneOtp: String,
    isPhoneVerified: { type: Boolean, default: false }
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

// 1️⃣ تسجيل حساب جديد
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        if (user) {
            if (user.isVerified) {
                return res.status(400).json({ error: "البريد الإلكتروني مستخدم بالفعل." });
            }
            // تحديث حساب غير مفعل
            user.name = name;
            user.password = password;
            user.otp = otpCode;
            user.otpExpires = otpExpiry;
            await user.save();
        } else {
            // إنشاء جديد
            user = new User({
                email, password, name,
                isVerified: false,
                otp: otpCode,
                otpExpires: otpExpiry
            });
            await user.save();
        }

        // تصميم الرسالة
        const emailDesign = `
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
            <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
            </div>
            <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.5;">
                    أهلاً بك في عائلة Filo. لتفعيل حسابك، استخدم الرمز التالي:
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
            subject: '🔐 رمز تفعيل حسابك',
            html: emailDesign
        });
        
        res.status(201).json({ message: "تم إرسال الرمز!" });

    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ error: "فشل التسجيل" });
    }
});

// 2️⃣ تفعيل الإيميل
// 2️⃣ تفعيل الإيميل (مع طباعة السبب للمساعدة)
app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "المستخدم غير موجود" });

        // 👇👇👇 طباعة البيانات لكشف المشكلة في اللوج
        console.log("--- عملية التحقق ---");
        console.log(`📧 الإيميل: ${email}`);
        console.log(`📥 الرمز القادم من التطبيق: '${otp}'`);
        console.log(`💾 الرمز المخزن في الداتا: '${user.otp}'`);
        console.log(`⏰ الوقت الحالي: ${Date.now()}`);
        console.log(`⌛ وقت انتهاء الرمز: ${new Date(user.otpExpires).getTime()}`);

        // تحويل القيم لنصوص وتنظيف الفراغات لضمان المطابقة
        const inputOtp = String(otp).trim();
        const storedOtp = String(user.otp).trim();

        // 1. فحص التطابق
        if (storedOtp !== inputOtp) {
            console.log("❌ النتيجة: الرموز غير متطابقة!");
            return res.status(400).json({ error: "الرمز غير صحيح (تأكد من آخر إيميل وصلك)" });
        }

        // 2. فحص الوقت
        if (user.otpExpires < Date.now()) {
            console.log("❌ النتيجة: الرمز منتهي الصلاحية!");
            return res.status(400).json({ error: "انتهت صلاحية الرمز، حاول التسجيل مجدداً" });
        }

        // نجاح
        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        console.log("✅ النتيجة: تم التفعيل بنجاح!");
        res.status(200).json({ message: "تم تفعيل الإيميل!" });

    } catch (error) {
        console.error("Verify Error:", error);
        res.status(500).json({ error: "خطأ في التفعيل" });
    }
});

// 3️⃣ طلب رمز الهاتف (تحديث للمستخدم الموجود)
app.post('/api/auth/phone/send', async (req, res) => {
    const { email, phone } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });

        const smsCode = Math.floor(1000 + Math.random() * 9000).toString();
        
        user.phone = phone;
        user.phoneOtp = smsCode;
        await user.save();

        console.log(`📲 SMS SIMULATION -> To: ${phone} | Code: ${smsCode}`);
        res.json({ message: "تم إرسال الرمز (راجع الكونسول)" });
    } catch (error) {
        res.status(500).json({ error: "فشل إرسال الرمز" });
    }
});

// 4️⃣ تفعيل الهاتف
app.post('/api/auth/phone/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });

        if (user.phoneOtp !== otp) {
            return res.status(400).json({ error: "رمز الهاتف خطأ" });
        }

        user.isPhoneVerified = true;
        user.phoneOtp = undefined;
        await user.save();

        res.json({ message: "تم تفعيل الهاتف!" });
    } catch (error) {
        res.status(500).json({ error: "فشل التفعيل" });
    }
});

// 5️⃣ تسجيل الدخول (مع التصحيح والتصميم الفخم)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        
        if (!user || user.password !== password) {
            return res.status(401).json({ error: "البيانات غير صحيحة" });
        }

        // فحص تفعيل الإيميل
        if (!user.isVerified) {
            const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.otp = otpCode;
            user.otpExpires = Date.now() + 10 * 60 * 1000;
            await user.save();

            // ✅ تم التصحيح: استخدام user.name
            const emailDesign = `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
                <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
                </div>
                <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                    <h2 style="color: #333;">مرحباً بك يا ${user.name}! 👋</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.5;">
                        حاولت تسجيل الدخول والحساب غير مفعل. رمز التفعيل الجديد هو:
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

            return res.status(403).json({ error: "NOT_VERIFIED", message: "الحساب غير مفعل." });
        }

        // فحص تفعيل الهاتف
        if (!user.isPhoneVerified) {
            return res.status(403).json({ error: "PHONE_NOT_VERIFIED", message: "رقم الهاتف غير مفعل" });
        }

        res.json({ message: "تم الدخول!", user: { name: user.name, email: user.email } });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

// --- المنيو والطلبات ---
app.get('/api/menu', async (req, res) => {
    const menu = await Menu.find();
    res.json(menu);
});
app.get('/api/orders', async (req, res) => {
    const orders = await Order.find();
    res.json(orders);
});
app.post('/api/orders', async (req, res) => {
    const newOrder = new Order(req.body);
    await newOrder.save();
    res.status(201).json({ message: "Saved!" });
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));