require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// AdminJS Imports
const AdminJS = require('adminjs');
const AdminJSExpress = require('@adminjs/express');
const AdminJSMongoose = require('@adminjs/mongoose');

// --- إعدادات التطبيق ---
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ضروري لـ Render عشان الكوكيز والبروكسي
app.set('trust proxy', 1);

// --- Socket.io (للطلبات الفورية) ---
const io = new Server(server, {
    cors: {
        origin: "*", // للسماح للتطبيق والموقع بالاتصال
        methods: ["GET", "POST"]
    }
});

// --- Middleware ---
app.use(
  helmet({
    contentSecurityPolicy: false, // تعطيل CSP مؤقتاً ليعمل AdminJS
    crossOriginEmbedderPolicy: false,
  })
);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // لدعم البيانات المرسلة من AdminJS

// Rate Limiting (حماية من الضغط)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    message: "Too many requests, please try again later."
});
app.use('/api', apiLimiter);

// --- قاعدة البيانات ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected Securely'))
    .catch(err => console.error('❌ DB Connection Error:', err));

// --- الجداول (Schemas) ---
AdminJS.registerAdapter(AdminJSMongoose);

// 1. المستخدمين
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    role: { type: String, enum: ['user', 'driver', 'admin', 'owner'], default: 'user' },
    // تفعيل الإيميل
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    // تفعيل الهاتف
    phone: String,
    phoneOtp: String,
    isPhoneVerified: { type: Boolean, default: false },
    // إضافات
    location: { lat: Number, lng: Number },
    fcmToken: String
});
const User = mongoose.model('User', userSchema);

// 2. المنتجات
const productSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    price: { type: Number, required: true },
    imageUrl: String, // وحدنا الاسم ليكون imageUrl مثل التطبيق
    category: String,
    isAvailable: { type: Boolean, default: true }
});
const Product = mongoose.model('Product', productSchema);
// ملاحظة: لكي يعمل التطبيق، سنستخدم اسم المودل "Menu" في الروابط للسهولة، أو نربط Product بـ Menu
const Menu = mongoose.model('Menu', productSchema); // اسم مستعار ليتوافق مع كود التطبيق

// 3. الطلبات
const OrderSchema = new mongoose.Schema({
    // customer: { type: mongoose.Types.ObjectId, ref: 'User' }, // اختياري حالياً
    items: { type: mongoose.Schema.Types.Mixed, default: [] }, // Mixed لحل مشاكل AdminJS
    totalPrice: Number,
    status: { type: String, default: 'pending' },
    tableNumber: String, // مهم للكيو آر كود
    date: { type: String, default: () => new Date().toISOString() }, // لتوحيد التاريخ
    createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

// --- إعدادات الجلسة (Session) لـ AdminJS ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'super_secret_filo_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
        secure: true, // ضروري لـ Render (HTTPS)
        sameSite: 'none', // ضروري للكروس دومين أحياناً
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// --- تشغيل AdminJS ---
const startAdmin = async () => {
    const admin = new AdminJS({
        databases: [mongoose],
        rootPath: '/admin',
        branding: {
            companyName: 'Filo Dashboard',
            logo: 'https://filomenu.com/assets/icons/icon-192.png', // شعار افتراضي
            withMadeWithLove: false,
        },
    });
    const adminRouter = AdminJSExpress.buildRouter(admin);
    app.use(admin.options.rootPath, adminRouter);
};
startAdmin();

// --- إعداد الإيميل (Brevo) ---
const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- Socket.io ---
io.on('connection', (socket) => {
    console.log(`⚡ New Socket: ${socket.id}`);
    // يمكن إضافة غرف خاصة للسائقين أو المطبخ هنا
});

// --- تصميم الإيميل الموحد (الفخم) ---
const getEmailDesign = (name, otpCode, messageTitle) => `
<div style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 12px; overflow: hidden;">
    <div style="background-color: #1A1A1A; padding: 30px; text-align: center;">
        <h1 style="color: #C5A028; margin: 0; font-size: 28px; letter-spacing: 2px; font-weight: 800;">FILO MENU</h1>
        <p style="color: #888; margin: 5px 0 0; font-size: 12px; letter-spacing: 1px;">PREMIUM DELIVERY</p>
    </div>
    <div style="padding: 40px 30px; text-align: center; color: #333333;">
        <h2 style="margin-top: 0; color: #1A1A1A; font-size: 24px;">مرحباً بك يا ${name} 👋</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #555;">${messageTitle}</p>
        <div style="margin: 35px 0;">
            <div style="display: inline-block; background-color: #f8f9fa; border: 2px dashed #C5A028; padding: 15px 40px; border-radius: 8px;">
                <span style="font-size: 32px; font-weight: 900; color: #1A1A1A; letter-spacing: 8px; font-family: monospace;">${otpCode}</span>
            </div>
        </div>
        <p style="font-size: 14px; color: #999;">⚠️ الرمز صالح لمدة 10 دقائق.</p>
    </div>
    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 12px; color: #999; border-top: 1px solid #e0e0e0;">
        <p style="margin: 0;">&copy; 2025 Filo Menu. All rights reserved.</p>
    </div>
</div>
`;

// --- API Routes ---

app.get('/', (req, res) => res.send('🚀 Filo Server is Running!'));

// 1️⃣ تسجيل حساب جديد (مع التحقق من التكرار والتفعيل)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        if (user) {
            if (user.isVerified) {
                return res.status(400).json({ error: "البريد الإلكتروني مستخدم بالفعل." });
            }
            // تحديث الحساب المعلق
            user.name = name;
            user.password = hashedPassword;
            user.otp = otpCode;
            user.otpExpires = otpExpiry;
            await user.save();
        } else {
            // إنشاء جديد
            user = new User({
                email, password: hashedPassword, name,
                isVerified: false,
                otp: otpCode, otpExpires: otpExpiry
            });
            await user.save();
        }

        await transporter.sendMail({
            from: '"Filo Menu Support" <no-reply@filomenu.com>',
            to: email,
            subject: '🔐 رمز تفعيل حسابك',
            html: getEmailDesign(name, otpCode, "لتفعيل حسابك والبدء، يرجى استخدام الرمز أدناه:")
        });
        
        res.status(201).json({ message: "تم إرسال الرمز!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "فشل التسجيل" });
    }
});

// 2️⃣ تفعيل الإيميل
app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "المستخدم غير موجود" });
        
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

// 3️⃣ تسجيل الدخول (مع فحص الهاتف والإيميل)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: "البيانات غير صحيحة" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "البيانات غير صحيحة" });

        // فحص الإيميل
        if (!user.isVerified) {
            const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.otp = otpCode;
            user.otpExpires = Date.now() + 10 * 60 * 1000;
            await user.save();

            await transporter.sendMail({
                from: '"Filo Menu Support" <no-reply@filomenu.com>',
                to: email,
                subject: '⚠️ تفعيل حسابك مطلوب',
                html: getEmailDesign(user.name, otpCode, "حاولت تسجيل الدخول والحساب غير مفعل. رمزك الجديد:")
            });
            return res.status(403).json({ error: "NOT_VERIFIED", message: "الإيميل غير مفعل" });
        }

        // فحص الهاتف
        if (!user.isPhoneVerified) {
            return res.status(403).json({ error: "PHONE_NOT_VERIFIED", message: "رقم الهاتف غير مفعل" });
        }

        res.json({ message: "تم الدخول!", user: { name: user.name, email: user.email, role: user.role } });

    } catch (error) {
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

// 4️⃣ طلب رمز الهاتف
app.post('/api/auth/phone/send', async (req, res) => {
    const { email, phone } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });

        const smsCode = Math.floor(1000 + Math.random() * 9000).toString();
        user.phone = phone;
        user.phoneOtp = smsCode;
        await user.save();

        console.log(`📲 SMS to ${phone}: ${smsCode}`); // محاكاة
        res.json({ message: "تم إرسال الرمز" });
    } catch (error) {
        res.status(500).json({ error: "فشل الإرسال" });
    }
});

// 5️⃣ تفعيل الهاتف
app.post('/api/auth/phone/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });

        if (user.phoneOtp !== otp) return res.status(400).json({ error: "رمز الهاتف خطأ" });

        user.isPhoneVerified = true;
        user.phoneOtp = undefined;
        await user.save();

        res.json({ message: "تم تفعيل الهاتف!" });
    } catch (error) {
        res.status(500).json({ error: "فشل التفعيل" });
    }
});

// --- المنيو والطلبات ---
app.get('/api/menu', async (req, res) => {
    try {
        // جلب المنتجات وعكس ترتيبها لتظهر الأحدث أولاً
        const menu = await Menu.find().sort({ _id: -1 });
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "Error" });
    }
});

app.get('/api/orders', async (req, res) => {
    const orders = await Order.find().sort({ createdAt: -1 }); // الأحدث أولاً
    res.json(orders);
});

app.post('/api/orders', async (req, res) => {
    const orderData = req.body;
    try {
        const newOrder = new Order(orderData);
        const savedOrder = await newOrder.save();
        
        // إشعار المطبخ فوراً (Socket.io)
        io.emit('new_order', savedOrder);
        
        res.status(201).json({ message: "Saved!" });
    } catch (error) {
        res.status(500).json({ error: "Error" });
    }
});

// تشغيل السيرفر
server.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`👨‍💼 Admin Panel: https://filo-menu.onrender.com/admin`);
});