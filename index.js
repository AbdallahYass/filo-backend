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
// استيراد MongoStore بالطريقة التي تمنع الأخطاء
const MongoStore = require('connect-mongo').default || require('connect-mongo');

// AdminJS Imports
const AdminJS = require('adminjs');
const AdminJSExpress = require('@adminjs/express');
const AdminJSMongoose = require('@adminjs/mongoose');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// تسجيل المودلز في AdminJS
AdminJS.registerAdapter(AdminJSMongoose);

const startServer = async () => {
    const app = express();
    const server = http.createServer(app);

    // 1. الاتصال بقاعدة البيانات
    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ MongoDB Connected Securely');
    } catch (err) {
        console.error('❌ DB Connection Error:', err);
        return;
    }

    // --- تعريف الجداول (Schemas) ---
    const userSchema = new mongoose.Schema({
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        name: String,
        role: { type: String, enum: ['user', 'driver', 'admin', 'owner'], default: 'user' },
        isVerified: { type: Boolean, default: false },
        otp: String, otpExpires: Date,
        phone: String, phoneOtp: String, isPhoneVerified: { type: Boolean, default: false },
        location: { lat: Number, lng: Number },
        fcmToken: String
    });
    const User = mongoose.models.User || mongoose.model('User', userSchema);

    const productSchema = new mongoose.Schema({
        title: { type: String, required: true },
        description: String,
        price: { type: Number, required: true },
        imageUrl: String,
        category: String,
        isAvailable: { type: Boolean, default: true }
    });
    const Product = mongoose.models.Product || mongoose.model('Product', productSchema);
    const Menu = mongoose.models.Menu || mongoose.model('Menu', productSchema);

    const OrderSchema = new mongoose.Schema({
        // استخدام Mixed لتجنب مشاكل AdminJS مع المصفوفات المعقدة
        items: { type: mongoose.Schema.Types.Mixed, default: [] },
        totalPrice: Number,
        status: { type: String, default: 'pending' },
        tableNumber: String,
        date: { type: String, default: () => new Date().toISOString() },
        createdAt: { type: Date, default: Date.now }
    });
    const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);

    // 2. إعدادات الأمان والبروكسي (قبل كل شيء)
    app.set('trust proxy', 1);
    app.use(helmet({
        contentSecurityPolicy: false, // ضروري لعمل AdminJS
        crossOriginEmbedderPolicy: false,
    }));
    app.use(cors());

    // 3. إعداد الجلسة (Session) - ضروري للأدمن
    app.use(session({
        secret: process.env.SESSION_SECRET || 'filo_secure_key',
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({ mongoUrl: MONGO_URI }),
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000
        }
    }));

    // 4. إعداد وتشغيل AdminJS (يجب أن يكون هنا قبل body-parser) 🚨
    // هذا الترتيب هو الذي يحل مشكلة NotFoundError
    const admin = new AdminJS({
        resources: [User, Product, Order],
        rootPath: '/admin',
        branding: {
            companyName: 'Filo Dashboard',
            logo: 'https://filomenu.com/assets/icons/filo.png',
            withMadeWithLove: false,
        },
    });
    const adminRouter = AdminJSExpress.buildRouter(admin);
    app.use(admin.options.rootPath, adminRouter);

    // 5. تفعيل قراءة JSON (لباقي التطبيق - يأتي بعد الأدمن)
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Rate Limiting
    const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
    app.use('/api', apiLimiter);

    // 6. Socket.io & Email
    const io = new Server(server, {
        cors: { origin: "*", methods: ["GET", "POST"] }
    });
    io.on('connection', (socket) => { console.log(`⚡ New Socket: ${socket.id}`); });

    const transporter = nodemailer.createTransport({
        host: "smtp-relay.brevo.com",
        port: 587,
        secure: false,
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    // 7. API Routes Middleware (حماية بكلمة سر)
    const checkAuth = (req, res, next) => {
        // السماح لصفحة الأدمن والصفحة الرئيسية بالمرور
        if (req.path === '/' || req.path.startsWith('/admin')) return next();
        
        const secret = req.headers['x-api-key'];
        if (secret === process.env.API_SECRET) {
            next();
        } else {
            res.status(403).json({ error: "Access Denied" });
        }
    };
    // تطبيق الحماية على الروابط التي تبدأ بـ /api فقط
    app.use('/api', checkAuth);

    // --- APIs ---

    app.get('/', (req, res) => res.send('🚀 Filo Server is Running!'));

    // تسجيل
    app.post('/api/auth/register', async (req, res) => {
        const { email, password, name } = req.body;
        try {
            let user = await User.findOne({ email });
            const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
            const otpExpiry = Date.now() + 10 * 60 * 1000;
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            if (user) {
                if (user.isVerified) return res.status(400).json({ error: "البريد مسجل مسبقاً" });
                // تحديث حساب غير مفعل
                user.name = name; user.password = hashedPassword; user.otp = otpCode; user.otpExpires = otpExpiry;
                await user.save();
            } else {
                user = new User({ email, password: hashedPassword, name, isVerified: false, otp: otpCode, otpExpires: otpExpiry });
                await user.save();
            }
            
            // تصميم الإيميل
             const emailDesign = `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
                <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
                </div>
                <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
                    <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.5;">رمز التفعيل الخاص بك هو:</p>
                    <div style="margin: 30px 0;">
                        <span style="background-color: #C5A028; color: #000; font-size: 32px; font-weight: bold; padding: 10px 30px; border-radius: 5px; letter-spacing: 5px;">${otpCode}</span>
                    </div>
                    <p style="color: #999; font-size: 14px;">⚠️ الرمز صالح لمدة 10 دقائق.</p>
                </div>
            </div>`;

            await transporter.sendMail({
                from: '"Filo Support" <no-reply@filomenu.com>',
                to: email, subject: '🔐 رمز التفعيل', html: emailDesign
            });
            res.status(201).json({ message: "تم إرسال الرمز" });
        } catch (error) { res.status(500).json({ error: "خطأ" }); }
    });

    // تفعيل الإيميل
    app.post('/api/auth/verify', async (req, res) => {
        const { email, otp } = req.body;
        try {
            const user = await User.findOne({ email });
            if (!user || user.otp !== otp) return res.status(400).json({ error: "رمز خطأ" });
            user.isVerified = true; user.otp = undefined;
            await user.save();
            res.json({ message: "تم التفعيل" });
        } catch (error) { res.status(500).json({ error: "خطأ" }); }
    });

    // دخول
    app.post('/api/auth/login', async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await User.findOne({ email });
            if (!user) return res.status(400).json({ error: "بيانات خطأ" });
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ error: "بيانات خطأ" });
            
            if (!user.isVerified) {
                 // إعادة إرسال الرمز
                const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
                user.otp = otpCode; user.otpExpires = Date.now() + 10 * 60 * 1000;
                await user.save();
                
                const emailDesign = `<div style="text-align:center"><h2>مرحباً ${user.name}</h2><p>حسابك غير مفعل. رمزك الجديد: <b>${otpCode}</b></p></div>`;
                await transporter.sendMail({
                    from: '"Filo Support" <no-reply@filomenu.com>',
                    to: email, subject: 'تفعيل الحساب', html: emailDesign
                });
                return res.status(403).json({ error: "NOT_VERIFIED" });
            }

            if (!user.isPhoneVerified && user.phone) {
                 return res.status(403).json({ error: "PHONE_NOT_VERIFIED" });
            }
            
            res.json({ message: "تم الدخول", user: { name: user.name, email: user.email } });
        } catch (error) { res.status(500).json({ error: "خطأ" }); }
    });
    
    // إرسال رمز الهاتف
    app.post('/api/auth/phone/send', async (req, res) => {
        const { email, phone } = req.body;
        try {
            const user = await User.findOne({ email });
            if (!user) return res.status(404).json({ error: "مستخدم غير موجود" });
            const smsCode = Math.floor(1000 + Math.random() * 9000).toString();
            user.phone = phone; user.phoneOtp = smsCode;
            await user.save();
            console.log(`📲 SMS to ${phone}: ${smsCode}`);
            res.json({ message: "تم الإرسال" });
        } catch (error) { res.status(500).json({ error: "خطأ" }); }
    });

    // تفعيل الهاتف
    app.post('/api/auth/phone/verify', async (req, res) => {
        const { email, otp } = req.body;
        try {
            const user = await User.findOne({ email });
            if (!user || user.phoneOtp !== otp) return res.status(400).json({ error: "رمز خطأ" });
            user.isPhoneVerified = true; user.phoneOtp = undefined;
            await user.save();
            res.json({ message: "تم تفعيل الهاتف" });
        } catch (error) { res.status(500).json({ error: "خطأ" }); }
    });

    // المنيو والطلبات
    app.get('/api/menu', async (req, res) => {
        const menu = await Menu.find().sort({ _id: -1 });
        res.json(menu);
    });

    app.post('/api/orders', async (req, res) => {
        try {
            const newOrder = new Order(req.body);
            const savedOrder = await newOrder.save();
            io.emit('new_order', savedOrder);
            res.status(201).json({ message: "Saved!" });
        } catch (error) { res.status(500).json({ error: "Error" }); }
    });
    
    app.get('/api/orders', async (req, res) => {
        const orders = await Order.find().sort({ createdAt: -1 });
        res.json(orders);
    });

    // تشغيل السيرفر
    server.listen(PORT, () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`👨‍💼 Admin Panel: https://filo-menu.onrender.com/admin`);
    });
};

startServer();