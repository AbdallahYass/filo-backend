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
const MongoStore = require('connect-mongo').default || require('connect-mongo');
// AdminJS Imports
const AdminJS = require('adminjs');
const AdminJSExpress = require('@adminjs/express');
const AdminJSMongoose = require('@adminjs/mongoose');

// --- إعدادات التطبيق ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// تسجيل المودلز في AdminJS
AdminJS.registerAdapter(AdminJSMongoose);

// --- دالة التشغيل الرئيسية (لضمان الترتيب الصحيح) ---
const startServer = async () => {
    const app = express();
    const server = http.createServer(app);

    // 1. الاتصال بقاعدة البيانات
    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ MongoDB Connected Securely');
    } catch (err) {
        console.error('❌ DB Connection Error:', err);
        return; // نوقف السيرفر إذا فشل الاتصال
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
        items: { type: mongoose.Schema.Types.Mixed, default: [] },
        totalPrice: Number,
        status: { type: String, default: 'pending' },
        tableNumber: String,
        date: { type: String, default: () => new Date().toISOString() },
        createdAt: { type: Date, default: Date.now }
    });
    const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);

    // 2. إعدادات الأمان والبروكسي
    app.set('trust proxy', 1);
    
    app.use(helmet({
        contentSecurityPolicy: false, // ضروري لـ AdminJS
        crossOriginEmbedderPolicy: false,
    }));
    
    app.use(cors());

    // 3. إعداد الجلسة (يجب أن يكون قبل AdminJS إذا كنا سنضيف Auth لاحقاً، وجيد وجوده هنا)
    app.use(session({
        secret: process.env.SESSION_SECRET || 'filo_secure_key',
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({ mongoUrl: MONGO_URI }),
        cookie: {
            secure: process.env.NODE_ENV === 'production', // تلقائي حسب البيئة
            maxAge: 24 * 60 * 60 * 1000
        }
    }));

    // 4. 🚨 إعداد AdminJS (يجب أن يكون قبل body-parser) 🚨
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

    // 5. 🚨 الآن نضيف محلل البيانات (Body Parser) لباقي التطبيق
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Rate Limiting
    const apiLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 300,
    });
    app.use('/api', apiLimiter);

    // --- Socket.io ---
    const io = new Server(server, {
        cors: { origin: "*", methods: ["GET", "POST"] }
    });

    io.on('connection', (socket) => {
        console.log(`⚡ New Socket: ${socket.id}`);
    });

    // --- Email Config ---
    const transporter = nodemailer.createTransport({
        host: "smtp-relay.brevo.com",
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    // --- API Routes ---
    
    app.get('/', (req, res) => res.send('🚀 Filo Server is Running!'));

    // تسجيل حساب
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
                user.name = name; user.password = hashedPassword; user.otp = otpCode; user.otpExpires = otpExpiry;
                await user.save();
            } else {
                user = new User({ email, password: hashedPassword, name, isVerified: false, otp: otpCode, otpExpires: otpExpiry });
                await user.save();
            }

            // إرسال الإيميل
            await transporter.sendMail({
                from: '"Filo Menu Support" <no-reply@filomenu.com>',
                to: email,
                subject: '🔐 رمز تفعيل حسابك',
                html: `<h2>مرحباً ${name}</h2><p>رمزك هو: <b>${otpCode}</b></p>`
            });
            res.status(201).json({ message: "تم إرسال الرمز" });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: "خطأ سيرفر" });
        }
    });

    // تفعيل
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
            if (!user) return res.status(400).json({ error: "خطأ في البيانات" });
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ error: "خطأ في البيانات" });
            if (!user.isVerified) return res.status(403).json({ error: "NOT_VERIFIED" });
            
            res.json({ message: "تم الدخول", user: { name: user.name, email: user.email } });
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

    // --- بدء الاستماع ---
    server.listen(PORT, () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`👨‍💼 Admin Panel: https://filo-menu.onrender.com/admin`);
    });
};

// تشغيل الدالة الرئيسية
startServer();