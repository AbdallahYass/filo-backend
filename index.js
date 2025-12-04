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
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// --- Socket.io ---
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// --- Middleware ---
app.use(
  helmet({
    contentSecurityPolicy: false, // تعطيل سياسة CSP مؤقتاً لتسمح لـ AdminJS بالعمل
    crossOriginEmbedderPolicy: false,
  })
);
app.use(cors());
app.use(express.json());

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    message: "Too many requests from this IP, please try again later."
});
app.use('/api', apiLimiter);

// --- قاعدة البيانات (MongoDB) ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected Securely'))
    .catch(err => console.error('❌ DB Connection Error:', err));

// --- تعريف الجداول (Schemas) ---
// تسجيل المودلز في AdminJS
AdminJS.registerAdapter(AdminJSMongoose);

// 1. جدول المستخدمين
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    role: { 
        type: String, 
        enum: ['user', 'driver', 'admin', 'owner'], 
        default: 'user' 
    },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    phone: String,
    phoneOtp: String,
    isPhoneVerified: { type: Boolean, default: false },
    location: { lat: Number, lng: Number },
    fcmToken: String
});
const User = mongoose.model('User', userSchema);

// 2. جدول المنتجات
const productSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    price: { type: Number, required: true },
    image: String,
    category: String,
    vendorId: String,
    isAvailable: { type: Boolean, default: true }
});
const Product = mongoose.model('Product', productSchema);

// 3. جدول الطلبات (تم تبسيطه لضمان عمل السيرفر)
const OrderSchema = new mongoose.Schema({
    customer: { type: mongoose.Types.ObjectId, ref: 'User' },
    
    // ✅✅✅ التعديل الجذري هنا: تعريفها كمصفوفة عامة ✅✅✅
    // هذا يمنع AdminJS من محاولة تحليل النوع الداخلي وبالتالي يمنع الانهيار
    items: { type: Array, default: [] }, 
    
    totalPrice: Number,
    status: { type: String, default: 'pending' },
    deliveryAddress: String,
    driver: { type: mongoose.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);


// --- إعدادات الجلسة (Session) ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'filo_secure_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
        secure: true, 
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// --- إعداد لوحة التحكم (AdminJS) ---
const startAdmin = async () => {
    try {
        const admin = new AdminJS({
            databases: [mongoose],
            rootPath: '/admin',
            branding: {
                companyName: 'Filo Dashboard',
                logo: 'https://cdn-icons-png.flaticon.com/512/3081/3081367.png',
                withMadeWithLove: false,
            },
        });

        const adminRouter = AdminJSExpress.buildRouter(admin);
        app.use(admin.options.rootPath, adminRouter);
        console.log('👨‍💼 AdminJS initialized at /admin');
    } catch (error) {
        console.error("❌ AdminJS failed to start:", error);
    }
};
startAdmin();


// --- إعداد الإيميل ---
const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- Socket.io Logic ---
io.on('connection', (socket) => {
    console.log(`⚡ New Connection: ${socket.id}`);

    socket.on('driver_online', (driverId) => {
        socket.join('drivers_room');
        console.log(`Driver ${driverId} is Ready`);
    });

    socket.on('update_location', (data) => {
        io.to(`order_${data.orderId}`).emit('driver_location', data);
    });

    socket.on('track_order', (orderId) => {
        socket.join(`order_${orderId}`);
    });

    socket.on('disconnect', () => {
        console.log('User Disconnected');
    });
});

// --- API Routes ---

app.get('/', (req, res) => res.send('🚀 Filo Server System is Running Securely!'));

// 1️⃣ تسجيل حساب جديد
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name, phone } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user && user.isVerified) {
            return res.status(400).json({ error: "البريد الإلكتروني مسجل بالفعل" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        if (user) {
            user.password = hashedPassword;
            user.name = name;
            user.otp = otpCode;
            user.otpExpires = otpExpiry;
            await user.save();
        } else {
            user = new User({
                email,
                password: hashedPassword,
                name,
                phone,
                otp: otpCode,
                otpExpires: otpExpiry
            });
            await user.save();
        }

        const emailDesign = `
        <div style="direction: rtl; font-family: sans-serif; text-align: center; background-color: #f4f4f4; padding: 20px;">
            <div style="background-color: #fff; padding: 30px; border-radius: 10px; max-width: 500px; margin: auto;">
                <h2 style="color: #C5A028;">أهلاً بك في فيلو! 🍔</h2>
                <p>:رمز التفعيل الخاص بك هو:</p>
                <h1 style="background: #eee; padding: 10px; letter-spacing: 5px;">${otpCode}</h1>
                <p style="color: #888;">صالح لمدة 10 دقائق</p>
            </div>
        </div>
        `;

        await transporter.sendMail({
            from: '"Filo App" <no-reply@filo.com>',
            to: email,
            subject: '🔐 رمز تفعيل حسابك',
            html: emailDesign
        });

        res.status(201).json({ message: "تم التسجيل، يرجى تفعيل الحساب" });

    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

// 2️⃣ تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "البيانات غير صحيحة" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "البيانات غير صحيحة" });

        if (!user.isVerified) return res.status(403).json({ error: "الحساب غير مفعل" });

        res.json({
            message: "تم تسجيل الدخول بنجاح",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

// 3️⃣ تفعيل الحساب
app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "المستخدم غير موجود" });

        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ error: "الرمز غير صحيح أو منتهي الصلاحية" });
        }

        user.isVerified = true;
        user.otp = undefined;
        await user.save();

        res.json({ message: "تم تفعيل الحساب بنجاح!" });
    } catch (error) {
        res.status(500).json({ error: "خطأ في التفعيل" });
    }
});

// 4️⃣ جلب المنيو
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({ isAvailable: true });
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: "فشل جلب المنتجات" });
    }
});

// 5️⃣ إنشاء طلب جديد
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        const savedOrder = await newOrder.save();

        io.emit('new_order', savedOrder);

        res.status(201).json(savedOrder);
    } catch (error) {
        console.error("Order Error:", error);
        res.status(500).json({ error: "فشل إنشاء الطلب" });
    }
});

// --- تشغيل السيرفر ---
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔐 Security Layers Active`);
    console.log(`👨‍💼 Admin Dashboard: http://localhost:${PORT}/admin`);
});