/**
 * ============================================================
 * 1. IMPORTS & CONFIGURATION (الإعدادات والمكتبات)
 * ============================================================
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

// إعدادات المتغيرات البيئية
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

// الاتصال بقاعدة البيانات
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB!'))
    .catch(err => console.error('❌ Connection Error:', err));


/**
 * ============================================================
 * 2. DATABASE MODELS (نماذج قاعدة البيانات)
 * ============================================================
 */

// --- User Schema ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    name: String,
    role: { type: String, default: 'user', enum: ['user', 'admin'] }, // قمنا بتحديد الأدوار المسموحة
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    phone: { type: String },
    phoneOtp: String,
    isPhoneVerified: { type: Boolean, default: false }
});

// ابحث عن هذا الجزء واستبدله بالكود التالي 👇

userSchema.pre('save', async function() { // ❌ حذفنا كلمة next من الأقواس
    const user = this;
    
    // إذا لم تتغير كلمة السر، لا تفعل شيئاً
    if (!user.isModified('password')) return; 

    try {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
        // ✅ حذفنا استدعاء next() لأن الدالة async
    } catch (error) {
        throw error; // ارمي الخطأ ليمسكه السيرفر
    }
});

const User = mongoose.model('User', userSchema);

// --- Order Schema ---
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: Array,
    totalPrice: Number,
    date: { type: Date, default: Date.now }, // جعل التاريخ تلقائي
    tableNumber: String,
    status: { type: String, default: 'pending', enum: ['pending', 'completed', 'cancelled'] } // إضافة حالة الطلب
});
const Order = mongoose.model('Order', orderSchema);

// --- Menu Schema ---
const menuSchema = new mongoose.Schema({
    title: { type: String, required: true }, 
    description: String, 
    price: { type: Number, required: true }, 
    imageUrl: String, 
    category: { type: String, required: true }
    // ملاحظة: MongoDB يضيف تلقائياً _id، لا داعي لتعريفه يدوياً
});
const Menu = mongoose.model('Menu', menuSchema);


/**
 * ============================================================
 * 3. SERVICES & HELPERS (الخدمات والدوال المساعدة)
 * ============================================================
 */

const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,            // 👈 أفضل منفذ للاستضافات السحابية
    secure: false,        // 👈 يجب أن تكون false مع المنفذ 587
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false // 👈 لتجاهل مشاكل شهادات الحماية إن وجدت
    }
});

const sendOTPEmail = async (email, name, otpCode) => {
    const emailDesign = `
    <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
        <div style="background-color: #1A1A1A; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: #C5A028; margin: 0; font-size: 24px;">Filo Menu</h1>
        </div>
        <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; border: 1px solid #ddd; border-top: none;">
            <h2 style="color: #333;">مرحباً بك يا ${name}! 👋</h2>
            <p style="color: #666; font-size: 16px; line-height: 1.5;">
                رمز تفعيل حسابك هو:
            </p>
            <div style="margin: 30px 0;">
                <span style="background-color: #C5A028; color: #000; font-size: 32px; font-weight: bold; padding: 10px 30px; border-radius: 5px; letter-spacing: 5px;">
                    ${otpCode}
                </span>
            </div>
        </div>
    </div>
    `;

    await transporter.sendMail({
        from: '"Filo Menu Support" <no-reply@filomenu.com>',
        to: email,
        subject: '🔐 رمز تفعيل حسابك',
        html: emailDesign
    });
};


/**
 * ============================================================
 * 4. MIDDLEWARES (الطبقات الوسيطة)
 * ============================================================
 */

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });

// 1. التحقق من التوكن (Authentication)
const authMiddleware = (req, res, next) => {
    // 👇 طباعة للمراقبة (عشان تشوف المسار اللي شايفه السيرفر)
    console.log("Middleware Path Check:", req.path);

    // 1. السماح للمسارات العامة (تسجيل، تفعيل، دخول، عرض منيو)
    // المشكلة كانت هنا: المسار يوصل '/auth/register' بدون كلمة api
    if (req.path.startsWith('/auth') || 
        req.path.startsWith('/api/auth') || 
        (req.method === 'GET' && req.path === '/menu')) {
        return next(); // تفضل، ادخل بدون توكن
    }

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'فشل المصادقة: لا يوجد رمز (Token)' });
        }

        const token = authHeader.split(' ')[1];
        const decodedToken = jwt.verify(token, JWT_SECRET);

        req.userData = { userId: decodedToken.userId, role: decodedToken.role };
        next();

    } catch (error) {
        return res.status(401).json({ message: 'فشل المصادقة: الرمز غير صالح' });
    }
};

// 2. 🚨 التحقق من صلاحية الأدمن (Authorization) - جديد!
const checkRole = (requiredRole) => (req, res, next) => {
    if (req.userData && req.userData.role === requiredRole) {
        next(); // المستخدم لديه الصلاحية، تفضل
    } else {
        res.status(403).json({ message: '⛔ غير مصرح: هذه العملية خاصة بالمدراء فقط' });
    }
};


/**
 * ============================================================
 * 5. APP SETUP (إعداد التطبيق)
 * ============================================================
 */
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(limiter);

app.use('/api', authMiddleware);

app.get('/', (req, res) => res.send('Filo Server is Live! 🚀'));

//
/**
 * ============================================================
 * 6. ROUTES (نقاط الاتصال)
 * ============================================================
 */

// --- AUTH ROUTES ---

app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "البريد مستخدم." });
            user.name = name; user.password = password; user.otp = otpCode; user.otpExpires = otpExpiry;
            await user.save();
        } else {
            user = new User({ email, password, name, isVerified: false, otp: otpCode, otpExpires: otpExpiry });
            await user.save();
        }

        await sendOTPEmail(email, name, otpCode);
       // console.log("TESTING OTP CODE:", otpCode);
        res.status(201).json({ message: "تم إرسال الرمز!" });
    } catch (error) {
        console.error("❌ تفاصيل الخطأ:", error); // هذا السطر سيطبع السبب في التيرمينال
        res.status(500).json({ error: "!!", details: error.message });
    }
});
//
app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "غير موجود" });

        if (String(user.otp).trim() !== String(otp).trim()) return res.status(400).json({ error: "رمز خطأ" });
        if (user.otpExpires < Date.now()) return res.status(400).json({ error: "رمز منتهي" });

        user.isVerified = true; user.otp = undefined;
        await user.save();
        res.status(200).json({ message: "تم تفعيل الإيميل!" });
    } catch (error) {
        res.status(500).json({ error: "خطأ" });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).select('+password');
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "البيانات غير صحيحة" });
        }
        if (!user.isVerified) return res.status(403).json({ error: "NOT_VERIFIED", message: "فعل الإيميل أولاً" });
        
        // (تم تخطي فحص الهاتف مؤقتاً لتسهيل التجربة، يمكنك إعادته بحذف التعليق)
        // if (!user.isPhoneVerified) return res.status(403).json({ error: "PHONE_NOT_VERIFIED" });

        const token = jwt.sign(
            { userId: user._id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        user.password = undefined;
        res.json({ message: "تم الدخول!", token, user });
    } catch (error) {
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

//
// --- MENU ROUTES (إدارة المنيو) ---

// عرض المنيو (متاح للجميع - تم استثناؤه في الـ middleware)
app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find();
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "فشل جلب المنيو" });
    }
});

// 🟢 إضافة وجبة (للأدمن فقط)
app.post('/api/menu', checkRole('admin'), async (req, res) => {
    try {
        const newMeal = new Menu(req.body);
        await newMeal.save();
        res.status(201).json({ message: "تمت إضافة الوجبة بنجاح!", meal: newMeal });
    } catch (error) {
        res.status(500).json({ error: "فشل إضافة الوجبة" });
    }
});

// 🟠 تعديل وجبة (للأدمن فقط)
app.put('/api/menu/:id', checkRole('admin'), async (req, res) => {
    try {
        const updatedMeal = await Menu.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedMeal) return res.status(404).json({ error: "الوجبة غير موجودة" });
        res.json({ message: "تم تعديل الوجبة!", meal: updatedMeal });
    } catch (error) {
        res.status(500).json({ error: "فشل التعديل" });
    }
});

// 🔴 حذف وجبة (للأدمن فقط)
app.delete('/api/menu/:id', checkRole('admin'), async (req, res) => {
    try {
        const deletedMeal = await Menu.findByIdAndDelete(req.params.id);
        if (!deletedMeal) return res.status(404).json({ error: "الوجبة غير موجودة" });
        res.json({ message: "تم حذف الوجبة بنجاح" });
    } catch (error) {
        res.status(500).json({ error: "فشل الحذف" });
    }
});


// --- ORDER ROUTES (الطلبات) ---

app.get('/api/orders', async (req, res) => {
    try {
        // إذا كان أدمن: يرى كل الطلبات، إذا مستخدم: يرى طلباته فقط
        const filter = req.userData.role === 'admin' ? {} : { userId: req.userData.userId };
        const orders = await Order.find(filter).populate('userId', 'name email');
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "فشل جلب الطلبات" });
    }
});

app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order({
            ...req.body,
            userId: req.userData.userId
        });
        await newOrder.save();
        res.status(201).json({ message: "تم إرسال الطلب!", order: newOrder });
    } catch (error) {
        res.status(500).json({ error: "فشل حفظ الطلب" });
    }
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));