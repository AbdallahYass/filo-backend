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

/**
 * ============================================================
 * 3. SERVICES & HELPERS (الخدمات والدوال المساعدة)
 * ============================================================
 */

const sendOTPEmail = async (email, name, otpCode) => {
    const url = "https://api.brevo.com/v3/smtp/email";
    
    // 🎨 تصميم إيميل احترافي وعصري
    const emailDesign = `
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <style>
            body { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4; }
            .email-container { max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .header { background-color: #1A1A1A; padding: 40px 20px; text-align: center; background-image: linear-gradient(135deg, #1A1A1A 0%, #2c2c2c 100%); }
            .logo-text { color: #C5A028; margin: 0; font-size: 32px; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; }
            .content { padding: 40px 30px; text-align: center; color: #333333; }
            .welcome-text { font-size: 22px; margin-bottom: 10px; color: #1A1A1A; font-weight: bold; }
            .sub-text { font-size: 16px; color: #666666; margin-bottom: 30px; line-height: 1.6; }
            .otp-box { background-color: #FFF9E6; border: 2px dashed #C5A028; border-radius: 12px; padding: 20px; display: inline-block; margin: 20px 0; }
            .otp-code { color: #1A1A1A; font-size: 36px; font-weight: 800; letter-spacing: 8px; font-family: monospace; }
            .footer { background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #999999; border-top: 1px solid #eeeeee; }
            .note { font-size: 14px; color: #e74c3c; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <h1 class="logo-text">FILO MENU</h1>
            </div>
            
            <div class="content">
                <p class="welcome-text">أهلاً بك يا ${name} 👋</p>
                <p class="sub-text">
                    سعداء بانضمامك إلينا! لإكمال عملية التسجيل وتأمين حسابك، يرجى استخدام رمز التحقق أدناه.
                </p>
                
                <div class="otp-box">
                    <div class="otp-code">${otpCode}</div>
                </div>

                <p class="sub-text" style="margin-bottom: 0;">
                    هذا الرمز صالح لمدة <strong style="color: #C5A028;">10 دقائق</strong> فقط.
                </p>
                <p class="note">⚠️ لا تشارك هذا الرمز مع أي شخص.</p>
            </div>

            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} Filo Menu App. جميع الحقوق محفوظة.</p>
                <p>تم إرسال هذا البريد تلقائياً، الرجاء عدم الرد.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    const options = {
        method: "POST",
        headers: {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": process.env.BREVO_API_KEY
        },
        body: JSON.stringify({
            sender: { 
                name: "Filo Menu Team", 
                email: "no-reply@filomenu.com" 
            },
            to: [{ email: email, name: name }],
            subject: "🔐 رمز تفعيل حسابك - Filo Menu",
            htmlContent: emailDesign
        })
    };

    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            const errorData = await response.json();
            console.error("❌ فشل إرسال الإيميل (API Error):", JSON.stringify(errorData));
        } else {
            console.log(`✅ تم إرسال رمز التفعيل بنجاح إلى: ${email}`);
        }
    } catch (error) {
        console.error("❌ خطأ في الاتصال بخدمة Brevo:", error);
    }
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