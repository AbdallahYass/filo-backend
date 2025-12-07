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
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

// إعدادات المتغيرات البيئية
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
// const EMAIL_USER = process.env.EMAIL_USER; // لم نعد نستخدمه مباشرة مع Brevo API

// الاتصال بقاعدة البيانات
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB (Super App DB)!'))
    .catch(err => console.error('❌ Connection Error:', err));


/**
 * ============================================================
 * 2. DATABASE MODELS (نماذج قاعدة البيانات - شاملة)
 * ============================================================
 */

// --- User Schema (زبون، سائق، تاجر، أدمن) ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    name: String,
    
    // 🎭 الأدوار المتاحة في النظام
    role: { 
        type: String, 
        default: 'customer', 
        enum: ['customer', 'admin', 'vendor', 'driver'] 
    },
    
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    
    phone: { type: String }, // 📞 رقم الهاتف
    phoneOtp: String,
    isPhoneVerified: { type: Boolean, default: false }, // ✅ حالة تفعيل الهاتف

    // 🏠 عناوين الزبون
    savedAddresses: [{
        label: String,
        street: String,
        city: String,
        location: { lat: Number, lng: Number }
    }],

    // 🛵 بيانات السائق (تستخدم فقط إذا كان الدور driver)
    driverStatus: {
        isOnline: { type: Boolean, default: false },
        currentLocation: { lat: Number, lng: Number },
        vehicleType: String,
        licensePlate: String
    },

    // 🏪 بيانات المتجر (تستخدم فقط إذا كان الدور vendor)
    storeInfo: {
        storeName: String,
        description: String,
        logoUrl: String,
        isOpen: { type: Boolean, default: true }
    }
});

userSchema.pre('save', async function() {
    const user = this;
    if (!user.isModified('password')) return; 
    try {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
    } catch (error) { throw error; }
});
const User = mongoose.model('User', userSchema);


// --- Menu Schema (المنتجات) ---
const menuSchema = new mongoose.Schema({
    // 🔗 ربط المنتج بصاحب المتجر (Vendor) - جعلناها اختيارية مؤقتاً للأدمن
    vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 

    title: { type: String, required: true }, 
    description: String, 
    price: { type: Number, required: true }, 
    imageUrl: String, 
    category: { type: String, required: true },
    isAvailable: { type: Boolean, default: true }
});
const Menu = mongoose.model('Menu', menuSchema);


// --- Order Schema (الطلبات ودورة التوصيل) ---
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // الزبون
    
    // 🔗 المتجر المسؤول عن الطلب (اختياري حالياً حتى نجهز تطبيق المتاجر)
    vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

    // 🛵 السائق المسؤول (يضاف لاحقاً عند قبول الطلب)
    driverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

    items: [{
        menuId: { type: mongoose.Schema.Types.ObjectId, ref: 'Menu' },
        title: String,
        quantity: Number,
        price: Number
    }],
    
    totalPrice: { type: Number, required: true },
    orderType: { type: String, required: true, enum: ['delivery', 'pickup', 'dine_in'], default: 'delivery' },
    
    shippingAddress: {
        street: String,
        city: String,
        location: { lat: Number, lng: Number }
    },
    contactPhone: { type: String },
    
    // 🚦 حالات الطلب الكاملة
    status: { 
        type: String, 
        default: 'pending', 
        enum: [
            'pending',          // بانتظار موافقة المتجر
            'accepted',         // المتجر وافق وجاري التحضير
            'ready_for_pickup', // جاهز، بانتظار سائق
            'picked_up',        // السائق استلمه
            'out_for_delivery', // في الطريق
            'completed',        // وصل للزبون
            'cancelled'         // ملغي
        ] 
    },

    deliveryFee: { type: Number, default: 0 },
    date: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);


/**
 * ============================================================
 * 3. SERVICES (خدمات الإيميل وغيرها)
 * ============================================================
 */
const sendOTPEmail = async (email, name, otpCode) => {
    const url = "https://api.brevo.com/v3/smtp/email";
    
    const emailDesign = `
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <style>
            body { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4; }
            .email-container { max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .header { background-color: #1A1A1A; padding: 30px 20px; text-align: center; }
            .logo-image { max-width: 180px; height: auto; display: block; margin: 0 auto; }
            .content { padding: 40px 30px; text-align: center; color: #333333; }
            .welcome-text { font-size: 22px; margin-bottom: 10px; color: #1A1A1A; font-weight: bold; }
            .sub-text { font-size: 16px; color: #666666; margin-bottom: 30px; line-height: 1.6; }
            .otp-box { background-color: #FFF9E6; border: 2px dashed #C5A028; border-radius: 12px; padding: 20px; display: inline-block; margin: 20px 0; }
            .otp-code { color: #1A1A1A; font-size: 36px; font-weight: 800; letter-spacing: 8px; font-family: monospace; }
            .footer { background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #999999; border-top: 1px solid #eeeeee; }
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <img src="https://placehold.co/400x150/1A1A1A/C5A028?text=FILO+MENU+LOGO" alt="Filo Logo" class="logo-image">
            </div>
            <div class="content">
                <p class="welcome-text">أهلاً بك يا ${name} 👋</p>
                <p class="sub-text">رمز التفعيل الخاص بك هو:</p>
                <div class="otp-box"><div class="otp-code">${otpCode}</div></div>
                <p class="sub-text">صالح لمدة 10 دقائق.</p>
            </div>
            <div class="footer"><p>&copy; ${new Date().getFullYear()} Filo App.</p></div>
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
            sender: { name: "Filo Menu Team", email: "no-reply@filomenu.com" },
            to: [{ email: email, name: name }],
            subject: "🔐 رمز تفعيل حسابك - Filo",
            htmlContent: emailDesign
        })
    };

    try {
        const response = await fetch(url, options);
        if (!response.ok) console.error("❌ Email API Error");
        else console.log(`✅ Email sent to: ${email}`);
    } catch (error) { console.error("❌ Email Network Error", error); }
};


/**
 * ============================================================
 * 4. MIDDLEWARES & AUTH
 * ============================================================
 */
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });

const authMiddleware = (req, res, next) => {
    // السماح للمسارات العامة
    if (req.path.startsWith('/auth') || req.path.startsWith('/api/auth')) return next();

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'No Token Provided' });
        }
        const token = authHeader.split(' ')[1];
        const decodedToken = jwt.verify(token, JWT_SECRET);
        req.userData = { userId: decodedToken.userId, role: decodedToken.role };
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
};

// التحقق من الصلاحيات (Role-Based Access Control)
const checkRole = (allowedRoles) => (req, res, next) => {
    // نسمح بإدخال مصفوفة أدوار، مثلاً ['admin', 'vendor']
    const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
    if (req.userData && roles.includes(req.userData.role)) {
        next();
    } else {
        res.status(403).json({ message: '⛔ غير مصرح لك (Not Authorized)' });
    }
};


/**
 * ============================================================
 * 5. APP SETUP & ROUTES
 * ============================================================
 */
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(limiter);
app.use('/api', authMiddleware);

app.get('/', (req, res) => res.send('Filo Super-App Server is Live! 🚀'));

// --- AUTH (التسجيل والدخول) ---

app.post('/api/auth/register', async (req, res) => {
    // 🛠️ التحديث: استقبال الهاتف والدور من التطبيق
    const { email, password, name, phone, role } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        // الدور الافتراضي customer إذا لم يرسله التطبيق
        const userRole = role || 'customer'; 

        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "البريد مستخدم" });
            user.name = name; 
            user.password = password; 
            user.otp = otpCode; 
            user.otpExpires = otpExpiry; 
            user.role = userRole; 
            user.phone = phone; // ✅ تحديث الهاتف
            await user.save();
        } else {
            user = new User({ 
                email, 
                password, 
                name, 
                phone, // ✅ حفظ الهاتف
                role: userRole, 
                isVerified: false, 
                otp: otpCode, 
                otpExpires: otpExpiry 
            });
            await user.save();
        }
        await sendOTPEmail(email, name, otpCode);
        res.status(201).json({ message: "تم إرسال الرمز" });
    } catch (error) { res.status(500).json({ error: "Server Error", details: error.message }); }
});

app.post('/api/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || user.otpExpires < Date.now()) return res.status(400).json({ error: "Invalid Code" });
        user.isVerified = true; user.otp = undefined;
        await user.save();
        res.status(200).json({ message: "Verified!" });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).select('+password');
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Wrong Credentials" });
        if (!user.isVerified) return res.status(403).json({ error: "NOT_VERIFIED" });
        
        // 🚧 يمكن تفعيل هذا السطر لاحقاً لإجبار تفعيل الهاتف
        // if (!user.isPhoneVerified) return res.status(403).json({ error: "PHONE_NOT_VERIFIED" });

        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' }); // مدة طويلة
        user.password = undefined;
        res.json({ message: "Logged In", token, user });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});


// --- Google Auth Route (New) ---
app.post('/api/auth/google', async (req, res) => {
    const { accessToken } = req.body;

    if (!accessToken) {
        return res.status(400).json({ error: "Access token is required" });
    }

    try {
        // 1. التحقق من التوكن وجلب بيانات المستخدم من جوجل
        const googleResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        if (!googleResponse.ok) {
            return res.status(400).json({ error: "Invalid Google Token" });
        }

        const googleData = await googleResponse.json();
        const { email, name, sub, picture } = googleData; // sub هو الـ Google ID

        // 2. البحث عن المستخدم في الداتابيز
        let user = await User.findOne({ email });

        if (user) {
            // --- المستخدم موجود مسبقاً ---
            
            // تحديث الاسم أو الصورة إذا حبيت (اختياري)
            // user.name = name;
            // await user.save();

        } else {
            // --- مستخدم جديد (أول مرة) ---
            
            // ملاحظة: بما أن الباسوورد مطلوب في الموديل، بنعمل باسوورد عشوائي قوي
            // المستخدم ما رح يستخدمه، رح يدخل دائماً عبر جوجل
            const randomPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);

            user = new User({
                email: email,
                name: name,
                password: randomPassword, // سيتم تشفيره تلقائياً عبر الـ Pre-save hook
                role: 'customer', // الدور الافتراضي
                isVerified: true, // جوجل يعتبر جهة موثوقة، فالحساب مفعل
                isPhoneVerified: false, // لا يزال يحتاج تفعيل رقم الهاتف لاحقاً
                // يمكن حفظ الصورة إذا عدلت الموديل لاحقاً
                // photoUrl: picture 
            });

            await user.save();
        }

        // 3. إنشاء التوكن الخاص بسيرفرنا (JWT)
        const token = jwt.sign(
            { userId: user._id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        // 4. إرسال الرد للتطبيق
        res.status(200).json({
            message: "Google Login Success",
            token: token,
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                isVerified: user.isVerified
            }
        });

    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(500).json({ error: "Internal Server Error during Google Auth" });
    }
});
// --- Forgot Password Flow ---

// 1. طلب إعادة تعيين كلمة المرور (إرسال الكود)
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Email not found" });

        // إنشاء كود جديد
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otpCode;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 دقائق
        await user.save();

        // إرسال الإيميل (تعديل الرسالة لتكون مناسبة للريسيت)
        await sendOTPEmail(email, user.name || "User", otpCode);

        res.json({ message: "OTP sent to email" });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. تعيين كلمة المرور الجديدة
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        // التحقق من الكود والوقت
        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ error: "Invalid or Expired OTP" });
        }

        // تحديث كلمة المرور
        user.password = newPassword; // الـ Hook في الموديل رح يشفرها تلقائياً
        user.otp = undefined; // حذف الكود
        user.otpExpires = undefined;
        
        // مهم جداً: إذا كان الحساب غير مفعل، نفعله بالمرة
        if (!user.isVerified) user.isVerified = true;

        await user.save();

        res.json({ message: "Password updated successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Server Error" });
    }
});
// إرسال كود الهاتف (وهمي حالياً لعدم وجود اشتراك SMS)
app.post('/api/auth/phone/send', async (req, res) => {
    const { email, phone } = req.body;
    // هنا المفروض نربط مع خدمة مثل Twilio
    // حالياً سنقوم "بتمثيل" النجاح
    console.log(`📲 [MOCK SMS] Sending code to ${phone} for user ${email}`);
    res.status(200).json({ message: "SMS sent (Mock)" });
});
// التحقق من كود الهاتف
app.post('/api/auth/phone/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if(!user) return res.status(404).json({error: "User not found"});
        
        // للتبسيط في التجربة: أي كود "123456" سنعتبره صحيحاً
        // أو يمكنك حفظ الكود في الداتابيز ومقارنته مثل الإيميل
        if (otp === "123456") {
            user.isPhoneVerified = true;
            await user.save();
            res.status(200).json({ message: "Phone Verified!" });
        } else {
            res.status(400).json({ error: "Invalid SMS Code" });
        }
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});


// --- MENU (للمتاجر) ---
// 🛠️ التحديث: السماح للمتاجر والأدمن بالإضافة
app.post('/api/menu', checkRole(['admin', 'vendor']), async (req, res) => {
    try {
        const mealData = { ...req.body };
        // إذا كان الفاعل متجر، نربط الوجبة به تلقائياً
        if (req.userData.role === 'vendor') {
            mealData.vendorId = req.userData.userId;
        }
        const newMeal = new Menu(mealData);
        await newMeal.save();
        res.status(201).json({ message: "Item Added", meal: newMeal });
    } catch (error) { res.status(500).json({ error: "Failed to add item" }); }
});

app.get('/api/menu', async (req, res) => {
    const { vendorId } = req.query;
    const filter = vendorId ? { vendorId } : {};
    try {
        const menu = await Menu.find(filter);
        res.json(menu);
    } catch (error) { res.status(500).json({ error: "Failed to fetch menu" }); }
});

// --- ORDERS (الطلبات) ---
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order({ ...req.body, userId: req.userData.userId });
        await newOrder.save();
        res.status(201).json({ message: "Order Placed", order: newOrder });
    } catch (error) { res.status(500).json({ error: "Failed to place order" }); }
});

app.get('/api/orders', async (req, res) => {
    try {
        let filter = {};
        // 🛠️ التحديث: منطق العرض حسب الدور
        if (req.userData.role === 'customer') {
            filter = { userId: req.userData.userId };
        } else if (req.userData.role === 'vendor') {
            filter = { vendorId: req.userData.userId };
        } else if (req.userData.role === 'driver') {
            filter = { 
                $or: [
                    { driverId: req.userData.userId }, // طلباته
                    { status: 'ready_for_pickup', driverId: { $exists: false } } // طلبات متاحة
                ]
            };
        }
        
        const orders = await Order.find(filter).populate('userId', 'name phone').sort({ date: -1 });
        res.json(orders);
    } catch (error) { res.status(500).json({ error: "Failed to fetch orders" }); }
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));