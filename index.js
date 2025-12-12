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
const fetch = require('node-fetch');

const app = express();
// 🔥 تعريف Router جديد للمسارات العامة 🔥
const publicRoutes = express.Router(); 
// 🔥 تعريف Router جديد للمسارات المحمية 🔥
const protectedRoutes = express.Router(); 

// إعدادات المتغيرات البيئية
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost/filo_super_app';
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_JWT_SECRET_KEY';
const API_KEY = process.env.API_KEY || 'FiloSecretKey202512341234'; 

// الاتصال بقاعدة البيانات
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB (Super App DB)!'))
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
    role: { type: String, default: 'customer', enum: ['customer', 'admin', 'vendor', 'driver'] },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    phone: { type: String }, 
    isPhoneVerified: { type: Boolean, default: false },
    // 🔥🔥 حقول التقييم والطلبات 🔥🔥
    averageRating: { type: Number, default: 0 },
    ordersCount: { type: Number, default: 0 }, 
    savedAddresses: [{
        title: { type: String, required: true },
        details: { type: String, required: true },
        latitude: { type: Number, default: 0 },
        longitude: { type: Number, default: 0 }
    }],
    driverStatus: {
        isOnline: { type: Boolean, default: false },
        currentLocation: { lat: Number, lng: Number },
        vehicleType: String,
        licensePlate: String
    },
    storeInfo: {
        storeName: String,
        description: String,
        logoUrl: String,
        isOpen: { type: Boolean, default: true },
        // 🔥🔥 ساعات العمل المضافة لتوافق مع Flutter 🔥🔥
        openTime: { type: String, default: '09:00' }, 
        closeTime: { type: String, default: '22:00' }, 
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


// --- Menu Schema ---
const menuSchema = new mongoose.Schema({
    vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    title: { type: String, required: true }, 
    description: String, 
    price: { type: Number, required: true }, 
    imageUrl: String, 
    category: { type: String, required: true },
    isAvailable: { type: Boolean, default: true }
});
const Menu = mongoose.model('Menu', menuSchema);


// --- Order Schema ---
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    driverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    items: [{
        menuId: { type: mongoose.Schema.Types.ObjectId, ref: 'Menu' },
        title: String,
        quantity: Number,
        price: Number
    }],
    totalPrice: { type: Number, required: true },
    orderType: { type: String, required: true, enum: ['delivery', 'pickup', 'dine_in'], default: 'delivery' },
    shippingAddress: { street: String, city: String, location: { lat: Number, lng: Number } },
    contactPhone: { type: String },
    status: { type: String, default: 'pending', enum: ['pending', 'accepted', 'ready_for_pickup', 'picked_up', 'out_for_delivery', 'completed', 'cancelled'] },
    deliveryFee: { type: Number, default: 0 },
    date: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// 🔥🔥 Category Schema 🔥🔥
const categorySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true, lowercase: true }, 
    name: { en: { type: String, required: true }, ar: { type: String, required: true } },
    icon: { type: String },
    description: String,
    isAvailable: { type: Boolean, default: true }
});

const Category = mongoose.model('Category', categorySchema);
// ----------------------------------------------------------------


/**
 * ============================================================
 * 3. SERVICES (خدمات الإيميل فقط)
 * ============================================================
 */
const sendOTPEmail = async (email, name, otpCode, subject) => {
    const url = "https://api.brevo.com/v3/smtp/email";
    
    const emailDesign = `
     <!DOCTYPE html>
     <html lang="ar" dir="rtl">
     <head>
        <meta charset="UTF-8">
        <style> /* ... (Styles omitted for brevity) ... */ </style>
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
            subject: subject || "🔐 رمز تفعيل حسابك - Filo", 
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

// 🛡️ Middleware للتحقق من التوكن (JWT)
const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No Token Provided' });
        }
        const token = authHeader.split(' ')[1];
        const decodedToken = jwt.verify(token, JWT_SECRET);
        req.userData = { userId: decodedToken.userId, role: decodedToken.role };
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid Token' });
    }
};

// 🛡️ Middleware للتحقق من الدور (Role Check)
const checkRole = (allowedRoles) => (req, res, next) => {
    const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
    if (req.userData && roles.includes(req.userData.role)) {
        next();
    } else {
        res.status(403).json({ error: 'NOT_AUTHORIZED' }); 
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

// ----------------------------------------------------
// 🔥 المسارات العامة (Public Routes - لا تتطلب توكن)
// ----------------------------------------------------

app.get('/', (req, res) => res.send('Filo Super-App Server is Live! 🚀'));


// ================= AUTH ROUTES (عامة) =================

publicRoutes.post('/auth/register', async (req, res) => {
    const { email, password, name, phone, role } = req.body;
    try {
        let user = await User.findOne({ email });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;
        const userRole = role || 'customer'; 

        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "EMAIL_IN_USE" });
            user.name = name; 
            user.password = password; 
            user.otp = otpCode; 
            user.otpExpires = otpExpiry; 
            user.role = userRole; 
            user.phone = phone; 
            if(phone) user.isPhoneVerified = true; 
            await user.save();
        } else {
            user = new User({ 
                email, password, name, phone, 
                role: userRole, 
                isVerified: false, 
                otp: otpCode, otpExpires: otpExpiry,
                isPhoneVerified: !!phone 
            });
            await user.save();
        }
        await sendOTPEmail(email, name, otpCode);
        res.status(201).json({ message: "OTP sent" });
    } catch (error) { res.status(500).json({ error: "Server Error", details: error.message }); }
});

publicRoutes.post('/auth/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || user.otpExpires < Date.now()) return res.status(400).json({ error: "INVALID_OTP" });
        user.isVerified = true; user.otp = undefined;
        await user.save();
        res.status(200).json({ message: "Verified" });
    } catch (error) { res.status(500).json({ error: "Server Error" }); }
});

publicRoutes.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).select('+password');
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "WRONG_CREDENTIALS" });
        if (!user.isVerified) return res.status(403).json({ error: "NOT_VERIFIED" });
        
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
        user.password = undefined;
        res.json({ message: "Logged In", token, user });
    } catch (error) { res.status(500).json({ error: "Server Error" }); }
});

publicRoutes.post('/auth/google', async (req, res) => {
    const { accessToken } = req.body;
    if (!accessToken) return res.status(400).json({ error: "Access token is required" });

    try {
        const googleResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        if (!googleResponse.ok) return res.status(400).json({ error: "INVALID_GOOGLE_TOKEN" });

        const googleData = await googleResponse.json();
        const { email, name } = googleData;

        let user = await User.findOne({ email });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
            user = new User({
                email: email,
                name: name,
                password: randomPassword,
                role: 'customer',
                isVerified: true,
                isPhoneVerified: false
            });
            await user.save();
        }

        const token = jwt.sign(
            { userId: user._id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.status(200).json({
            message: "Google Login Success",
            token: token,
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                isVerified: user.isVerified,
                phone: user.phone
            }
        });

    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

publicRoutes.post('/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "EMAIL_NOT_FOUND" }); 

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otpCode;
        user.otpExpires = Date.now() + 10 * 60 * 1000;
        await user.save();

        await sendOTPEmail(
            email, 
            user.name || "User", 
            otpCode, 
            "🔑 كود استرجاع كلمة المرور الخاصة بك - Filo" 
        ); 
        
        res.json({ message: "RESET_CODE_SENT" }); 
    } catch (error) { res.status(500).json({ error: "Server Error" }); }
});

publicRoutes.post('/auth/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });

        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ error: "INVALID_OTP_OR_EXPIRED" }); 
        }

        user.password = newPassword;
        user.otp = undefined;
        user.otpExpires = undefined;
        if (!user.isVerified) user.isVerified = true;

        await user.save();
        res.json({ message: "PASSWORD_RESET_SUCCESS" }); 
    } catch (error) { res.status(500).json({ error: "Server Error" }); }
});


// ================= CATEGORIES ROUTES (عامة) =================

// 1. جلب جميع الفئات (متاحة للجميع)
publicRoutes.get('/categories', async (req, res) => {
    try {
        const categories = await Category.find({ isAvailable: true }).sort({ name: 1 });
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});


// ================= VENDORS ROUTES (عامة - مع الفرز) =================

// 1. جلب التجار (متاح للجميع)
publicRoutes.get('/vendors', async (req, res) => {
    const { sortBy } = req.query; 
    let filter = { role: 'vendor', 'storeInfo.isOpen': true };
    let sortOptions = {}; 

    // 🔥 منطق تحديد الفرز 🔥
    if (sortBy === 'rating') {
        sortOptions = { averageRating: -1 }; 
    } else if (sortBy === 'popular') {
        sortOptions = { ordersCount: -1 }; 
    } else {
        sortOptions = { name: 1 }; // الافتراضي
    }
    
    try {
        const vendors = await User.find(filter)
                                 .select('-password')
                                 .sort(sortOptions); 
        
        res.json(vendors);
    } catch (error) {
        console.error("Vendor Fetch Error:", error);
        res.status(500).json({ error: "Failed to fetch vendors" });
    }
});


// ================= MENU ROUTES (عامة) =================

// 1. جلب قائمة الطعام لتاجر معين (متاح للجميع)
publicRoutes.get('/menu', async (req, res) => {
    const { vendorId } = req.query;
    const filter = vendorId ? { vendorId } : {};
    try {
        const menu = await Menu.find(filter);
        res.json(menu);
    } catch (error) { res.status(500).json({ error: "Failed to fetch menu" }); }
});

// 🔥🔥 تطبيق المسارات العامة أولاً (لن تخضع للحماية) 🔥🔥
app.use('/api', publicRoutes);


// ----------------------------------------------------
// 🛡️ تطبيق الحماية (Protected Routes)
// ----------------------------------------------------

// 🔥 تطبيق الـ middleware على Router المحمي 🔥
protectedRoutes.use(authMiddleware); 


// ================= USER & ADDRESSES ROUTES (محمية) =================

// 🔥 تحديث رقم الهاتف (محمية) 🔥
protectedRoutes.post('/user/update-phone', async (req, res) => {
    const { phone } = req.body;
    
    if (!phone) return res.status(400).json({ error: "PHONE_REQUIRED" });

    try {
        await User.findByIdAndUpdate(req.userData.userId, { 
            phone: phone,
            isPhoneVerified: true 
        });
        
        res.json({ message: "Phone saved successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 1. جلب بيانات المستخدم الحالية
protectedRoutes.get('/user/profile', async (req, res) => {
    try {
        const user = await User.findById(req.userData.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. تحديث الاسم ورقم الهاتف
protectedRoutes.put('/user/update-profile', async (req, res) => {
    const { name, phone } = req.body;
    try {
        const user = await User.findById(req.userData.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        if (name) user.name = name;
        if (phone) user.phone = phone;

        await user.save();
        res.json({ message: "Profile updated successfully", user });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. تغيير كلمة المرور (للمسجل دخول)
protectedRoutes.put('/user/change-password', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.userData.userId).select('+password');
        
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ error: "INCORRECT_OLD_PASSWORD" });

        user.password = newPassword;
        await user.save();
        
        res.json({ message: "Password changed successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// ================= ADDRESS ROUTES (محمية) =================
// 1. Fetch Addresses
protectedRoutes.get('/user/addresses', async (req, res) => {
    try {
        const user = await User.findById(req.userData.userId, 'savedAddresses');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(user.savedAddresses);
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. Add Address
protectedRoutes.post('/user/addresses', async (req, res) => {
    const { title, details, latitude, longitude } = req.body;

    if (!title || !details || latitude === undefined || longitude === undefined) {
        return res.status(400).json({ error: "MISSING_ADDRESS_FIELDS" });
    }

    try {
        const user = await User.findById(req.userData.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const newAddress = {
            title: title, 
            details: details, 
            latitude: latitude, 
            longitude: longitude
        };
        
        user.savedAddresses.push(newAddress);
        await user.save();
        
        const addedAddress = user.savedAddresses[user.savedAddresses.length - 1]; 
        res.status(201).json({ 
            message: "Address added successfully", 
            address: addedAddress 
        });
    } catch (error) {
        console.error("Address Add Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. updated Address
protectedRoutes.put('/user/addresses/:addressId', async (req, res) => {
    const { addressId } = req.params;
    const { title, details, latitude, longitude } = req.body;

    if (!title || !details || latitude === undefined || longitude === undefined) {
        return res.status(400).json({ error: "MISSING_ADDRESS_FIELDS" });
    }

    try {
        const user = await User.findById(req.userData.userId);
        if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });

        // 1. العثور على فهرس (Index) العنوان المراد تعديله
        const addressIndex = user.savedAddresses.findIndex(
            addr => addr._id.toString() === addressId
        );

        if (addressIndex === -1) {
            return res.status(404).json({ error: "ADDRESS_NOT_FOUND" });
        }

        // 2. تحديث البيانات مباشرة في المخطط الفرعي (Subdocument)
        user.savedAddresses[addressIndex].title = title;
        user.savedAddresses[addressIndex].details = details;
        user.savedAddresses[addressIndex].latitude = latitude;
        user.savedAddresses[addressIndex].longitude = longitude;

        await user.save();

        res.status(200).json({ 
            message: "Address updated successfully",
            address: user.savedAddresses[addressIndex]
        });

    } catch (error) {
        console.error("Address Update Error:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 4. Delete Address
protectedRoutes.delete('/user/addresses/:addressId', async (req, res) => {
    const { addressId } = req.params;
    try {
        const user = await User.findById(req.userData.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        
        user.savedAddresses.pull(addressId); 
        await user.save();

        res.json({ message: "Address deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// ================= ADMIN/VENDOR ROUTES (محمية) =================

// 1. إضافة فئة جديدة (للمسؤولين فقط)
protectedRoutes.post('/categories', checkRole(['admin']), async (req, res) => {
    try {
        const { name, key, icon, description } = req.body;
        if (!name || !key || !icon) {
            return res.status(400).json({ error: "MISSING_CATEGORY_FIELDS" });
        }
        
        const newCategory = new Category({ name, key, icon, description });
        await newCategory.save();
        res.status(201).json({ message: "Category added successfully", category: newCategory });
        
    } catch (error) {
        if (error.code === 11000) { // MongoDB duplicate key error
            return res.status(409).json({ error: "CATEGORY_KEY_EXISTS" });
        }
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. حذف فئة (للمسؤولين فقط)
protectedRoutes.delete('/categories/:categoryId', checkRole(['admin']), async (req, res) => {
    try {
        const result = await Category.findByIdAndDelete(req.params.categoryId);
        if (!result) {
            return res.status(404).json({ error: "CATEGORY_NOT_FOUND" });
        }
        res.json({ message: "Category deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. إضافة عنصر للقائمة (للتاجر والمسؤول)
protectedRoutes.post('/menu', checkRole(['admin', 'vendor']), async (req, res) => {
    try {
        const mealData = { ...req.body };
        if (req.userData.role === 'vendor') {
            mealData.vendorId = req.userData.userId;
        }
        const newMeal = new Menu(mealData);
        await newMeal.save();
        res.status(201).json({ message: "Item Added", meal: newMeal });
    } catch (error) { res.status(500).json({ error: "Failed to add item" }); }
});


// ================= ORDERS ROUTES (محمية) =================

// 1. إضافة طلب
protectedRoutes.post('/orders', async (req, res) => {
    try {
        const newOrder = new Order({ ...req.body, userId: req.userData.userId });
        await newOrder.save();
        res.status(201).json({ message: "Order Placed", order: newOrder });
    } catch (error) { res.status(500).json({ error: "Failed to place order" }); }
});

// 2. جلب الطلبات (فلترة حسب الدور)
protectedRoutes.get('/orders', async (req, res) => {
    try {
        let filter = {};
        if (req.userData.role === 'customer') {
            filter = { userId: req.userData.userId };
        } else if (req.userData.role === 'vendor') {
            filter = { vendorId: req.userData.userId };
        } else if (req.userData.role === 'driver') {
            filter = { 
                $or: [
                    { driverId: req.userData.userId }, 
                    { status: 'ready_for_pickup', driverId: { $exists: false } } 
                ]
            };
        }
        
        const orders = await Order.find(filter).populate('userId', 'name phone').sort({ date: -1 });
        res.json(orders);
    } catch (error) { res.status(500).json({ error: "Failed to fetch orders" }); }
});

// 🔥🔥 تطبيق المسارات المحمية ثانياً 🔥🔥
app.use('/api', protectedRoutes);


app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));