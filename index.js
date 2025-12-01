require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
// const mongoSanitize = require('express-mongo-sanitize'); // ❌ عطلناها مؤقتاً
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// 1. الاتصال بقاعدة البيانات
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ تم الاتصال بـ MongoDB بأمان!'))
    .catch(err => console.error('❌ خطأ في الاتصال:', err));

// 2. إعدادات الحماية
app.use(helmet());

// 👇👇👇 تعديل هام: السماح للجميع (لحل مشكلة CORS Error)
app.use(cors()); 

app.use(bodyParser.json());

// ❌ تعطيل هذا السطر لأنه يسبب الـ TypeError
// app.use(mongoSanitize());

// تحديد عدد الطلبات (حماية من السبام)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 300, // رفعنا الحد قليلاً
    message: "تم حظرك مؤقتاً!"
});
app.use(limiter);

// 3. التحقق من مفتاح API (الحماية الأساسية)
const checkAuth = (req, res, next) => {
    // السماح للصفحة الرئيسية
    if (req.path === '/') return next();

    // ⚠️ للتسهيل: إذا واجهت مشاكل في التطبيق، يمكنك تفعيل هذا السطر للسماح بجلب المنيو بدون مفتاح
    // if (req.method === 'GET') return next();

    const secret = req.headers['x-api-key'];
    // 👇👇👇 أضف هذين السطرين هنا لنكشف السر
    console.log("🔑 المفتاح القادم من التطبيق:", secret);
    console.log("🔒 المفتاح المخزن في السيرفر:", process.env.API_SECRET);
    // 👆👆👆
    if (secret === process.env.API_SECRET) {
        next();
    } else {
        console.log(`دخول مرفوض من: ${req.ip}`);
        res.status(403).json({ error: "Access Denied 🚫 Wrong API Key" });
    }
};
app.use('/api', checkAuth);


// --- الجداول (Schemas) ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    role: { type: String, default: 'user' }
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

app.get('/', (req, res) => res.send('Filo Server is Running (Fixed)! 🛠️'));

// تسجيل حساب
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: "بيانات ناقصة" });

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "المستخدم موجود مسبقاً" });

        const newUser = new User({ email, password, name });
        await newUser.save();
        res.status(201).json({ message: "تم التسجيل بنجاح!", user: { email, name } });
    } catch (error) {
        res.status(500).json({ error: "فشل التسجيل" });
    }
});

// تسجيل دخول
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.password !== password) {
            return res.status(401).json({ error: "خطأ في البيانات" });
        }
        res.json({ message: "تم الدخول", user: { name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: "خطأ سيرفر" });
    }
});

// المنيو
app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find();
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "Error fetching menu" });
    }
});

// الطلبات
app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "Error fetching orders" });
    }
});

app.post('/api/orders', async (req, res) => {
    // التحقق من البيانات (Joi)
    const schema = Joi.object({
        items: Joi.array().required(),
        totalPrice: Joi.number().min(0).required(),
        date: Joi.string().required(),
        tableNumber: Joi.string().allow(null, '')
    });
    
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    try {
        const newOrder = new Order(req.body);
        await newOrder.save();
        console.log("تم حفظ الطلب! 💾");
        res.status(201).json({ message: "Saved!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error saving order" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});