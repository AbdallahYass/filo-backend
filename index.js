require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize'); // 🆕 تعقيم البيانات
const Joi = require('joi'); // 🆕 التحقق من صحة البيانات

const app = express();
const PORT = process.env.PORT || 3000;

const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ تم الاتصال بـ MongoDB بأمان!'))
    .catch(err => console.error('❌ خطأ في الاتصال:', err));

// --- إعدادات الحماية ---

app.use(helmet()); 

// 1️⃣ Strict CORS: السماح فقط لموقعك وللمحلي (للتجربة)
const allowedOrigins = ['https://filomenu.com', 'https://www.filomenu.com', 'http://localhost:3000'];
app.use(cors({
    origin: function (origin, callback) {
        // السماح بالطلبات التي ليس لها origin (مثل تطبيقات الموبايل و Postman) أو الموجودة في القائمة
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('غير مسموح به من قبل CORS'));
        }
    }
}));

app.use(bodyParser.json());

// 2️⃣ تعقيم البيانات ضد NoSQL Injection
app.use(mongoSanitize());

// تحديد عدد الطلبات
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: "تم حظرك مؤقتاً!"
});
app.use(limiter);

// التحقق من مفتاح API
const checkAuth = (req, res, next) => {
    if (req.method === 'GET') return next();
    const secret = req.headers['x-api-key'];
    if (secret === process.env.API_SECRET) {
        next();
    } else {
        res.status(403).json({ error: "Access Denied 🚫" });
    }
};
app.use(checkAuth);

// --- الجداول ---
const orderSchema = new mongoose.Schema({
    items: Array,        
    totalPrice: Number, 
    date: String,
    tableNumber: String
});
const Order = mongoose.model('Order', orderSchema);

const menuSchema = new mongoose.Schema({
    id: String, title: String, description: String, price: Number, imageUrl: String, category: String
});
const Menu = mongoose.model('Menu', menuSchema);

// --- 3️⃣ دالة التحقق من صحة البيانات (Validation) ---
const validateOrder = (data) => {
    const schema = Joi.object({
        items: Joi.array().required(), // يجب أن تكون مصفوفة
        totalPrice: Joi.number().min(0).required(), // رقم ولا يقل عن صفر
        date: Joi.string().required(),
        tableNumber: Joi.string().allow(null, '') // نص (مسموح فارغ)
    });
    return schema.validate(data);
};

// --- نقاط الاتصال ---

app.get('/', (req, res) => res.send('Filo Server Secure 🛡️'));

app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find();
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "Error" });
    }
});

app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find(); 
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "Error" });
    }
});

app.post('/api/orders', async (req, res) => {
    // 🔍 أولاً: نفحص البيانات قبل قبولها
    const { error } = validateOrder(req.body);
    if (error) {
        // إذا البيانات غلط (سعر سالب، فورمات غلط)، نرفض الطلب فوراً
        return res.status(400).json({ error: error.details[0].message });
    }

    const orderData = req.body;
    try {
        const newOrder = new Order(orderData);
        await newOrder.save();
        console.log("تم حفظ طلب جديد بأمان! 💾");
        res.status(201).json({ message: "Saved!" });
    } catch (error) {
        res.status(500).json({ error: "Error saving" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server Secure & Running on port ${PORT}`);
});