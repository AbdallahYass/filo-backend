require('dotenv').config(); // تحميل المتغيرات السرية
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const helmet = require('helmet'); // حماية الهيدرز
const rateLimit = require('express-rate-limit'); // حماية من السبام

const app = express();
const PORT = process.env.PORT || 3000; // Render يعطي بورت تلقائي

// 1. الاتصال بقاعدة البيانات (من المتغيرات السرية)
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ تم الاتصال بـ MongoDB بأمان!'))
    .catch(err => console.error('❌ خطأ في الاتصال:', err));

// 2. إعدادات الحماية
app.use(helmet()); // تفعيل خوذة الحماية
app.use(cors());   // يمكن تخصيصه لاحقاً ليقبل فقط موقعك
app.use(bodyParser.json());

// 3. تحديد عدد الطلبات (مثلاً 100 طلب كل 15 دقيقة لكل IP)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // الحد الأقصى
    message: "تم حظرك مؤقتاً بسبب كثرة الطلبات!"
});
app.use(limiter); // تطبيق الحد على كل الراوتس

// 4. حماية إضافية (كلمة سر للتطبيق)
// أي طلب لا يحمل الكود السري سيتم رفضه
const checkAuth = (req, res, next) => {
    // نسمح بطلبات الـ GET (عرض المنيو) للجميع
    if (req.method === 'GET') return next();

    const secret = req.headers['x-api-key'];
    if (secret === process.env.API_SECRET) {
        next(); // السماح بالمرور
    } else {
        res.status(403).json({ error: "غير مصرح لك بالدخول! 🚫" });
    }
};
app.use(checkAuth);

// --- الجداول (Schemas) ---
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

// --- نقاط الاتصال ---

app.get('/', (req, res) => res.send('Filo Server is Secure & Running! 🔒'));

app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find();
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "Error fetching menu" });
    }
});

app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find(); 
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "Error fetching orders" });
    }
});

app.post('/api/orders', async (req, res) => {
    const orderData = req.body;
    try {
        const newOrder = new Order(orderData);
        await newOrder.save();
        console.log("تم حفظ طلب جديد بأمان! 💾");
        res.status(201).json({ message: "تم الحفظ بنجاح!" });
    } catch (error) {
        res.status(500).json({ error: "Error saving order" });
    }
});

// تعبئة المنيو (محمية بكلمة السر أيضاً)
app.get('/api/fill-menu', async (req, res) => {
    // يمكنك إضافة منطق حماية خاص هنا
    res.send("تم إيقاف هذه الخاصية للأمان."); 
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});