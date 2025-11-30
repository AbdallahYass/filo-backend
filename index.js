const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = 3000;

// 👇👇👇 تأكد من وجود رابط قاعدة البيانات الخاص بك هنا
const MONGO_URI = 'mongodb+srv://admin:filo1234$$1234@filocluster.xsiuhaq.mongodb.net/?retryWrites=true&w=majority&appName=FiloCluster';

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ تم الاتصال بـ MongoDB بنجاح!'))
    .catch(err => console.error('❌ فشل الاتصال:', err));

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
// ----------------------------------------------------
// 1. تصميم الجداول (Schemas)
// ----------------------------------------------------

// جدول الطلبات
const orderSchema = new mongoose.Schema({
    items: Array,        
    totalPrice: Number, 
    date: String,
    tableNumber: String // 👈 أضفنا هذا الحقل الجديد
});
const Order = mongoose.model('Order', orderSchema);

// 👇 جدول قائمة الطعام (الجديد)
const menuSchema = new mongoose.Schema({
    id: String,
    title: String,
    description: String,
    price: Number,
    imageUrl: String,
    category: String
});
const Menu = mongoose.model('Menu', menuSchema);

// ----------------------------------------------------
// 2. البيانات الأولية (سنستخدمها مرة واحدة للتعبئة)
// ----------------------------------------------------
const initialMenu = [
    { id: "1", title: "برجر كلاسيك", price: 8.5, imageUrl: "https://images.unsplash.com/photo-1568901346375-23c9450c58cd?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80", description: "شريحة لحم بقري مشوية مع جبنة شيدر وخس طازج.", category: "رئيسية" },
    { id: "2", title: "بطاطس ذهبية", price: 3.5, imageUrl: "https://images.unsplash.com/photo-1573080496987-a199f8cd75c5?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80", description: "بطاطس مقلية مقرمشة مع خلطة بهارات سرية.", category: "مقبلات" },
    { id: "3", title: "بيتزا مارغريتا", price: 10.0, imageUrl: "https://images.unsplash.com/photo-1574071318508-1cdbab80d002?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80", description: "صلصة طماطم إيطالية، جبنة موزاريلا، وريحان طازج.", category: "رئيسية" }
];

// ----------------------------------------------------
// 3. نقاط الاتصال (APIs)
// ----------------------------------------------------

app.get('/', (req, res) => {
    res.send('Filo Server is Running!');
});

// 👇 الرابط السحري: اضغط عليه مرة واحدة لملء قاعدة البيانات
app.get('/api/fill-menu', async (req, res) => {
    try {
        // نتحقق أولاً إذا كانت القائمة فارغة
        const count = await Menu.countDocuments();
        if (count === 0) {
            await Menu.insertMany(initialMenu);
            res.send("✅ تمت إضافة الأصناف إلى قاعدة البيانات بنجاح!");
        } else {
            res.send("⚠️ الأصناف موجودة بالفعل، لم تتم إضافة شيء.");
        }
    } catch (error) {
        res.status(500).send("حدث خطأ: " + error.message);
    }
});

// جلب القائمة (الآن نجلبها من قاعدة البيانات وليس المصفوفة)
app.get('/api/menu', async (req, res) => {
    try {
        const menu = await Menu.find(); // هات كل شيء من جدول Menu
        res.json(menu);
    } catch (error) {
        res.status(500).json({ error: "فشل جلب القائمة" });
    }
});

// جلب الطلبات
app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find(); 
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: "فشل جلب الطلبات" });
    }
});

// حفظ طلب جديد
app.post('/api/orders', async (req, res) => {
    const orderData = req.body;
    try {
        const newOrder = new Order(orderData);
        await newOrder.save();
        console.log("تم حفظ الطلب! 💾");
        res.status(201).json({ message: "تم الحفظ بنجاح!" });
    } catch (error) {
        res.status(500).json({ error: "فشل حفظ الطلب" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ السيرفر يعمل على: http://localhost:${PORT}`);
});