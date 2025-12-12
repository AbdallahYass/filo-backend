/**
 * ============================================================
 * SCRIPT: seed_vendors.js
 * وظيفة: حذف جميع التجار الوهميين القدامى وإضافة 50 متجر جديد للاختبار
 * ============================================================
 */
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { faker } = require('@faker-js/faker'); 

// ------------------------------------------------------------
// 1. CONFIGURATION & MODELS
// ------------------------------------------------------------
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost/filo_super_app';

// يجب أن تكون هذه النماذج مطابقة لما هو موجود في server.js (مع إضافة حقل isMock)
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    name: String,
    role: { type: String, default: 'customer', enum: ['customer', 'admin', 'vendor', 'driver'] },
    isVerified: { type: Boolean, default: false },
    phone: { type: String },
    // حقول الفرز والتقييم
    averageRating: { type: Number, default: 0 },
    ordersCount: { type: Number, default: 0 },
    reviewsCount: { type: Number, default: 0 },
    isMock: { type: Boolean, default: false }, // لتمييز التجار الوهميين
    savedAddresses: [{}],
    driverStatus: {},
    storeInfo: {
        storeName: String,
        description: String,
        logoUrl: String,
        isOpen: { type: Boolean, default: true },
        // ساعات العمل لدعم الحالة الذكية في Flutter
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


// ------------------------------------------------------------
// 2. CLEANUP FUNCTION (دالة التنظيف)
// ------------------------------------------------------------

async function cleanupOldVendors() {
    // التنظيف: حذف كل المستخدمين الذين يحملون دور 'vendor'
    const filter = { role: 'vendor' }; 
    const result = await User.deleteMany(filter);
    console.log(`\n🧹 Cleanup Complete: Deleted ${result.deletedCount} old 'vendor' entries.`);
}


// ------------------------------------------------------------
// 3. MAIN SEEDING FUNCTION
// ------------------------------------------------------------

async function seedVendors() {
    console.log('Connecting to MongoDB...');
    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB!');

        // 🔥🔥 الخطوة الأولى: التنظيف قبل التوليد 🔥🔥
        await cleanupOldVendors(); 

        const vendorsToCreate = 50;
        const vendorData = [];
        const hashedPassword = await bcrypt.hash('password123', 10); 

        const categories = [
            'fastfood', 'coffee', 'sweets', 'groceries', 'seafood', 'asian', 'burgers', 'pizza'
        ];

        for (let i = 1; i <= vendorsToCreate; i++) {
            const storeName = faker.company.name() + ' Store';
            const email = `vendor${i}@testfilo.com`;
            
            // 🔥 قيم عشوائية للفرز 🔥
            const rating = parseFloat(faker.number.float({ min: 3.0, max: 5.0, precision: 0.1 }).toFixed(1));
            const orders = faker.number.int({ min: 50, max: 3000 });
            
            // 🐛 إصلاح خطأ Max < Min للمراجعات 🐛
            const minReviews = 20; 
            const maxReviewsCalculated = Math.floor(orders / 5); 
            const maxReviews = Math.max(minReviews + 5, maxReviewsCalculated); 
            const reviews = faker.number.int({ 
                min: minReviews, 
                max: maxReviews 
            });
            // -------------------------------------------------------
            
            // 🔥 توليد ساعات عمل عشوائية (HH:MM) 🔥
            const openHour = faker.number.int({ min: 6, max: 10 }).toString().padStart(2, '0');
            const closeHour = faker.number.int({ min: 18, max: 23 }).toString().padStart(2, '0');
            const minute = faker.helpers.arrayElement(['00', '30']);
            const openTimeStr = `${openHour}:${minute}`;
            const closeTimeStr = `${closeHour}:${minute}`;
            
            const logoUrl = faker.image.url({width: 60, height: 60, category: 'food', random: true});


            vendorData.push({
                email: email,
                password: hashedPassword,
                name: storeName,
                role: 'vendor',
                isVerified: true,
                isMock: true, 
                averageRating: rating,
                ordersCount: orders,
                reviewsCount: reviews, 
                storeInfo: {
                    storeName: storeName,
                    description: `متجر متخصص في ${faker.helpers.arrayElement(categories)} ويقدم خدمة ممتازة.`,
                    logoUrl: logoUrl,
                    isOpen: faker.datatype.boolean(0.8), 
                    openTime: openTimeStr, 
                    closeTime: closeTimeStr, 
                }
            });
        }

        // 4. إضافة البيانات الجديدة
        let insertedCount = 0;
        for (const data of vendorData) {
            try {
                // استخدام findOneAndUpdate مع upsert: true لتجنب تكرار الإدخال
                await User.findOneAndUpdate(
                    { email: data.email },
                    data,
                    { upsert: true, new: true, runValidators: true }
                );
                insertedCount++;
            } catch (error) {
                if (error.code !== 11000) { 
                    console.error(`Error inserting ${data.email}:`, error.message);
                }
            }
        }

        console.log(`\n✅ Seeding Complete: ${insertedCount} new or updated vendors added.`);

    } catch (error) {
        console.error('❌ MongoDB Connection/Seeding Error:', error);
    } finally {
        await mongoose.disconnect();
        console.log('👋 Disconnected from MongoDB.');
    }
}

seedVendors();