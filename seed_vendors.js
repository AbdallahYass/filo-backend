/**
 * ============================================================
 * SCRIPT: seed_menu_items.js
 * وظيفة: إضافة 50 صنف (Menu Items) لكل تاجر موجود في MongoDB.
 * ============================================================
 */
require('dotenv').config();
const mongoose = require('mongoose');
const { faker } = require('@faker-js/faker'); // تأكد من تثبيت هذه الحزمة

// ------------------------------------------------------------
// 1. CONFIGURATION & MODELS
// ------------------------------------------------------------
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost/filo_super_app';

// ⚠️ يجب التأكد من تطابق المخططات مع server.js
const User = mongoose.model('User', new mongoose.Schema({ /* Minimal schema for query */ }, { strict: false }));

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


// ------------------------------------------------------------
// 2. MAIN SEEDING FUNCTION
// ------------------------------------------------------------

async function seedMenuItems() {
    console.log('Connecting to MongoDB...');
    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB!');

        // 1. جلب جميع التجار (فقط الـ IDs)
        const vendors = await User.find({ role: 'vendor' }, '_id storeInfo');
        
        if (vendors.length === 0) {
            console.log('🛑 No vendors found in the database. Please run seed_vendors.js first.');
            return;
        }

        console.log(`\nFound ${vendors.length} vendors. Starting to insert 50 items for each...`);

        let totalItemsInserted = 0;
        const categories = ['Main Dish', 'Appetizer', 'Dessert', 'Drinks', 'Promotions'];

        for (const vendor of vendors) {
            const vendorId = vendor._id;
            const vendorName = vendor.storeInfo?.storeName || 'Unknown Vendor';
            const itemsToCreate = 50;
            const menuItemsData = [];

            for (let i = 0; i < itemsToCreate; i++) {
                const title = faker.commerce.productName();
                
                menuItemsData.push({
                    vendorId: vendorId,
                    title: title,
                    description: faker.commerce.productDescription(),
                    price: faker.number.float({ min: 5, max: 50, precision: 0.5 }),
                    imageUrl: faker.image.url({ width: 400, height: 300, category: 'food', random: true }),
                    category: faker.helpers.arrayElement(categories),
                    isAvailable: faker.datatype.boolean(0.9), // 90% متاح
                });
            }

            // إدراج جميع الأصناف لهذا التاجر
            const result = await Menu.insertMany(menuItemsData);
            totalItemsInserted += result.length;
            console.log(`   -> Inserted ${result.length} items for: ${vendorName}`);
        }

        console.log(`\n✅ Seeding Complete! Total items inserted: ${totalItemsInserted}`);

    } catch (error) {
        console.error('❌ Database/Seeding Error:', error);
    } finally {
        await mongoose.disconnect();
        console.log('👋 Disconnected from MongoDB.');
    }
}

seedMenuItems();