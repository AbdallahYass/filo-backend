const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    try {
        const JWT_SECRET = process.env.JWT_SECRET;
        
        // التحقق من وجود رأس التخويل (Authorization Header)
        if (!req.headers.authorization) {
            return res.status(401).json({ message: 'Authentication failed: Missing Authorization Header' });
        }
        
        // استخراج الرمز (عادةً يكون بتنسيق: Bearer <token>)
        const token = req.headers.authorization.split(' ')[1]; 
        
        if (!token) {
            return res.status(401).json({ message: 'Authentication failed: Token format invalid' });
        }

        // التحقق من الرمز باستخدام المفتاح السري
        const decodedToken = jwt.verify(token, JWT_SECRET);
        
        // إضافة بيانات المستخدم إلى كائن الطلب (Request Object)
        req.userData = { userId: decodedToken.userId };
        
        // المتابعة إلى الدالة التالية (Route Handler)
        next();
        
    } catch (error) {
        // إذا فشل التحقق (مثل انتهاء الصلاحية أو توقيع غير صحيح)
        return res.status(401).json({ message: 'Authentication failed: Invalid or expired token' });
    }
};