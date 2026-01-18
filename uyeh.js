// ========== UYEH TECH BACKEND SERVER v6.0 - PART 1 OF 6 ==========
// COMPLETE ADMIN DASHBOARD SYSTEM WITH DOWNLOAD LINKS
// Setup, Configuration, and Core Schemas
// Admin Email: uyehtech@gmail.com

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();
const app = express();

// ========== MIDDLEWARE ==========
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ========== CONFIGURATION ==========
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const TERMII_API_KEY = process.env.TERMII_API_KEY;
const TERMII_EMAIL_CONFIG_ID = '4de5e6c7-415f-43f1-812a-0bbbb213c126';
const TERMII_BASE_URL = 'https://v3.api.termii.com';
const TERMII_SENDER_EMAIL = process.env.TERMII_SENDER_EMAIL || 'noreply@uyehtech.com';
const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY;
const ADMIN_EMAIL = 'uyehtech@gmail.com';
const PORT = process.env.PORT || 3000;

// ========== STARTUP VALIDATION ==========
console.log('\n╔═══════════════════════════════════════════════════════════════╗');
console.log('║     UYEH TECH SERVER v6.0 - ADMIN DASHBOARD + DOWNLOADS     ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');
console.log('📋 Configuration Status:');
console.log('  MongoDB:', MONGO_URI ? '✅ Connected' : '❌ Missing');
console.log('  JWT Secret:', JWT_SECRET ? '✅ Configured' : '❌ Missing');
console.log('  Termii API:', TERMII_API_KEY ? '✅ Configured' : '❌ Missing');
console.log('  Flutterwave:', FLUTTERWAVE_SECRET_KEY ? '✅ Configured' : '❌ Missing');
console.log('  Admin Email:', ADMIN_EMAIL);
console.log('\n🎉 NEW in v6.0: Download Links + Admin Dashboard\n');

// ========== CONNECT TO MONGODB ==========
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ========== USER SCHEMA ==========
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  phone: String,
  country: String,
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  profileImage: String,
  bio: String,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: String,
  notificationPreferences: {
    email: { type: Boolean, default: true },
    orders: { type: Boolean, default: true },
    marketing: { type: Boolean, default: false }
  },
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  banReason: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  if (this.email.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
    this.isAdmin = true;
  }
  next();
});

const User = mongoose.model('User', userSchema);

// ========== ORDER SCHEMA ==========
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderReference: { type: String, required: true, unique: true },
  items: [{
    id: String,
    title: String,
    category: String,
    price: Number,
    icon: String
  }],
  subtotal: { type: Number, required: true },
  discount: { type: Number, default: 0 },
  total: { type: Number, required: true },
  couponCode: String,
  customerInfo: {
    name: String,
    email: String,
    phone: String,
    country: String
  },
  paymentInfo: {
    method: { type: String, default: 'flutterwave' },
    transactionId: String,
    transactionRef: String,
    status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending' },
    paidAt: Date
  },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending' },
  downloadLinks: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

orderSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Order = mongoose.model('Order', orderSchema);

// ========== PAYMENT METHOD SCHEMA ==========
const paymentMethodSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true, enum: ['Visa', 'Mastercard', 'American Express', 'Discover', 'Credit Card'] },
  lastFour: { type: String, required: true },
  expiry: { type: String, required: true },
  cardholderName: { type: String, required: true },
  isDefault: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const PaymentMethod = mongoose.model('PaymentMethod', paymentMethodSchema);

// ========== COUPON SCHEMA ==========
const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true, trim: true },
  discount: { type: Number, required: true, min: 0 },
  type: { type: String, enum: ['percentage', 'fixed'], required: true },
  isActive: { type: Boolean, default: true },
  usageLimit: { type: Number, default: null },
  usageCount: { type: Number, default: 0 },
  expiresAt: { type: Date, default: null },
  minPurchaseAmount: { type: Number, default: 0 },
  description: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

couponSchema.index({ code: 1 });

const Coupon = mongoose.model('Coupon', couponSchema);

// ========== PRODUCT SCHEMA (WITH DOWNLOAD LINKS) ==========
const productSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  comparePrice: { type: Number, default: 0 },
  icon: String,
  image: String,
  images: [String],
  features: [String],
  downloadLink: { type: String, default: '' }, // DOWNLOAD LINK FIELD
  fileSize: String,
  version: String,
  requirements: [String],
  isActive: { type: Boolean, default: true },
  isFeatured: { type: Boolean, default: false },
  stock: { type: Number, default: 999 },
  soldCount: { type: Number, default: 0 },
  rating: { type: Number, default: 0, min: 0, max: 5 },
  reviewCount: { type: Number, default: 0 },
  tags: [String],
  seoTitle: String,
  seoDescription: String,
  seoKeywords: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

productSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Product = mongoose.model('Product', productSchema);

// ========== DOWNLOAD TRACKING SCHEMA (NEW) ==========
const downloadSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  downloadedAt: { type: Date, default: Date.now },
  ipAddress: String,
  userAgent: String
});

downloadSchema.index({ userId: 1, productId: 1 });
downloadSchema.index({ downloadedAt: -1 });

const Download = mongoose.model('Download', downloadSchema);

// ========== BLOG POST SCHEMA ==========
const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
  excerpt: { type: String, required: true, maxlength: 300 },
  content: { type: String, required: true },
  featuredImage: { type: String, default: '' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  category: { type: String, required: true, enum: ['Technology', 'Business', 'Tutorial', 'News', 'Product', 'Design', 'Marketing', 'Development', 'Other'] },
  tags: [{ type: String, trim: true }],
  status: { type: String, enum: ['draft', 'published', 'archived'], default: 'draft' },
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    userName: String,
    userEmail: String,
    comment: String,
    createdAt: { type: Date, default: Date.now },
    approved: { type: Boolean, default: false }
  }],
  metaTitle: String,
  metaDescription: String,
  metaKeywords: [String],
  publishedAt: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

blogPostSchema.index({ slug: 1 });
blogPostSchema.index({ status: 1 });
blogPostSchema.index({ category: 1 });
blogPostSchema.index({ publishedAt: -1 });

blogPostSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  if (!this.slug && this.title) {
    this.slug = this.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  }
  if (this.status === 'published' && !this.publishedAt) {
    this.publishedAt = Date.now();
  }
  next();
});

const BlogPost = mongoose.model('BlogPost', blogPostSchema);

// ========== SYSTEM SETTINGS SCHEMA ==========
const systemSettingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'UYEH TECH' },
  siteDescription: String,
  siteUrl: String,
  contactEmail: String,
  supportEmail: String,
  phone: String,
  address: String,
  logo: String,
  favicon: String,
  socialMedia: {
    facebook: String,
    twitter: String,
    instagram: String,
    linkedin: String,
    youtube: String
  },
  emailSettings: {
    smtpHost: String,
    smtpPort: Number,
    smtpUser: String,
    smtpPassword: String,
    fromEmail: String,
    fromName: String
  },
  paymentSettings: {
    flutterwaveEnabled: { type: Boolean, default: true },
    paystackEnabled: { type: Boolean, default: false },
    stripeEnabled: { type: Boolean, default: false }
  },
  maintenanceMode: { type: Boolean, default: false },
  maintenanceMessage: String,
  allowRegistration: { type: Boolean, default: true },
  requireEmailVerification: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ========== ANALYTICS SCHEMA ==========
const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true, index: true },
  pageViews: { type: Number, default: 0 },
  uniqueVisitors: { type: Number, default: 0 },
  newUsers: { type: Number, default: 0 },
  orders: { type: Number, default: 0 },
  revenue: { type: Number, default: 0 },
  downloads: { type: Number, default: 0 },
  topProducts: [{
    productId: String,
    productName: String,
    sales: Number
  }],
  topPages: [{
    page: String,
    views: Number
  }],
  createdAt: { type: Date, default: Date.now }
});

analyticsSchema.index({ date: -1 });

const Analytics = mongoose.model('Analytics', analyticsSchema);

// ========== EMAIL OTP STORAGE ==========
const otpStore = new Map();

// ========== UTILITY FUNCTIONS ==========
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateSlug(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

console.log('✅ Part 1 loaded: All Schemas configured with Download support');
console.log('📦 Models: User, Order, Coupon, Product, Download, Blog, Analytics, Settings');

// ========== END OF PART 1 ==========
// Continue to Part 2 for Email Functions and Auth Routes// ========== UYEH TECH SERVER v6.0 - PART 2 OF 6 ==========
// Email Functions and Authentication Routes
// COPY THIS AFTER PART 1

// ========== SEND EMAIL WITH OTP ==========
async function sendEmailOTP(to, otp, purpose = 'verification') {
  try {
    console.log(`\n📧 Sending ${purpose} OTP to ${to}`);
    console.log(`🔑 OTP Code: ${otp}`);
   
    if (!TERMII_API_KEY) {
      console.error('❌ TERMII_API_KEY not configured');
      console.log(`📧 OTP for ${to}: ${otp}`);
      return { success: true, method: 'console_log', otp };
    }
   
    let subject, emailBody;
   
    if (purpose === 'verification') {
      subject = 'Verify Your Email - UYEH TECH';
      emailBody = `Your UYEH TECH verification code is: ${otp}\n\nValid for 10 minutes.\n\nBest regards,\nUYEH TECH Team`;
    } else if (purpose === 'password-reset') {
      subject = 'Password Reset Code - UYEH TECH';
      emailBody = `Your password reset code is: ${otp}\n\nValid for 10 minutes.\n\nBest regards,\nUYEH TECH Team`;
    }

    try {
      const termiiPayload = {
        api_key: TERMII_API_KEY,
        to: to,
        from: TERMII_SENDER_EMAIL,
        subject: subject,
        body: emailBody,
        email_configuration_id: TERMII_EMAIL_CONFIG_ID
      };

      const response = await axios.post(`${TERMII_BASE_URL}/api/send-mail`, termiiPayload, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 15000
      });
     
      console.log('✅ Email sent via Termii');
      return { success: true, method: 'termii_email', data: response.data };
     
    } catch (termiiError) {
      console.error('❌ Termii error:', termiiError.message);
      console.log(`📧 OTP for ${to}: ${otp}`);
      return { success: true, method: 'console_log', otp };
    }
   
  } catch (error) {
    console.error('❌ Send Email Error:', error);
    console.log(`📧 OTP for ${to}: ${otp}`);
    return { success: false, error: error.message, otp };
  }
}

// ========== SEND ORDER CONFIRMATION WITH DOWNLOAD LINKS ==========
async function sendOrderConfirmationEmail(to, orderData) {
  try {
    if (!TERMII_API_KEY) {
      console.log(`📧 Order confirmation for ${to}: ${orderData.orderReference}`);
      return { success: true, method: 'console_log' };
    }
   
    const subject = `Order Confirmation - ${orderData.orderReference}`;
    const emailBody = `
Thank you for your purchase!

Order Reference: ${orderData.orderReference}
Total Amount: $${orderData.total}

Items: ${orderData.items.map(i => `\n- ${i.title} ($${i.price})`).join('')}

Your digital products are ready for download!
Access your downloads from your account dashboard.

Best regards,
UYEH TECH Team
    `.trim();

    try {
      await axios.post(`${TERMII_BASE_URL}/api/send-mail`, {
        api_key: TERMII_API_KEY,
        to: to,
        from: TERMII_SENDER_EMAIL,
        subject: subject,
        body: emailBody,
        email_configuration_id: TERMII_EMAIL_CONFIG_ID
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 15000
      });
     
      console.log('✅ Order confirmation sent');
      return { success: true, method: 'termii_email' };
     
    } catch (error) {
      console.log(`📧 Order confirmation logged: ${orderData.orderReference}`);
      return { success: true, method: 'console_log' };
    }
   
  } catch (error) {
    console.error('❌ Send confirmation error:', error);
    return { success: false, error: error.message };
  }
}

// ========== MIDDLEWARE: AUTHENTICATE TOKEN ==========
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// ========== MIDDLEWARE: AUTHENTICATE ADMIN ==========
async function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }

    try {
      const user = await User.findById(decoded.userId);
      
      if (!user || !user.isAdmin) {
        return res.status(403).json({ 
          success: false, 
          message: 'Admin access required',
          isAdmin: false 
        });
      }

      req.user = decoded;
      req.adminUser = user;
      next();
    } catch (error) {
      return res.status(500).json({ success: false, message: 'Auth failed' });
    }
  });
}

// ========== ROUTES ==========
app.get('/', (req, res) => {
  res.json({
    message: '🚀 UYEH TECH API v6.0 - Admin Dashboard + Downloads',
    version: '6.0.0',
    status: 'active',
    adminEmail: ADMIN_EMAIL,
    features: [
      '✅ Complete Admin Dashboard',
      '✅ Download Link Management',
      '✅ Download Tracking',
      '✅ Analytics System',
      '✅ User Management',
      '✅ Order Management',
      '✅ Coupon System',
      '✅ Blog Management',
      '✅ Product Management',
      '✅ System Settings'
    ]
  });
});

// ========== AUTH ROUTES ==========
app.post('/api/auth/send-email-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const otp = generateOTP();
   
    otpStore.set(cleanEmail, {
      code: otp,
      expires: Date.now() + 10 * 60 * 1000,
      attempts: 0
    });

    await sendEmailOTP(cleanEmail, otp, 'verification');

    res.json({
      success: true,
      message: 'Verification code sent',
      email: cleanEmail,
      ...(process.env.NODE_ENV === 'development' && { debug_otp: otp })
    });
  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ success: false, message: 'Failed to send code' });
  }
});

app.post('/api/auth/verify-email-otp', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'Email and code required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const storedOTP = otpStore.get(cleanEmail);

    if (!storedOTP) {
      return res.status(400).json({ success: false, message: 'No code found' });
    }

    if (Date.now() > storedOTP.expires) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ success: false, message: 'Code expired' });
    }

    if (storedOTP.attempts >= 5) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ success: false, message: 'Too many attempts' });
    }

    if (storedOTP.code !== code) {
      storedOTP.attempts += 1;
      otpStore.set(cleanEmail, storedOTP);
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    otpStore.delete(cleanEmail);
    res.json({ success: true, message: 'Email verified' });
  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, password, emailVerified } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    if (!emailVerified) {
      return res.status(400).json({ success: false, message: 'Verify email first' });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be 8+ characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      emailVerified: true
    });

    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({ success: false, message: 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (user.isBanned) {
      return res.status(403).json({ success: false, message: `Account banned: ${user.banReason || 'Contact support'}` });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({ success: true, message: 'If account exists, code sent' });
    }

    const resetOTP = generateOTP();
   
    otpStore.set(`reset_${email.toLowerCase()}`, {
      code: resetOTP,
      expires: Date.now() + 10 * 60 * 1000,
      attempts: 0
    });

    await sendEmailOTP(email, resetOTP, 'password-reset');

    res.json({ success: true, message: 'Reset code sent' });
  } catch (error) {
    console.error('❌ Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Request failed' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be 8+ characters' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const storedOTP = otpStore.get(`reset_${cleanEmail}`);

    if (!storedOTP || Date.now() > storedOTP.expires) {
      return res.status(400).json({ success: false, message: 'Invalid or expired code' });
    }

    if (storedOTP.code !== code) {
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    otpStore.delete(`reset_${cleanEmail}`);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ success: false, message: 'Reset failed' });
  }
});

// ========== ADMIN AUTH ==========
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admin access required', isAdmin: false });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      isAdmin: true,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email
      }
    });
  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.get('/api/auth/admin/verify', authenticateAdmin, async (req, res) => {
  res.json({
    success: true,
    isAdmin: true,
    user: {
      id: req.adminUser._id,
      name: req.adminUser.fullName,
      email: req.adminUser.email
    }
  });
});

// ========== USER PROFILE ==========
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -twoFactorSecret');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        phone: user.phone,
        country: user.country,
        profileImage: user.profileImage,
        bio: user.bio,
        isAdmin: user.isAdmin,
        isBanned: user.isBanned,
        emailVerified: user.emailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('❌ Profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, bio, profileImage, phone, country } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (fullName) user.fullName = fullName;
    if (bio !== undefined) user.bio = bio;
    if (profileImage) user.profileImage = profileImage;
    if (phone !== undefined) user.phone = phone;
    if (country) user.country = country;

    await user.save();

    res.json({
      success: true,
      message: 'Profile updated',
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        phone: user.phone,
        country: user.country,
        profileImage: user.profileImage,
        bio: user.bio
      }
    });
  } catch (error) {
    console.error('❌ Update profile error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

console.log('✅ Part 2 loaded: Auth & User routes configured');

// ========== END OF PART 2 ==========
// Continue to Part 3 for Admin Dashboard & Analytics// ========== UYEH TECH SERVER v6.0 - PART 3 OF 6 ==========
// Admin Dashboard, Analytics & User Management
// COPY THIS AFTER PART 2

// ========== ADMIN DASHBOARD OVERVIEW ==========
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalProducts = await Product.countDocuments();
    const totalBlogPosts = await BlogPost.countDocuments();
    const publishedPosts = await BlogPost.countDocuments({ status: 'published' });
    const activeCoupons = await Coupon.countDocuments({ isActive: true });
    const totalDownloads = await Download.countDocuments();
    
    // Revenue calculation
    const revenueData = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    const totalRevenue = revenueData[0]?.total || 0;

    // Recent orders (last 7 days)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentOrders = await Order.countDocuments({ createdAt: { $gte: sevenDaysAgo } });
    const recentRevenue = await Order.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: sevenDaysAgo } } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    const recentDownloads = await Download.countDocuments({ downloadedAt: { $gte: sevenDaysAgo } });

    // New users (last 7 days)
    const newUsers = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });

    // Top selling products
    const topProducts = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $unwind: '$items' },
      { $group: { _id: '$items.title', count: { $sum: 1 }, revenue: { $sum: '$items.price' } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Recent orders list
    const recentOrdersList = await Order.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'fullName email');

    res.json({
      success: true,
      dashboard: {
        overview: {
          totalUsers,
          totalOrders,
          totalProducts,
          totalRevenue,
          activeCoupons,
          totalBlogPosts,
          publishedPosts,
          totalDownloads
        },
        recentStats: {
          newUsers,
          recentOrders,
          recentRevenue: recentRevenue[0]?.total || 0,
          recentDownloads
        },
        topProducts,
        recentOrdersList
      }
    });
  } catch (error) {
    console.error('❌ Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch dashboard' });
  }
});

// ========== ADMIN ANALYTICS ==========
app.get('/api/admin/analytics', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    
    let startDate;
    const now = new Date();
    
    switch(period) {
      case '24h':
        startDate = new Date(now - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        startDate = new Date(now - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
    }

    // Daily revenue and orders
    const dailyStats = await Order.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
        orders: { $sum: 1 },
        revenue: { $sum: '$total' },
        completed: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } }
      }},
      { $sort: { _id: 1 } }
    ]);

    // User growth
    const userGrowth = await User.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
        count: { $sum: 1 }
      }},
      { $sort: { _id: 1 } }
    ]);

    // Download trends
    const downloadTrends = await Download.aggregate([
      { $match: { downloadedAt: { $gte: startDate } } },
      { $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$downloadedAt' } },
        count: { $sum: 1 }
      }},
      { $sort: { _id: 1 } }
    ]);

    // Product performance
    const productPerformance = await Order.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: startDate } } },
      { $unwind: '$items' },
      { $group: {
        _id: '$items.title',
        sales: { $sum: 1 },
        revenue: { $sum: '$items.price' }
      }},
      { $sort: { revenue: -1 } },
      { $limit: 10 }
    ]);

    // Category distribution
    const categoryStats = await Order.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: startDate } } },
      { $unwind: '$items' },
      { $group: {
        _id: '$items.category',
        count: { $sum: 1 },
        revenue: { $sum: '$items.price' }
      }},
      { $sort: { revenue: -1 } }
    ]);

    res.json({
      success: true,
      analytics: {
        period,
        dailyStats,
        userGrowth,
        downloadTrends,
        productPerformance,
        categoryStats
      }
    });
  } catch (error) {
    console.error('❌ Analytics error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch analytics' });
  }
});

// ========== USER MANAGEMENT ==========
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = 'all' } = req.query;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'banned') {
      query.isBanned = true;
    } else if (status === 'admin') {
      query.isAdmin = true;
    } else if (status === 'active') {
      query.isBanned = false;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const users = await User.find(query)
      .select('-password -twoFactorSecret')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await User.countDocuments(query);

    // Add order count and download count for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const orderCount = await Order.countDocuments({ userId: user._id });
        const downloadCount = await Download.countDocuments({ userId: user._id });
        const totalSpent = await Order.aggregate([
          { $match: { userId: user._id, status: 'completed' } },
          { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        return {
          ...user.toObject(),
          orderCount,
          downloadCount,
          totalSpent: totalSpent[0]?.total || 0
        };
      })
    );

    res.json({
      success: true,
      users: usersWithStats,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

app.get('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password -twoFactorSecret');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const orders = await Order.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
    const orderCount = await Order.countDocuments({ userId: user._id });
    const downloadCount = await Download.countDocuments({ userId: user._id });
    const totalSpent = await Order.aggregate([
      { $match: { userId: user._id, status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);

    res.json({
      success: true,
      user: {
        ...user.toObject(),
        orderCount,
        downloadCount,
        totalSpent: totalSpent[0]?.total || 0,
        recentOrders: orders
      }
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user' });
  }
});

app.put('/api/admin/users/:userId/ban', authenticateAdmin, async (req, res) => {
  try {
    const { isBanned, banReason } = req.body;
    
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.isAdmin) {
      return res.status(400).json({ success: false, message: 'Cannot ban admin' });
    }

    user.isBanned = isBanned;
    user.banReason = banReason || '';
    await user.save();

    res.json({
      success: true,
      message: isBanned ? 'User banned' : 'User unbanned',
      user: {
        id: user._id,
        name: user.fullName,
        isBanned: user.isBanned
      }
    });
  } catch (error) {
    console.error('❌ Ban user error:', error);
    res.status(500).json({ success: false, message: 'Failed to update user' });
  }
});

app.delete('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;

    if (userId === req.user.userId) {
      return res.status(400).json({ success: false, message: 'Cannot delete own account' });
    }

    const user = await User.findById(userId);
    if (user && user.isAdmin) {
      return res.status(400).json({ success: false, message: 'Cannot delete admin account' });
    }

    await Order.deleteMany({ userId });
    await PaymentMethod.deleteMany({ userId });
    await Download.deleteMany({ userId });
    await User.findByIdAndDelete(userId);

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('❌ Delete user error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// ========== ORDER MANAGEMENT ==========
app.get('/api/admin/orders', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = 'all', search = '' } = req.query;
    
    let query = {};
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    if (search) {
      query.$or = [
        { orderReference: { $regex: search, $options: 'i' } },
        { 'customerInfo.email': { $regex: search, $options: 'i' } },
        { 'customerInfo.name': { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const orders = await Order.find(query)
      .populate('userId', 'fullName email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await Order.countDocuments(query);

    res.json({
      success: true,
      orders: orders,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Get orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch orders' });
  }
});

app.get('/api/admin/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.orderId).populate('userId', 'fullName email phone');
    
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    res.json({
      success: true,
      order: order
    });
  } catch (error) {
    console.error('❌ Get order error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch order' });
  }
});

app.put('/api/admin/orders/:orderId/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['pending', 'completed', 'failed', 'refunded'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const order = await Order.findById(req.params.orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    order.status = status;
    await order.save();

    res.json({
      success: true,
      message: 'Order status updated',
      order: order
    });
  } catch (error) {
    console.error('❌ Update order error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.orderId);
    
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (error) {
    console.error('❌ Delete order error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// ========== USER ORDERS ==========
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId }).sort({ createdAt: -1 });

    res.json({
      success: true,
      orders: orders,
      count: orders.length
    });
  } catch (error) {
    console.error('❌ Get orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch orders' });
  }
});

// ========== CREATE ORDER WITH COUPON ==========
app.post('/api/orders/create-with-coupon', authenticateToken, async (req, res) => {
  try {
    const { items, subtotal, couponCode, customerInfo, orderReference } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Order must have items' });
    }

    if (!subtotal || !customerInfo) {
      return res.status(400).json({ success: false, message: 'Missing order data' });
    }

    let discount = 0;
    let finalTotal = subtotal;
    let isFree = false;

    if (couponCode) {
      const cleanCode = couponCode.trim().toUpperCase();
      const coupon = await Coupon.findOne({ code: cleanCode, isActive: true });

      if (coupon) {
        if (coupon.type === 'percentage') {
          discount = (subtotal * coupon.discount) / 100;
        } else {
          discount = coupon.discount;
        }

        discount = Math.min(discount, subtotal);
        finalTotal = Math.max(0, subtotal - discount);
        isFree = finalTotal === 0;

        coupon.usageCount += 1;
        await coupon.save();
      }
    }

    const order = new Order({
      userId: req.user.userId,
      orderReference: orderReference || 'UYEH-' + Date.now(),
      items,
      subtotal,
      discount,
      total: finalTotal,
      couponCode: couponCode || null,
      customerInfo,
      status: isFree ? 'completed' : 'pending',
      paymentInfo: {
        method: isFree ? 'coupon' : 'flutterwave',
        status: isFree ? 'successful' : 'pending',
        paidAt: isFree ? new Date() : null
      }
    });

    await order.save();

    if (isFree) {
      await sendOrderConfirmationEmail(customerInfo.email, order);
    }

    res.status(201).json({
      success: true,
      message: isFree ? '🎉 Order completed!' : 'Order created',
      order: {
        _id: order._id,
        orderReference: order.orderReference,
        total: order.total,
        discount: order.discount,
        status: order.status,
        items: order.items,
        isFree: isFree,
        paymentRequired: !isFree
      }
    });

  } catch (error) {
    console.error('❌ Create order error:', error);
    res.status(500).json({ success: false, message: 'Order creation failed' });
  }
});

// ========== VERIFY PAYMENT ==========
app.post('/api/orders/verify-payment', authenticateToken, async (req, res) => {
  try {
    const { transactionId, orderId } = req.body;

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    const response = await axios.get(
      `https://api.flutterwave.com/v3/transactions/${transactionId}/verify`,
      { headers: { 'Authorization': `Bearer ${FLUTTERWAVE_SECRET_KEY}` } }
    );

    const paymentData = response.data.data;

    if (paymentData.status === 'successful' && paymentData.amount >= order.total) {
      order.status = 'completed';
      order.paymentInfo.transactionId = transactionId;
      order.paymentInfo.transactionRef = paymentData.tx_ref;
      order.paymentInfo.status = 'successful';
      order.paymentInfo.paidAt = new Date();
      await order.save();

      await sendOrderConfirmationEmail(order.customerInfo.email, order);

      res.json({
        success: true,
        message: 'Payment verified',
        order: order
      });
    } else {
      order.status = 'failed';
      order.paymentInfo.status = 'failed';
      await order.save();

      res.status(400).json({ success: false, message: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('❌ Verify payment error:', error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

console.log('✅ Part 3 loaded: Dashboard, Analytics, Users & Orders configured');

// ========== END OF PART 3 ==========
// Continue to Part 4 for Download Links & Product Management// ========== UYEH TECH SERVER v6.0 - PART 4 OF 6 ==========
// Download Links, Product Management & Coupon System
// COPY THIS AFTER PART 3

// ========== DOWNLOAD LINK SYSTEM ==========

// Get orders with full product details including download links
app.get('/api/orders/detailed', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });

    // Enhance orders with full product details including download links
    const enhancedOrders = await Promise.all(
      orders.map(async (order) => {
        const enhancedItems = await Promise.all(
          order.items.map(async (item) => {
            // Try to find product by MongoDB ID first, then by title
            let product = null;
            if (mongoose.Types.ObjectId.isValid(item.id)) {
              product = await Product.findById(item.id);
            }
            if (!product) {
              product = await Product.findOne({ title: item.title });
            }
            
            return {
              ...item.toObject(),
              downloadLink: product?.downloadLink || '',
              image: product?.image || item.icon || '',
              description: product?.description || '',
              fileSize: product?.fileSize || '',
              version: product?.version || '',
              productId: product?._id || null
            };
          })
        );

        return {
          ...order.toObject(),
          items: enhancedItems,
          canDownload: order.status === 'completed'
        };
      })
    );

    res.json({
      success: true,
      orders: enhancedOrders,
      count: enhancedOrders.length
    });
  } catch (error) {
    console.error('❌ Get detailed orders error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch orders' 
    });
  }
});

// Track downloads
app.post('/api/orders/track-download', authenticateToken, async (req, res) => {
  try {
    const { productId, orderId } = req.body;

    if (!productId || !orderId) {
      return res.status(400).json({
        success: false,
        message: 'Product ID and Order ID required'
      });
    }

    // Verify user owns this order
    const order = await Order.findOne({ _id: orderId, userId: req.user.userId });
    if (!order) {
      return res.status(403).json({
        success: false,
        message: 'Order not found or access denied'
      });
    }

    if (order.status !== 'completed') {
      return res.status(403).json({
        success: false,
        message: 'Order must be completed to download'
      });
    }

    const download = new Download({
      userId: req.user.userId,
      productId,
      orderId,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    await download.save();

    res.json({
      success: true,
      message: 'Download tracked successfully'
    });
  } catch (error) {
    console.error('❌ Track download error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to track download' 
    });
  }
});

// Admin: View download statistics
app.get('/api/admin/downloads/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalDownloads = await Download.countDocuments();
    
    const popularProducts = await Download.aggregate([
      { 
        $group: { 
          _id: '$productId', 
          count: { $sum: 1 } 
        } 
      },
      { $sort: { count: -1 } },
      { $limit: 10 },
      {
        $lookup: {
          from: 'products',
          localField: '_id',
          foreignField: '_id',
          as: 'product'
        }
      },
      { $unwind: { path: '$product', preserveNullAndEmptyArrays: true } }
    ]);

    const recentDownloads = await Download.find()
      .populate('userId', 'fullName email')
      .populate('productId', 'title category')
      .sort({ downloadedAt: -1 })
      .limit(20);

    // Downloads by date (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const downloadsByDate = await Download.aggregate([
      { $match: { downloadedAt: { $gte: thirtyDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$downloadedAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json({
      success: true,
      stats: {
        totalDownloads,
        popularProducts,
        recentDownloads,
        downloadsByDate
      }
    });
  } catch (error) {
    console.error('❌ Download stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch stats' 
    });
  }
});

// ========== PRODUCT MANAGEMENT ==========
app.get('/api/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, category = 'all', status = 'all', search = '' } = req.query;
    
    let query = {};
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    } else if (status === 'featured') {
      query.isFeatured = true;
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const products = await Product.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await Product.countDocuments(query);

    res.json({
      success: true,
      products: products,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Get products error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch products' });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const { category = 'all', featured = false, limit = 20, skip = 0 } = req.query;
    
    let query = { isActive: true };
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.isFeatured = true;
    }

    const products = await Product.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip));

    const total = await Product.countDocuments(query);

    res.json({
      success: true,
      products: products,
      count: products.length,
      total: total
    });
  } catch (error) {
    console.error('❌ Get products error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch products' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.json({
      success: true,
      product: product
    });
  } catch (error) {
    console.error('❌ Get product error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch product' });
  }
});

app.post('/api/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const productData = req.body;

    if (!productData.title || !productData.description || !productData.category || productData.price === undefined) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const product = new Product(productData);
    await product.save();

    res.status(201).json({
      success: true,
      message: 'Product created successfully',
      product: product
    });
  } catch (error) {
    console.error('❌ Create product error:', error);
    res.status(500).json({ success: false, message: 'Creation failed' });
  }
});

app.put('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    Object.assign(product, req.body);
    await product.save();

    res.json({
      success: true,
      message: 'Product updated successfully',
      product: product
    });
  } catch (error) {
    console.error('❌ Update product error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('❌ Delete product error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// Seed products with download links
app.post('/api/admin/products/seed-with-downloads', authenticateAdmin, async (req, res) => {
  try {
    const sampleProducts = [
      {
        title: 'Premium Landing Page Template',
        description: 'Beautiful, responsive landing page template with modern design. Includes source files and documentation.',
        category: 'Templates',
        price: 49.99,
        comparePrice: 99.99,
        icon: '🎨',
        downloadLink: 'https://drive.google.com/file/d/YOUR_FILE_ID_1/view?usp=sharing',
        fileSize: '5.2 MB',
        version: '1.0',
        features: ['Fully Responsive', 'Modern Design', 'Easy Customization', 'Documentation Included'],
        isActive: true,
        isFeatured: true,
        stock: 999
      },
      {
        title: 'React Dashboard Components',
        description: 'Complete set of React dashboard components ready to use in your projects. Built with TypeScript.',
        category: 'Components',
        price: 79.99,
        comparePrice: 149.99,
        icon: '⚛️',
        downloadLink: 'https://drive.google.com/file/d/YOUR_FILE_ID_2/view?usp=sharing',
        fileSize: '12.8 MB',
        version: '2.1',
        features: ['TypeScript Support', '50+ Components', 'Dark Mode', 'Fully Documented'],
        isActive: true,
        isFeatured: true,
        stock: 999
      },
      {
        title: 'Web Development Course Bundle',
        description: 'Complete web development course from beginner to advanced. Includes video tutorials and project files.',
        category: 'Courses',
        price: 129.99,
        comparePrice: 299.99,
        icon: '📚',
        downloadLink: 'https://drive.google.com/file/d/YOUR_FILE_ID_3/view?usp=sharing',
        fileSize: '2.5 GB',
        version: '1.0',
        features: ['40+ Hours Video', 'Source Code', 'Certificate', 'Lifetime Access'],
        isActive: true,
        isFeatured: false,
        stock: 999
      },
      {
        title: 'E-commerce Admin Dashboard',
        description: 'Professional admin dashboard for e-commerce platforms with analytics and management tools.',
        category: 'Templates',
        price: 89.99,
        comparePrice: 179.99,
        icon: '🛒',
        downloadLink: 'https://drive.google.com/file/d/YOUR_FILE_ID_4/view?usp=sharing',
        fileSize: '8.4 MB',
        version: '1.5',
        features: ['Analytics Dashboard', 'Order Management', 'User Management', 'Responsive Design'],
        isActive: true,
        isFeatured: true,
        stock: 999
      }
    ];

    let created = 0;
    for (const productData of sampleProducts) {
      const existing = await Product.findOne({ title: productData.title });
      if (!existing) {
        await Product.create(productData);
        created++;
      }
    }

    res.json({
      success: true,
      message: `Seeded ${created} products with download links`,
      note: 'Remember to update the Google Drive links with actual file IDs!'
    });
  } catch (error) {
    console.error('❌ Seed products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to seed products' 
    });
  }
});

// ========== COUPON MANAGEMENT ==========
app.get('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const { status = 'all' } = req.query;
    
    let query = {};
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }

    const coupons = await Coupon.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      coupons: coupons,
      count: coupons.length
    });
  } catch (error) {
    console.error('❌ Get coupons error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch coupons' });
  }
});

app.post('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const { code, discount, type, usageLimit, expiresAt, minPurchaseAmount, description } = req.body;

    if (!code || discount === undefined || !type) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const existing = await Coupon.findOne({ code: code.toUpperCase() });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Coupon code already exists' });
    }

    const coupon = new Coupon({
      code: code.toUpperCase(),
      discount,
      type,
      usageLimit: usageLimit || null,
      expiresAt: expiresAt || null,
      minPurchaseAmount: minPurchaseAmount || 0,
      description: description || ''
    });

    await coupon.save();

    res.status(201).json({
      success: true,
      message: 'Coupon created successfully',
      coupon: coupon
    });
  } catch (error) {
    console.error('❌ Create coupon error:', error);
    res.status(500).json({ success: false, message: 'Creation failed' });
  }
});

app.put('/api/admin/coupons/:code', authenticateAdmin, async (req, res) => {
  try {
    const { discount, type, usageLimit, expiresAt, minPurchaseAmount, description, isActive } = req.body;

    const coupon = await Coupon.findOne({ code: req.params.code.toUpperCase() });
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    if (discount !== undefined) coupon.discount = discount;
    if (type) coupon.type = type;
    if (usageLimit !== undefined) coupon.usageLimit = usageLimit;
    if (expiresAt !== undefined) coupon.expiresAt = expiresAt;
    if (minPurchaseAmount !== undefined) coupon.minPurchaseAmount = minPurchaseAmount;
    if (description !== undefined) coupon.description = description;
    if (isActive !== undefined) coupon.isActive = isActive;

    await coupon.save();

    res.json({
      success: true,
      message: 'Coupon updated successfully',
      coupon: coupon
    });
  } catch (error) {
    console.error('❌ Update coupon error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/coupons/:code', authenticateAdmin, async (req, res) => {
  try {
    const coupon = await Coupon.findOneAndDelete({ code: req.params.code.toUpperCase() });
    
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    res.json({ success: true, message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('❌ Delete coupon error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

app.post('/api/coupons/validate', authenticateToken, async (req, res) => {
  try {
    const { code, orderTotal } = req.body;
    if (!code) {
      return res.status(400).json({ success: false, message: 'Coupon code required' });
    }

    const cleanCode = code.trim().toUpperCase();
    const coupon = await Coupon.findOne({ code: cleanCode });

    if (!coupon) {
      return res.status(404).json({ success: false, message: `Invalid coupon "${cleanCode}"` });
    }

    if (!coupon.isActive) {
      return res.status(400).json({ success: false, message: 'Coupon inactive' });
    }

    if (coupon.expiresAt && new Date() > coupon.expiresAt) {
      return res.status(400).json({ success: false, message: 'Coupon expired' });
    }

    if (coupon.usageLimit && coupon.usageCount >= coupon.usageLimit) {
      return res.status(400).json({ success: false, message: 'Usage limit reached' });
    }

    if (orderTotal < coupon.minPurchaseAmount) {
      return res.status(400).json({ success: false, message: `Minimum purchase of $${coupon.minPurchaseAmount} required` });
    }

    let discountAmount = 0;
    if (coupon.type === 'percentage') {
      discountAmount = (orderTotal * coupon.discount) / 100;
    } else {
      discountAmount = coupon.discount;
    }

    discountAmount = Math.min(discountAmount, orderTotal);
    const finalAmount = Math.max(0, orderTotal - discountAmount);
    const isFree = finalAmount === 0;

    res.json({
      success: true,
      coupon: {
        code: coupon.code,
        discount: coupon.discount,
        type: coupon.type,
        discountAmount: discountAmount,
        finalAmount: finalAmount,
        isFree: isFree
      },
      message: isFree ? '🎉 Order is FREE!' : `✅ Saved $${discountAmount.toFixed(2)}`
    });

  } catch (error) {
    console.error('❌ Validate coupon error:', error);
    res.status(500).json({ success: false, message: 'Validation failed' });
  }
});

app.post('/api/coupons/seed', async (req, res) => {
  try {
    const defaultCoupons = [
      { code: 'WELCOME10', discount: 10, type: 'percentage', isActive: true, description: 'Welcome bonus - 10% off' },
      { code: 'SAVE20', discount: 20, type: 'percentage', isActive: true, description: 'Save 20% on your order' },
      { code: 'FLAT50', discount: 50, type: 'fixed', isActive: true, description: '$50 off your purchase' },
      { code: 'NEWUSER', discount: 15, type: 'percentage', isActive: true, description: 'New user discount' },
      { code: 'FREE100', discount: 100, type: 'percentage', isActive: true, usageLimit: 50, description: 'Free order - Limited to 50 uses' }
    ];

    let created = 0;
    for (const couponData of defaultCoupons) {
      const existing = await Coupon.findOne({ code: couponData.code });
      if (!existing) {
        await Coupon.create(couponData);
        created++;
      }
    }

    res.json({
      success: true,
      message: `Seeded ${created} coupons`,
      coupons: defaultCoupons.map(c => c.code)
    });
  } catch (error) {
    console.error('❌ Seed coupons error:', error);
    res.status(500).json({ success: false, message: 'Seed failed' });
  }
});

console.log('✅ Part 4 loaded: Download Links, Products & Coupons configured');

// ========== END OF PART 4 ==========
// Continue to Part 5 for Blog Management & System Settings// ========== UYEH TECH SERVER v6.0 - PART 5 OF 6 ==========
// Blog Management & System Settings
// COPY THIS AFTER PART 4

// ========== BLOG MANAGEMENT ==========
app.get('/api/admin/blog/posts', authenticateAdmin, async (req, res) => {
  try {
    const { status = 'all', category = 'all' } = req.query;
    
    let query = {};
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    if (category && category !== 'all') {
      query.category = category;
    }

    const posts = await BlogPost.find(query)
      .populate('author', 'fullName email')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      posts: posts,
      count: posts.length
    });
  } catch (error) {
    console.error('❌ Get posts error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch posts' });
  }
});

app.post('/api/admin/blog/posts', authenticateAdmin, async (req, res) => {
  try {
    const { title, excerpt, content, featuredImage, category, tags, status, metaTitle, metaDescription, metaKeywords } = req.body;

    if (!title || !excerpt || !content || !category) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const slug = generateSlug(title);
    const existing = await BlogPost.findOne({ slug });
    
    if (existing) {
      return res.status(400).json({ success: false, message: 'Post with this title exists' });
    }

    const blogPost = new BlogPost({
      title,
      slug,
      excerpt,
      content,
      featuredImage: featuredImage || '',
      author: req.user.userId,
      category,
      tags: tags || [],
      status: status || 'draft',
      metaTitle: metaTitle || title,
      metaDescription: metaDescription || excerpt,
      metaKeywords: metaKeywords || []
    });

    await blogPost.save();

    res.status(201).json({
      success: true,
      message: 'Blog post created',
      post: blogPost
    });
  } catch (error) {
    console.error('❌ Create post error:', error);
    res.status(500).json({ success: false, message: 'Creation failed' });
  }
});

app.put('/api/admin/blog/posts/:id', authenticateAdmin, async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    const allowedUpdates = ['title', 'excerpt', 'content', 'featuredImage', 'category', 'tags', 'status', 'metaTitle', 'metaDescription', 'metaKeywords'];
    
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        post[field] = req.body[field];
      }
    });

    if (req.body.title && req.body.title !== post.title) {
      post.slug = generateSlug(req.body.title);
    }

    await post.save();

    res.json({
      success: true,
      message: 'Post updated',
      post: post
    });
  } catch (error) {
    console.error('❌ Update post error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/blog/posts/:id', authenticateAdmin, async (req, res) => {
  try {
    const post = await BlogPost.findByIdAndDelete(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    res.json({ success: true, message: 'Post deleted' });
  } catch (error) {
    console.error('❌ Delete post error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

app.get('/api/blog/posts', async (req, res) => {
  try {
    const { limit = 10, skip = 0, category = 'all' } = req.query;

    let query = { status: 'published' };
    if (category && category !== 'all') {
      query.category = category;
    }

    const posts = await BlogPost.find(query)
      .populate('author', 'fullName profileImage')
      .sort({ publishedAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .select('-content');

    const total = await BlogPost.countDocuments(query);

    res.json({
      success: true,
      posts: posts,
      count: posts.length,
      total: total
    });
  } catch (error) {
    console.error('❌ Get published posts error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch posts' });
  }
});

app.get('/api/blog/posts/:slug', async (req, res) => {
  try {
    const post = await BlogPost.findOne({ slug: req.params.slug })
      .populate('author', 'fullName profileImage bio');

    if (!post || post.status !== 'published') {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    post.views += 1;
    await post.save();

    res.json({
      success: true,
      post: post
    });
  } catch (error) {
    console.error('❌ Get post error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch post' });
  }
});

app.post('/api/blog/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    post.likes += 1;
    await post.save();

    res.json({
      success: true,
      likes: post.likes
    });
  } catch (error) {
    console.error('❌ Like post error:', error);
    res.status(500).json({ success: false, message: 'Like failed' });
  }
});

app.post('/api/blog/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { comment } = req.body;
    
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    const user = await User.findById(req.user.userId);
    
    post.comments.push({
      user: user._id,
      userName: user.fullName,
      userEmail: user.email,
      comment: comment,
      approved: false
    });

    await post.save();

    res.json({
      success: true,
      message: 'Comment added (pending approval)',
      comments: post.comments
    });
  } catch (error) {
    console.error('❌ Add comment error:', error);
    res.status(500).json({ success: false, message: 'Comment failed' });
  }
});

app.put('/api/admin/blog/posts/:postId/comments/:commentId/approve', authenticateAdmin, async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    const comment = post.comments.id(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ success: false, message: 'Comment not found' });
    }

    comment.approved = true;
    await post.save();

    res.json({
      success: true,
      message: 'Comment approved'
    });
  } catch (error) {
    console.error('❌ Approve comment error:', error);
    res.status(500).json({ success: false, message: 'Approval failed' });
  }
});

app.get('/api/blog/categories', async (req, res) => {
  try {
    const categories = await BlogPost.aggregate([
      { $match: { status: 'published' } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    res.json({
      success: true,
      categories: categories.map(c => ({
        name: c._id,
        count: c.count
      }))
    });
  } catch (error) {
    console.error('❌ Get categories error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch categories' });
  }
});

app.get('/api/blog/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) {
      return res.status(400).json({ success: false, message: 'Search query required' });
    }

    const posts = await BlogPost.find({
      status: 'published',
      $or: [
        { title: { $regex: query, $options: 'i' } },
        { excerpt: { $regex: query, $options: 'i' } },
        { content: { $regex: query, $options: 'i' } },
        { tags: { $regex: query, $options: 'i' } }
      ]
    })
    .populate('author', 'fullName')
    .sort({ publishedAt: -1 })
    .limit(20)
    .select('-content');

    res.json({
      success: true,
      posts: posts,
      count: posts.length
    });
  } catch (error) {
    console.error('❌ Search posts error:', error);
    res.status(500).json({ success: false, message: 'Search failed' });
  }
});

app.get('/api/blog/featured', async (req, res) => {
  try {
    const posts = await BlogPost.find({ status: 'published' })
      .populate('author', 'fullName profileImage')
      .sort({ views: -1, likes: -1 })
      .limit(5)
      .select('-content');

    res.json({
      success: true,
      posts: posts
    });
  } catch (error) {
    console.error('❌ Get featured posts error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch featured posts' });
  }
});

// ========== SYSTEM SETTINGS ==========
app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    let settings = await SystemSettings.findOne();
    
    if (!settings) {
      settings = new SystemSettings({
        siteName: 'UYEH TECH',
        contactEmail: 'contact@uyehtech.com',
        supportEmail: 'support@uyehtech.com',
        allowRegistration: true,
        requireEmailVerification: true
      });
      await settings.save();
    }

    res.json({
      success: true,
      settings: settings
    });
  } catch (error) {
    console.error('❌ Get settings error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    let settings = await SystemSettings.findOne();
    
    if (!settings) {
      settings = new SystemSettings();
    }

    Object.assign(settings, req.body);
    settings.updatedAt = Date.now();
    await settings.save();

    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: settings
    });
  } catch (error) {
    console.error('❌ Update settings error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.get('/api/settings/public', async (req, res) => {
  try {
    const settings = await SystemSettings.findOne();
    
    res.json({
      success: true,
      settings: {
        siteName: settings?.siteName || 'UYEH TECH',
        siteDescription: settings?.siteDescription || '',
        contactEmail: settings?.contactEmail || '',
        phone: settings?.phone || '',
        socialMedia: settings?.socialMedia || {},
        maintenanceMode: settings?.maintenanceMode || false,
        maintenanceMessage: settings?.maintenanceMessage || '',
        allowRegistration: settings?.allowRegistration || true
      }
    });
  } catch (error) {
    res.json({
      success: true,
      settings: {
        siteName: 'UYEH TECH',
        allowRegistration: true
      }
    });
  }
});

// ========== NOTIFICATION PREFERENCES ==========
app.get('/api/user/notifications', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    res.json({
      success: true,
      preferences: user.notificationPreferences || {
        email: true,
        orders: true,
        marketing: false
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch preferences' });
  }
});

app.put('/api/user/notifications/update', authenticateToken, async (req, res) => {
  try {
    const { email, orders, marketing } = req.body;
    const user = await User.findById(req.user.userId);

    if (!user.notificationPreferences) {
      user.notificationPreferences = { email: true, orders: true, marketing: false };
    }

    if (email !== undefined) user.notificationPreferences.email = email;
    if (orders !== undefined) user.notificationPreferences.orders = orders;
    if (marketing !== undefined) user.notificationPreferences.marketing = marketing;

    await user.save();

    res.json({
      success: true,
      message: 'Preferences updated',
      preferences: user.notificationPreferences
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

// ========== PAYMENT METHODS ==========
app.get('/api/user/payment-methods', authenticateToken, async (req, res) => {
  try {
    const methods = await PaymentMethod.find({ userId: req.user.userId }).sort({ createdAt: -1 });

    res.json({
      success: true,
      methods: methods
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch methods' });
  }
});

app.post('/api/user/payment-methods/add', authenticateToken, async (req, res) => {
  try {
    const { type, lastFour, expiry, cardholderName, isDefault } = req.body;

    if (isDefault) {
      await PaymentMethod.updateMany({ userId: req.user.userId }, { $set: { isDefault: false } });
    }

    const paymentMethod = new PaymentMethod({
      userId: req.user.userId,
      type,
      lastFour,
      expiry,
      cardholderName,
      isDefault: isDefault || false
    });

    await paymentMethod.save();

    res.status(201).json({
      success: true,
      message: 'Payment method added',
      method: paymentMethod
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add method' });
  }
});

// ========== CHANGE PASSWORD ==========
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.userId);
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ success: true, message: 'Password changed' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to change password' });
  }
});

// ========== TOGGLE 2FA ==========
app.post('/api/auth/toggle-2fa', authenticateToken, async (req, res) => {
  try {
    const { enabled } = req.body;
    const user = await User.findById(req.user.userId);

    user.twoFactorEnabled = !!enabled;
    if (enabled && !user.twoFactorSecret) {
      user.twoFactorSecret = generateToken();
    }

    await user.save();

    res.json({
      success: true,
      message: enabled ? '2FA enabled' : '2FA disabled',
      user: {
        id: user._id,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to toggle 2FA' });
  }
});

// ========== DELETE ACCOUNT ==========
app.delete('/api/auth/delete-account', authenticateToken, async (req, res) => {
  try {
    await Order.deleteMany({ userId: req.user.userId });
    await PaymentMethod.deleteMany({ userId: req.user.userId });
    await Download.deleteMany({ userId: req.user.userId });
    await User.findByIdAndDelete(req.user.userId);

    res.json({ success: true, message: 'Account deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

console.log('✅ Part 5 loaded: Blog Management & System Settings configured');

// ========== END OF PART 5 ==========
// Continue to Part 6 for Server Startup & Documentation// ========== UYEH TECH SERVER v6.0 - PART 6 OF 6 (FINAL) ==========
// Server Startup, Error Handling & Complete Documentation
// COPY THIS AFTER PART 5

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║   🚀 UYEH TECH SERVER v6.0 - READY WITH DOWNLOAD LINKS     ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`📧 Admin Email: ${ADMIN_EMAIL}`);
  console.log(`🔐 Admin Portal: Admind.html`);
  console.log(`📊 Dashboard: admin-dashboard.html\n`);
  
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║              🎉 COMPLETE FEATURE LIST                       ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  console.log('  📊 Dashboard Overview with Real-time Stats');
  console.log('  📈 Analytics System (Revenue, Orders, Downloads)');
  console.log('  👥 User Management (View, Ban, Delete)');
  console.log('  📦 Order Management (Track, Update, Refund)');
  console.log('  🎫 Coupon System (Create, Edit, Validate)');
  console.log('  📝 Blog Management (Posts, Comments, SEO)');
  console.log('  🛍️  Product Management (CRUD + Images)');
  console.log('  📥 Download Link Management (NEW!)');
  console.log('  📊 Download Tracking & Statistics (NEW!)');
  console.log('  ⚙️  System Settings (Configuration)\n');
  
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║               🔗 COMPLETE API ENDPOINTS                      ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  console.log('🔐 AUTHENTICATION:');
  console.log('  POST   /api/auth/signup              - User signup');
  console.log('  POST   /api/auth/login               - User login');
  console.log('  POST   /api/auth/admin/login         - Admin login');
  console.log('  GET    /api/auth/admin/verify        - Verify admin token');
  console.log('  POST   /api/auth/send-email-otp      - Send verification OTP');
  console.log('  POST   /api/auth/verify-email-otp    - Verify email OTP');
  console.log('  POST   /api/auth/forgot-password     - Request password reset');
  console.log('  POST   /api/auth/reset-password      - Reset password');
  console.log('  POST   /api/auth/change-password     - Change password');
  console.log('  POST   /api/auth/toggle-2fa          - Toggle 2FA');
  console.log('  DELETE /api/auth/delete-account      - Delete account\n');
  
  console.log('📊 DASHBOARD & ANALYTICS:');
  console.log('  GET    /api/admin/dashboard          - Dashboard overview');
  console.log('  GET    /api/admin/analytics          - Analytics data\n');
  
  console.log('👥 USER MANAGEMENT:');
  console.log('  GET    /api/admin/users              - List all users');
  console.log('  GET    /api/admin/users/:userId      - Get user details');
  console.log('  PUT    /api/admin/users/:userId/ban  - Ban/unban user');
  console.log('  DELETE /api/admin/users/:userId      - Delete user');
  console.log('  GET    /api/profile                  - Get user profile');
  console.log('  PUT    /api/profile                  - Update profile\n');
  
  console.log('📦 ORDER MANAGEMENT:');
  console.log('  GET    /api/admin/orders             - List all orders (admin)');
  console.log('  GET    /api/admin/orders/:orderId    - Get order details (admin)');
  console.log('  PUT    /api/admin/orders/:orderId/status - Update order status');
  console.log('  DELETE /api/admin/orders/:orderId    - Delete order');
  console.log('  GET    /api/orders                   - Get user orders');
  console.log('  GET    /api/orders/detailed          - Get orders with download links');
  console.log('  POST   /api/orders/create-with-coupon - Create order with coupon');
  console.log('  POST   /api/orders/verify-payment    - Verify Flutterwave payment\n');
  
  console.log('📥 DOWNLOAD MANAGEMENT (NEW):');
  console.log('  GET    /api/orders/detailed          - Get orders with download links');
  console.log('  POST   /api/orders/track-download    - Track product download');
  console.log('  GET    /api/admin/downloads/stats    - Download statistics (admin)\n');
  
  console.log('🎫 COUPON MANAGEMENT:');
  console.log('  GET    /api/admin/coupons            - List all coupons');
  console.log('  POST   /api/admin/coupons            - Create coupon');
  console.log('  PUT    /api/admin/coupons/:code      - Update coupon');
  console.log('  DELETE /api/admin/coupons/:code      - Delete coupon');
  console.log('  POST   /api/coupons/validate         - Validate coupon code');
  console.log('  POST   /api/coupons/seed             - Seed default coupons\n');
  
  console.log('🛍️  PRODUCT MANAGEMENT:');
  console.log('  GET    /api/admin/products           - List products (admin)');
  console.log('  GET    /api/products                 - List products (public)');
  console.log('  GET    /api/products/:id             - Get product details');
  console.log('  POST   /api/admin/products           - Create product');
  console.log('  PUT    /api/admin/products/:id       - Update product (includes downloadLink)');
  console.log('  DELETE /api/admin/products/:id       - Delete product');
  console.log('  POST   /api/admin/products/seed-with-downloads - Seed sample products\n');
  
  console.log('📝 BLOG MANAGEMENT:');
  console.log('  GET    /api/admin/blog/posts         - List all posts (admin)');
  console.log('  POST   /api/admin/blog/posts         - Create blog post');
  console.log('  PUT    /api/admin/blog/posts/:id     - Update blog post');
  console.log('  DELETE /api/admin/blog/posts/:id     - Delete blog post');
  console.log('  GET    /api/blog/posts               - List published posts');
  console.log('  GET    /api/blog/posts/:slug         - Get single post');
  console.log('  POST   /api/blog/posts/:id/like      - Like post');
  console.log('  POST   /api/blog/posts/:id/comments  - Add comment');
  console.log('  PUT    /api/admin/blog/posts/:postId/comments/:commentId/approve');
  console.log('  GET    /api/blog/categories          - Get blog categories');
  console.log('  GET    /api/blog/search              - Search blog posts');
  console.log('  GET    /api/blog/featured            - Get featured posts\n');
  
  console.log('⚙️  SYSTEM SETTINGS:');
  console.log('  GET    /api/admin/settings           - Get system settings');
  console.log('  PUT    /api/admin/settings           - Update settings');
  console.log('  GET    /api/settings/public          - Get public settings\n');
  
  console.log('👤 USER PREFERENCES:');
  console.log('  GET    /api/user/notifications       - Get notification preferences');
  console.log('  PUT    /api/user/notifications/update - Update preferences');
  console.log('  GET    /api/user/payment-methods     - Get payment methods');
  console.log('  POST   /api/user/payment-methods/add - Add payment method\n');
  
  console.log('════════════════════════════════════════════════════════════════');
  console.log('🔐 ADMIN SETUP INSTRUCTIONS:');
  console.log('════════════════════════════════════════════════════════════════');
  console.log(`  1. Sign up with email: ${ADMIN_EMAIL}`);
  console.log('  2. System automatically grants admin privileges');
  console.log('  3. Login at Admind.html');
  console.log('  4. Access admin dashboard at admin-dashboard.html\n');
  
  console.log('📥 DOWNLOAD LINK SETUP:');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('  1. Upload files to Google Drive');
  console.log('  2. Set sharing to "Anyone with the link"');
  console.log('  3. Copy link and add to product in admin dashboard');
  console.log('  4. Use direct download format:');
  console.log('     https://drive.google.com/uc?export=download&id=FILE_ID');
  console.log('  5. Or use POST /api/admin/products/seed-with-downloads\n');
  
  console.log('🎯 QUICK START COMMANDS:');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('  Seed Coupons:  POST /api/coupons/seed');
  console.log('  Seed Products: POST /api/admin/products/seed-with-downloads\n');
  
  console.log('✅ Server ready to accept connections!\n');
});

// ========== ERROR HANDLING ==========
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Promise Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  console.log('\n⚠️  SIGTERM signal received');
  await mongoose.connection.close();
  console.log('✅ MongoDB connection closed');
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('\n⚠️  SIGINT signal received');
  await mongoose.connection.close();
  console.log('✅ MongoDB connection closed');
  process.exit(0);
});

console.log('✅ Part 6 loaded: Server startup complete!');
console.log('\n🎉 ALL 6 PARTS LOADED SUCCESSFULLY! SERVER v6.0 READY!\n');

// ========== END OF PART 6 ==========
// ========== SERVER v6.0 COMPLETE WITH DOWNLOAD LINKS ==========

/*
═══════════════════════════════════════════════════════════════════════════
                  UYEH TECH SERVER v6.0 - COMPLETE DOCUMENTATION
═══════════════════════════════════════════════════════════════════════════

VERSION: 6.0.0 with Download Links
RELEASE DATE: December 2024
STATUS: Production Ready
ADMIN EMAIL: uyehtech@gmail.com

COMPLETE INSTALLATION GUIDE:
───────────────────────────────────────────────────────────────────────────
1. CREATE PROJECT:
   mkdir uyeh-tech-server
   cd uyeh-tech-server
   npm init -y

2. INSTALL DEPENDENCIES:
   npm install express mongoose bcryptjs jsonwebtoken cors axios dotenv

3. CREATE server.js:
   - Copy all 6 parts into a single server.js file
   - Parts must be in order (1-6)

4. CREATE .env FILE:
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_secret_key_here
   TERMII_API_KEY=your_termii_key (optional)
   TERMII_SENDER_EMAIL=noreply@uyehtech.com
   FLUTTERWAVE_SECRET_KEY=your_flutterwave_key
   PORT=3000
   NODE_ENV=production

5. RUN SERVER:
   node server.js

DOWNLOAD LINK FEATURE - COMPLETE GUIDE:
───────────────────────────────────────────────────────────────────────────
✨ NEW FEATURES IN v6.0:
  ✅ Download link field in Product schema
  ✅ Enhanced orders endpoint with download links
  ✅ Download tracking system
  ✅ Download statistics for admins
  ✅ Automatic product linking to orders
  ✅ Sample products with download links

📥 SETTING UP DOWNLOAD LINKS:

OPTION 1: Google Drive (Recommended for beginners)
  1. Upload your product file to Google Drive
  2. Right-click → Share → Change to "Anyone with the link"
  3. Copy the link (looks like: drive.google.com/file/d/FILE_ID/view)
  4. Extract the FILE_ID from the URL
  5. Use direct download format in product:
     https://drive.google.com/uc?export=download&id=FILE_ID
  6. Or use view format (users click to download):
     https://drive.google.com/file/d/FILE_ID/view?usp=sharing

OPTION 2: Dropbox
  1. Upload file to Dropbox
  2. Get shareable link
  3. Add ?dl=1 to the end for direct download
  4. Example: https://www.dropbox.com/s/FILE_ID/file.zip?dl=1

OPTION 3: Your Own Server
  1. Upload files to your server
  2. Use direct URL: https://yourserver.com/downloads/product.zip
  3. Make sure files are publicly accessible

OPTION 4: AWS S3 / Cloudflare R2
  1. Upload to cloud storage
  2. Generate public or presigned URLs
  3. Use those URLs as download links

📝 ADDING DOWNLOAD LINKS TO PRODUCTS:

METHOD 1: Admin Dashboard
  1. Login to admin dashboard (admin-dashboard.html)
  2. Go to Products section
  3. Create or Edit product
  4. Add download link in the "Download Link" field
  5. Save product

METHOD 2: API Request
  POST /api/admin/products
  {
    "title": "Product Name",
    "description": "Description",
    "category": "Category",
    "price": 49.99,
    "downloadLink": "https://drive.google.com/uc?export=download&id=YOUR_FILE_ID",
    "fileSize": "5.2 MB",
    "version": "1.0"
  }

METHOD 3: Seed Sample Products
  POST /api/admin/products/seed-with-downloads
  (Remember to update the FILE_ID placeholders in the code!)

🎯 HOW DOWNLOAD LINKS WORK:

1. CUSTOMER PURCHASES:
   - Customer completes order
   - Order status becomes "completed"
   - Download links are accessible

2. ACCESSING DOWNLOADS:
   - Customer visits my-orders.html or success.html
   - Frontend calls GET /api/orders/detailed
   - Response includes full product details with download links
   - Customer can download immediately

3. DOWNLOAD TRACKING:
   - When customer clicks download button
   - Frontend calls POST /api/orders/track-download
   - System records: user, product, order, timestamp, IP, user-agent
   - Admin can view download statistics

4. ADMIN MONITORING:
   - View download stats: GET /api/admin/downloads/stats
   - See: total downloads, popular products, recent downloads
   - Track download trends over time

API ENDPOINTS FOR DOWNLOAD SYSTEM:
───────────────────────────────────────────────────────────────────────────
📥 USER ENDPOINTS:
  GET  /api/orders/detailed
    - Returns orders with full product details including download links
    - Only shows downloads for completed orders
    - Automatically links products to order items

  POST /api/orders/track-download
    Body: { "productId": "...", "orderId": "..." }
    - Tracks when user downloads a product
    - Verifies user owns the order
    - Records download statistics

📊 ADMIN ENDPOINTS:
  GET  /api/admin/downloads/stats
    - Total downloads count
    - Most popular products
    - Recent downloads list
    - Downloads by date (last 30 days)

  POST /api/admin/products/seed-with-downloads
    - Seeds 4 sample products with download links
    - Includes templates, components, and courses
    - Remember to update FILE_IDs!

FRONTEND INTEGRATION EXAMPLE:
───────────────────────────────────────────────────────────────────────────
// Fetch orders with download links
const response = await fetch('http://localhost:3000/api/orders/detailed', {
  headers: { 'Authorization': `Bearer ${token}` }
});
const data = await response.json();

// Display download buttons for completed orders
data.orders.forEach(order => {
  if (order.canDownload) {
    order.items.forEach(item => {
      if (item.downloadLink) {
        // Show download button
        console.log(`Download: ${item.title}`);
        console.log(`Link: ${item.downloadLink}`);
        
        // Track download when clicked
        await fetch('http://localhost:3000/api/orders/track-download', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            productId: item.productId,
            orderId: order._id
          })
        });
      }
    });
  }
});

SECURITY CONSIDERATIONS:
───────────────────────────────────────────────────────────────────────────
✅ Download verification:
  - Only completed orders can download
  - User must own the order
  - JWT authentication required

✅ Link protection options:
  - Use presigned URLs (AWS S3, R2)
  - Implement download tokens
  - Set expiring links
  - Limit download attempts

✅ File storage best practices:
  - Don't store sensitive files publicly
  - Use CDN for large files
  - Monitor bandwidth usage
  - Consider download limits per user

COMPLETE FEATURE CHECKLIST:
───────────────────────────────────────────────────────────────────────────
✅ Admin Dashboard System
✅ User Management (Ban, Delete, View)
✅ Order Management (Track, Update, Refund)
✅ Product Management (CRUD Operations)
✅ Download Link Management (NEW!)
✅ Download Tracking System (NEW!)
✅ Download Statistics (NEW!)
✅ Coupon System (Create, Validate)
✅ Blog Management (Posts, Comments, SEO)
✅ Analytics Dashboard (Revenue, Orders, Downloads)
✅ Email OTP Verification
✅ Payment Integration (Flutterwave)
✅ 2FA Support
✅ System Settings
✅ User Preferences
✅ Profile Management
✅ Password Reset
✅ Ban System

TESTING THE DOWNLOAD SYSTEM:
───────────────────────────────────────────────────────────────────────────
1. Start server: node server.js
2. Create admin account with uyehtech@gmail.com
3. Seed products: POST /api/admin/products/seed-with-downloads
4. Update FILE_IDs in seeded products
5. Create test order with test user
6. Mark order as completed (admin dashboard)
7. Test user fetches orders: GET /api/orders/detailed
8. Download links should appear
9. Track download: POST /api/orders/track-download
10. View stats: GET /api/admin/downloads/stats

TROUBLESHOOTING:
───────────────────────────────────────────────────────────────────────────
❌ Download links not showing?
  → Check order status is "completed"
  → Verify product has downloadLink field populated
  → Check user authentication token

❌ Google Drive links not working?
  → Ensure file sharing is "Anyone with the link"
  → Use correct format: drive.google.com/uc?export=download&id=FILE_ID
  → Check file ID is correct

❌ Download tracking not working?
  → Verify productId and orderId are valid
  → Check user owns the order
  → Ensure authentication token is valid

SUPPORT:
───────────────────────────────────────────────────────────────────────────
For issues or questions:
  📧 Email: uyehtech@gmail.com
  📝 Check server logs for detailed error messages
  🔍 Use console.log statements for debugging

═══════════════════════════════════════════════════════════════════════════
                    🎉 SERVER v6.0 COMPLETE & READY!
                       WITH FULL DOWNLOAD LINK SUPPORT
═══════════════════════════════════════════════════════════════════════════
*/

// ========== UYEH TECH SUPPORT SYSTEM SERVER ==========
// Complete Support Agent System with Real-time Chat
// WebSocket Integration, Desktop Notifications, File Uploads
// Admin Email: uyehtech@gmail.com
// Agent Emails: uyehsub@gmail.com, okonb310@gmail.com, bayortv002@gmail.com

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// ========== CONFIGURATION ==========
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = 'uyehtech@gmail.com';
const ALLOWED_AGENT_EMAILS = [
  'uyehsub@gmail.com',
  'okonb310@gmail.com',
  'bayortv002@gmail.com'
];

// ========== MIDDLEWARE ==========
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static('uploads'));

// Create uploads directory
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// ========== FILE UPLOAD CONFIGURATION ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Invalid file type'));
  }
});

// ========== MONGODB CONNECTION ==========
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// ========== SCHEMAS ==========

// Support Agent Schema
const supportAgentSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['agent', 'super_admin'], default: 'agent' },
  status: { type: String, enum: ['online', 'offline', 'away'], default: 'offline' },
  avatar: String,
  department: String,
  isActive: { type: Boolean, default: true },
  stats: {
    totalTickets: { type: Number, default: 0 },
    resolvedTickets: { type: Number, default: 0 },
    avgResponseTime: { type: Number, default: 0 },
    satisfaction: { type: Number, default: 0 }
  },
  lastSeen: Date,
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'SupportAgent' }
});

const SupportAgent = mongoose.model('SupportAgent', supportAgentSchema);

// Support Ticket Schema
const supportTicketSchema = new mongoose.Schema({
  ticketNumber: { type: String, required: true, unique: true },
  customerName: { type: String, required: true },
  customerEmail: { type: String, required: true },
  subject: { type: String, required: true },
  category: { type: String, default: 'general' },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  status: { type: String, enum: ['open', 'in_progress', 'pending', 'resolved', 'closed'], default: 'open' },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'SupportAgent' },
  tags: [String],
  messages: [{
    sender: String, // 'customer' or 'agent'
    senderName: String,
    message: String,
    isInternal: { type: Boolean, default: false }, // Internal notes
    attachments: [{
      filename: String,
      url: String,
      size: Number
    }],
    timestamp: { type: Date, default: Date.now }
  }],
  satisfaction: {
    rating: Number,
    feedback: String,
    ratedAt: Date
  },
  metadata: {
    browser: String,
    ip: String,
    referrer: String,
    userAgent: String
  },
  sessionId: String, // For linking widget conversations
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  resolvedAt: Date,
  firstResponseAt: Date,
  closedAt: Date
});

supportTicketSchema.index({ ticketNumber: 1 });
supportTicketSchema.index({ customerEmail: 1 });
supportTicketSchema.index({ status: 1 });
supportTicketSchema.index({ assignedTo: 1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Canned Response Schema
const cannedResponseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  shortcut: { type: String, required: true, unique: true },
  message: { type: String, required: true },
  category: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'SupportAgent' },
  createdAt: { type: Date, default: Date.now }
});

const CannedResponse = mongoose.model('CannedResponse', cannedResponseSchema);

// Chat Session Schema (for widget)
const chatSessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  customerName: String,
  customerEmail: String,
  status: { type: String, enum: ['active', 'closed'], default: 'active' },
  assignedAgent: { type: mongoose.Schema.Types.ObjectId, ref: 'SupportAgent' },
  messages: [{
    sender: String, // 'customer' or 'agent'
    senderName: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
  }],
  metadata: {
    browser: String,
    ip: String,
    userAgent: String
  },
  createdAt: { type: Date, default: Date.now },
  lastMessageAt: { type: Date, default: Date.now }
});

chatSessionSchema.index({ sessionId: 1 });
chatSessionSchema.index({ status: 1 });

const ChatSession = mongoose.model('ChatSession', chatSessionSchema);

// ========== WEBSOCKET MANAGEMENT ==========
const connectedAgents = new Map(); // Map of agentId -> socketId
const connectedCustomers = new Map(); // Map of sessionId -> socketId

io.on('connection', (socket) => {
  console.log('🔌 New connection:', socket.id);

  // Agent connects
  socket.on('agent:connect', async (data) => {
    const { agentId, token } = data;
    try {
      jwt.verify(token, JWT_SECRET);
      connectedAgents.set(agentId, socket.id);
      socket.agentId = agentId;
      
      // Update agent status
      await SupportAgent.findByIdAndUpdate(agentId, {
        status: 'online',
        lastSeen: new Date()
      });

      // Broadcast to all agents
      io.emit('agent:status', { agentId, status: 'online' });
      
      console.log(`✅ Agent ${agentId} connected`);
    } catch (error) {
      console.error('Agent connect error:', error);
    }
  });

  // Customer connects via widget
  socket.on('customer:connect', (data) => {
    const { sessionId } = data;
    connectedCustomers.set(sessionId, socket.id);
    socket.sessionId = sessionId;
    console.log(`✅ Customer ${sessionId} connected`);
    
    // Notify all agents of new customer
    io.emit('customer:online', { sessionId });
  });

  // Agent sends message
  socket.on('agent:message', async (data) => {
    const { ticketId, sessionId, message, agentName } = data;
    
    try {
      if (ticketId) {
        // Add message to ticket
        const ticket = await SupportTicket.findById(ticketId);
        ticket.messages.push({
          sender: 'agent',
          senderName: agentName,
          message: message,
          timestamp: new Date()
        });
        ticket.updatedAt = new Date();
        await ticket.save();

        // Broadcast to all agents
        io.emit('ticket:update', { ticketId, ticket });
      }

      if (sessionId) {
        // Send to customer in widget
        const customerSocket = connectedCustomers.get(sessionId);
        if (customerSocket) {
          io.to(customerSocket).emit('agent:reply', {
            message,
            agentName,
            timestamp: new Date()
          });
        }

        // Update chat session
        await ChatSession.findOneAndUpdate(
          { sessionId },
          {
            $push: {
              messages: {
                sender: 'agent',
                senderName: agentName,
                message,
                timestamp: new Date()
              }
            },
            lastMessageAt: new Date()
          }
        );
      }
    } catch (error) {
      console.error('Agent message error:', error);
    }
  });

  // Customer sends message
  socket.on('customer:message', async (data) => {
    const { sessionId, message, customerName, customerEmail } = data;
    
    try {
      // Update or create chat session
      let session = await ChatSession.findOne({ sessionId });
      
      if (!session) {
        session = new ChatSession({
          sessionId,
          customerName,
          customerEmail,
          messages: []
        });
      }

      session.messages.push({
        sender: 'customer',
        senderName: customerName,
        message,
        timestamp: new Date()
      });
      session.lastMessageAt = new Date();
      await session.save();

      // Notify all agents with sound notification trigger
      io.emit('customer:new_message', {
        sessionId,
        customerName,
        message,
        timestamp: new Date(),
        playSound: true
      });

      console.log(`💬 New message from ${customerName}`);
    } catch (error) {
      console.error('Customer message error:', error);
    }
  });

  // Agent typing indicator
  socket.on('agent:typing', (data) => {
    const { sessionId, agentName, isTyping } = data;
    const customerSocket = connectedCustomers.get(sessionId);
    if (customerSocket) {
      io.to(customerSocket).emit('agent:typing', { agentName, isTyping });
    }
  });

  // Customer typing indicator
  socket.on('customer:typing', (data) => {
    const { sessionId, isTyping } = data;
    io.emit('customer:typing', { sessionId, isTyping });
  });

  // Disconnect
  socket.on('disconnect', async () => {
    if (socket.agentId) {
      connectedAgents.delete(socket.agentId);
      
      // Update agent status
      await SupportAgent.findByIdAndUpdate(socket.agentId, {
        status: 'offline',
        lastSeen: new Date()
      });

      io.emit('agent:status', { agentId: socket.agentId, status: 'offline' });
      console.log(`❌ Agent ${socket.agentId} disconnected`);
    }

    if (socket.sessionId) {
      connectedCustomers.delete(socket.sessionId);
      io.emit('customer:offline', { sessionId: socket.sessionId });
      console.log(`❌ Customer ${socket.sessionId} disconnected`);
    }
  });
});

// ========== MIDDLEWARE ==========
function authenticateAgent(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token required' });

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    
    const agent = await SupportAgent.findById(decoded.agentId);
    if (!agent || !agent.isActive) {
      return res.status(403).json({ success: false, message: 'Agent not found or inactive' });
    }

    req.agent = agent;
    next();
  });
}

function authenticateSuperAdmin(req, res, next) {
  authenticateAgent(req, res, () => {
    if (req.agent.role !== 'super_admin') {
      return res.status(403).json({ success: false, message: 'Super admin access required' });
    }
    next();
  });
}

// ========== ROUTES ==========

app.get('/', (req, res) => {
  res.json({
    message: '🎯 UYEH TECH Support System v1.0',
    features: [
      '✅ Real-time WebSocket chat',
      '✅ Desktop notifications',
      '✅ File attachments',
      '✅ Canned responses',
      '✅ Agent management',
      '✅ Ticket system',
      '✅ Live chat widget',
      '✅ Internal notes',
      '✅ Agent status tracking',
      '✅ Performance metrics'
    ]
  });
});

// ========== AGENT AUTHENTICATION ==========

app.post('/api/support/agent/signup', async (req, res) => {
  try {
    const { fullName, email, password, signupKey } = req.body;

    // Verify email is allowed
    if (!ALLOWED_AGENT_EMAILS.includes(email.toLowerCase())) {
      return res.status(403).json({
        success: false,
        message: 'Email not authorized for agent account'
      });
    }

    // Check if already exists
    const existing = await SupportAgent.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Agent already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Determine role
    const role = email.toLowerCase() === ADMIN_EMAIL ? 'super_admin' : 'agent';

    const agent = new SupportAgent({
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      role,
      isActive: true
    });

    await agent.save();

    const token = jwt.sign({ agentId: agent._id, role: agent.role }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Agent account created',
      token,
      agent: {
        id: agent._id,
        name: agent.fullName,
        email: agent.email,
        role: agent.role
      }
    });
  } catch (error) {
    console.error('Agent signup error:', error);
    res.status(500).json({ success: false, message: 'Signup failed' });
  }
});

app.post('/api/support/agent/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const agent = await SupportAgent.findOne({ email: email.toLowerCase() });
    if (!agent) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (!agent.isActive) {
      return res.status(403).json({ success: false, message: 'Account deactivated' });
    }

    const isValid = await bcrypt.compare(password, agent.password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    agent.lastSeen = new Date();
    await agent.save();

    const token = jwt.sign({ agentId: agent._id, role: agent.role }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      agent: {
        id: agent._id,
        name: agent.fullName,
        email: agent.email,
        role: agent.role,
        status: agent.status,
        avatar: agent.avatar
      }
    });
  } catch (error) {
    console.error('Agent login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.get('/api/support/agent/verify', authenticateAgent, (req, res) => {
  res.json({
    success: true,
    agent: {
      id: req.agent._id,
      name: req.agent.fullName,
      email: req.agent.email,
      role: req.agent.role,
      status: req.agent.status
    }
  });
});

// ========== AGENT MANAGEMENT (Super Admin) ==========

app.get('/api/support/admin/agents', authenticateSuperAdmin, async (req, res) => {
  try {
    const agents = await SupportAgent.find().select('-password').sort({ createdAt: -1 });
    res.json({ success: true, agents });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch agents' });
  }
});

app.post('/api/support/admin/agents/create', authenticateSuperAdmin, async (req, res) => {
  try {
    const { fullName, email, password, department } = req.body;

    if (!ALLOWED_AGENT_EMAILS.includes(email.toLowerCase())) {
      return res.status(403).json({ success: false, message: 'Email not in allowed list' });
    }

    const existing = await SupportAgent.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Agent already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const agent = new SupportAgent({
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      department,
      role: 'agent',
      createdBy: req.agent._id
    });

    await agent.save();

    res.status(201).json({
      success: true,
      message: 'Agent created',
      agent: {
        id: agent._id,
        name: agent.fullName,
        email: agent.email
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Creation failed' });
  }
});

app.put('/api/support/admin/agents/:agentId/toggle', authenticateSuperAdmin, async (req, res) => {
  try {
    const agent = await SupportAgent.findById(req.params.agentId);
    if (!agent) {
      return res.status(404).json({ success: false, message: 'Agent not found' });
    }

    if (agent.role === 'super_admin') {
      return res.status(403).json({ success: false, message: 'Cannot deactivate super admin' });
    }

    agent.isActive = !agent.isActive;
    await agent.save();

    res.json({
      success: true,
      message: agent.isActive ? 'Agent activated' : 'Agent deactivated',
      agent: { id: agent._id, isActive: agent.isActive }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/support/admin/agents/:agentId', authenticateSuperAdmin, async (req, res) => {
  try {
    const agent = await SupportAgent.findById(req.params.agentId);
    if (!agent) {
      return res.status(404).json({ success: false, message: 'Agent not found' });
    }

    if (agent.role === 'super_admin') {
      return res.status(403).json({ success: false, message: 'Cannot delete super admin' });
    }

    await SupportAgent.findByIdAndDelete(req.params.agentId);

    res.json({ success: true, message: 'Agent deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Deletion failed' });
  }
});

// ========== TICKET MANAGEMENT ==========

app.get('/api/support/tickets', authenticateAgent, async (req, res) => {
  try {
    const { status, priority, assignedTo, search, limit = 50 } = req.query;

    let query = {};
    if (status && status !== 'all') query.status = status;
    if (priority && priority !== 'all') query.priority = priority;
    if (assignedTo && assignedTo !== 'all') query.assignedTo = assignedTo;
    
    if (search) {
      query.$or = [
        { ticketNumber: { $regex: search, $options: 'i' } },
        { customerName: { $regex: search, $options: 'i' } },
        { customerEmail: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } }
      ];
    }

    const tickets = await SupportTicket.find(query)
      .populate('assignedTo', 'fullName email avatar')
      .sort({ updatedAt: -1 })
      .limit(parseInt(limit));

    res.json({ success: true, tickets, count: tickets.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tickets' });
  }
});

app.get('/api/support/tickets/:ticketId', authenticateAgent, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.ticketId)
      .populate('assignedTo', 'fullName email avatar');

    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    res.json({ success: true, ticket });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch ticket' });
  }
});

app.post('/api/support/tickets/create', async (req, res) => {
  try {
    const { customerName, customerEmail, subject, message, category, metadata } = req.body;

    const ticketNumber = 'TKT-' + Date.now();

    const ticket = new SupportTicket({
      ticketNumber,
      customerName,
      customerEmail,
      subject,
      category: category || 'general',
      messages: [{
        sender: 'customer',
        senderName: customerName,
        message
      }],
      metadata: metadata || {}
    });

    await ticket.save();

    // Notify all agents
    io.emit('ticket:new', { ticket });

    res.status(201).json({
      success: true,
      message: 'Ticket created',
      ticket: { id: ticket._id, ticketNumber: ticket.ticketNumber }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create ticket' });
  }
});

app.put('/api/support/tickets/:ticketId/assign', authenticateAgent, async (req, res) => {
  try {
    const { assignedTo } = req.body;

    const ticket = await SupportTicket.findById(req.params.ticketId);
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.assignedTo = assignedTo;
    ticket.status = 'in_progress';
    ticket.updatedAt = new Date();
    await ticket.save();

    // Update agent stats
    if (assignedTo) {
      await SupportAgent.findByIdAndUpdate(assignedTo, {
        $inc: { 'stats.totalTickets': 1 }
      });
    }

    io.emit('ticket:update', { ticketId: ticket._id, ticket });

    res.json({ success: true, message: 'Ticket assigned', ticket });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Assignment failed' });
  }
});

app.put('/api/support/tickets/:ticketId/status', authenticateAgent, async (req, res) => {
  try {
    const { status } = req.body;

    const ticket = await SupportTicket.findById(req.params.ticketId);
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.status = status;
    ticket.updatedAt = new Date();

    if (status === 'resolved') {
      ticket.resolvedAt = new Date();
      if (ticket.assignedTo) {
        await SupportAgent.findByIdAndUpdate(ticket.assignedTo, {
          $inc: { 'stats.resolvedTickets': 1 }
        });
      }
    } else if (status === 'closed') {
      ticket.closedAt = new Date();
    }

    await ticket.save();

    io.emit('ticket:update', { ticketId: ticket._id, ticket });

    res.json({ success: true, message: 'Status updated', ticket });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.post('/api/support/tickets/:ticketId/reply', authenticateAgent, async (req, res) => {
  try {
    const { message, isInternal } = req.body;

    const ticket = await SupportTicket.findById(req.params.ticketId);
    if (!ticket) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }

    ticket.messages.push({
      sender: 'agent',
      senderName: req.agent.fullName,
      message,
      isInternal: isInternal || false
    });

    if (!ticket.firstResponseAt) {
      ticket.firstResponseAt = new Date();
    }

    ticket.updatedAt = new Date();
    await ticket.save();

    io.emit('ticket:update', { ticketId: ticket._id, ticket });

    res.json({ success: true, message: 'Reply added', ticket });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Reply failed' });
  }
});

app.post('/api/support/tickets/:ticketId/tags', authenticateAgent, async (req, res) => {
  try {
    const { tags } = req.body;

    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.ticketId,
      { $set: { tags }, updatedAt: new Date() },
      { new: true }
    );

    io.emit('ticket:update', { ticketId: ticket._id, ticket });

    res.json({ success: true, message: 'Tags updated', ticket });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/support/tickets/:ticketId', authenticateSuperAdmin, async (req, res) => {
  try {
    await SupportTicket.findByIdAndDelete(req.params.ticketId);
    res.json({ success: true, message: 'Ticket deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Deletion failed' });
  }
});

// Bulk actions
app.post('/api/support/tickets/bulk-action', authenticateAgent, async (req, res) => {
  try {
    const { ticketIds, action, value } = req.body;

    let updateData = {};
    if (action === 'assign') updateData.assignedTo = value;
    else if (action === 'status') updateData.status = value;
    else if (action === 'priority') updateData.priority = value;

    updateData.updatedAt = new Date();

    await SupportTicket.updateMany(
      { _id: { $in: ticketIds } },
      { $set: updateData }
    );

    res.json({ success: true, message: `Bulk ${action} completed` });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Bulk action failed' });
  }
});

// ========== FILE UPLOAD ==========
app.post('/api/support/upload', authenticateAgent, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const fileUrl = `/uploads/${req.file.filename}`;

    res.json({
      success: true,
      file: {
        filename: req.file.originalname,
        url: fileUrl,
        size: req.file.size
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Upload failed' });
  }
});

// ========== CANNED RESPONSES ==========

app.get('/api/support/canned-responses', authenticateAgent, async (req, res) => {
  try {
    const responses = await CannedResponse.find().sort({ title: 1 });
    res.json({ success: true, responses });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch responses' });
  }
});

app.post('/api/support/canned-responses', authenticateAgent, async (req, res) => {
  try {
    const { title, shortcut, message, category } = req.body;

    const response = new CannedResponse({
      title,
      shortcut: shortcut.toUpperCase(),
      message,
      category,
      createdBy: req.agent._id
    });

    await response.save();

    res.status(201).json({ success: true, message: 'Canned response created', response });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Creation failed' });
  }
});

app.delete('/api/support/canned-responses/:id', authenticateAgent, async (req, res) => {
  try {
    await CannedResponse.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Canned response deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Deletion failed' });
  }
});

// ========== CHAT WIDGET API ==========

app.post('/api/support/widget/session/start', async (req, res) => {
  try {
    const { customerName, customerEmail, metadata } = req.body;

    const sessionId = 'session-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);

    const session = new ChatSession({
      sessionId,
      customerName,
      customerEmail,
      metadata: metadata || {}
    });

    await session.save();

    res.json({ success: true, sessionId });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to start session' });
  }
});

app.get('/api/support/widget/sessions', authenticateAgent, async (req, res) => {
  try {
    const { status = 'active' } = req.query;

    const sessions = await ChatSession.find({ status })
      .sort({ lastMessageAt: -1 })
      .limit(50);

    res.json({ success: true, sessions });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch sessions' });
  }
});

app.get('/api/support/widget/sessions/:sessionId', async (req, res) => {
  try {
    const session = await ChatSession.findOne({ sessionId: req.params.sessionId });

    if (!session) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }

    res.json({ success: true, session });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch session' });
  }
});

app.post('/api/support/widget/sessions/:sessionId/convert', authenticateAgent, async (req, res) => {
  try {
    const session = await ChatSession.findOne({ sessionId: req.params.sessionId });

    if (!session) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }

    const ticketNumber = 'TKT-' + Date.now();

    const ticket = new SupportTicket({
      ticketNumber,
      customerName: session.customerName,
      customerEmail: session.customerEmail,
      subject: 'Chat conversation',
      messages: session.messages,
      sessionId: session.sessionId,
      assignedTo: req.agent._id
    });

    await ticket.save();

    session.status = 'closed';
    await session.save();

    res.json({
      success: true,
      message: 'Converted to ticket',
      ticket: { id: ticket._id, ticketNumber: ticket.ticketNumber }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Conversion failed' });
  }
});

// ========== DASHBOARD STATS ==========

app.get('/api/support/dashboard/stats', authenticateAgent, async (req, res) => {
  try {
    const totalTickets = await SupportTicket.countDocuments();
    const openTickets = await SupportTicket.countDocuments({ status: 'open' });
    const inProgressTickets = await SupportTicket.countDocuments({ status: 'in_progress' });
    const resolvedTickets = await SupportTicket.countDocuments({ status: 'resolved' });
    const activeSessions = await ChatSession.countDocuments({ status: 'active' });
    const totalAgents = await SupportAgent.countDocuments({ isActive: true });
    const onlineAgents = await SupportAgent.countDocuments({ status: 'online', isActive: true });

    // Recent tickets
    const recentTickets = await SupportTicket.find()
      .populate('assignedTo', 'fullName avatar')
      .sort({ createdAt: -1 })
      .limit(10);

    // Agent performance
    const agentStats = await SupportAgent.find({ isActive: true })
      .select('fullName email stats status')
      .sort({ 'stats.resolvedTickets': -1 })
      .limit(5);

    res.json({
      success: true,
      stats: {
        totalTickets,
        openTickets,
        inProgressTickets,
        resolvedTickets,
        activeSessions,
        totalAgents,
        onlineAgents,
        recentTickets,
        agentStats
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

// ========== AGENT STATUS UPDATE ==========

app.put('/api/support/agent/status', authenticateAgent, async (req, res) => {
  try {
    const { status } = req.body; // online, offline, away

    req.agent.status = status;
    req.agent.lastSeen = new Date();
    await req.agent.save();

    io.emit('agent:status', { agentId: req.agent._id, status });

    res.json({ success: true, message: 'Status updated', status });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

// ========== START SERVER ==========
server.listen(PORT, () => {
  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║      🎯 UYEH TECH SUPPORT SYSTEM v1.0 - LIVE               ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🔌 WebSocket: Active`);
  console.log(`📧 Admin: ${ADMIN_EMAIL}`);
  console.log(`👥 Agents: ${ALLOWED_AGENT_EMAILS.join(', ')}\n`);
  console.log('✅ Real-time chat enabled');
  console.log('✅ Desktop notifications ready');
  console.log('✅ File uploads configured\n');
});

// ========== END OF SERVER ==========
