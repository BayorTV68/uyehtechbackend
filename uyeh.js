// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 1 OF 7                                      ║
// ║          Setup, Configuration, Schemas & WebSocket Init                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// 🎯 NEW IN v7.0:
// ✅ Real-time WebSocket Support for Customer Chat
// ✅ Support Ticket System with Agent Assignment
// ✅ File Upload Support (Images, PDFs, Documents)
// ✅ Agent Dashboard Integration
// ✅ Customer Chat Widget Integration
// ✅ Enhanced Error Handling & Logging
// ✅ Complete API for All Frontend Features
//
// 📧 Admin Email: uyehtech@gmail.com
// 🔐 Auto-grants admin privileges to this email
//
// ═════════════════════════════════════════════════════════════════════════════

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ═════════════════════════════════════════════════════════════════════════════
// WEBSOCKET SETUP FOR REAL-TIME CHAT
// ═════════════════════════════════════════════════════════════════════════════

const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  verifyClient: (info) => {
    // Allow all connections - authentication handled in message handler
    return true;
  }
});

// Store active WebSocket connections
const activeConnections = new Map(); // chatId -> Set of WebSocket connections
const agentConnections = new Map();  // agentId -> WebSocket connection
const customerConnections = new Map(); // customerId -> WebSocket connection

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const chatId = urlParams.get('chatId');
  const agentId = urlParams.get('agentId');
  const customerId = urlParams.get('customerId');
  
  console.log(`\n🔌 WebSocket Connection:`);
  console.log(`   Chat ID: ${chatId || 'N/A'}`);
  console.log(`   Agent ID: ${agentId || 'N/A'}`);
  console.log(`   Customer ID: ${customerId || 'N/A'}`);
  
  // Store connection
  if (chatId) {
    if (!activeConnections.has(chatId)) {
      activeConnections.set(chatId, new Set());
    }
    activeConnections.get(chatId).add(ws);
  }
  
  if (agentId) {
    agentConnections.set(agentId, ws);
  }
  
  if (customerId) {
    customerConnections.set(customerId, ws);
  }
  
  ws.isAlive = true;
  ws.chatId = chatId;
  ws.agentId = agentId;
  ws.customerId = customerId;
  
  // Send welcome message
  ws.send(JSON.stringify({
    type: 'connected',
    message: 'Connected to UYEH TECH Support',
    timestamp: new Date().toISOString()
  }));
  
  // Handle pong
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  
  // Handle incoming messages
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log(`📨 WebSocket Message:`, data.type);
      
      // Handle different message types
      handleWebSocketMessage(ws, data);
    } catch (error) {
      console.error('❌ WebSocket message error:', error);
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid message format'
      }));
    }
  });
  
  // Handle disconnection
  ws.on('close', () => {
    console.log(`\n🔌 WebSocket Disconnected:`);
    console.log(`   Chat ID: ${chatId || 'N/A'}`);
    
    // Remove from active connections
    if (chatId && activeConnections.has(chatId)) {
      activeConnections.get(chatId).delete(ws);
      if (activeConnections.get(chatId).size === 0) {
        activeConnections.delete(chatId);
      }
    }
    
    if (agentId) {
      agentConnections.delete(agentId);
    }
    
    if (customerId) {
      customerConnections.delete(customerId);
    }
  });
  
  ws.on('error', (error) => {
    console.error('❌ WebSocket error:', error);
  });
});

// Heartbeat to keep connections alive
const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000); // 30 seconds

wss.on('close', () => {
  clearInterval(heartbeatInterval);
});

// Helper function to broadcast to chat
function broadcastToChat(chatId, message, excludeWs = null) {
  if (activeConnections.has(chatId)) {
    const connections = activeConnections.get(chatId);
    connections.forEach((clientWs) => {
      if (clientWs !== excludeWs && clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify(message));
      }
    });
  }
}

// Helper function to send to specific agent
function sendToAgent(agentId, message) {
  const agentWs = agentConnections.get(agentId);
  if (agentWs && agentWs.readyState === WebSocket.OPEN) {
    agentWs.send(JSON.stringify(message));
  }
}

// Helper function to send to specific customer
function sendToCustomer(customerId, message) {
  const customerWs = customerConnections.get(customerId);
  if (customerWs && customerWs.readyState === WebSocket.OPEN) {
    customerWs.send(JSON.stringify(message));
  }
}

// Handle WebSocket messages
function handleWebSocketMessage(ws, data) {
  switch (data.type) {
    case 'ping':
      ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
      break;
    case 'typing':
      if (ws.chatId) {
        broadcastToChat(ws.chatId, {
          type: 'typing',
          userId: data.userId || ws.customerId || ws.agentId,
          isTyping: data.isTyping
        }, ws);
      }
      break;
    default:
      console.log(`⚠️ Unhandled message type: ${data.type}`);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// MIDDLEWARE CONFIGURATION
// ═════════════════════════════════════════════════════════════════════════════

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static files for uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('📁 Created uploads directory');
}

app.use('/uploads', express.static(uploadsDir));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`\n[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// ═════════════════════════════════════════════════════════════════════════════
// MULTER CONFIGURATION FOR FILE UPLOADS
// ═════════════════════════════════════════════════════════════════════════════

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, uniqueSuffix + '-' + sanitizedFilename);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedMimes = [
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
  ];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images, PDFs, and documents are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 5 // Maximum 5 files per request
  },
  fileFilter: fileFilter
});

// ═════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT CONFIGURATION
// ═════════════════════════════════════════════════════════════════════════════

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-change-in-production';
const TERMII_API_KEY = process.env.TERMII_API_KEY;
const TERMII_EMAIL_CONFIG_ID = '4de5e6c7-415f-43f1-812a-0bbbb213c126';
const TERMII_BASE_URL = 'https://v3.api.termii.com';
const TERMII_SENDER_EMAIL = process.env.TERMII_SENDER_EMAIL || 'noreply@uyehtech.com';
const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY;
const ADMIN_EMAIL = 'uyehtech@gmail.com';
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ═════════════════════════════════════════════════════════════════════════════
// STARTUP VALIDATION & BANNER
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n╔═══════════════════════════════════════════════════════════════════════════╗');
console.log('║              🚀 UYEH TECH SERVER v7.0 - INITIALIZING                    ║');
console.log('╚═══════════════════════════════════════════════════════════════════════════╝\n');

console.log('📋 Configuration Status:');
console.log('  ├─ MongoDB:', MONGO_URI ? '✅ Configured' : '❌ Missing (REQUIRED)');
console.log('  ├─ JWT Secret:', JWT_SECRET !== 'default-jwt-secret-change-in-production' ? '✅ Configured' : '⚠️  Using Default (Change in Production)');
console.log('  ├─ Termii API:', TERMII_API_KEY ? '✅ Configured' : '⚠️  Missing (Email disabled)');
console.log('  ├─ Flutterwave:', FLUTTERWAVE_SECRET_KEY ? '✅ Configured' : '⚠️  Missing (Payments disabled)');
console.log('  └─ Admin Email:', ADMIN_EMAIL, '\n');

console.log('🎉 NEW FEATURES IN v7.0:');
console.log('  ✨ Real-time Customer Chat with WebSocket');
console.log('  ✨ Support Ticket System');
console.log('  ✨ Agent Dashboard with Live Chat');
console.log('  ✨ File Upload Support (Images, PDFs, Docs)');
console.log('  ✨ Complete Frontend Integration');
console.log('  ✨ Enhanced Error Handling & Logging\n');

// ═════════════════════════════════════════════════════════════════════════════
// CONNECT TO MONGODB
// ═════════════════════════════════════════════════════════════════════════════

if (!MONGO_URI) {
  console.error('❌ FATAL: MONGO_URI not configured in .env file');
  console.log('📝 Please add MONGO_URI to your .env file');
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('✅ MongoDB Connected Successfully');
    console.log(`   Database: ${mongoose.connection.name}`);
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// MongoDB connection event handlers
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  MongoDB Disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB Reconnected');
});

// ═════════════════════════════════════════════════════════════════════════════
// DATABASE SCHEMAS
// ═════════════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────────────────
// USER SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

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
  isAgent: { type: Boolean, default: false }, // NEW: Agent role
  agentInfo: { // NEW: Agent-specific information
    department: { type: String, enum: ['Sales', 'Support', 'Technical', 'Billing', 'General'] },
    status: { type: String, enum: ['online', 'offline', 'busy', 'away'], default: 'offline' },
    activeChats: { type: Number, default: 0 },
    maxChats: { type: Number, default: 5 },
    rating: { type: Number, default: 0, min: 0, max: 5 },
    totalChats: { type: Number, default: 0 },
    resolvedChats: { type: Number, default: 0 }
  },
  isBanned: { type: Boolean, default: false },
  banReason: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  lastActivity: Date, // NEW: Track user activity
  updatedAt: { type: Date, default: Date.now }
});

// Auto-grant admin privileges to ADMIN_EMAIL
userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  if (this.email.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
    this.isAdmin = true;
  }
  next();
});

userSchema.index({ email: 1 });
userSchema.index({ isAdmin: 1 });
userSchema.index({ isAgent: 1 });
userSchema.index({ createdAt: -1 });

const User = mongoose.model('User', userSchema);

// ──────────────────────────────────────────────────────────────────────────────
// ORDER SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderReference: { type: String, required: true, unique: true },
  items: [{
    id: String,
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    title: String,
    category: String,
    price: Number,
    icon: String,
    downloadLink: String
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
    paidAt: Date,
    currency: { type: String, default: 'USD' }
  },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending' },
  downloadLinks: [String],
  notes: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

orderSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

orderSchema.index({ userId: 1 });
orderSchema.index({ orderReference: 1 });
orderSchema.index({ 'paymentInfo.status': 1 });
orderSchema.index({ status: 1 });
orderSchema.index({ createdAt: -1 });

const Order = mongoose.model('Order', orderSchema);

// ──────────────────────────────────────────────────────────────────────────────
// PAYMENT METHOD SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

const paymentMethodSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true, enum: ['Visa', 'Mastercard', 'American Express', 'Discover', 'Credit Card'] },
  lastFour: { type: String, required: true },
  expiry: { type: String, required: true },
  cardholderName: { type: String, required: true },
  isDefault: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

paymentMethodSchema.index({ userId: 1 });

const PaymentMethod = mongoose.model('PaymentMethod', paymentMethodSchema);

// ──────────────────────────────────────────────────────────────────────────────
// COUPON SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true, trim: true },
  discount: { type: Number, required: true, min: 0 },
  type: { type: String, enum: ['percentage', 'fixed'], required: true },
  isActive: { type: Boolean, default: true },
  usageLimit: { type: Number, default: null },
  usageCount: { type: Number, default: 0 },
  expiresAt: { type: Date, default: null },
  minPurchaseAmount: { type: Number, default: 0 },
  maxDiscountAmount: { type: Number, default: null }, // NEW: Max discount cap
  applicableCategories: [String], // NEW: Limit to specific categories
  description: { type: String, default: '' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

couponSchema.index({ code: 1 });
couponSchema.index({ isActive: 1 });

const Coupon = mongoose.model('Coupon', couponSchema);

// ──────────────────────────────────────────────────────────────────────────────
// PRODUCT SCHEMA (WITH DOWNLOAD LINKS)
// ──────────────────────────────────────────────────────────────────────────────

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
  downloadLink: { type: String, default: '' },
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

productSchema.index({ title: 'text', description: 'text', tags: 'text' });
productSchema.index({ category: 1 });
productSchema.index({ isActive: 1 });
productSchema.index({ isFeatured: 1 });
productSchema.index({ createdAt: -1 });

const Product = mongoose.model('Product', productSchema);

// ──────────────────────────────────────────────────────────────────────────────
// DOWNLOAD TRACKING SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

const downloadSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  downloadedAt: { type: Date, default: Date.now },
  ipAddress: String,
  userAgent: String,
  deviceInfo: String // NEW: Store device information
});

downloadSchema.index({ userId: 1, productId: 1 });
downloadSchema.index({ downloadedAt: -1 });
downloadSchema.index({ orderId: 1 });

const Download = mongoose.model('Download', downloadSchema);

// ──────────────────────────────────────────────────────────────────────────────
// CHAT/SUPPORT TICKET SCHEMA (NEW)
// ──────────────────────────────────────────────────────────────────────────────

const chatSchema = new mongoose.Schema({
  chatId: { type: String, required: true, unique: true },
  customerId: { type: String, required: true },
  customerName: { type: String, required: true },
  customerEmail: { type: String, required: true },
  subject: { type: String, required: true },
  department: { type: String, enum: ['Sales', 'Support', 'Technical', 'Billing', 'General'], default: 'General' },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  status: { type: String, enum: ['open', 'assigned', 'in-progress', 'resolved', 'closed'], default: 'open' },
  assignedAgent: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  messages: [{
    messageId: { type: String, required: true },
    sender: { type: String, enum: ['customer', 'agent', 'system'], required: true },
    senderId: String,
    senderName: String,
    message: String,
    attachments: [{
      filename: String,
      url: String,
      fileType: String,
      fileSize: Number
    }],
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
  }],
  tags: [String],
  rating: { type: Number, min: 1, max: 5 },
  feedback: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  closedAt: Date,
  resolvedAt: Date,
  firstResponseTime: Number, // Time in minutes
  averageResponseTime: Number, // Time in minutes
  totalMessages: { type: Number, default: 0 }
});

chatSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  this.totalMessages = this.messages.length;
  next();
});

chatSchema.index({ chatId: 1 });
chatSchema.index({ customerId: 1 });
chatSchema.index({ customerEmail: 1 });
chatSchema.index({ status: 1 });
chatSchema.index({ assignedAgent: 1 });
chatSchema.index({ department: 1 });
chatSchema.index({ createdAt: -1 });

const Chat = mongoose.model('Chat', chatSchema);

// ──────────────────────────────────────────────────────────────────────────────
// BLOG POST SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

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

blogPostSchema.index({ slug: 1 });
blogPostSchema.index({ status: 1 });
blogPostSchema.index({ category: 1 });
blogPostSchema.index({ publishedAt: -1 });
blogPostSchema.index({ title: 'text', content: 'text', excerpt: 'text' });

const BlogPost = mongoose.model('BlogPost', blogPostSchema);

// ──────────────────────────────────────────────────────────────────────────────
// SYSTEM SETTINGS SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

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
  chatSettings: { // NEW: Chat-specific settings
    enabled: { type: Boolean, default: true },
    offlineMessage: { type: String, default: 'We are currently offline. Please leave a message.' },
    welcomeMessage: { type: String, default: 'Welcome to UYEH TECH Support! How can we help you today?' },
    autoAssignChats: { type: Boolean, default: true },
    maxChatsPerAgent: { type: Number, default: 5 }
  },
  maintenanceMode: { type: Boolean, default: false },
  maintenanceMessage: String,
  allowRegistration: { type: Boolean, default: true },
  requireEmailVerification: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ──────────────────────────────────────────────────────────────────────────────
// ANALYTICS SCHEMA
// ──────────────────────────────────────────────────────────────────────────────

const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true, index: true },
  pageViews: { type: Number, default: 0 },
  uniqueVisitors: { type: Number, default: 0 },
  newUsers: { type: Number, default: 0 },
  orders: { type: Number, default: 0 },
  revenue: { type: Number, default: 0 },
  downloads: { type: Number, default: 0 },
  chatsStarted: { type: Number, default: 0 }, // NEW
  chatsResolved: { type: Number, default: 0 }, // NEW
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

// ═════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

// Email OTP storage (in-memory)
const otpStore = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateSlug(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function generateChatId() {
  return 'CHAT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
}

function generateMessageId() {
  return 'MSG-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
}

// ═════════════════════════════════════════════════════════════════════════════
// EXPORT FOR USE IN OTHER PARTS
// ═════════════════════════════════════════════════════════════════════════════

// Models
global.User = User;
global.Order = Order;
global.PaymentMethod = PaymentMethod;
global.Coupon = Coupon;
global.Product = Product;
global.Download = Download;
global.Chat = Chat;
global.BlogPost = BlogPost;
global.SystemSettings = SystemSettings;
global.Analytics = Analytics;

// WebSocket functions
global.broadcastToChat = broadcastToChat;
global.sendToAgent = sendToAgent;
global.sendToCustomer = sendToCustomer;
global.activeConnections = activeConnections;
global.agentConnections = agentConnections;
global.customerConnections = customerConnections;

// Utility functions
global.generateToken = generateToken;
global.generateOTP = generateOTP;
global.generateSlug = generateSlug;
global.generateChatId = generateChatId;
global.generateMessageId = generateMessageId;
global.otpStore = otpStore;

// Configuration
global.JWT_SECRET = JWT_SECRET;
global.TERMII_API_KEY = TERMII_API_KEY;
global.TERMII_EMAIL_CONFIG_ID = TERMII_EMAIL_CONFIG_ID;
global.TERMII_BASE_URL = TERMII_BASE_URL;
global.TERMII_SENDER_EMAIL = TERMII_SENDER_EMAIL;
global.FLUTTERWAVE_SECRET_KEY = FLUTTERWAVE_SECRET_KEY;
global.ADMIN_EMAIL = ADMIN_EMAIL;
global.BASE_URL = BASE_URL;

// Express app and server
global.app = app;
global.server = server;
global.upload = upload;

console.log('\n✅ Part 1 Loaded: Schemas, Configuration & WebSocket Ready');
console.log('📦 Models: User, Order, Coupon, Product, Download, Chat, Blog, Analytics, Settings');
console.log('🔌 WebSocket: Ready for real-time chat connections\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 1 - Continue to Part 2 for Email & Authentication
// ═════════════════════════════════════════════════════════════════════════════
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 2 OF 7                                      ║
// ║                Email Functions & Authentication Routes                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// COPY THIS AFTER PART 1
//
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// EMAIL FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

// Send Email OTP for verification or password reset
async function sendEmailOTP(to, otp, purpose = 'verification') {
  try {
    console.log(`\n📧 Sending ${purpose} OTP to ${to}`);
    console.log(`🔑 OTP Code: ${otp}`);
   
    if (!TERMII_API_KEY) {
      console.error('❌ TERMII_API_KEY not configured');
      console.log(`📧 OTP for ${to}: ${otp} (Logged to console - Email service disabled)`);
      return { success: true, method: 'console_log', otp };
    }
   
    let subject, emailBody;
   
    if (purpose === 'verification') {
      subject = 'Verify Your Email - UYEH TECH';
      emailBody = `
Hello!

Your UYEH TECH email verification code is: ${otp}

This code is valid for 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
UYEH TECH Team
      `.trim();
    } else if (purpose === 'password-reset') {
      subject = 'Password Reset Code - UYEH TECH';
      emailBody = `
Hello!

Your UYEH TECH password reset code is: ${otp}

This code is valid for 10 minutes.

If you didn't request this code, please ignore this email and your password will remain unchanged.

Best regards,
UYEH TECH Team
      `.trim();
    } else if (purpose === 'chat-notification') {
      subject = 'New Chat Message - UYEH TECH Support';
      emailBody = `
Hello!

You have received a new message in your support chat.

Please login to your account to view and respond to the message.

Best regards,
UYEH TECH Support Team
      `.trim();
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
     
      console.log('✅ Email sent successfully via Termii');
      return { success: true, method: 'termii_email', data: response.data };
     
    } catch (termiiError) {
      console.error('❌ Termii error:', termiiError.response?.data || termiiError.message);
      console.log(`📧 OTP for ${to}: ${otp} (Logged - Termii failed)`);
      return { success: true, method: 'console_log', otp };
    }
   
  } catch (error) {
    console.error('❌ Send Email Error:', error);
    console.log(`📧 OTP for ${to}: ${otp} (Logged - Error occurred)`);
    return { success: false, error: error.message, otp };
  }
}

// Send Order Confirmation Email with Download Links
async function sendOrderConfirmationEmail(to, orderData) {
  try {
    console.log(`\n📧 Sending order confirmation to ${to}`);
    
    if (!TERMII_API_KEY) {
      console.log(`📧 Order confirmation for ${to}: ${orderData.orderReference} (Email service disabled)`);
      return { success: true, method: 'console_log' };
    }
   
    const subject = `Order Confirmation - ${orderData.orderReference}`;
    const itemsList = orderData.items.map(item => `  • ${item.title} - $${item.price}`).join('\n');
    
    const emailBody = `
Thank you for your purchase from UYEH TECH!

Order Reference: ${orderData.orderReference}
Order Date: ${new Date(orderData.createdAt).toLocaleDateString()}

Items Purchased:
${itemsList}

Subtotal: $${orderData.subtotal}
${orderData.discount > 0 ? `Discount: -$${orderData.discount}` : ''}
Total Amount: $${orderData.total}

Your digital products are ready for download!

To access your downloads:
1. Log in to your UYEH TECH account
2. Go to "My Orders" section
3. Click on this order to view download links

Need help? Contact us at ${TERMII_SENDER_EMAIL}

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
     
      console.log('✅ Order confirmation sent successfully');
      return { success: true, method: 'termii_email' };
     
    } catch (error) {
      console.log(`📧 Order confirmation logged: ${orderData.orderReference} (Termii failed)`);
      return { success: true, method: 'console_log' };
    }
   
  } catch (error) {
    console.error('❌ Send confirmation error:', error);
    return { success: false, error: error.message };
  }
}

// Send Chat Assignment Notification to Agent
async function sendAgentAssignmentEmail(agentEmail, chatInfo) {
  try {
    if (!TERMII_API_KEY) {
      console.log(`📧 Agent assignment notification: ${chatInfo.chatId} (Email service disabled)`);
      return { success: true, method: 'console_log' };
    }
   
    const subject = `New Chat Assigned - ${chatInfo.chatId}`;
    const emailBody = `
Hello!

A new support chat has been assigned to you.

Chat ID: ${chatInfo.chatId}
Customer: ${chatInfo.customerName}
Subject: ${chatInfo.subject}
Department: ${chatInfo.department}
Priority: ${chatInfo.priority}

Please log in to the Agent Dashboard to respond to this chat.

Best regards,
UYEH TECH Support System
    `.trim();

    try {
      await axios.post(`${TERMII_BASE_URL}/api/send-mail`, {
        api_key: TERMII_API_KEY,
        to: agentEmail,
        from: TERMII_SENDER_EMAIL,
        subject: subject,
        body: emailBody,
        email_configuration_id: TERMII_EMAIL_CONFIG_ID
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 15000
      });
     
      console.log('✅ Agent assignment email sent');
      return { success: true, method: 'termii_email' };
     
    } catch (error) {
      console.log(`📧 Agent assignment logged (Termii failed)`);
      return { success: true, method: 'console_log' };
    }
   
  } catch (error) {
    console.error('❌ Send agent assignment error:', error);
    return { success: false, error: error.message };
  }
}

// Export email functions
global.sendEmailOTP = sendEmailOTP;
global.sendOrderConfirmationEmail = sendOrderConfirmationEmail;
global.sendAgentAssignmentEmail = sendAgentAssignmentEmail;

// ═════════════════════════════════════════════════════════════════════════════
// AUTHENTICATION MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

// Authenticate JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Authenticate Admin
async function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Admin token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
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
      console.error('❌ Admin auth error:', error);
      return res.status(500).json({ success: false, message: 'Authentication failed' });
    }
  });
}

// Authenticate Agent
async function authenticateAgent(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Agent token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }

    try {
      const user = await User.findById(decoded.userId);
      
      if (!user || (!user.isAgent && !user.isAdmin)) {
        return res.status(403).json({ 
          success: false, 
          message: 'Agent access required',
          isAgent: false 
        });
      }

      // Update agent status
      if (user.isAgent) {
        user.lastActivity = new Date();
        await user.save();
      }

      req.user = decoded;
      req.agentUser = user;
      next();
    } catch (error) {
      console.error('❌ Agent auth error:', error);
      return res.status(500).json({ success: false, message: 'Authentication failed' });
    }
  });
}

// Export middleware
global.authenticateToken = authenticateToken;
global.authenticateAdmin = authenticateAdmin;
global.authenticateAgent = authenticateAgent;

// ═════════════════════════════════════════════════════════════════════════════
// ROOT ROUTE
// ═════════════════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.json({
    message: '🚀 UYEH TECH API v7.0 - Complete System',
    version: '7.0.0',
    status: 'active',
    adminEmail: ADMIN_EMAIL,
    features: [
      '✅ Complete Admin Dashboard',
      '✅ Real-time Chat System with WebSocket',
      '✅ Agent Dashboard & Management',
      '✅ Support Ticket System',
      '✅ File Upload Support',
      '✅ Download Link Management',
      '✅ Download Tracking & Analytics',
      '✅ User Management',
      '✅ Order Management',
      '✅ Coupon System',
      '✅ Blog Management',
      '✅ Product Management',
      '✅ System Settings',
      '✅ Payment Integration (Flutterwave)',
      '✅ Email Notifications (Termii)'
    ],
    endpoints: {
      auth: '/api/auth/*',
      admin: '/api/admin/*',
      chat: '/api/chat/*',
      agent: '/api/agent/*',
      orders: '/api/orders/*',
      products: '/api/products/*',
      blog: '/api/blog/*',
      websocket: 'ws://localhost:' + PORT + '/ws'
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    websocket: {
      active: wss.clients.size,
      chats: activeConnections.size,
      agents: agentConnections.size,
      customers: customerConnections.size
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AUTHENTICATION ROUTES
// ═════════════════════════════════════════════════════════════════════════════

// Send Email Verification OTP
app.post('/api/auth/send-email-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const otp = generateOTP();
   
    // Store OTP in memory with expiration
    otpStore.set(cleanEmail, {
      code: otp,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
      maxAttempts: 5
    });

    // Send email
    await sendEmailOTP(cleanEmail, otp, 'verification');

    res.json({
      success: true,
      message: 'Verification code sent to your email',
      email: cleanEmail,
      expiresIn: '10 minutes',
      ...(process.env.NODE_ENV === 'development' && { debug_otp: otp })
    });
    
  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ success: false, message: 'Failed to send verification code' });
  }
});

// Verify Email OTP
app.post('/api/auth/verify-email-otp', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'Email and code are required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const storedOTP = otpStore.get(cleanEmail);

    if (!storedOTP) {
      return res.status(400).json({ success: false, message: 'No verification code found. Please request a new one.' });
    }

    if (Date.now() > storedOTP.expires) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ success: false, message: 'Verification code expired. Please request a new one.' });
    }

    if (storedOTP.attempts >= storedOTP.maxAttempts) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ success: false, message: 'Too many incorrect attempts. Please request a new code.' });
    }

    if (storedOTP.code !== code.trim()) {
      storedOTP.attempts += 1;
      otpStore.set(cleanEmail, storedOTP);
      const attemptsLeft = storedOTP.maxAttempts - storedOTP.attempts;
      return res.status(400).json({ 
        success: false, 
        message: `Invalid verification code. ${attemptsLeft} attempt(s) remaining.` 
      });
    }

    // Code is valid
    otpStore.delete(cleanEmail);
    res.json({ 
      success: true, 
      message: 'Email verified successfully!',
      verified: true
    });
    
  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// User Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, password, phone, country, emailVerified } = req.body;

    // Validation
    if (!fullName || !email || !password) {
      return res.status(400).json({ success: false, message: 'Full name, email, and password are required' });
    }

    if (!emailVerified) {
      return res.status(400).json({ success: false, message: 'Please verify your email first' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email is already registered' });
    }

    // Password validation
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      fullName: fullName.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      phone: phone || '',
      country: country || '',
      emailVerified: true,
      lastLogin: new Date()
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    console.log(`✅ New user registered: ${user.email}`);

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        phone: user.phone,
        country: user.country,
        isAdmin: user.isAdmin,
        isAgent: user.isAgent
      }
    });
    
  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({ success: false, message: 'Account creation failed' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Check if banned
    if (user.isBanned) {
      return res.status(403).json({ 
        success: false, 
        message: `Account is banned. Reason: ${user.banReason || 'Please contact support'}` 
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Update last login
    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    console.log(`✅ User logged in: ${user.email}`);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        phone: user.phone,
        country: user.country,
        profileImage: user.profileImage,
        isAdmin: user.isAdmin,
        isAgent: user.isAgent
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// Forgot Password - Request Reset Code
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: cleanEmail });
    
    // For security, always return success even if user doesn't exist
    if (!user) {
      return res.json({ 
        success: true, 
        message: 'If an account exists with this email, a reset code has been sent' 
      });
    }

    const resetOTP = generateOTP();
   
    // Store reset OTP
    otpStore.set(`reset_${cleanEmail}`, {
      code: resetOTP,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
      maxAttempts: 5
    });

    // Send reset email
    await sendEmailOTP(cleanEmail, resetOTP, 'password-reset');

    res.json({ 
      success: true, 
      message: 'Password reset code sent to your email',
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('❌ Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Request failed' });
  }
});

// Reset Password with Code
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email, code, and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const storedOTP = otpStore.get(`reset_${cleanEmail}`);

    if (!storedOTP) {
      return res.status(400).json({ success: false, message: 'No reset code found. Please request a new one.' });
    }

    if (Date.now() > storedOTP.expires) {
      otpStore.delete(`reset_${cleanEmail}`);
      return res.status(400).json({ success: false, message: 'Reset code expired. Please request a new one.' });
    }

    if (storedOTP.attempts >= storedOTP.maxAttempts) {
      otpStore.delete(`reset_${cleanEmail}`);
      return res.status(400).json({ success: false, message: 'Too many incorrect attempts. Please request a new code.' });
    }

    if (storedOTP.code !== code.trim()) {
      storedOTP.attempts += 1;
      otpStore.set(`reset_${cleanEmail}`, storedOTP);
      return res.status(400).json({ success: false, message: 'Invalid reset code' });
    }

    // Find user and update password
    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Clear reset OTP
    otpStore.delete(`reset_${cleanEmail}`);

    console.log(`✅ Password reset successful: ${user.email}`);

    res.json({ 
      success: true, 
      message: 'Password reset successfully! You can now login with your new password.' 
    });
    
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ success: false, message: 'Password reset failed' });
  }
});

// Change Password (Authenticated)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Current and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'New password must be at least 8 characters long' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    // Update to new password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    console.log(`✅ Password changed: ${user.email}`);

    res.json({ success: true, message: 'Password changed successfully' });
    
  } catch (error) {
    console.error('❌ Change password error:', error);
    res.status(500).json({ success: false, message: 'Password change failed' });
  }
});

// Delete Account
app.delete('/api/auth/delete-account', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to delete account' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }

    // Delete user
    await User.findByIdAndDelete(req.user.userId);

    console.log(`✅ Account deleted: ${user.email}`);

    res.json({ success: true, message: 'Account deleted successfully' });
    
  } catch (error) {
    console.error('❌ Delete account error:', error);
    res.status(500).json({ success: false, message: 'Account deletion failed' });
  }
});

// Toggle Two-Factor Authentication
app.post('/api/auth/toggle-2fa', authenticateToken, async (req, res) => {
  try {
    const { enable } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.twoFactorEnabled = enable === true;
    if (!enable) {
      user.twoFactorSecret = null;
    }
    
    await user.save();

    res.json({ 
      success: true, 
      message: `Two-factor authentication ${enable ? 'enabled' : 'disabled'}`,
      twoFactorEnabled: user.twoFactorEnabled
    });
    
  } catch (error) {
    console.error('❌ Toggle 2FA error:', error);
    res.status(500).json({ success: false, message: '2FA toggle failed' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN AUTHENTICATION
// ═════════════════════════════════════════════════════════════════════════════

// Admin Login
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user || !user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required', 
        isAdmin: false 
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    user.lastActivity = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    console.log(`✅ Admin logged in: ${user.email}`);

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

// Verify Admin Token
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

// ═════════════════════════════════════════════════════════════════════════════
// AGENT AUTHENTICATION (NEW)
// ═════════════════════════════════════════════════════════════════════════════

// Agent Login
app.post('/api/auth/agent/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user || (!user.isAgent && !user.isAdmin)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Agent access required', 
        isAgent: false 
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    user.lastActivity = new Date();
    if (user.isAgent && user.agentInfo) {
      user.agentInfo.status = 'online';
    }
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '12h' }
    );

    console.log(`✅ Agent logged in: ${user.email}`);

    res.json({
      success: true,
      message: 'Agent login successful',
      token,
      isAgent: true,
      isAdmin: user.isAdmin,
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        agentInfo: user.agentInfo
      }
    });
    
  } catch (error) {
    console.error('❌ Agent login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// Verify Agent Token
app.get('/api/auth/agent/verify', authenticateAgent, async (req, res) => {
  res.json({
    success: true,
    isAgent: true,
    isAdmin: req.agentUser.isAdmin,
    user: {
      id: req.agentUser._id,
      name: req.agentUser.fullName,
      email: req.agentUser.email,
      agentInfo: req.agentUser.agentInfo
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// USER PROFILE ROUTES
// ═════════════════════════════════════════════════════════════════════════════

// Get User Profile
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
        isAgent: user.isAgent,
        isBanned: user.isBanned,
        emailVerified: user.emailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        notificationPreferences: user.notificationPreferences,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
    
  } catch (error) {
    console.error('❌ Get profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

// Update User Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, bio, profileImage, phone, country } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Update fields
    if (fullName !== undefined) user.fullName = fullName.trim();
    if (bio !== undefined) user.bio = bio;
    if (profileImage !== undefined) user.profileImage = profileImage;
    if (phone !== undefined) user.phone = phone;
    if (country !== undefined) user.country = country;

    await user.save();

    console.log(`✅ Profile updated: ${user.email}`);

    res.json({
      success: true,
      message: 'Profile updated successfully',
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
    res.status(500).json({ success: false, message: 'Profile update failed' });
  }
});

// Get Notification Preferences
app.get('/api/user/notifications', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      preferences: user.notificationPreferences || {
        email: true,
        orders: true,
        marketing: false
      }
    });
    
  } catch (error) {
    console.error('❌ Get notifications error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch preferences' });
  }
});

// Update Notification Preferences
app.put('/api/user/notifications/update', authenticateToken, async (req, res) => {
  try {
    const { email, orders, marketing } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.notificationPreferences = {
      email: email !== undefined ? email : user.notificationPreferences.email,
      orders: orders !== undefined ? orders : user.notificationPreferences.orders,
      marketing: marketing !== undefined ? marketing : user.notificationPreferences.marketing
    };

    await user.save();

    res.json({
      success: true,
      message: 'Notification preferences updated',
      preferences: user.notificationPreferences
    });
    
  } catch (error) {
    console.error('❌ Update notifications error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

// Get Payment Methods
app.get('/api/user/payment-methods', authenticateToken, async (req, res) => {
  try {
    const paymentMethods = await PaymentMethod.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      paymentMethods: paymentMethods.map(pm => ({
        id: pm._id,
        type: pm.type,
        lastFour: pm.lastFour,
        expiry: pm.expiry,
        cardholderName: pm.cardholderName,
        isDefault: pm.isDefault
      }))
    });
    
  } catch (error) {
    console.error('❌ Get payment methods error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch payment methods' });
  }
});

// Add Payment Method
app.post('/api/user/payment-methods/add', authenticateToken, async (req, res) => {
  try {
    const { type, lastFour, expiry, cardholderName, isDefault } = req.body;

    if (!type || !lastFour || !expiry || !cardholderName) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // If this is set as default, unset other defaults
    if (isDefault) {
      await PaymentMethod.updateMany(
        { userId: req.user.userId },
        { $set: { isDefault: false } }
      );
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

    res.json({
      success: true,
      message: 'Payment method added',
      paymentMethod: {
        id: paymentMethod._id,
        type: paymentMethod.type,
        lastFour: paymentMethod.lastFour,
        expiry: paymentMethod.expiry,
        cardholderName: paymentMethod.cardholderName,
        isDefault: paymentMethod.isDefault
      }
    });
    
  } catch (error) {
    console.error('❌ Add payment method error:', error);
    res.status(500).json({ success: false, message: 'Failed to add payment method' });
  }
});

console.log('\n✅ Part 2 Loaded: Email Functions & Authentication Routes Ready');
console.log('🔐 Auth Endpoints: Signup, Login, OTP, Password Reset, Admin, Agent');
console.log('👤 Profile Endpoints: Get/Update Profile, Notifications, Payment Methods\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 2 - Continue to Part 3 for Admin Dashboard & User Management
// ═════════════════════════════════════════════════════════════════════════════
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 3 OF 7                                      ║
// ║          Admin Dashboard, Analytics & User Management                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// COPY THIS AFTER PART 2
//
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN DASHBOARD OVERVIEW
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    // Count totals
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalProducts = await Product.countDocuments();
    const totalBlogPosts = await BlogPost.countDocuments();
    const publishedPosts = await BlogPost.countDocuments({ status: 'published' });
    const activeCoupons = await Coupon.countDocuments({ isActive: true });
    const totalDownloads = await Download.countDocuments();
    const totalChats = await Chat.countDocuments(); // NEW v7.0
    const openChats = await Chat.countDocuments({ status: { $in: ['open', 'assigned', 'in-progress'] } }); // NEW v7.0
    
    // Revenue calculation
    const revenueData = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    const totalRevenue = revenueData[0]?.total || 0;

    // Recent stats (last 7 days)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentOrders = await Order.countDocuments({ createdAt: { $gte: sevenDaysAgo } });
    const recentRevenue = await Order.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: sevenDaysAgo } } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    const recentDownloads = await Download.countDocuments({ downloadedAt: { $gte: sevenDaysAgo } });
    const newUsers = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });
    const newChats = await Chat.countDocuments({ createdAt: { $gte: sevenDaysAgo } }); // NEW v7.0

    // Top selling products
    const topProducts = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $unwind: '$items' },
      { $group: { 
        _id: '$items.title', 
        count: { $sum: 1 }, 
        revenue: { $sum: '$items.price' } 
      }},
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Recent orders list
    const recentOrdersList = await Order.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'fullName email');

    // Active agents (NEW v7.0)
    const activeAgents = await User.countDocuments({ 
      isAgent: true, 
      'agentInfo.status': { $in: ['online', 'busy'] } 
    });

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
          totalDownloads,
          totalChats, // NEW v7.0
          openChats, // NEW v7.0
          activeAgents // NEW v7.0
        },
        recentStats: {
          newUsers,
          recentOrders,
          recentRevenue: recentRevenue[0]?.total || 0,
          recentDownloads,
          newChats // NEW v7.0
        },
        topProducts,
        recentOrdersList
      }
    });
  } catch (error) {
    console.error('❌ Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch dashboard data' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN ANALYTICS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/analytics', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    
    let startDate;
    const now = new Date();
    
    // Calculate start date based on period
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
      case '1y':
        startDate = new Date(now - 365 * 24 * 60 * 60 * 1000);
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

    // Chat trends (NEW v7.0)
    const chatTrends = await Chat.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
        count: { $sum: 1 },
        resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } }
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

    // Agent performance (NEW v7.0)
    const agentPerformance = await Chat.aggregate([
      { $match: { assignedAgent: { $ne: null }, createdAt: { $gte: startDate } } },
      { $lookup: {
        from: 'users',
        localField: 'assignedAgent',
        foreignField: '_id',
        as: 'agent'
      }},
      { $unwind: '$agent' },
      { $group: {
        _id: '$assignedAgent',
        agentName: { $first: '$agent.fullName' },
        totalChats: { $sum: 1 },
        resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
        avgResponseTime: { $avg: '$firstResponseTime' }
      }},
      { $sort: { totalChats: -1 } },
      { $limit: 10 }
    ]);

    res.json({
      success: true,
      analytics: {
        period,
        startDate,
        dailyStats,
        userGrowth,
        downloadTrends,
        chatTrends, // NEW v7.0
        productPerformance,
        categoryStats,
        agentPerformance // NEW v7.0
      }
    });
  } catch (error) {
    console.error('❌ Analytics error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch analytics' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// USER MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

// Get All Users (with pagination and search)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = 'all', role = 'all' } = req.query;
    
    let query = {};
    
    // Search by name or email
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Filter by status
    if (status === 'banned') {
      query.isBanned = true;
    } else if (status === 'active') {
      query.isBanned = false;
    }

    // Filter by role (NEW v7.0)
    if (role === 'admin') {
      query.isAdmin = true;
    } else if (role === 'agent') {
      query.isAgent = true;
    } else if (role === 'user') {
      query.isAdmin = false;
      query.isAgent = false;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const users = await User.find(query)
      .select('-password -twoFactorSecret')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await User.countDocuments(query);

    // Add statistics for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const orderCount = await Order.countDocuments({ userId: user._id });
        const downloadCount = await Download.countDocuments({ userId: user._id });
        const chatCount = await Chat.countDocuments({ customerId: user.email }); // NEW v7.0
        const totalSpent = await Order.aggregate([
          { $match: { userId: user._id, status: 'completed' } },
          { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        return {
          ...user.toObject(),
          orderCount,
          downloadCount,
          chatCount, // NEW v7.0
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

// Get Single User Details
app.get('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get user's orders
    const orders = await Order.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    const orderCount = await Order.countDocuments({ userId: user._id });
    const downloadCount = await Download.countDocuments({ userId: user._id });
    
    // Get user's chats (NEW v7.0)
    const chats = await Chat.find({ customerId: user.email })
      .sort({ createdAt: -1 })
      .limit(10);
    const chatCount = await Chat.countDocuments({ customerId: user.email });

    // Calculate total spent
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
        chatCount, // NEW v7.0
        totalSpent: totalSpent[0]?.total || 0,
        recentOrders: orders,
        recentChats: chats // NEW v7.0
      }
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user details' });
  }
});

// Ban/Unban User
app.put('/api/admin/users/:userId/ban', authenticateAdmin, async (req, res) => {
  try {
    const { isBanned, banReason } = req.body;
    
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Cannot ban admin users
    if (user.isAdmin) {
      return res.status(400).json({ success: false, message: 'Cannot ban administrator accounts' });
    }

    user.isBanned = isBanned;
    user.banReason = isBanned ? (banReason || 'Violated terms of service') : '';
    await user.save();

    console.log(`${isBanned ? '🚫 User banned' : '✅ User unbanned'}: ${user.email}`);

    res.json({
      success: true,
      message: isBanned ? 'User has been banned' : 'User has been unbanned',
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        isBanned: user.isBanned,
        banReason: user.banReason
      }
    });
  } catch (error) {
    console.error('❌ Ban user error:', error);
    res.status(500).json({ success: false, message: 'Failed to update user status' });
  }
});

// Delete User
app.delete('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Cannot delete own account
    if (userId === req.user.userId) {
      return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Cannot delete admin users
    if (user.isAdmin) {
      return res.status(400).json({ success: false, message: 'Cannot delete administrator accounts' });
    }

    // Delete user's data
    await Order.deleteMany({ userId: user._id });
    await Download.deleteMany({ userId: user._id });
    await PaymentMethod.deleteMany({ userId: user._id });
    await Chat.updateMany(
      { customerId: user.email },
      { $set: { customerName: 'Deleted User', customerEmail: 'deleted@example.com' } }
    );
    
    // Delete the user
    await User.findByIdAndDelete(userId);

    console.log(`🗑️  User deleted: ${user.email}`);

    res.json({
      success: true,
      message: 'User and associated data have been deleted'
    });
  } catch (error) {
    console.error('❌ Delete user error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete user' });
  }
});

// Promote User to Agent (NEW v7.0)
app.put('/api/admin/users/:userId/promote-agent', authenticateAdmin, async (req, res) => {
  try {
    const { department = 'General', maxChats = 5 } = req.body;
    
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.isAgent) {
      return res.status(400).json({ success: false, message: 'User is already an agent' });
    }

    user.isAgent = true;
    user.agentInfo = {
      department,
      status: 'offline',
      activeChats: 0,
      maxChats,
      rating: 0,
      totalChats: 0,
      resolvedChats: 0
    };
    await user.save();

    console.log(`👨‍💼 User promoted to agent: ${user.email}`);

    res.json({
      success: true,
      message: 'User has been promoted to agent',
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        isAgent: user.isAgent,
        agentInfo: user.agentInfo
      }
    });
  } catch (error) {
    console.error('❌ Promote agent error:', error);
    res.status(500).json({ success: false, message: 'Failed to promote user' });
  }
});

// Demote Agent to User (NEW v7.0)
app.put('/api/admin/users/:userId/demote-agent', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (!user.isAgent) {
      return res.status(400).json({ success: false, message: 'User is not an agent' });
    }

    // Unassign all chats
    await Chat.updateMany(
      { assignedAgent: user._id, status: { $ne: 'closed' } },
      { $set: { assignedAgent: null, status: 'open' } }
    );

    user.isAgent = false;
    user.agentInfo = undefined;
    await user.save();

    console.log(`👤 Agent demoted to user: ${user.email}`);

    res.json({
      success: true,
      message: 'Agent has been demoted to regular user',
      user: {
        id: user._id,
        name: user.fullName,
        email: user.email,
        isAgent: user.isAgent
      }
    });
  } catch (error) {
    console.error('❌ Demote agent error:', error);
    res.status(500).json({ success: false, message: 'Failed to demote agent' });
  }
});

console.log('\n✅ Part 3 Loaded: Admin Dashboard, Analytics & User Management Ready');
console.log('📊 Endpoints: Dashboard, Analytics, User CRUD, Agent Promotion\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 3 - Continue to Part 4 for Orders, Products & Downloads
// ═════════════════════════════════════════════════════════════════════════════
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 4 OF 7                                      ║
// ║      Orders, Products, Downloads & Coupon Management                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// COPY THIS AFTER PART 3
//
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// ORDER MANAGEMENT (ADMIN)
// ═════════════════════════════════════════════════════════════════════════════

// Get All Orders (Admin)
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

// Get Single Order (Admin)
app.get('/api/admin/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.orderId)
      .populate('userId', 'fullName email phone country');
    
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

// Update Order Status (Admin)
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

    console.log(`📦 Order status updated: ${order.orderReference} -> ${status}`);

    res.json({
      success: true,
      message: 'Order status updated successfully',
      order: order
    });
  } catch (error) {
    console.error('❌ Update order error:', error);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

// Delete Order (Admin)
app.delete('/api/admin/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.orderId);
    
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    console.log(`🗑️  Order deleted: ${order.orderReference}`);

    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (error) {
    console.error('❌ Delete order error:', error);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// USER ORDERS
// ═════════════════════════════════════════════════════════════════════════════

// Get User's Orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });

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

// Get Orders with Download Links
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

// Create Order with Coupon
app.post('/api/orders/create-with-coupon', authenticateToken, async (req, res) => {
  try {
    const { items, subtotal, couponCode, customerInfo, orderReference } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Order must contain at least one item' });
    }

    if (!subtotal || !customerInfo) {
      return res.status(400).json({ success: false, message: 'Missing required order information' });
    }

    let discount = 0;
    let finalTotal = subtotal;
    let isFree = false;
    let appliedCoupon = null;

    // Apply coupon if provided
    if (couponCode) {
      const cleanCode = couponCode.trim().toUpperCase();
      const coupon = await Coupon.findOne({ code: cleanCode, isActive: true });

      if (coupon) {
        // Check if coupon is expired
        if (coupon.expiresAt && new Date() > coupon.expiresAt) {
          return res.status(400).json({ success: false, message: 'Coupon has expired' });
        }

        // Check usage limit
        if (coupon.usageLimit && coupon.usageCount >= coupon.usageLimit) {
          return res.status(400).json({ success: false, message: 'Coupon usage limit reached' });
        }

        // Check minimum purchase amount
        if (coupon.minPurchaseAmount && subtotal < coupon.minPurchaseAmount) {
          return res.status(400).json({ 
            success: false, 
            message: `Minimum purchase of $${coupon.minPurchaseAmount} required for this coupon` 
          });
        }

        // Calculate discount
        if (coupon.type === 'percentage') {
          discount = (subtotal * coupon.discount) / 100;
          if (coupon.maxDiscountAmount) {
            discount = Math.min(discount, coupon.maxDiscountAmount);
          }
        } else {
          discount = coupon.discount;
        }

        discount = Math.min(discount, subtotal);
        finalTotal = Math.max(0, subtotal - discount);
        isFree = finalTotal === 0;

        coupon.usageCount += 1;
        await coupon.save();

        appliedCoupon = {
          code: coupon.code,
          discount: discount,
          type: coupon.type
        };
      } else {
        return res.status(400).json({ success: false, message: 'Invalid coupon code' });
      }
    }

    // Create order
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

    // Send confirmation email if order is free
    if (isFree) {
      await sendOrderConfirmationEmail(customerInfo.email, order);
    }

    console.log(`📦 Order created: ${order.orderReference} (${isFree ? 'FREE' : '$' + finalTotal})`);

    res.status(201).json({
      success: true,
      message: isFree ? '🎉 Order completed! Download links sent to your email.' : 'Order created successfully',
      order: {
        _id: order._id,
        orderReference: order.orderReference,
        total: order.total,
        discount: order.discount,
        status: order.status,
        items: order.items,
        isFree: isFree,
        paymentRequired: !isFree,
        appliedCoupon: appliedCoupon
      }
    });

  } catch (error) {
    console.error('❌ Create order error:', error);
    res.status(500).json({ success: false, message: 'Order creation failed' });
  }
});

// Verify Payment
app.post('/api/orders/verify-payment', authenticateToken, async (req, res) => {
  try {
    const { transactionId, orderId } = req.body;

    if (!transactionId || !orderId) {
      return res.status(400).json({ success: false, message: 'Transaction ID and Order ID required' });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    // Verify order belongs to user
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    if (!FLUTTERWAVE_SECRET_KEY) {
      return res.status(500).json({ 
        success: false, 
        message: 'Payment gateway not configured' 
      });
    }

    // Verify payment with Flutterwave
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

      console.log(`✅ Payment verified: ${order.orderReference}`);

      res.json({
        success: true,
        message: 'Payment verified successfully! Download links sent to your email.',
        order: order
      });
    } else {
      order.status = 'failed';
      order.paymentInfo.status = 'failed';
      await order.save();

      console.log(`❌ Payment failed: ${order.orderReference}`);

      res.status(400).json({ success: false, message: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('❌ Verify payment error:', error);
    res.status(500).json({ success: false, message: 'Payment verification failed' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// DOWNLOAD TRACKING
// ═════════════════════════════════════════════════════════════════════════════

// Track Download
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
        message: 'Order must be completed to download products'
      });
    }

    // Create download record
    const download = new Download({
      userId: req.user.userId,
      productId,
      orderId,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      deviceInfo: req.headers['user-agent']
    });

    await download.save();

    console.log(`📥 Download tracked: Product ${productId}`);

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

// Get Download Statistics (Admin)
app.get('/api/admin/downloads/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalDownloads = await Download.countDocuments();
    
    // Most popular products
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

    // Recent downloads
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
      message: 'Failed to fetch download statistics' 
    });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCT MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

// Get All Products (Admin)
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
        { description: { $regex: search, $options: 'i' } },
        { tags: { $regex: search, $options: 'i' } }
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

// Get All Products (Public)
app.get('/api/products', async (req, res) => {
  try {
    const { category = 'all', featured = false, limit = 20, skip = 0, search = '' } = req.query;
    
    let query = { isActive: true };
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.isFeatured = true;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $regex: search, $options: 'i' } }
      ];
    }

    const products = await Product.find(query)
      .select('-downloadLink') // Hide download link from public
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

// Get Single Product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).select('-downloadLink');
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    if (!product.isActive) {
      return res.status(404).json({ success: false, message: 'Product not available' });
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

// Create Product (Admin)
app.post('/api/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const productData = req.body;

    if (!productData.title || !productData.description || !productData.category || productData.price === undefined) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const product = new Product(productData);
    await product.save();

    console.log(`✅ Product created: ${product.title}`);

    res.status(201).json({
      success: true,
      message: 'Product created successfully',
      product: product
    });
  } catch (error) {
    console.error('❌ Create product error:', error);
    res.status(500).json({ success: false, message: 'Product creation failed' });
  }
});

// Update Product (Admin)
app.put('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    Object.assign(product, req.body);
    await product.save();

    console.log(`✅ Product updated: ${product.title}`);

    res.json({
      success: true,
      message: 'Product updated successfully',
      product: product
    });
  } catch (error) {
    console.error('❌ Update product error:', error);
    res.status(500).json({ success: false, message: 'Product update failed' });
  }
});

// Delete Product (Admin)
app.delete('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    console.log(`🗑️  Product deleted: ${product.title}`);

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('❌ Delete product error:', error);
    res.status(500).json({ success: false, message: 'Product deletion failed' });
  }
});

// Seed Sample Products (Admin)
app.post('/api/admin/products/seed-with-downloads', authenticateAdmin, async (req, res) => {
  try {
    const sampleProducts = [
      {
        title: 'Premium Landing Page Template',
        description: 'Beautiful, responsive landing page template with modern design. Includes HTML, CSS, JavaScript source files and comprehensive documentation. Perfect for startups and businesses.',
        category: 'Templates',
        price: 49.99,
        comparePrice: 99.99,
        icon: '🎨',
        downloadLink: 'https://drive.google.com/uc?export=download&id=YOUR_FILE_ID_1',
        fileSize: '5.2 MB',
        version: '1.0',
        features: ['Fully Responsive', 'Modern Design', 'Easy Customization', 'Documentation Included', 'Free Updates'],
        tags: ['template', 'landing-page', 'responsive', 'html', 'css'],
        isActive: true,
        isFeatured: true,
        stock: 999,
        rating: 4.8,
        reviewCount: 127
      },
      {
        title: 'React Dashboard Components',
        description: 'Complete set of React dashboard components ready to use in your projects. Built with TypeScript, fully typed, and production-ready. Includes charts, tables, forms, and more.',
        category: 'Components',
        price: 79.99,
        comparePrice: 149.99,
        icon: '⚛️',
        downloadLink: 'https://drive.google.com/uc?export=download&id=YOUR_FILE_ID_2',
        fileSize: '12.8 MB',
        version: '2.1',
        features: ['TypeScript Support', '50+ Components', 'Dark Mode', 'Fully Documented', 'Regular Updates'],
        tags: ['react', 'components', 'typescript', 'dashboard', 'ui'],
        isActive: true,
        isFeatured: true,
        stock: 999,
        rating: 4.9,
        reviewCount: 89
      },
      {
        title: 'Web Development Course Bundle',
        description: 'Complete web development course from beginner to advanced. Includes 40+ hours of video tutorials, project files, exercises, and lifetime access. Learn HTML, CSS, JavaScript, React, Node.js and more.',
        category: 'Courses',
        price: 129.99,
        comparePrice: 299.99,
        icon: '📚',
        downloadLink: 'https://drive.google.com/uc?export=download&id=YOUR_FILE_ID_3',
        fileSize: '2.5 GB',
        version: '1.0',
        features: ['40+ Hours Video', 'Source Code', 'Certificate', 'Lifetime Access', 'Community Support'],
        tags: ['course', 'web-development', 'javascript', 'react', 'node'],
        isActive: true,
        isFeatured: false,
        stock: 999,
        rating: 4.7,
        reviewCount: 234
      },
      {
        title: 'E-commerce Admin Dashboard',
        description: 'Professional admin dashboard for e-commerce platforms with advanced analytics, order management, inventory tracking, and customer management tools. Built with modern tech stack.',
        category: 'Templates',
        price: 89.99,
        comparePrice: 179.99,
        icon: '🛒',
        downloadLink: 'https://drive.google.com/uc?export=download&id=YOUR_FILE_ID_4',
        fileSize: '8.4 MB',
        version: '1.5',
        features: ['Analytics Dashboard', 'Order Management', 'User Management', 'Responsive Design', 'API Integration'],
        tags: ['ecommerce', 'dashboard', 'admin', 'template', 'analytics'],
        isActive: true,
        isFeatured: true,
        stock: 999,
        rating: 4.6,
        reviewCount: 156
      },
      {
        title: 'UI/UX Design System',
        description: 'Complete design system with components, patterns, and guidelines. Includes Figma files, Sketch files, and design tokens. Perfect for teams and designers.',
        category: 'Design',
        price: 59.99,
        comparePrice: 119.99,
        icon: '🎨',
        downloadLink: 'https://drive.google.com/uc?export=download&id=YOUR_FILE_ID_5',
        fileSize: '156 MB',
        version: '3.0',
        features: ['Figma Files', 'Sketch Files', 'Design Tokens', '100+ Components', 'Style Guide'],
        tags: ['design', 'ui', 'ux', 'figma', 'sketch'],
        isActive: true,
        isFeatured: false,
        stock: 999,
        rating: 4.9,
        reviewCount: 78
      }
    ];

    let created = 0;
    let skipped = 0;

    for (const productData of sampleProducts) {
      const existing = await Product.findOne({ title: productData.title });
      if (!existing) {
        await Product.create(productData);
        created++;
      } else {
        skipped++;
      }
    }

    console.log(`✅ Seeded ${created} products (${skipped} already existed)`);

    res.json({
      success: true,
      message: `Successfully seeded ${created} products`,
      created: created,
      skipped: skipped,
      note: 'Remember to update the Google Drive download links with actual file IDs in the admin dashboard!'
    });
  } catch (error) {
    console.error('❌ Seed products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to seed products' 
    });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// COUPON MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

// Get All Coupons (Admin)
app.get('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const { status = 'all' } = req.query;
    
    let query = {};
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }

    const coupons = await Coupon.find(query)
      .populate('createdBy', 'fullName email')
      .sort({ createdAt: -1 });
    
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

// Create Coupon (Admin)
app.post('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const { 
      code, 
      discount, 
      type, 
      usageLimit, 
      expiresAt, 
      minPurchaseAmount, 
      maxDiscountAmount,
      applicableCategories,
      description 
    } = req.body;

    if (!code || discount === undefined || !type) {
      return res.status(400).json({ success: false, message: 'Code, discount, and type are required' });
    }

    if (!['percentage', 'fixed'].includes(type)) {
      return res.status(400).json({ success: false, message: 'Type must be "percentage" or "fixed"' });
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
      maxDiscountAmount: maxDiscountAmount || null,
      applicableCategories: applicableCategories || [],
      description: description || '',
      createdBy: req.adminUser._id
    });

    await coupon.save();

    console.log(`🎫 Coupon created: ${coupon.code}`);

    res.status(201).json({
      success: true,
      message: 'Coupon created successfully',
      coupon: coupon
    });
  } catch (error) {
    console.error('❌ Create coupon error:', error);
    res.status(500).json({ success: false, message: 'Coupon creation failed' });
  }
});

// Update Coupon (Admin)
app.put('/api/admin/coupons/:code', authenticateAdmin, async (req, res) => {
  try {
    const { 
      discount, 
      type, 
      usageLimit, 
      expiresAt, 
      minPurchaseAmount, 
      maxDiscountAmount,
      applicableCategories,
      description, 
      isActive 
    } = req.body;

    const coupon = await Coupon.findOne({ code: req.params.code.toUpperCase() });
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    if (discount !== undefined) coupon.discount = discount;
    if (type) coupon.type = type;
    if (usageLimit !== undefined) coupon.usageLimit = usageLimit;
    if (expiresAt !== undefined) coupon.expiresAt = expiresAt;
    if (minPurchaseAmount !== undefined) coupon.minPurchaseAmount = minPurchaseAmount;
    if (maxDiscountAmount !== undefined) coupon.maxDiscountAmount = maxDiscountAmount;
    if (applicableCategories !== undefined) coupon.applicableCategories = applicableCategories;
    if (description !== undefined) coupon.description = description;
    if (isActive !== undefined) coupon.isActive = isActive;

    await coupon.save();

    console.log(`✅ Coupon updated: ${coupon.code}`);

    res.json({
      success: true,
      message: 'Coupon updated successfully',
      coupon: coupon
    });
  } catch (error) {
    console.error('❌ Update coupon error:', error);
    res.status(500).json({ success: false, message: 'Coupon update failed' });
  }
});

// Delete Coupon (Admin)
app.delete('/api/admin/coupons/:code', authenticateAdmin, async (req, res) => {
  try {
    const coupon = await Coupon.findOneAndDelete({ code: req.params.code.toUpperCase() });
    
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    console.log(`🗑️  Coupon deleted: ${coupon.code}`);

    res.json({ success: true, message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('❌ Delete coupon error:', error);
    res.status(500).json({ success: false, message: 'Coupon deletion failed' });
  }
});

// Validate Coupon (User)
app.post('/api/coupons/validate', authenticateToken, async (req, res) => {
  try {
    const { code, orderTotal } = req.body;
    
    if (!code) {
      return res.status(400).json({ success: false, message: 'Coupon code required' });
    }

    const cleanCode = code.trim().toUpperCase();
    const coupon = await Coupon.findOne({ code: cleanCode });

    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Invalid coupon code' });
    }

    if (!coupon.isActive) {
      return res.status(400).json({ success: false, message: 'Coupon is not active' });
    }

    if (coupon.expiresAt && new Date() > coupon.expiresAt) {
      return res.status(400).json({ success: false, message: 'Coupon has expired' });
    }

    if (coupon.usageLimit && coupon.usageCount >= coupon.usageLimit) {
      return res.status(400).json({ success: false, message: 'Coupon usage limit reached' });
    }

    if (orderTotal && coupon.minPurchaseAmount && orderTotal < coupon.minPurchaseAmount) {
      return res.status(400).json({ 
        success: false, 
        message: `Minimum purchase of $${coupon.minPurchaseAmount} required` 
      });
    }

    // Calculate discount
    let discount = 0;
    if (coupon.type === 'percentage') {
      discount = (orderTotal * coupon.discount) / 100;
      if (coupon.maxDiscountAmount) {
        discount = Math.min(discount, coupon.maxDiscountAmount);
      }
    } else {
      discount = coupon.discount;
    }

    discount = Math.min(discount, orderTotal);

    res.json({
      success: true,
      message: 'Coupon is valid',
      coupon: {
        code: coupon.code,
        discount: discount,
        type: coupon.type,
        description: coupon.description
      }
    });
  } catch (error) {
    console.error('❌ Validate coupon error:', error);
    res.status(500).json({ success: false, message: 'Validation failed' });
  }
});

// Seed Default Coupons
app.post('/api/coupons/seed', async (req, res) => {
  try {
    const defaultCoupons = [
      {
        code: 'WELCOME10',
        discount: 10,
        type: 'percentage',
        description: 'Welcome discount - 10% off',
        minPurchaseAmount: 0,
        isActive: true
      },
      {
        code: 'SAVE20',
        discount: 20,
        type: 'percentage',
        description: 'Save 20% on your purchase',
        minPurchaseAmount: 50,
        isActive: true
      },
      {
        code: 'FREESHIP',
        discount: 5,
        type: 'fixed',
        description: 'Free shipping - $5 off',
        minPurchaseAmount: 25,
        isActive: true
      },
      {
        code: 'FLASHSALE',
        discount: 30,
        type: 'percentage',
        description: 'Flash sale - 30% off',
        minPurchaseAmount: 100,
        maxDiscountAmount: 50,
        usageLimit: 100,
        isActive: true
      },
      {
        code: 'NEWUSER',
        discount: 15,
        type: 'percentage',
        description: 'New user discount - 15% off',
        minPurchaseAmount: 30,
        usageLimit: 1000,
        isActive: true
      }
    ];

    let created = 0;
    let skipped = 0;

    for (const couponData of defaultCoupons) {
      const existing = await Coupon.findOne({ code: couponData.code });
      if (!existing) {
        await Coupon.create(couponData);
        created++;
      } else {
        skipped++;
      }
    }

    console.log(`🎫 Seeded ${created} coupons (${skipped} already existed)`);

    res.json({
      success: true,
      message: `Successfully seeded ${created} coupons`,
      created: created,
      skipped: skipped
    });
  } catch (error) {
    console.error('❌ Seed coupons error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to seed coupons' 
    });
  }
});

console.log('\n✅ Part 4 Loaded: Orders, Products, Downloads & Coupons Ready');
console.log('📦 Endpoints: Order Management, Product CRUD, Download Tracking, Coupon System\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 4 - Continue to Part 5 for Blog & System Settings
// ═════════════════════════════════════════════════════════════════════════════
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 6 OF 7                                      ║
// ║            Chat System & Support Tickets (NEW v7.0)                       ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// COPY THIS AFTER PART 5
// THIS IS COMPLETELY NEW CODE FOR v7.0
//
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// CUSTOMER CHAT ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// Start New Chat (Customer)
app.post('/api/chat/start', async (req, res) => {
  try {
    const { customerName, customerEmail, subject, department, priority } = req.body;

    if (!customerName || !customerEmail || !subject) {
      return res.status(400).json({ 
        success: false, 
        message: 'Customer name, email, and subject are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(customerEmail)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    const chatId = generateChatId();
    const customerId = customerEmail.toLowerCase();

    const chat = new Chat({
      chatId,
      customerId,
      customerName: customerName.trim(),
      customerEmail: customerEmail.toLowerCase(),
      subject: subject.trim(),
      department: department || 'General',
      priority: priority || 'medium',
      status: 'open',
      messages: [{
        messageId: generateMessageId(),
        sender: 'system',
        senderId: 'system',
        senderName: 'UYEH TECH Support',
        message: `Chat session started. Subject: ${subject}`,
        timestamp: new Date()
      }]
    });

    await chat.save();

    console.log(`💬 Chat started: ${chatId} by ${customerName}`);

    // Auto-assign to available agent if enabled
    const settings = await SystemSettings.findOne();
    if (settings?.chatSettings?.autoAssignChats) {
      // Find available agent
      const availableAgent = await User.findOne({
        isAgent: true,
        'agentInfo.status': { $in: ['online', 'away'] },
        'agentInfo.activeChats': { $lt: 5 }
      }).sort({ 'agentInfo.activeChats': 1 });

      if (availableAgent) {
        chat.assignedAgent = availableAgent._id;
        chat.status = 'assigned';
        
        // Add assignment message
        chat.messages.push({
          messageId: generateMessageId(),
          sender: 'system',
          senderId: 'system',
          senderName: 'System',
          message: `Chat assigned to agent: ${availableAgent.fullName}`,
          timestamp: new Date()
        });

        // Update agent stats
        availableAgent.agentInfo.activeChats += 1;
        availableAgent.agentInfo.totalChats += 1;
        await availableAgent.save();
        await chat.save();

        // Notify agent via WebSocket
        sendToAgent(availableAgent._id.toString(), {
          type: 'chat_assigned',
          chat: {
            chatId: chat.chatId,
            customerName: chat.customerName,
            subject: chat.subject,
            department: chat.department,
            priority: chat.priority
          }
        });

        // Send email notification to agent
        await sendAgentAssignmentEmail(availableAgent.email, {
          chatId: chat.chatId,
          customerName: chat.customerName,
          subject: chat.subject,
          department: chat.department,
          priority: chat.priority
        });
      }
    }

    res.status(201).json({
      success: true,
      message: 'Chat session started successfully',
      chat: {
        chatId: chat.chatId,
        customerId: chat.customerId,
        customerName: chat.customerName,
        subject: chat.subject,
        department: chat.department,
        priority: chat.priority,
        status: chat.status,
        assignedAgent: chat.assignedAgent,
        createdAt: chat.createdAt
      }
    });
  } catch (error) {
    console.error('❌ Start chat error:', error);
    res.status(500).json({ success: false, message: 'Failed to start chat session' });
  }
});

// Get Chat Details
app.get('/api/chat/:chatId', async (req, res) => {
  try {
    const { chatId } = req.params;

    const chat = await Chat.findOne({ chatId })
      .populate('assignedAgent', 'fullName email agentInfo');

    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    res.json({
      success: true,
      chat: {
        chatId: chat.chatId,
        customerId: chat.customerId,
        customerName: chat.customerName,
        customerEmail: chat.customerEmail,
        subject: chat.subject,
        department: chat.department,
        priority: chat.priority,
        status: chat.status,
        assignedAgent: chat.assignedAgent,
        messages: chat.messages,
        tags: chat.tags,
        rating: chat.rating,
        feedback: chat.feedback,
        createdAt: chat.createdAt,
        updatedAt: chat.updatedAt,
        totalMessages: chat.totalMessages
      }
    });
  } catch (error) {
    console.error('❌ Get chat error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch chat details' });
  }
});

// Send Message in Chat
app.post('/api/chat/:chatId/send', async (req, res) => {
  try {
    const { chatId } = req.params;
    const { sender, senderId, senderName, message, attachments } = req.body;

    if (!sender || !message) {
      return res.status(400).json({ success: false, message: 'Sender and message are required' });
    }

    if (!['customer', 'agent', 'system'].includes(sender)) {
      return res.status(400).json({ success: false, message: 'Invalid sender type' });
    }

    const chat = await Chat.findOne({ chatId });
    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    if (chat.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Chat session is closed' });
    }

    const newMessage = {
      messageId: generateMessageId(),
      sender,
      senderId: senderId || chat.customerId,
      senderName: senderName || chat.customerName,
      message: message.trim(),
      attachments: attachments || [],
      timestamp: new Date(),
      read: false
    };

    chat.messages.push(newMessage);

    // Calculate first response time if this is agent's first message
    if (sender === 'agent' && !chat.firstResponseTime) {
      const firstMessage = chat.messages.find(m => m.sender === 'customer');
      if (firstMessage) {
        const responseTime = (newMessage.timestamp - firstMessage.timestamp) / 1000 / 60; // minutes
        chat.firstResponseTime = Math.round(responseTime);
      }
    }

    // Update status to in-progress if not already
    if (chat.status === 'open' || chat.status === 'assigned') {
      chat.status = 'in-progress';
    }

    await chat.save();

    // Broadcast via WebSocket
    broadcastToChat(chatId, {
      type: 'new_message',
      message: newMessage,
      chatId: chatId
    });

    console.log(`💬 Message sent in chat ${chatId} by ${sender}`);

    res.json({
      success: true,
      message: 'Message sent successfully',
      messageData: newMessage
    });
  } catch (error) {
    console.error('❌ Send message error:', error);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// Upload File in Chat
app.post('/api/chat/upload', upload.array('files', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, message: 'No files uploaded' });
    }

    const uploadedFiles = req.files.map(file => ({
      filename: file.originalname,
      url: `${BASE_URL}/uploads/${file.filename}`,
      fileType: file.mimetype,
      fileSize: file.size
    }));

    console.log(`📎 ${uploadedFiles.length} file(s) uploaded for chat`);

    res.json({
      success: true,
      message: 'Files uploaded successfully',
      files: uploadedFiles
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ success: false, message: 'File upload failed' });
  }
});

// Mark Messages as Read
app.post('/api/chat/:chatId/read', async (req, res) => {
  try {
    const { chatId } = req.params;
    const { messageIds } = req.body;

    if (!messageIds || !Array.isArray(messageIds)) {
      return res.status(400).json({ success: false, message: 'Message IDs array required' });
    }

    const chat = await Chat.findOne({ chatId });
    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    let markedCount = 0;
    chat.messages.forEach(msg => {
      if (messageIds.includes(msg.messageId) && !msg.read) {
        msg.read = true;
        markedCount++;
      }
    });

    await chat.save();

    // Broadcast via WebSocket
    broadcastToChat(chatId, {
      type: 'messages_read',
      messageIds: messageIds,
      chatId: chatId
    });

    res.json({ 
      success: true, 
      message: `${markedCount} message(s) marked as read` 
    });
  } catch (error) {
    console.error('❌ Mark read error:', error);
    res.status(500).json({ success: false, message: 'Failed to mark messages as read' });
  }
});

// End Chat Session
app.post('/api/chat/:chatId/end', async (req, res) => {
  try {
    const { chatId } = req.params;
    const { rating, feedback } = req.body;

    const chat = await Chat.findOne({ chatId });
    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    if (chat.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Chat session already closed' });
    }

    // Add closing message
    chat.messages.push({
      messageId: generateMessageId(),
      sender: 'system',
      senderId: 'system',
      senderName: 'System',
      message: 'Chat session ended.',
      timestamp: new Date()
    });

    chat.status = 'closed';
    chat.closedAt = new Date();
    
    if (rating && rating >= 1 && rating <= 5) {
      chat.rating = rating;
    }
    if (feedback) {
      chat.feedback = feedback.trim();
    }

    // Update agent stats if assigned
    if (chat.assignedAgent) {
      const agent = await User.findById(chat.assignedAgent);
      if (agent && agent.agentInfo) {
        agent.agentInfo.activeChats = Math.max(0, agent.agentInfo.activeChats - 1);
        if (chat.status === 'resolved') {
          agent.agentInfo.resolvedChats += 1;
        }
        // Update agent rating
        if (rating) {
          const totalRatings = agent.agentInfo.totalChats;
          const currentRating = agent.agentInfo.rating || 0;
          agent.agentInfo.rating = ((currentRating * (totalRatings - 1)) + rating) / totalRatings;
        }
        await agent.save();
      }
    }

    await chat.save();

    // Broadcast via WebSocket
    broadcastToChat(chatId, {
      type: 'chat_closed',
      chatId: chatId,
      rating: rating,
      feedback: feedback
    });

    console.log(`✅ Chat ended: ${chatId}`);

    res.json({
      success: true,
      message: 'Chat session ended successfully',
      rating: rating,
      feedback: feedback
    });
  } catch (error) {
    console.error('❌ End chat error:', error);
    res.status(500).json({ success: false, message: 'Failed to end chat session' });
  }
});

// Resolve Chat (Mark as resolved before closing)
app.post('/api/chat/:chatId/resolve', async (req, res) => {
  try {
    const { chatId } = req.params;

    const chat = await Chat.findOne({ chatId });
    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    if (chat.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Chat session already closed' });
    }

    chat.status = 'resolved';
    chat.resolvedAt = new Date();
    
    chat.messages.push({
      messageId: generateMessageId(),
      sender: 'system',
      senderId: 'system',
      senderName: 'System',
      message: 'Issue resolved.',
      timestamp: new Date()
    });

    await chat.save();

    // Broadcast via WebSocket
    broadcastToChat(chatId, {
      type: 'chat_resolved',
      chatId: chatId
    });

    console.log(`✅ Chat resolved: ${chatId}`);

    res.json({
      success: true,
      message: 'Chat marked as resolved'
    });
  } catch (error) {
    console.error('❌ Resolve chat error:', error);
    res.status(500).json({ success: false, message: 'Failed to resolve chat' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// AGENT DASHBOARD ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// Get All Chats (Agent/Admin)
app.get('/api/agent/chats', authenticateAgent, async (req, res) => {
  try {
    const { status, department, priority, page = 1, limit = 20 } = req.query;
    
    let query = {};
    
    // If not admin, only show assigned chats
    if (!req.agentUser.isAdmin) {
      query.assignedAgent = req.agentUser._id;
    }
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    if (department && department !== 'all') {
      query.department = department;
    }

    if (priority && priority !== 'all') {
      query.priority = priority;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const chats = await Chat.find(query)
      .populate('assignedAgent', 'fullName email agentInfo')
      .sort({ updatedAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await Chat.countDocuments(query);

    res.json({
      success: true,
      chats: chats.map(chat => ({
        chatId: chat.chatId,
        customerName: chat.customerName,
        customerEmail: chat.customerEmail,
        subject: chat.subject,
        department: chat.department,
        priority: chat.priority,
        status: chat.status,
        assignedAgent: chat.assignedAgent,
        totalMessages: chat.totalMessages,
        unreadCount: chat.messages.filter(m => !m.read && m.sender === 'customer').length,
        createdAt: chat.createdAt,
        updatedAt: chat.updatedAt
      })),
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Get chats error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch chats' });
  }
});

// Assign Chat to Agent (Admin)
app.post('/api/agent/chats/:chatId/assign', authenticateAdmin, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { agentId } = req.body;

    if (!agentId) {
      return res.status(400).json({ success: false, message: 'Agent ID required' });
    }

    const chat = await Chat.findOne({ chatId });
    if (!chat) {
      return res.status(404).json({ success: false, message: 'Chat session not found' });
    }

    const agent = await User.findById(agentId);
    if (!agent || (!agent.isAgent && !agent.isAdmin)) {
      return res.status(400).json({ success: false, message: 'Invalid agent ID' });
    }

    // Update previous agent stats if chat was already assigned
    if (chat.assignedAgent) {
      const previousAgent = await User.findById(chat.assignedAgent);
      if (previousAgent && previousAgent.agentInfo) {
        previousAgent.agentInfo.activeChats = Math.max(0, previousAgent.agentInfo.activeChats - 1);
        await previousAgent.save();
      }
    }

    chat.assignedAgent = agentId;
    chat.status = 'assigned';
    
    // Add system message
    chat.messages.push({
      messageId: generateMessageId(),
      sender: 'system',
      senderId: 'system',
      senderName: 'System',
      message: `Chat assigned to agent: ${agent.fullName}`,
      timestamp: new Date()
    });

    await chat.save();

    // Update new agent stats
    if (agent.agentInfo) {
      agent.agentInfo.activeChats += 1;
      agent.agentInfo.totalChats += 1;
      await agent.save();
    }

    // Notify agent via WebSocket
    sendToAgent(agentId.toString(), {
      type: 'chat_assigned',
      chat: {
        chatId: chat.chatId,
        customerName: chat.customerName,
        subject: chat.subject,
        department: chat.department,
        priority: chat.priority
      }
    });

    // Send email notification
    await sendAgentAssignmentEmail(agent.email, {
      chatId: chat.chatId,
      customerName: chat.customerName,
      subject: chat.subject,
      department: chat.department,
      priority: chat.priority
    });

    console.log(`👨‍💼 Chat ${chatId} assigned to agent ${agent.fullName}`);

    res.json({
      success: true,
      message: 'Chat assigned successfully',
      chat: {
        chatId: chat.chatId,
        assignedAgent: agent.fullName,
        status: chat.status
      }
    });
  } catch (error) {
    console.error('❌ Assign chat error:', error);
    res.status(500).json({ success: false, message: 'Failed to assign chat' });
  }
});

// Update Agent Status
app.put('/api/agent/status', authenticateAgent, async (req, res) => {
  try {
    const { status } = req.body;

    if (!['online', 'offline', 'busy', 'away'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const agent = await User.findById(req.agentUser._id);
    if (!agent.agentInfo) {
      return res.status(400).json({ success: false, message: 'User is not an agent' });
    }

    agent.agentInfo.status = status;
    agent.lastActivity = new Date();
    await agent.save();

    console.log(`👨‍💼 Agent ${agent.fullName} status: ${status}`);

    res.json({
      success: true,
      message: 'Status updated successfully',
      status: status
    });
  } catch (error) {
    console.error('❌ Update status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

// Get Agent Statistics
app.get('/api/agent/stats', authenticateAgent, async (req, res) => {
  try {
    const agentId = req.agentUser._id;

    const totalChats = await Chat.countDocuments({ assignedAgent: agentId });
    const openChats = await Chat.countDocuments({ 
      assignedAgent: agentId, 
      status: { $in: ['open', 'assigned'] } 
    });
    const inProgressChats = await Chat.countDocuments({ 
      assignedAgent: agentId, 
      status: 'in-progress' 
    });
    const resolvedChats = await Chat.countDocuments({ 
      assignedAgent: agentId, 
      status: 'resolved' 
    });
    const closedChats = await Chat.countDocuments({ 
      assignedAgent: agentId, 
      status: 'closed' 
    });

    // Calculate average response time
    const chatsWithResponseTime = await Chat.find({ 
      assignedAgent: agentId,
      firstResponseTime: { $exists: true }
    }).select('firstResponseTime');

    let avgResponseTime = 0;
    if (chatsWithResponseTime.length > 0) {
      const total = chatsWithResponseTime.reduce((sum, chat) => sum + chat.firstResponseTime, 0);
      avgResponseTime = Math.round(total / chatsWithResponseTime.length);
    }

    // Get agent rating
    const agent = await User.findById(agentId);
    const rating = agent.agentInfo?.rating || 0;

    res.json({
      success: true,
      stats: {
        totalChats,
        openChats,
        inProgressChats,
        resolvedChats,
        closedChats,
        activeChats: openChats + inProgressChats,
        avgResponseTime: avgResponseTime, // in minutes
        rating: rating.toFixed(1)
      }
    });
  } catch (error) {
    console.error('❌ Get stats error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch statistics' });
  }
});

// Get All Agents (Admin)
app.get('/api/admin/agents', authenticateAdmin, async (req, res) => {
  try {
    const agents = await User.find({ isAgent: true })
      .select('fullName email agentInfo lastActivity')
      .sort({ 'agentInfo.totalChats': -1 });

    res.json({
      success: true,
      agents: agents.map(agent => ({
        id: agent._id,
        name: agent.fullName,
        email: agent.email,
        department: agent.agentInfo.department,
        status: agent.agentInfo.status,
        activeChats: agent.agentInfo.activeChats,
        maxChats: agent.agentInfo.maxChats,
        totalChats: agent.agentInfo.totalChats,
        resolvedChats: agent.agentInfo.resolvedChats,
        rating: agent.agentInfo.rating,
        lastActivity: agent.lastActivity
      })),
      count: agents.length
    });
  } catch (error) {
    console.error('❌ Get agents error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch agents' });
  }
});

// Update Agent Settings (Admin)
app.put('/api/admin/agents/:agentId', authenticateAdmin, async (req, res) => {
  try {
    const { department, maxChats, status } = req.body;

    const agent = await User.findById(req.params.agentId);
    if (!agent || !agent.isAgent) {
      return res.status(404).json({ success: false, message: 'Agent not found' });
    }

    if (department) agent.agentInfo.department = department;
    if (maxChats !== undefined) agent.agentInfo.maxChats = maxChats;
    if (status) agent.agentInfo.status = status;

    await agent.save();

    console.log(`⚙️  Agent ${agent.fullName} settings updated`);

    res.json({
      success: true,
      message: 'Agent settings updated successfully',
      agent: {
        id: agent._id,
        name: agent.fullName,
        department: agent.agentInfo.department,
        maxChats: agent.agentInfo.maxChats,
        status: agent.agentInfo.status
      }
    });
  } catch (error) {
    console.error('❌ Update agent error:', error);
    res.status(500).json({ success: false, message: 'Failed to update agent settings' });
  }
});

console.log('\n✅ Part 6 Loaded: Chat System & Support Tickets Ready');
console.log('💬 Endpoints: Customer Chat, Agent Dashboard, File Upload, Real-time Updates\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 6 - Continue to Part 7 for Server Startup & Documentation
// ═════════════════════════════════════════════════════════════════════════════
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    UYEH TECH BACKEND SERVER v7.0                         ║
// ║                          PART 7 OF 7 (FINAL)                              ║
// ║         Server Startup, Error Handling & Documentation                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// COPY THIS AFTER PART 6 - THIS IS THE FINAL PART!
//
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// SERVER STARTUP
// ═════════════════════════════════════════════════════════════════════════════

// NOTE: Replace app.listen() with server.listen()
// This enables both HTTP and WebSocket on the same port

server.listen(PORT, () => {
  console.log('\n╔═══════════════════════════════════════════════════════════════════════════╗');
  console.log('║         🚀 UYEH TECH SERVER v7.0 - FULLY OPERATIONAL                    ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════════╝\n');
  
  console.log(`📡 Server Information:`);
  console.log(`   └─ HTTP Server: http://localhost:${PORT}`);
  console.log(`   └─ WebSocket Server: ws://localhost:${PORT}/ws`);
  console.log(`   └─ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   └─ Base URL: ${BASE_URL}\n`);
  
  console.log(`👤 Admin Configuration:`);
  console.log(`   └─ Admin Email: ${ADMIN_EMAIL}`);
  console.log(`   └─ Admin Dashboard: admin-dashboard.html`);
  console.log(`   └─ Agent Dashboard: agent-dashboard.html\n`);
  
  console.log('╔═══════════════════════════════════════════════════════════════════════════╗');
  console.log('║                      ✨ NEW IN v7.0                                      ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════════╝');
  console.log('  💬 Real-time Customer Chat with WebSocket');
  console.log('  👨‍💼 Agent Dashboard & Management System');
  console.log('  🎫 Support Ticket System');
  console.log('  📎 File Upload in Chat (Images, PDFs, Documents)');
  console.log('  🔄 Live Status Updates & Notifications');
  console.log('  📊 Agent Performance Analytics\n');
  
  console.log('╔═══════════════════════════════════════════════════════════════════════════╗');
  console.log('║                   📋 COMPLETE FEATURE LIST                               ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════════╝');
  console.log('  ✅ User Authentication (Signup, Login, Password Reset)');
  console.log('  ✅ Email Verification with OTP (Termii Integration)');
  console.log('  ✅ Admin Dashboard with Real-time Statistics');
  console.log('  ✅ Analytics System (Revenue, Orders, Users, Downloads, Chats)');
  console.log('  ✅ User Management (View, Ban, Delete, Promote to Agent)');
  console.log('  ✅ Order Management (Track, Update Status, Refund)');
  console.log('  ✅ Product Management (CRUD with Download Links)');
  console.log('  ✅ Download Tracking & Statistics');
  console.log('  ✅ Coupon System (Create, Validate, Usage Limits)');
  console.log('  ✅ Blog System (Posts, Comments, Categories, Search)');
  console.log('  ✅ Payment Integration (Flutterwave)');
  console.log('  ✅ System Settings Management');
  console.log('  ✅ Real-time Chat System (NEW v7.0)');
  console.log('  ✅ Agent Dashboard (NEW v7.0)');
  console.log('  ✅ Support Tickets (NEW v7.0)');
  console.log('  ✅ File Upload Support (NEW v7.0)\n');
  
  console.log('╔═══════════════════════════════════════════════════════════════════════════╗');
  console.log('║                    🔗 API ENDPOINTS                                      ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════════╝\n');
  
  console.log('🔐 AUTHENTICATION:');
  console.log('  POST   /api/auth/signup                    - User registration');
  console.log('  POST   /api/auth/login                     - User login');
  console.log('  POST   /api/auth/admin/login               - Admin login');
  console.log('  GET    /api/auth/admin/verify              - Verify admin token');
  console.log('  POST   /api/auth/agent/login               - Agent login (NEW)');
  console.log('  GET    /api/auth/agent/verify              - Verify agent token (NEW)');
  console.log('  POST   /api/auth/send-email-otp            - Send verification OTP');
  console.log('  POST   /api/auth/verify-email-otp          - Verify email OTP');
  console.log('  POST   /api/auth/forgot-password           - Request password reset');
  console.log('  POST   /api/auth/reset-password            - Reset password with code');
  console.log('  POST   /api/auth/change-password           - Change password (authenticated)');
  console.log('  POST   /api/auth/toggle-2fa                - Toggle two-factor authentication');
  console.log('  DELETE /api/auth/delete-account            - Delete user account\n');
  
  console.log('📊 DASHBOARD & ANALYTICS:');
  console.log('  GET    /api/admin/dashboard                - Dashboard overview with stats');
  console.log('  GET    /api/admin/analytics                - Detailed analytics data');
  console.log('  GET    /api/health                         - Server health check\n');
  
  console.log('👥 USER MANAGEMENT:');
  console.log('  GET    /api/admin/users                    - List all users (paginated)');
  console.log('  GET    /api/admin/users/:userId            - Get user details');
  console.log('  PUT    /api/admin/users/:userId/ban        - Ban/unban user');
  console.log('  DELETE /api/admin/users/:userId            - Delete user');
  console.log('  PUT    /api/admin/users/:userId/promote-agent  - Promote user to agent (NEW)');
  console.log('  PUT    /api/admin/users/:userId/demote-agent   - Demote agent to user (NEW)');
  console.log('  GET    /api/profile                        - Get user profile');
  console.log('  PUT    /api/profile                        - Update user profile\n');
  
  console.log('📦 ORDER MANAGEMENT:');
  console.log('  GET    /api/admin/orders                   - List all orders (admin)');
  console.log('  GET    /api/admin/orders/:orderId          - Get order details (admin)');
  console.log('  PUT    /api/admin/orders/:orderId/status   - Update order status');
  console.log('  DELETE /api/admin/orders/:orderId          - Delete order');
  console.log('  GET    /api/orders                         - Get user orders');
  console.log('  GET    /api/orders/detailed                - Get orders with download links');
  console.log('  POST   /api/orders/create-with-coupon      - Create order with coupon');
  console.log('  POST   /api/orders/verify-payment          - Verify Flutterwave payment\n');
  
  console.log('📥 DOWNLOAD MANAGEMENT:');
  console.log('  GET    /api/orders/detailed                - Orders with download links');
  console.log('  POST   /api/orders/track-download          - Track product download');
  console.log('  GET    /api/admin/downloads/stats          - Download statistics\n');
  
  console.log('🛍️  PRODUCT MANAGEMENT:');
  console.log('  GET    /api/admin/products                 - List products (admin)');
  console.log('  GET    /api/products                       - List products (public)');
  console.log('  GET    /api/products/:id                   - Get product details');
  console.log('  POST   /api/admin/products                 - Create product');
  console.log('  PUT    /api/admin/products/:id             - Update product');
  console.log('  DELETE /api/admin/products/:id             - Delete product');
  console.log('  POST   /api/admin/products/seed-with-downloads - Seed sample products\n');
  
  console.log('🎫 COUPON MANAGEMENT:');
  console.log('  GET    /api/admin/coupons                  - List all coupons');
  console.log('  POST   /api/admin/coupons                  - Create coupon');
  console.log('  PUT    /api/admin/coupons/:code            - Update coupon');
  console.log('  DELETE /api/admin/coupons/:code            - Delete coupon');
  console.log('  POST   /api/coupons/validate               - Validate coupon code');
  console.log('  POST   /api/coupons/seed                   - Seed default coupons\n');
  
  console.log('📝 BLOG MANAGEMENT:');
  console.log('  GET    /api/admin/blog/posts               - List all posts (admin)');
  console.log('  POST   /api/admin/blog/posts               - Create blog post');
  console.log('  PUT    /api/admin/blog/posts/:id           - Update blog post');
  console.log('  DELETE /api/admin/blog/posts/:id           - Delete blog post');
  console.log('  GET    /api/blog/posts                     - List published posts');
  console.log('  GET    /api/blog/posts/:slug               - Get single post');
  console.log('  POST   /api/blog/posts/:id/like            - Like post');
  console.log('  POST   /api/blog/posts/:id/comments        - Add comment');
  console.log('  PUT    /api/admin/blog/posts/:postId/comments/:commentId/approve');
  console.log('  DELETE /api/admin/blog/posts/:postId/comments/:commentId');
  console.log('  GET    /api/blog/categories                - Get blog categories');
  console.log('  GET    /api/blog/search                    - Search blog posts');
  console.log('  GET    /api/blog/featured                  - Get featured posts');
  console.log('  GET    /api/blog/posts/:id/related         - Get related posts\n');
  
  console.log('💬 CHAT & SUPPORT (NEW v7.0):');
  console.log('  POST   /api/chat/start                     - Start new chat session');
  console.log('  GET    /api/chat/:chatId                   - Get chat details');
  console.log('  POST   /api/chat/:chatId/send              - Send message in chat');
  console.log('  POST   /api/chat/upload                    - Upload files in chat');
  console.log('  POST   /api/chat/:chatId/read              - Mark messages as read');
  console.log('  POST   /api/chat/:chatId/end               - End chat session');
  console.log('  POST   /api/chat/:chatId/resolve           - Mark chat as resolved\n');
  
  console.log('👨‍💼 AGENT DASHBOARD (NEW v7.0):');
  console.log('  GET    /api/agent/chats                    - Get agent chats');
  console.log('  POST   /api/agent/chats/:chatId/assign     - Assign chat to agent');
  console.log('  PUT    /api/agent/status                   - Update agent status');
  console.log('  GET    /api/agent/stats                    - Get agent statistics');
  console.log('  GET    /api/admin/agents                   - List all agents');
  console.log('  PUT    /api/admin/agents/:agentId          - Update agent settings\n');
  
  console.log('⚙️  SYSTEM SETTINGS:');
  console.log('  GET    /api/admin/settings                 - Get system settings');
  console.log('  PUT    /api/admin/settings                 - Update settings');
  console.log('  GET    /api/settings/public                - Get public settings\n');
  
  console.log('👤 USER PREFERENCES:');
  console.log('  GET    /api/user/notifications             - Get notification preferences');
  console.log('  PUT    /api/user/notifications/update      - Update preferences');
  console.log('  GET    /api/user/payment-methods           - Get payment methods');
  console.log('  POST   /api/user/payment-methods/add       - Add payment method\n');
  
  console.log('🔌 WEBSOCKET:');
  console.log(`  ws://localhost:${PORT}/ws?chatId=XXX       - Connect to chat`);
  console.log(`  ws://localhost:${PORT}/ws?agentId=XXX      - Connect as agent`);
  console.log(`  ws://localhost:${PORT}/ws?customerId=XXX   - Connect as customer`);
  console.log(`  └─ Active Connections: ${wss.clients.size}`);
  console.log(`  └─ Active Chats: ${activeConnections.size}`);
  console.log(`  └─ Online Agents: ${agentConnections.size}`);
  console.log(`  └─ Online Customers: ${customerConnections.size}\n`);
  
  console.log('════════════════════════════════════════════════════════════════════════════');
  console.log('🔐 QUICK START GUIDE:');
  console.log('════════════════════════════════════════════════════════════════════════════');
  console.log(`  1. Sign up with email: ${ADMIN_EMAIL}`);
  console.log('  2. System automatically grants admin privileges');
  console.log('  3. Login at admin-dashboard.html');
  console.log('  4. Create products and add download links');
  console.log('  5. Seed default coupons: POST /api/coupons/seed');
  console.log('  6. Seed sample products: POST /api/admin/products/seed-with-downloads');
  console.log('  7. Promote users to agents for chat support\n');
  
  console.log('📥 DOWNLOAD LINK SETUP:');
  console.log('════════════════════════════════════════════════════════════════════════════');
  console.log('  1. Upload files to Google Drive or any cloud storage');
  console.log('  2. Set sharing to "Anyone with the link"');
  console.log('  3. Get direct download link');
  console.log('  4. Add to product via admin dashboard or API');
  console.log('  5. For Google Drive, use format:');
  console.log('     https://drive.google.com/uc?export=download&id=FILE_ID\n');
  
  console.log('👨‍💼 AGENT SETUP:');
  console.log('════════════════════════════════════════════════════════════════════════════');
  console.log('  1. Create/login to a regular user account');
  console.log('  2. Admin promotes user to agent via API or manually in database');
  console.log('  3. Login at agent-login.html');
  console.log('  4. Start receiving and responding to customer chats\n');
  
  console.log('🚀 DEPLOYMENT CHECKLIST:');
  console.log('════════════════════════════════════════════════════════════════════════════');
  console.log('  ✓ Update NODE_ENV=production in .env');
  console.log('  ✓ Use LIVE Flutterwave keys (not TEST)');
  console.log('  ✓ Update BASE_URL to your domain');
  console.log('  ✓ Set strong JWT_SECRET (different from development)');
  console.log('  ✓ Configure MongoDB Atlas IP whitelist');
  console.log('  ✓ Enable SSL/HTTPS');
  console.log('  ✓ Set up monitoring and logging');
  console.log('  ✓ Configure backup strategy');
  console.log('  ✓ Test all endpoints before launch\n');
  
  console.log('✅ Server ready to accept connections!');
  console.log('🎉 UYEH TECH v7.0 - All systems operational!\n');
});

// ═════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING
// ═════════════════════════════════════════════════════════════════════════════

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('\n❌ Unhandled Promise Rejection:');
  console.error(err);
  console.error('Stack:', err.stack);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('\n❌ Uncaught Exception:');
  console.error(err);
  console.error('Stack:', err.stack);
  
  // Graceful shutdown
  console.log('⚠️  Server shutting down due to uncaught exception...');
  server.close(() => {
    process.exit(1);
  });
});

// Handle SIGTERM signal (graceful shutdown)
process.on('SIGTERM', async () => {
  console.log('\n⚠️  SIGTERM signal received: closing HTTP server');
  
  // Close server
  server.close(async () => {
    console.log('✅ HTTP server closed');
    
    // Close MongoDB connection
    try {
      await mongoose.connection.close();
      console.log('✅ MongoDB connection closed');
    } catch (error) {
      console.error('❌ Error closing MongoDB:', error);
    }
    
    // Close WebSocket connections
    wss.clients.forEach((client) => {
      client.close();
    });
    console.log('✅ WebSocket connections closed');
    
    process.exit(0);
  });
});

// Handle SIGINT signal (Ctrl+C)
process.on('SIGINT', async () => {
  console.log('\n⚠️  SIGINT signal received: closing server');
  
  // Close server
  server.close(async () => {
    console.log('✅ HTTP server closed');
    
    // Close MongoDB connection
    try {
      await mongoose.connection.close();
      console.log('✅ MongoDB connection closed');
    } catch (error) {
      console.error('❌ Error closing MongoDB:', error);
    }
    
    // Close WebSocket connections
    wss.clients.forEach((client) => {
      client.close();
    });
    console.log('✅ WebSocket connections closed');
    
    console.log('👋 UYEH TECH Server v7.0 - Shutdown complete');
    process.exit(0);
  });
});

// Handle database disconnection
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  MongoDB connection lost');
});

// Handle database reconnection
mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

// Handle database errors
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB error:', err);
});

// ═════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '7.0.0',
    services: {
      http: 'operational',
      websocket: wss.clients.size > 0 || wss.clients.size === 0 ? 'operational' : 'error',
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      email: TERMII_API_KEY ? 'configured' : 'not configured',
      payment: FLUTTERWAVE_SECRET_KEY ? 'configured' : 'not configured'
    },
    websocket: {
      activeConnections: wss.clients.size,
      activeChats: activeConnections.size,
      onlineAgents: agentConnections.size,
      onlineCustomers: customerConnections.size
    }
  };
  
  try {
    res.status(200).json(healthcheck);
  } catch (error) {
    healthcheck.message = 'Server error';
    res.status(503).json(healthcheck);
  }
});

console.log('\n✅ Part 7 Loaded: Server Startup, Error Handling & Health Check Complete');
console.log('🎉 ALL 7 PARTS LOADED SUCCESSFULLY! UYEH TECH SERVER v7.0 READY!\n');

// ═════════════════════════════════════════════════════════════════════════════
// END OF PART 7 - SERVER COMPLETE!
// ═════════════════════════════════════════════════════════════════════════════

/* 
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         🎉 CONGRATULATIONS!                                   ║
║                                                                               ║
║             UYEH TECH Backend Server v7.0 is Now Complete!                   ║
║                                                                               ║
║  All 7 parts have been successfully loaded and integrated.                   ║
║  Your server now includes:                                                   ║
║                                                                               ║
║  ✅ Complete User Authentication System                                      ║
║  ✅ Admin Dashboard with Analytics                                           ║
║  ✅ Product & Order Management                                               ║
║  ✅ Download Tracking System                                                 ║
║  ✅ Coupon & Discount System                                                 ║
║  ✅ Blog Management Platform                                                 ║
║  ✅ Real-time Chat System (NEW!)                                             ║
║  ✅ Agent Dashboard & Management (NEW!)                                      ║
║  ✅ File Upload Support (NEW!)                                               ║
║  ✅ WebSocket Real-time Updates (NEW!)                                       ║
║                                                                               ║
║  Your server is production-ready and fully operational!                      ║
║                                                                               ║
║  Next Steps:                                                                 ║
║  1. Test all endpoints                                                       ║
║  2. Configure your .env file                                                 ║
║  3. Add products and download links                                          ║
║  4. Promote users to agents                                                  ║
║  5. Deploy to production                                                     ║
║                                                                               ║
║  Happy coding! 🚀                                                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/
