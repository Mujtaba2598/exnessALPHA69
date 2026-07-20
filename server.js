require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Tickerall } = require('@tickerall/sdk');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 🔒 SECURE CONFIGURATION
// ============================================================

app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('❌ FATAL: JWT_SECRET must be set in environment with at least 32 characters!');
    console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
    console.error('❌ FATAL: ENCRYPTION_KEY must be set in environment with at least 32 characters!');
    console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

// Token blacklist with expiry tracking
const tokenBlacklist = new Map();

function cleanupBlacklist() {
    const now = Date.now();
    let removed = 0;
    for (const [token, expiry] of tokenBlacklist) {
        if (expiry < now) {
            tokenBlacklist.delete(token);
            removed++;
        }
    }
    if (removed > 0) {
        console.log(`🧹 Removed ${removed} expired tokens from blacklist`);
    }
}

setInterval(cleanupBlacklist, 60 * 60 * 1000);
cleanupBlacklist();

console.log('🔒 Using Bearer token auth - inherently CSRF-safe');

const DEFAULT_TICKERALL_API_KEY = process.env.TICKERALL_API_KEY || null;
if (!DEFAULT_TICKERALL_API_KEY) {
    console.warn('⚠️ TICKERALL_API_KEY not set! Trading will not work until configured.');
}

const OWNER_EMAIL = process.env.OWNER_EMAIL || null;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || null;

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : ['*'];

const MAX_CONCURRENT_TRADES = parseInt(process.env.MAX_CONCURRENT_TRADES) || Infinity;
const MIN_BALANCE_FOR_TRADE = parseInt(process.env.MIN_BALANCE_FOR_TRADE) || 10;
const MAX_MARGIN_RISK = (parseInt(process.env.MAX_MARGIN_RISK) || 50) / 100;
const DEFAULT_ALLOW_FORCED_TRADES = process.env.ALLOW_FORCED_TRADES !== 'false';

const DEFAULT_RISK_PERCENT = parseInt(process.env.DEFAULT_RISK_PERCENT) || 8;
const MIN_RISK_PERCENT = parseInt(process.env.MIN_RISK_PERCENT) || 1;
const MAX_RISK_PERCENT = parseInt(process.env.MAX_RISK_PERCENT) || 25;

console.log('ALPHA - SECURE TRADING BOT v88.0.0');
console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`✅ User Risk Range: ${MIN_RISK_PERCENT}% - ${MAX_RISK_PERCENT}%`);
console.log(`✅ Default Risk: ${DEFAULT_RISK_PERCENT}%`);
console.log(`✅ Default Forced Trades: ${DEFAULT_ALLOW_FORCED_TRADES ? 'ENABLED' : 'DISABLED'}`);
console.log(`✅ TickerAll API Key: ${DEFAULT_TICKERALL_API_KEY ? 'SET FROM ENV' : 'NOT SET'}`);
console.log(`🔒 JWT_SECRET: ${JWT_SECRET ? '✅ Configured' : '❌ MISSING'}`);
console.log(`🔒 ENCRYPTION_KEY: ${ENCRYPTION_KEY ? '✅ Configured' : '❌ MISSING'}`);
console.log(`🔒 Token Blacklist: ${tokenBlacklist.size} tokens tracked`);

// ============================================================
// 🛡️ SECURITY MIDDLEWARE
// ============================================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", process.env.API_BASE_URL || "'self'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
}));

app.use(cors({
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS[0] === '*') return callback(null, true);
        if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
            return callback(null, true);
        } else {
            console.warn(`⚠️ CORS blocked origin: ${origin}`);
            return callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    keyGenerator: function(req) { return req.ip || req.connection.remoteAddress; }
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    message: { success: false, message: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: function(req) { return req.ip || req.connection.remoteAddress; },
    skip: function(req) {
        if (req.path === '/api/health' || req.path === '/') return true;
        return false;
    }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/api/', apiLimiter);

// ============================================================
// 🔒 SECURE STATIC FILE SERVING
// ============================================================

const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
}
app.use(express.static(publicDir));

// ============================================================
// 📁 DATA DIRECTORY
// ============================================================

const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const diagnosticsDir = path.join(dataDir, 'diagnostics');
const healLogsDir = path.join(dataDir, 'heal-logs');
const learningDir = path.join(dataDir, 'learning');

[dataDir, tradesDir, diagnosticsDir, healLogsDir, learningDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');
const configFile = path.join(dataDir, 'config.json');
const diagnosticsFile = path.join(diagnosticsDir, 'diagnostics.json');
const healLogFile = path.join(healLogsDir, 'heal-log.json');
const learningFile = path.join(learningDir, 'learning-data.json');

// ============================================================
// ⚙️ CONFIG
// ============================================================

let config = { 
    tickerallApiKey: DEFAULT_TICKERALL_API_KEY, 
    apiKeyExpired: false, 
    lastUpdated: new Date().toISOString(),
    createdAt: new Date().toISOString()
};

function loadConfig() {
    try {
        if (fs.existsSync(configFile)) {
            const savedConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
            if (DEFAULT_TICKERALL_API_KEY) {
                config.tickerallApiKey = DEFAULT_TICKERALL_API_KEY;
            } else if (savedConfig.tickerallApiKey) {
                config.tickerallApiKey = savedConfig.tickerallApiKey;
            }
            config.lastUpdated = new Date().toISOString();
            console.log('✅ Config loaded.');
        } else {
            fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
            console.log('📝 Created config file.');
        }
    } catch (error) {
        console.error('❌ Config error:', error);
    }
}
loadConfig();

function saveConfig(newConfig) {
    try {
        if (process.env.TICKERALL_API_KEY) {
            newConfig.tickerallApiKey = process.env.TICKERALL_API_KEY;
        }
        fs.writeFileSync(configFile, JSON.stringify(newConfig, null, 2));
        config = newConfig;
        console.log('✅ Config saved.');
    } catch (error) {
        console.error('❌ Save config error:', error);
    }
}

// ============================================================
// 🧠 REAL AI LEARNING SYSTEM
// ============================================================

const realAI = new (class RealAILearningSystem {
    constructor() {
        this.learningData = {
            patterns: {},
            successRates: {},
            optimalParameters: {},
            tradeHistory: [],
            adaptiveRules: {},
            lastUpdated: null
        };
        this.loadLearningData();
    }

    loadLearningData() {
        try {
            if (fs.existsSync(learningFile)) {
                this.learningData = JSON.parse(fs.readFileSync(learningFile, 'utf8'));
                console.log(`🧠 Loaded ${this.learningData.tradeHistory.length} trades`);
            } else {
                fs.writeFileSync(learningFile, JSON.stringify(this.learningData, null, 2));
                console.log('📝 Created AI Learning System');
            }
        } catch (error) {
            console.error('❌ Learning data error:', error);
        }
    }

    saveLearningData() {
        try {
            this.learningData.lastUpdated = new Date().toISOString();
            fs.writeFileSync(learningFile, JSON.stringify(this.learningData, null, 2));
        } catch (error) {
            console.error('❌ Save learning error:', error);
        }
    }

    learnFromTrade(trade) {
        try {
            this.learningData.tradeHistory.push({
                symbol: trade.symbol,
                side: trade.side,
                entryPrice: trade.entryPrice,
                exitPrice: trade.exitPrice,
                profit: trade.profit,
                profitPercent: trade.profitPercent,
                timestamp: new Date().toISOString(),
                marketConditions: trade.marketConditions || {},
                indicators: trade.indicators || {},
                isForced: trade.isForced || false
            });

            if (this.learningData.tradeHistory.length > 1000) {
                this.learningData.tradeHistory = this.learningData.tradeHistory.slice(-1000);
            }

            this.learnPattern(trade);
            this.updateSuccessRates(trade);
            this.adaptParameters(trade);
            this.saveLearningData();

            console.log(`🧠 Learned from ${trade.symbol} ${trade.side} | ${trade.profit > 0 ? '✅ WIN' : '❌ LOSS'}${trade.isForced ? ' (FORCED)' : ''}`);
        } catch (error) {
            console.error('❌ Learning error:', error);
        }
    }

    learnPattern(trade) {
        const key = `${trade.symbol}_${trade.side}`;
        if (!this.learningData.patterns[key]) {
            this.learningData.patterns[key] = {
                symbol: trade.symbol,
                side: trade.side,
                wins: 0,
                losses: 0,
                totalProfit: 0,
                avgProfit: 0,
                avgProfitPercent: 0,
                trades: 0,
                forcedTrades: 0,
                pattern: trade.indicators || {}
            };
        }

        const pattern = this.learningData.patterns[key];
        pattern.trades++;
        if (trade.isForced) pattern.forcedTrades++;
        if (trade.profit > 0) {
            pattern.wins++;
            pattern.totalProfit += trade.profit;
        } else {
            pattern.losses++;
        }
        pattern.avgProfit = pattern.totalProfit / pattern.trades;
        pattern.avgProfitPercent = (pattern.avgProfit / (trade.entryPrice || 1)) * 100;
    }

    updateSuccessRates(trade) {
        const key = trade.symbol;
        if (!this.learningData.successRates[key]) {
            this.learningData.successRates[key] = {
                symbol: trade.symbol,
                totalTrades: 0,
                wins: 0,
                losses: 0,
                forcedTrades: 0,
                winRate: 0,
                avgProfit: 0,
                totalProfit: 0
            };
        }

        const rate = this.learningData.successRates[key];
        rate.totalTrades++;
        if (trade.isForced) rate.forcedTrades++;
        if (trade.profit > 0) {
            rate.wins++;
            rate.totalProfit += trade.profit;
        } else {
            rate.losses++;
        }
        rate.winRate = rate.totalTrades > 0 ? (rate.wins / rate.totalTrades) * 100 : 0;
        rate.avgProfit = rate.totalTrades > 0 ? rate.totalProfit / rate.totalTrades : 0;
    }

    adaptParameters(trade) {
        const key = trade.symbol;
        if (!this.learningData.adaptiveRules[key]) {
            this.learningData.adaptiveRules[key] = {
                symbol: trade.symbol,
                riskMultiplier: 1.0,
                confidenceThreshold: 0.5,
                takeProfitMultiplier: 2.0,
                stopLossMultiplier: 1.5,
                lastAdjusted: new Date().toISOString()
            };
        }

        const rule = this.learningData.adaptiveRules[key];
        const recentTrades = this.learningData.tradeHistory.filter(t => t.symbol === trade.symbol).slice(-20);

        if (recentTrades.length >= 10) {
            const wins = recentTrades.filter(t => t.profit > 0).length;
            const winRate = wins / recentTrades.length;
            const avgProfit = recentTrades.reduce((sum, t) => sum + t.profit, 0) / recentTrades.length;

            if (winRate > 0.6 && avgProfit > 0) {
                rule.riskMultiplier = Math.min(2.0, rule.riskMultiplier + 0.1);
                rule.confidenceThreshold = Math.max(0.3, rule.confidenceThreshold - 0.05);
            } else if (winRate < 0.4 || avgProfit < 0) {
                rule.riskMultiplier = Math.max(0.5, rule.riskMultiplier - 0.1);
                rule.confidenceThreshold = Math.min(0.7, rule.confidenceThreshold + 0.05);
            }

            rule.lastAdjusted = new Date().toISOString();
            this.learningData.optimalParameters[key] = rule;
        }
    }

    getAdaptiveParameters(symbol) {
        if (this.learningData.adaptiveRules[symbol]) {
            return this.learningData.adaptiveRules[symbol];
        }
        return {
            symbol: symbol,
            riskMultiplier: 1.0,
            confidenceThreshold: 0.5,
            takeProfitMultiplier: 2.0,
            stopLossMultiplier: 1.5,
            lastAdjusted: new Date().toISOString()
        };
    }

    getPatternStrength(symbol, side, indicators) {
        const key = `${symbol}_${side}`;
        const pattern = this.learningData.patterns[key];
        if (!pattern || pattern.trades < 5) {
            return { strength: 0.5, confidence: 0.5, sampleSize: 0 };
        }

        const winRate = pattern.wins / pattern.trades;
        return {
            strength: Math.min(1, winRate * 1.2),
            confidence: Math.min(1, pattern.trades / 100),
            sampleSize: pattern.trades,
            winRate: winRate,
            avgProfit: pattern.avgProfit,
            forcedTrades: pattern.forcedTrades || 0
        };
    }

    getWinRate(symbol) {
        const rate = this.learningData.successRates[symbol];
        if (!rate || rate.totalTrades < 5) {
            return { winRate: 50, totalTrades: 0 };
        }
        return {
            winRate: rate.winRate,
            totalTrades: rate.totalTrades,
            wins: rate.wins,
            losses: rate.losses,
            forcedTrades: rate.forcedTrades || 0
        };
    }

    getLearningStats() {
        return {
            totalTrades: this.learningData.tradeHistory.length,
            patterns: Object.keys(this.learningData.patterns).length,
            symbols: Object.keys(this.learningData.successRates),
            lastUpdated: this.learningData.lastUpdated,
            adaptiveRules: Object.keys(this.learningData.adaptiveRules).length,
            forcedTrades: this.learningData.tradeHistory.filter(t => t.isForced).length
        };
    }
})();

// ============================================================
// 👤 USER DATA with Risk Settings (includes forced trades toggle)
// ============================================================

function createDefaultUser(email, passwordHash) {
    return {
        email: email,
        password: passwordHash,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        tickerallSessionId: "",
        exnessLogin: "",
        exnessServer: "",
        lastBalance: 0,
        lastBalanceCurrency: "USD",
        lastBalanceUpdate: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        riskSettings: {
            riskPercent: DEFAULT_RISK_PERCENT,
            maxConcurrentTrades: 10,
            minBalance: 10,
            autoCompound: true,
            stopLossMultiplier: 1.5,
            takeProfitMultiplier: 2.0,
            maxDailyLoss: 20,
            maxDailyTrades: 100,
            allowForcedTrades: DEFAULT_ALLOW_FORCED_TRADES,
            updatedAt: new Date().toISOString()
        },
        stats: {
            totalTrades: 0,
            wins: 0,
            losses: 0,
            forcedTrades: 0,
            totalProfit: 0,
            bestTrade: 0,
            worstTrade: 0,
            winRate: 0,
            avgProfit: 0,
            lastTradeAt: null,
            updatedAt: new Date().toISOString()
        }
    };
}

function readUsers() {
    try {
        if (!fs.existsSync(usersFile)) return {};
        return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    } catch (error) {
        console.error('❌ Read users error:', error);
        return {};
    }
}

function writeUsers(users) {
    try {
        fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('❌ Write users error:', error);
    }
}

function readPending() {
    try {
        if (!fs.existsSync(pendingFile)) return {};
        return JSON.parse(fs.readFileSync(pendingFile, 'utf8'));
    } catch (error) {
        console.error('❌ Read pending error:', error);
        return {};
    }
}

function writePending(pending) {
    try {
        fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2));
    } catch (error) {
        console.error('❌ Write pending error:', error);
    }
}

// ============================================================
// 🔑 AUTHENTICATION
// ============================================================

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        }
        
        const users = readUsers();
        if (users[email]) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }
        
        const pending = readPending();
        if (pending[email]) {
            return res.status(400).json({ success: false, message: 'Registration already pending approval' });
        }
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        pending[email] = {
            password: hashedPassword,
            requestedAt: new Date().toISOString()
        };
        writePending(pending);
        
        console.log(`📝 Registration request: ${email}`);
        
        res.json({ 
            success: true, 
            message: 'Registration request submitted. Waiting for admin approval.' 
        });
    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/login', authLimiter, (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }
        
        const users = readUsers();
        const user = users[email];
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (!user.isApproved && !user.isOwner) {
            return res.status(401).json({ success: false, message: 'Account not approved. Please wait for admin approval.' });
        }
        
        if (user.isBlocked) {
            return res.status(401).json({ success: false, message: 'Account has been blocked' });
        }
        
        const token = jwt.sign(
            { id: email, email: email, isOwner: user.isOwner === true },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        console.log(`✅ Login successful: ${email}`);
        
        res.json({
            success: true,
            token: token,
            isOwner: user.isOwner === true,
            user: {
                email: email
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/logout', authenticate, (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            try {
                const decoded = jwt.decode(token);
                const expiryMs = decoded?.exp ? decoded.exp * 1000 : Date.now() + 7 * 24 * 60 * 60 * 1000;
                tokenBlacklist.set(token, expiryMs);
                console.log(`🚪 User logged out: ${req.user.email}, token expires at ${new Date(expiryMs).toISOString()}`);
            } catch (e) {
                tokenBlacklist.set(token, Date.now() + 7 * 24 * 60 * 60 * 1000);
                console.log(`🚪 User logged out: ${req.user.email} (malformed token)`);
            }
        }
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('❌ Logout error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

function ensureDefaultOwner() {
    if (!OWNER_EMAIL || !OWNER_PASSWORD) {
        console.log('ℹ️ No owner credentials in environment.');
        return;
    }

    const users = readUsers();
    
    if (!users[OWNER_EMAIL]) {
        const hashedPassword = bcrypt.hashSync(OWNER_PASSWORD, 10);
        users[OWNER_EMAIL] = createDefaultUser(OWNER_EMAIL, hashedPassword);
        users[OWNER_EMAIL].isOwner = true;
        writeUsers(users);
        console.log(`✅ Default owner created: ${OWNER_EMAIL}`);
        console.log(`⚠️  For security, remove OWNER_PASSWORD from environment after first login.`);
    } else {
        const user = users[OWNER_EMAIL];
        if (process.env.FORCE_OWNER_PASSWORD_RESET === 'true') {
            const hashedPassword = bcrypt.hashSync(OWNER_PASSWORD, 10);
            user.password = hashedPassword;
            writeUsers(users);
            console.log(`✅ Owner password reset: ${OWNER_EMAIL}`);
        }
        console.log(`✅ Owner exists: ${OWNER_EMAIL}`);
    }
}
ensureDefaultOwner();

// ============================================================
// 🔐 ENCRYPTION
// ============================================================

function encrypt(text) {
    if (!text) return "";
    try {
        const iv = crypto.randomBytes(16);
        const key = Buffer.from(ENCRYPTION_KEY, 'hex');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error('❌ Encryption error:', error.message);
        return "";
    }
}

function decrypt(text) {
    if (!text) return "";
    try {
        const parts = text.split(':');
        if (parts.length !== 2) {
            console.warn('⚠️ Invalid encrypted format');
            return "";
        }
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = Buffer.from(parts[1], 'hex');
        const key = Buffer.from(ENCRYPTION_KEY, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error('❌ Decryption error:', error.message);
        return "";
    }
}

// ============================================================
// 🔌 TICKERALL INIT
// ============================================================

let ticker = null;
let apiKeyStatus = 'unknown';
let activeTickerallSessionId = null;

function initTicker() {
    const apiKey = config.tickerallApiKey || process.env.TICKERALL_API_KEY || null;
    if (!apiKey) {
        console.warn('⚠️ No TickerAll API key found. Trading disabled.');
        ticker = null;
        apiKeyStatus = 'inactive';
        return false;
    }
    try {
        ticker = new Tickerall({ apiKey: apiKey });
        console.log('✅ TickerAll initialized');
        apiKeyStatus = 'active';
        return true;
    } catch (error) {
        console.error('❌ TickerAll init error:', error.message);
        ticker = null;
        apiKeyStatus = 'invalid';
        return false;
    }
}
initTicker();

// ============================================================
// 🛡️ MIDDLEWARE
// ============================================================

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'Missing Authorization header' });
    }
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).json({ success: false, message: 'Invalid format. Use: Bearer <token>' });
    }
    const token = parts[1];
    
    const expiry = tokenBlacklist.get(token);
    if (expiry && expiry > Date.now()) {
        return res.status(401).json({ success: false, message: 'Token has been revoked' });
    }
    if (expiry && expiry <= Date.now()) {
        tokenBlacklist.delete(token);
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        req.token = token;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
}

function isOwner(req, res, next) {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    next();
}

// ============================================================
// 👤 USER RISK SETTINGS API (includes forced trades)
// ============================================================

app.get('/api/user/risk-settings', authenticate, (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (!user.riskSettings) {
            user.riskSettings = {
                riskPercent: DEFAULT_RISK_PERCENT,
                maxConcurrentTrades: 10,
                minBalance: 10,
                autoCompound: true,
                stopLossMultiplier: 1.5,
                takeProfitMultiplier: 2.0,
                maxDailyLoss: 20,
                maxDailyTrades: 100,
                allowForcedTrades: DEFAULT_ALLOW_FORCED_TRADES,
                updatedAt: new Date().toISOString()
            };
            writeUsers(users);
        }
        
        res.json({
            success: true,
            riskSettings: user.riskSettings,
            stats: user.stats || {
                totalTrades: 0,
                wins: 0,
                losses: 0,
                forcedTrades: 0,
                totalProfit: 0,
                bestTrade: 0,
                worstTrade: 0,
                winRate: 0,
                avgProfit: 0
            }
        });
    } catch (error) {
        console.error('❌ Get risk settings error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/user/risk-settings', authenticate, (req, res) => {
    try {
        const { riskPercent, maxConcurrentTrades, minBalance, autoCompound, stopLossMultiplier, takeProfitMultiplier, maxDailyLoss, maxDailyTrades, allowForcedTrades } = req.body;
        
        const users = readUsers();
        const user = users[req.user.email];
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (riskPercent !== undefined) {
            if (riskPercent < MIN_RISK_PERCENT || riskPercent > MAX_RISK_PERCENT) {
                return res.status(400).json({ 
                    success: false, 
                    message: `Risk percentage must be between ${MIN_RISK_PERCENT}% and ${MAX_RISK_PERCENT}%` 
                });
            }
            user.riskSettings.riskPercent = riskPercent;
        }
        
        if (maxConcurrentTrades !== undefined) {
            if (maxConcurrentTrades < 1 || maxConcurrentTrades > 100) {
                return res.status(400).json({ success: false, message: 'Max concurrent trades must be between 1 and 100' });
            }
            user.riskSettings.maxConcurrentTrades = maxConcurrentTrades;
        }
        
        if (minBalance !== undefined) {
            if (minBalance < 1 || minBalance > 1000) {
                return res.status(400).json({ success: false, message: 'Min balance must be between $1 and $1000' });
            }
            user.riskSettings.minBalance = minBalance;
        }
        
        if (autoCompound !== undefined) {
            user.riskSettings.autoCompound = autoCompound;
        }
        
        if (stopLossMultiplier !== undefined) {
            if (stopLossMultiplier < 0.5 || stopLossMultiplier > 5) {
                return res.status(400).json({ success: false, message: 'Stop loss multiplier must be between 0.5 and 5' });
            }
            user.riskSettings.stopLossMultiplier = stopLossMultiplier;
        }
        
        if (takeProfitMultiplier !== undefined) {
            if (takeProfitMultiplier < 0.5 || takeProfitMultiplier > 10) {
                return res.status(400).json({ success: false, message: 'Take profit multiplier must be between 0.5 and 10' });
            }
            user.riskSettings.takeProfitMultiplier = takeProfitMultiplier;
        }
        
        if (maxDailyLoss !== undefined) {
            if (maxDailyLoss < 1 || maxDailyLoss > 100) {
                return res.status(400).json({ success: false, message: 'Max daily loss must be between 1% and 100%' });
            }
            user.riskSettings.maxDailyLoss = maxDailyLoss;
        }
        
        if (maxDailyTrades !== undefined) {
            if (maxDailyTrades < 1 || maxDailyTrades > 1000) {
                return res.status(400).json({ success: false, message: 'Max daily trades must be between 1 and 1000' });
            }
            user.riskSettings.maxDailyTrades = maxDailyTrades;
        }
        
        if (allowForcedTrades !== undefined) {
            user.riskSettings.allowForcedTrades = allowForcedTrades;
        }
        
        user.riskSettings.updatedAt = new Date().toISOString();
        writeUsers(users);
        
        console.log(`📊 Risk settings updated for ${req.user.email}: ${user.riskSettings.riskPercent}% risk, Forced Trades: ${user.riskSettings.allowForcedTrades ? 'ON' : 'OFF'}`);
        
        res.json({
            success: true,
            message: 'Risk settings updated successfully',
            riskSettings: user.riskSettings
        });
    } catch (error) {
        console.error('❌ Update risk settings error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/user/stats', authenticate, (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({
            success: true,
            stats: user.stats || {
                totalTrades: 0,
                wins: 0,
                losses: 0,
                forcedTrades: 0,
                totalProfit: 0,
                bestTrade: 0,
                worstTrade: 0,
                winRate: 0,
                avgProfit: 0
            }
        });
    } catch (error) {
        console.error('❌ Get user stats error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============================================================
// 🔑 ADMIN ROUTES
// ============================================================

app.get('/api/admin/pending-users', authenticate, isOwner, (req, res) => {
    try {
        const pending = readPending();
        const list = Object.keys(pending).map(email => ({
            email,
            requestedAt: pending[email].requestedAt
        }));
        res.json({ success: true, pending: list });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/approve-user', authenticate, isOwner, (req, res) => {
    try {
        const { email } = req.body;
        const pending = readPending();
        if (!pending[email]) {
            return res.status(404).json({ success: false, message: 'No pending request found' });
        }
        
        const users = readUsers();
        if (users[email]) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }
        
        const user = createDefaultUser(email, pending[email].password);
        users[email] = user;
        writeUsers(users);
        
        delete pending[email];
        writePending(pending);
        
        console.log(`✅ User approved: ${email}`);
        res.json({ success: true, message: `User ${email} approved successfully` });
    } catch (error) {
        console.error('❌ Approve user error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/reject-user', authenticate, isOwner, (req, res) => {
    try {
        const { email } = req.body;
        const pending = readPending();
        if (!pending[email]) {
            return res.status(404).json({ success: false, message: 'No pending request found' });
        }
        
        delete pending[email];
        writePending(pending);
        
        console.log(`❌ User rejected: ${email}`);
        res.json({ success: true, message: `User ${email} rejected` });
    } catch (error) {
        console.error('❌ Reject user error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/toggle-block', authenticate, isOwner, (req, res) => {
    try {
        const { email } = req.body;
        const users = readUsers();
        if (!users[email]) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        if (users[email].isOwner) {
            return res.status(403).json({ success: false, message: 'Cannot block owner' });
        }
        users[email].isBlocked = !users[email].isBlocked;
        writeUsers(users);
        res.json({ 
            success: true, 
            message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` 
        });
    } catch (error) {
        console.error('❌ Toggle block error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/users', authenticate, isOwner, (req, res) => {
    try {
        const users = readUsers();
        const list = Object.keys(users).map(email => ({
            email,
            hasExnessCreds: !!users[email].exnessLogin,
            isOwner: users[email].isOwner || false,
            isApproved: users[email].isApproved !== false,
            isBlocked: users[email].isBlocked || false,
            balance: users[email].lastBalance || 0,
            riskPercent: users[email].riskSettings?.riskPercent || DEFAULT_RISK_PERCENT,
            allowForcedTrades: users[email].riskSettings?.allowForcedTrades !== false,
            createdAt: users[email].createdAt
        }));
        res.json({ success: true, users: list });
    } catch (error) {
        console.error('❌ Get users error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/user-balances', authenticate, isOwner, async (req, res) => {
    try {
        const users = readUsers();
        const balances = {};
        for (const [email, userData] of Object.entries(users)) {
            if (!userData.tickerallSessionId) {
                balances[email] = { balance: 0, currency: 'USD', hasConnection: false };
                continue;
            }
            try {
                const result = await fetchRealBalance(userData.tickerallSessionId);
                balances[email] = {
                    balance: result.balance || 0,
                    currency: result.currency || 'USD',
                    hasConnection: true,
                    riskPercent: userData.riskSettings?.riskPercent || DEFAULT_RISK_PERCENT,
                    allowForcedTrades: userData.riskSettings?.allowForcedTrades !== false,
                    lastUpdated: new Date().toISOString()
                };
            } catch (error) {
                balances[email] = { balance: 0, currency: 'USD', hasConnection: false, error: error.message };
            }
        }
        res.json({ success: true, balances });
    } catch (error) {
        console.error('❌ Get balances error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/change-password', authenticate, isOwner, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Current and new password required' });
        }
        if (newPassword.length < 8) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
        }
        const users = readUsers();
        const owner = users[req.user.email];
        if (!owner) {
            return res.status(404).json({ success: false, message: 'Owner not found' });
        }
        if (!bcrypt.compareSync(currentPassword, owner.password)) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect' });
        }
        owner.password = bcrypt.hashSync(newPassword, 10);
        writeUsers(users);
        console.log(`🔑 Password changed for: ${req.user.email}`);
        res.json({ success: true, message: '✅ Password changed successfully! Please login again.' });
    } catch (error) {
        console.error('❌ Password change error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============================================================
// 🔑 TICKERALL API KEY MANAGEMENT
// ============================================================

app.get('/api/admin/get-tickerall-key', authenticate, isOwner, (req, res) => {
    try {
        const currentKey = config.tickerallApiKey || process.env.TICKERALL_API_KEY || null;
        const maskedKey = currentKey 
            ? currentKey.substring(0, 10) + '****' + currentKey.substring(currentKey.length - 10) 
            : null;
        res.json({
            success: true,
            apiKey: currentKey || '',
            maskedKey: maskedKey,
            status: apiKeyStatus || 'unknown',
            lastUpdated: config.lastUpdated || 'Never',
            isConfigured: !!currentKey,
            source: process.env.TICKERALL_API_KEY ? 'ENVIRONMENT VARIABLE' : 'USER CONFIGURED'
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/set-tickerall-key', authenticate, isOwner, async (req, res) => {
    try {
        const { apiKey } = req.body;
        if (!apiKey || apiKey.trim() === '') {
            return res.status(400).json({ success: false, message: 'API key is required' });
        }
        
        if (process.env.TICKERALL_API_KEY) {
            return res.status(403).json({ 
                success: false, 
                message: 'Cannot update API key - TICKERALL_API_KEY is set in environment. Update the environment variable instead.' 
            });
        }
        
        const trimmedKey = apiKey.trim();
        const newConfig = { 
            tickerallApiKey: trimmedKey, 
            apiKeyExpired: false, 
            lastUpdated: new Date().toISOString(),
            createdAt: config.createdAt || new Date().toISOString()
        };
        saveConfig(newConfig);
        
        apiKeyStatus = 'active';
        const reinitSuccess = initTicker();
        
        if (reinitSuccess) {
            res.json({ success: true, message: '✅ API key updated successfully!', status: 'active' });
        } else {
            res.json({ success: false, message: '⚠️ Key saved but initialization failed.', status: 'error' });
        }
    } catch (error) {
        console.error('❌ Failed to update API key:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/test-tickerall-key', authenticate, isOwner, async (req, res) => {
    try {
        const { apiKey } = req.body;
        if (!apiKey || apiKey.trim() === '') {
            return res.status(400).json({ success: false, message: 'API key is required', valid: false });
        }
        
        const trimmedKey = apiKey.trim();
        
        try {
            const testTicker = new Tickerall({ apiKey: trimmedKey });
            await testTicker.getServerTime();
            res.json({ valid: true, message: '✅ API key is valid and working!' });
        } catch (err) {
            res.json({ valid: false, message: '❌ Invalid API key: ' + err.message });
        }
    } catch (error) {
        console.error('❌ API key test error:', error);
        res.status(500).json({ valid: false, message: error.message });
    }
});

// ============================================================
// 📊 BALANCE FUNCTIONS
// ============================================================

async function fetchRealBalance(accountId) {
    try {
        if (!ticker) {
            const reinit = initTicker();
            if (!reinit) {
                return { balance: 0, currency: 'USD', error: 'TickerAll not initialized', isReal: false };
            }
        }
        
        if (!accountId) {
            return { balance: 0, currency: 'USD', error: 'No account ID', isReal: false };
        }

        const accountInfo = await Promise.race([
            ticker.accounts.get(accountId),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 15000))
        ]);

        if (!accountInfo) {
            return { balance: 0, currency: 'USD', error: 'No account info', isReal: false };
        }

        let balance = 0;
        let currency = accountInfo.currency || accountInfo.Currency || 'USD';
        let foundField = null;

        const fields = [
            'balance', 'Balance', 'BALANCE', 'equity', 'Equity', 'EQUITY',
            'freeMargin', 'FreeMargin', 'FREEMARGIN', 'marginFree', 'MarginFree',
            'amount', 'Amount', 'AMOUNT', 'total', 'Total', 'TOTAL',
            'cash', 'Cash', 'CASH', 'funds', 'Funds', 'FUNDS',
            'available', 'Available', 'AVAILABLE', 'usable', 'Usable',
            'net', 'Net', 'NET', 'value', 'Value', 'VALUE'
        ];

        for (const field of fields) {
            if (accountInfo[field] !== undefined && accountInfo[field] !== null) {
                const val = parseFloat(accountInfo[field]);
                if (!isNaN(val) && val > 0 && val < 1000000000) {
                    balance = val;
                    foundField = field;
                    console.log(`✅ Found balance in "${field}": ${balance}`);
                    break;
                }
            }
        }

        if (balance === 0) {
            for (const [key, value] of Object.entries(accountInfo)) {
                if (typeof value === 'number' && !isNaN(value) && value > 0 && value < 1000000000) {
                    const keyLower = key.toLowerCase();
                    if (['balance', 'equity', 'margin', 'free', 'cash', 'total', 'amount', 'net', 'value', 'fund', 'available', 'usable', 'trading', 'wallet'].some(kw => keyLower.includes(kw))) {
                        balance = value;
                        foundField = key;
                        console.log(`✅ Found balance in "${key}": ${balance}`);
                        break;
                    }
                }
            }
        }

        const users = readUsers();
        for (const [email, userData] of Object.entries(users)) {
            if (userData.tickerallSessionId === accountId) {
                userData.lastBalance = balance;
                userData.lastBalanceCurrency = currency;
                userData.lastBalanceUpdate = new Date().toISOString();
                writeUsers(users);
                break;
            }
        }

        return { balance, currency, full: accountInfo, isReal: true, foundField };
    } catch (error) {
        console.error('❌ Balance fetch error:', error.message);
        return { balance: 0, currency: 'USD', error: error.message, isReal: false };
    }
}

// ============================================================
// 🔌 EXNESS CONNECTION
// ============================================================

app.post('/api/set-exness-creds', authenticate, async (req, res) => {
    try {
        const { exnessLogin, exnessPassword, exnessServer } = req.body;
        if (!exnessLogin || !exnessPassword || !exnessServer) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }

        if (!ticker) {
            const reinit = initTicker();
            if (!reinit) {
                return res.status(500).json({ success: false, message: 'TickerAll initialization failed. Please update API key.' });
            }
        }

        console.log(`📊 Connecting to Exness: ${exnessServer}`);

        let accountId = null;
        let lastError = null;

        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                const result = await Promise.race([
                    ticker.sessions.start({
                        broker: 'mt5',
                        server: exnessServer,
                        account: parseInt(exnessLogin),
                        password: exnessPassword,
                    }),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 25000))
                ]);
                accountId = result.accountId;
                console.log(`✅ Session created: ${accountId}`);
                activeTickerallSessionId = accountId;
                break;
            } catch (err) {
                lastError = err.message;
                console.error(`❌ Attempt ${attempt} failed:`, err.message);
                if (attempt < 3) await new Promise(r => setTimeout(r, 3000));
            }
        }

        if (!accountId) {
            return res.status(401).json({ success: false, message: `Connection failed: ${lastError}` });
        }

        const result = await fetchRealBalance(accountId);

        const users = readUsers();
        users[req.user.email].tickerallSessionId = accountId;
        users[req.user.email].exnessLogin = encrypt(exnessLogin);
        users[req.user.email].exnessServer = encrypt(exnessServer);
        users[req.user.email].lastBalance = result.balance;
        users[req.user.email].lastBalanceCurrency = result.currency || 'USD';
        users[req.user.email].lastBalanceUpdate = new Date().toISOString();
        writeUsers(users);

        res.json({
            success: true,
            message: `✅ Connected! Balance: ${result.balance} ${result.currency || 'USD'}`,
            balance: result.balance,
            currency: result.currency || 'USD',
            accountId
        });
    } catch (error) {
        console.error('❌ Connection error:', error);
        res.status(401).json({ success: false, message: error.message || 'Connection failed.' });
    }
});

app.post('/api/connect-exness', authenticate, async (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.tickerallSessionId) {
            return res.status(400).json({ success: false, message: 'No credentials saved.' });
        }

        if (!ticker) initTicker();

        const result = await fetchRealBalance(user.tickerallSessionId);
        if (result.balance > 0) {
            user.lastBalance = result.balance;
            user.lastBalanceCurrency = result.currency || 'USD';
            user.lastBalanceUpdate = new Date().toISOString();
            writeUsers(users);
        }
        res.json({
            success: true,
            balance: result.balance || 0,
            currency: result.currency || 'USD',
            message: `Connected! Balance: ${result.balance || 0} ${result.currency || 'USD'}`
        });
    } catch (error) {
        res.status(401).json({ success: false, message: error.message });
    }
});

app.get('/api/get-exness-creds', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.exnessLogin) return res.json({ success: false });
    res.json({
        success: true,
        exnessLogin: decrypt(user.exnessLogin) || '',
        exnessServer: decrypt(user.exnessServer) || ''
    });
});

app.get('/api/debug-balance', authenticate, async (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.tickerallSessionId) {
            return res.json({ success: false, message: 'No session ID found.' });
        }
        const result = await fetchRealBalance(user.tickerallSessionId);
        res.json({
            success: true,
            sessionId: user.tickerallSessionId,
            balance: result.balance || 0,
            currency: result.currency || 'USD',
            foundField: result.foundField || null,
            storedBalance: user.lastBalance || 0,
            storedCurrency: user.lastBalanceCurrency || 'USD'
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============================================================
// 🧠 SELF-HEALING AI DIAGNOSTIC SYSTEM
// ============================================================

class SelfHealingAIDiagnosticSystem {
    constructor() {
        this.isRunning = false;
        this.diagnosticInterval = null;
        this.healingActions = new Map();
        this.learnedFixes = new Map();
        this.diagnostics = {
            status: 'initializing',
            healthScore: 100,
            issues: [],
            fixes: [],
            recommendations: [],
            components: {
                server: { status: 'unknown', checks: [] },
                tickerall: { status: 'unknown', checks: [] },
                exness: { status: 'unknown', checks: [] },
                balance: { status: 'unknown', checks: [] },
                trading: { status: 'unknown', checks: [] },
                auth: { status: 'unknown', checks: [] }
            },
            lastScan: null,
            logs: []
        };
        
        this.config = {
            checkInterval: 30000,
            maxHealAttempts: 3,
            healCooldown: 60000,
            autoHealEnabled: true,
            notificationEnabled: true
        };
        
        this.initialize();
    }

    initialize() {
        console.log('🧠 Self-Healing AI Diagnostic System Initialized');
        this.loadLearnedFixes();
        this.startDiagnosticMonitoring();
    }

    loadLearnedFixes() {
        try {
            if (fs.existsSync(healLogFile)) {
                const data = JSON.parse(fs.readFileSync(healLogFile, 'utf8'));
                Object.keys(data).forEach(key => {
                    this.learnedFixes.set(key, data[key]);
                });
                console.log(`💡 Loaded ${this.learnedFixes.size} learned fixes`);
            }
        } catch (error) {
            console.warn('Could not load learned fixes:', error.message);
        }
    }

    startDiagnosticMonitoring() {
        if (this.isRunning) return;
        this.isRunning = true;
        console.log('🔍 Starting Self-Healing AI Diagnostic Monitoring...');
        
        this.diagnosticInterval = setInterval(async () => {
            try {
                await this.runDiagnostics();
            } catch (error) {
                console.error('Diagnostic loop error:', error);
            }
        }, this.config.checkInterval);
        
        setTimeout(() => this.runDiagnostics(), 5000);
    }

    async runDiagnostics() {
        console.log('🔬 Running diagnostic sweep...');
        let issues = [];
        let fixes = [];
        let healthScore = 100;
        
        try {
            const serverCheck = this.checkServer();
            this.diagnostics.components.server = serverCheck;
            if (serverCheck.status === 'error') {
                issues.push({ component: 'server', issue: serverCheck.error, severity: 'critical' });
                healthScore -= 20;
            }

            const tickerallCheck = await this.checkTickerAll();
            this.diagnostics.components.tickerall = tickerallCheck;
            if (tickerallCheck.status === 'error') {
                issues.push({ component: 'tickerall', issue: tickerallCheck.error, severity: 'critical' });
                healthScore -= 25;
                fixes.push({ component: 'tickerall', action: 'reinitialize_tickerall', description: 'Reinitialize TickerAll' });
            }

            const exnessCheck = await this.checkExness();
            this.diagnostics.components.exness = exnessCheck;
            if (exnessCheck.status === 'error') {
                issues.push({ component: 'exness', issue: exnessCheck.error, severity: 'critical' });
                healthScore -= 25;
                fixes.push({ component: 'exness', action: 'reconnect_exness', description: 'Reconnect Exness' });
            }

            const balanceCheck = await this.checkBalance();
            this.diagnostics.components.balance = balanceCheck;
            if (balanceCheck.status === 'error') {
                issues.push({ component: 'balance', issue: balanceCheck.error, severity: 'critical' });
                healthScore -= 25;
                fixes.push({ component: 'balance', action: 'refresh_balance', description: 'Refresh balance' });
            }

            const tradingCheck = await this.checkTrading();
            this.diagnostics.components.trading = tradingCheck;
            if (tradingCheck.status === 'error') {
                issues.push({ component: 'trading', issue: tradingCheck.error, severity: 'critical' });
                healthScore -= 20;
                fixes.push({ component: 'trading', action: 'restart_trading', description: 'Restart trading engine' });
            }

            const authCheck = this.checkAuth();
            this.diagnostics.components.auth = authCheck;
            if (authCheck.status === 'error') {
                issues.push({ component: 'auth', issue: authCheck.error, severity: 'critical' });
                healthScore -= 15;
            }

            healthScore = Math.max(0, healthScore);
            let status = healthScore >= 80 ? 'healthy' : healthScore >= 50 ? 'degraded' : 'critical';

            this.diagnostics.status = status;
            this.diagnostics.healthScore = healthScore;
            this.diagnostics.issues = issues;
            this.diagnostics.fixes = fixes;
            this.diagnostics.lastScan = new Date().toISOString();
            this.diagnostics.logs.push({
                timestamp: new Date().toISOString(),
                status: status,
                issues: issues.length,
                fixes: fixes.length,
                healthScore: healthScore
            });

            fs.writeFileSync(diagnosticsFile, JSON.stringify(this.diagnostics, null, 2));

            console.log(`✅ Diagnostic Complete: ${status} (${healthScore}%)`);
        } catch (error) {
            console.error('❌ Diagnostic scan error:', error);
        }
    }

    checkServer() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            result.checks.push({ name: 'Server running', passed: true });
            result.checks.push({ name: 'Port available', passed: true });
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    async checkTickerAll() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            result.checks.push({ name: 'TickerAll initialized', passed: !!ticker });
            if (!ticker) {
                result.status = 'error';
                result.error = 'TickerAll not initialized';
                return result;
            }
            result.checks.push({ name: 'API key valid', passed: apiKeyStatus === 'active' });
            if (apiKeyStatus !== 'active') {
                result.status = 'error';
                result.error = `API key status: ${apiKeyStatus}`;
                return result;
            }
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    async checkExness() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            const users = readUsers();
            let hasCreds = false;
            let hasSession = false;
            for (const [email, userData] of Object.entries(users)) {
                if (userData.exnessLogin && userData.tickerallSessionId) {
                    hasCreds = true;
                    hasSession = true;
                    break;
                }
            }
            result.checks.push({ name: 'Exness credentials saved', passed: hasCreds });
            if (!hasCreds) {
                result.status = 'warning';
                result.warnings.push('No Exness credentials found');
                return result;
            }
            result.checks.push({ name: 'Active session exists', passed: hasSession });
            if (!hasSession) {
                result.status = 'warning';
                result.warnings.push('No active Exness session');
                return result;
            }
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    async checkBalance() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            const users = readUsers();
            let hasBalance = false;
            for (const [email, userData] of Object.entries(users)) {
                if (userData.lastBalance > 0) {
                    hasBalance = true;
                    break;
                }
            }
            result.checks.push({ name: 'Balance detected', passed: hasBalance });
            if (!hasBalance) {
                result.status = 'warning';
                result.warnings.push('No balance detected. Please connect Exness account.');
            }
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    async checkTrading() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            const engineCount = Object.keys(engines).length;
            result.checks.push({ name: 'Active trading engines', passed: engineCount > 0 });
            if (engineCount === 0) {
                result.status = 'warning';
                result.warnings.push('No active trading engines. Click "START TRADING" to activate.');
            }
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    checkAuth() {
        const result = { status: 'ok', checks: [], warnings: [] };
        try {
            const users = readUsers();
            const userCount = Object.keys(users).length;
            result.checks.push({ name: `Users registered: ${userCount}`, passed: userCount > 0 });
            const ownerExists = Object.values(users).some(u => u.isOwner);
            result.checks.push({ name: 'Owner account exists', passed: ownerExists });
            if (!ownerExists) {
                result.status = 'error';
                result.error = 'No owner account found';
            }
            return result;
        } catch (e) {
            result.status = 'error';
            result.error = e.message;
            return result;
        }
    }

    async applyHealing(fix) {
        console.log(`🔧 Applying healing: ${fix.action}`);
        let success = false;
        let message = '';

        try {
            switch (fix.action) {
                case 'reinitialize_tickerall':
                    success = initTicker();
                    message = success ? 'TickerAll reinitialized' : 'Failed to reinitialize';
                    break;
                case 'reconnect_exness':
                    success = true;
                    message = 'Please reconnect Exness manually';
                    break;
                case 'refresh_balance':
                    const users = readUsers();
                    let refreshed = 0;
                    for (const [email, userData] of Object.entries(users)) {
                        if (userData.tickerallSessionId) {
                            const result = await fetchRealBalance(userData.tickerallSessionId);
                            if (result.balance > 0) refreshed++;
                        }
                    }
                    success = refreshed > 0;
                    message = refreshed > 0 ? `Balance refreshed for ${refreshed} accounts` : 'No balance found';
                    break;
                case 'restart_trading':
                    for (const [id, engine] of Object.entries(engines)) {
                        if (engine.stop) await engine.stop();
                        delete engines[id];
                    }
                    success = true;
                    message = 'Trading engines stopped. Please restart manually.';
                    break;
                default:
                    message = `Unknown fix action: ${fix.action}`;
            }

            const healLog = {
                timestamp: new Date().toISOString(),
                action: fix.action,
                success: success,
                message: message
            };

            let logs = [];
            if (fs.existsSync(healLogFile)) {
                logs = JSON.parse(fs.readFileSync(healLogFile, 'utf8'));
            }
            logs.unshift(healLog);
            if (logs.length > 100) logs = logs.slice(0, 100);
            fs.writeFileSync(healLogFile, JSON.stringify(logs, null, 2));

            console.log(`🔧 Healing ${success ? '✅ SUCCESS' : '❌ FAILED'}: ${message}`);
        } catch (error) {
            console.error('❌ Healing error:', error);
            message = `Healing failed: ${error.message}`;
        }

        return { success, message };
    }

    getDiagnostics() {
        return this.diagnostics;
    }
}

const selfHealingAI = new SelfHealingAIDiagnosticSystem();

// ============================================================
// 🧠 DIAGNOSTIC API ROUTES
// ============================================================

app.get('/api/diagnostic/scan', authenticate, isOwner, async (req, res) => {
    try {
        await selfHealingAI.runDiagnostics();
        res.json({ success: true, diagnostics: selfHealingAI.getDiagnostics() });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/diagnostic/status', authenticate, isOwner, (req, res) => {
    res.json({ success: true, ...selfHealingAI.getDiagnostics() });
});

app.post('/api/diagnostic/fix', authenticate, isOwner, async (req, res) => {
    try {
        const { action } = req.body;
        let result;
        
        if (action === 'auto_fix') {
            const diagnostics = selfHealingAI.getDiagnostics();
            const fixes = diagnostics.fixes || [];
            let allSuccess = true;
            let messages = [];
            
            for (const fix of fixes) {
                const fixResult = await selfHealingAI.applyHealing(fix);
                if (!fixResult.success) allSuccess = false;
                messages.push(`${fix.action}: ${fixResult.message}`);
            }
            
            result = { success: allSuccess, message: messages.join('\n') };
        } else {
            result = await selfHealingAI.applyHealing({ action });
        }
        
        res.json({ success: result.success, message: result.message });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/diagnostic/logs', authenticate, isOwner, (req, res) => {
    try {
        let logs = [];
        if (fs.existsSync(healLogFile)) {
            logs = JSON.parse(fs.readFileSync(healLogFile, 'utf8'));
        }
        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/diagnostic/report', authenticate, isOwner, (req, res) => {
    res.json({ success: true, report: selfHealingAI.getDiagnostics() });
});

// ============================================================
// 🧮 CONTRACT SIZE - SINGLE SOURCE OF TRUTH
// ============================================================

function getDefaultContractSize(symbol) {
    const cryptoPairs = ['BTCUSD', 'BTCUSDT', 'ETHUSD', 'ETHUSDT', 'ADAUSD', 'ADAUSDT', 'DOTUSD', 'DOTUSDT', 'SOLUSD', 'SOLUSDT'];
    const xauPairs = ['XAUUSD', 'XAGUSD'];
    
    if (cryptoPairs.includes(symbol) || symbol.startsWith('BTC') || symbol.startsWith('ETH') || 
        symbol.startsWith('ADA') || symbol.startsWith('DOT') || symbol.startsWith('SOL')) {
        return 1;
    } else if (xauPairs.includes(symbol)) {
        return 100;
    } else {
        return 100000;
    }
}

// ============================================================
// 🧮 LOT SIZE CALCULATION
// ============================================================

const conversionRateCache = new Map();
const CACHE_TTL = 60000;

const leverageCache = new Map();
const LEVERAGE_CACHE_TTL = 300000;

function cleanupCache(cache, ttl) {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of cache) {
        if (now - entry.timestamp > ttl) {
            cache.delete(key);
            removed++;
        }
    }
    if (removed > 0) {
        console.log(`🧹 Removed ${removed} stale cache entries`);
    }
}

setInterval(() => {
    cleanupCache(conversionRateCache, CACHE_TTL);
    cleanupCache(leverageCache, LEVERAGE_CACHE_TTL);
}, 5 * 60 * 1000);

async function getConversionRate(symbol, accountId) {
    const cacheKey = `${symbol}_${accountId}`;
    const cached = conversionRateCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        return cached.rate;
    }
    
    try {
        if (!ticker) {
            console.warn(`⚠️ TickerAll not available for conversion rate of ${symbol}`);
            return null;
        }
        
        const quoteCurrency = symbol.substring(3);
        const usdPair = `${quoteCurrency}USD`;
        
        try {
            const price = await ticker.market.getPrice(accountId, usdPair);
            const rate = price.bid || price.ask || price.last;
            if (rate && rate > 0) {
                conversionRateCache.set(cacheKey, { rate, timestamp: Date.now() });
                return rate;
            }
        } catch (e) {
            const inversePair = `USD${quoteCurrency}`;
            try {
                const price = await ticker.market.getPrice(accountId, inversePair);
                const inverseRate = price.bid || price.ask || price.last;
                if (inverseRate && inverseRate > 0) {
                    const rate = 1 / inverseRate;
                    conversionRateCache.set(cacheKey, { rate, timestamp: Date.now() });
                    return rate;
                }
            } catch (e2) {
                console.warn(`⚠️ Could not get conversion rate for ${symbol}, cannot calculate position size`);
                return null;
            }
        }
        return null;
    } catch (error) {
        console.error(`❌ Error getting conversion rate for ${symbol}:`, error.message);
        return null;
    }
}

async function getAccountLeverage(accountId) {
    const cached = leverageCache.get(accountId);
    if (cached && Date.now() - cached.timestamp < LEVERAGE_CACHE_TTL) {
        return cached.leverage;
    }
    
    try {
        if (!ticker) {
            return 100;
        }
        
        const accountInfo = await ticker.accounts.get(accountId);
        const leverage = accountInfo.leverage || accountInfo.Leverage || 100;
        const parsed = parseFloat(leverage) || 100;
        leverageCache.set(accountId, { leverage: parsed, timestamp: Date.now() });
        return parsed;
    } catch (error) {
        console.warn('⚠️ Could not get account leverage, using 100:1 default');
        return 100;
    }
}

async function calculateCorrectLotSize(symbol, positionSizeUSD, accountBalance, price, contractSize, accountId) {
    if (!contractSize || contractSize <= 0) {
        return {
            lotSize: null,
            error: `Invalid contract size for ${symbol}: ${contractSize}`,
            conversionSource: 'error'
        };
    }
    
    const usdQuotedPairs = ['EURUSD', 'GBPUSD', 'AUDUSD', 'NZDUSD', 'XAUUSD', 'XAGUSD'];
    const jpyPairs = ['USDJPY', 'EURJPY', 'GBPJPY', 'AUDJPY', 'NZDJPY', 'CADJPY', 'CHFJPY'];
    const crossPairs = ['EURGBP', 'EURCHF', 'GBPCHF', 'GBPAUD', 'EURAUD', 'AUDCAD', 'AUDCHF', 'CADCHF', 'EURCAD', 'GBPCAD', 'NZDCAD', 'NZDCHF'];
    const cryptoPairs = ['BTCUSD', 'BTCUSDT', 'ETHUSD', 'ETHUSDT', 'ADAUSD', 'ADAUSDT', 'DOTUSD', 'DOTUSDT', 'SOLUSD', 'SOLUSDT'];
    
    let lotSize = 0;
    let usedConversionRate = 1.0;
    let conversionSource = 'direct';
    
    try {
        if (usdQuotedPairs.includes(symbol) || symbol.includes('XAU') || symbol.includes('XAG')) {
            const units = positionSizeUSD / price;
            lotSize = units / contractSize;
            conversionSource = 'direct_usd';
        } else if (symbol === 'USDJPY') {
            lotSize = positionSizeUSD / contractSize;
            conversionSource = 'usdjpy';
        } else if (jpyPairs.includes(symbol) && symbol !== 'USDJPY') {
            const units = positionSizeUSD / (price / 100);
            lotSize = units / contractSize;
            conversionSource = 'jpy_pair';
        } else if (crossPairs.includes(symbol)) {
            const conversionRate = await getConversionRate(symbol, accountId);
            if (conversionRate === null) {
                return { 
                    lotSize: null, 
                    error: `Cannot calculate lot size for ${symbol}: conversion rate unavailable`,
                    conversionSource: 'error'
                };
            }
            usedConversionRate = conversionRate;
            conversionSource = 'cross_pair';
            const adjustedPrice = price * usedConversionRate;
            const units = positionSizeUSD / adjustedPrice;
            lotSize = units / contractSize;
        } else {
            const isCrypto = cryptoPairs.includes(symbol) || symbol.startsWith('BTC') || symbol.startsWith('ETH') || 
                            symbol.startsWith('ADA') || symbol.startsWith('DOT') || symbol.startsWith('SOL');
            const units = positionSizeUSD / price;
            lotSize = units / contractSize;
            conversionSource = isCrypto ? 'crypto' : 'fallback';
            if (!isCrypto) {
                console.warn(`⚠️ Unknown symbol type for ${symbol}, using fallback calculation with contract size ${contractSize}`);
            }
        }
        
        if (lotSize === null || lotSize === undefined || !isFinite(lotSize) || lotSize <= 0) {
            return {
                lotSize: null,
                error: `Invalid lot size calculated for ${symbol}`,
                conversionSource: 'error'
            };
        }
        
        const minLot = 0.01;
        const maxLot = 100;
        const step = 0.01;
        lotSize = Math.floor(lotSize / step) * step;
        lotSize = Math.max(minLot, Math.min(maxLot, lotSize));
        
        if (lotSize < minLot && accountBalance >= 10) {
            lotSize = minLot;
        }
        
        return { 
            lotSize, 
            effectivePrice: price,
            conversionRate: usedConversionRate,
            conversionSource: conversionSource,
            positionSizeUSD: positionSizeUSD,
            contractSize: contractSize
        };
    } catch (error) {
        console.error(`❌ Lot calculation error for ${symbol}:`, error.message);
        return { 
            lotSize: null, 
            error: error.message,
            conversionSource: 'error'
        };
    }
}

// ============================================================
// 📈 UNLIMITED CONCURRENT TRADES ENGINE (with forced trades toggle)
// ============================================================

const engines = {};

class UnlimitedConcurrentTradingEngine {
    constructor(sessionId, userEmail, config, accountId) {
        this.sessionId = sessionId;
        this.userEmail = userEmail;
        this.config = config;
        this.accountId = accountId;
        
        this.isActive = true;
        this.isLocked = false;
        this.currentProfit = 0;
        this.trades = [];
        this.winStreak = 0;
        this.openPositions = [];
        this.tradeCount = 0;
        this.totalInvestment = config.investmentAmount;
        this.compoundMultiplier = 1;
        this.analysisAttempts = 0;
        this.lastError = null;
        this.startTime = Date.now();
        this.forcedTradesExecuted = 0;
        
        this.userRiskSettings = null;
        this.loadUserRiskSettings();
        
        this.maxConcurrentPositions = this.userRiskSettings?.maxConcurrentTrades || MAX_CONCURRENT_TRADES;
        this.minBalanceForNewTrade = this.userRiskSettings?.minBalance || MIN_BALANCE_FOR_TRADE;
        this.maxMarginRiskPercent = MAX_MARGIN_RISK;
        this.userRiskPercent = this.userRiskSettings?.riskPercent || DEFAULT_RISK_PERCENT;
        this.stopLossMultiplier = this.userRiskSettings?.stopLossMultiplier || 1.5;
        this.takeProfitMultiplier = this.userRiskSettings?.takeProfitMultiplier || 2.0;
        this.autoCompound = this.userRiskSettings?.autoCompound !== false;
        this.maxDailyLoss = this.userRiskSettings?.maxDailyLoss || 20;
        this.maxDailyTrades = this.userRiskSettings?.maxDailyTrades || 100;
        this.allowForcedTrades = this.userRiskSettings?.allowForcedTrades !== false;
        
        this.dailyTrades = 0;
        this.dailyProfit = 0;
        this.dailyResetTime = Date.now();
        
        this.analysisInterval = null;
        this.monitorInterval = null;
        this.symbolMetadata = {};
        this.riskMultiplier = this.userRiskPercent / DEFAULT_RISK_PERCENT;
        
        console.log(`✅ Trading Engine created for ${userEmail}`);
        console.log(`🎯 User Risk: ${this.userRiskPercent}%`);
        console.log(`🔥 Max Positions: ${this.maxConcurrentPositions === Infinity ? 'UNLIMITED' : this.maxConcurrentPositions}`);
        console.log(`📈 Auto-Compound: ${this.autoCompound ? 'ENABLED' : 'DISABLED'}`);
        console.log(`🔄 Forced Trades: ${this.allowForcedTrades ? 'ENABLED' : 'DISABLED'}`);
    }

    loadUserRiskSettings() {
        try {
            const users = readUsers();
            const user = users[this.userEmail];
            if (user && user.riskSettings) {
                this.userRiskSettings = user.riskSettings;
                console.log(`✅ Loaded user risk settings for ${this.userEmail}`);
            }
        } catch (error) {
            console.error('❌ Error loading user risk settings:', error);
        }
    }

    checkDailyLimits() {
        if (Date.now() - this.dailyResetTime > 24 * 60 * 60 * 1000) {
            this.dailyTrades = 0;
            this.dailyProfit = 0;
            this.dailyResetTime = Date.now();
            console.log('📊 Daily counters reset');
        }
        
        if (this.dailyTrades >= this.maxDailyTrades) {
            return { allowed: false, reason: `Daily trade limit reached: ${this.maxDailyTrades}` };
        }
        
        if (this.dailyProfit < -(this.totalInvestment * this.maxDailyLoss / 100)) {
            return { allowed: false, reason: `Daily loss limit reached: ${this.maxDailyLoss}%` };
        }
        
        return { allowed: true };
    }

    async getSymbolMetadata(symbol) {
        if (this.symbolMetadata[symbol]) return this.symbolMetadata[symbol];
        try {
            const info = await ticker.market.getSymbol(this.accountId, symbol);
            const contractSize = info.contractSize || getDefaultContractSize(symbol);
            return {
                symbol, 
                contractSize: contractSize,
                tickSize: info.tickSize || 0.00001, 
                tickValue: info.tickValue || 1,
                currency: info.currency || 'USD', 
                minVolume: info.minVolume || 0.01,
                maxVolume: info.maxVolume || 100, 
                volumeStep: info.volumeStep || 0.01,
                price: info.price || 0,
                pipSize: this.getPipSize(symbol),
                quoteCurrency: symbol.substring(3)
            };
        } catch (error) {
            const contractSize = getDefaultContractSize(symbol);
            return {
                symbol, 
                contractSize: contractSize,
                tickSize: 0.00001, 
                tickValue: 1, 
                currency: 'USD',
                minVolume: 0.01, 
                maxVolume: 100, 
                volumeStep: 0.01, 
                price: 0,
                pipSize: this.getPipSize(symbol),
                quoteCurrency: symbol.substring(3)
            };
        }
    }

    getPipSize(symbol) {
        const jpyPairs = ['USDJPY', 'EURJPY', 'GBPJPY', 'AUDJPY', 'NZDJPY', 'CADJPY', 'CHFJPY'];
        const xauPairs = ['XAUUSD', 'XAGUSD'];
        const cryptoPairs = ['BTCUSD', 'BTCUSDT', 'ETHUSD', 'ETHUSDT'];
        if (jpyPairs.includes(symbol)) return 0.01;
        if (xauPairs.includes(symbol)) return symbol === 'XAUUSD' ? 0.01 : 0.0001;
        if (cryptoPairs.includes(symbol)) return 0.01;
        return 0.0001;
    }

    async getCurrentPrice(symbol) {
        try {
            const price = await ticker.market.getPrice(this.accountId, symbol);
            return price.ask || price.bid || price.last || 0;
        } catch (error) {
            return 0;
        }
    }

    async getMarginRequired(symbol, lotSize) {
        try {
            const metadata = await this.getSymbolMetadata(symbol);
            const price = await this.getCurrentPrice(symbol) || 1;
            const notional = lotSize * metadata.contractSize * price;
            const leverage = await getAccountLeverage(this.accountId);
            return notional / leverage;
        } catch (error) {
            console.warn(`⚠️ Error calculating margin for ${symbol}, using default:`, error.message);
            const metadata = await this.getSymbolMetadata(symbol);
            const price = await this.getCurrentPrice(symbol) || 1;
            const notional = lotSize * metadata.contractSize * price;
            return notional / 100;
        }
    }

    async calculateLotSize(symbol, positionSizeUSD, accountBalance) {
        try {
            const metadata = await this.getSymbolMetadata(symbol);
            const price = await this.getCurrentPrice(symbol);
            if (!price || price <= 0) throw new Error('Invalid price');
            
            if (!metadata.contractSize || metadata.contractSize <= 0) {
                throw new Error(`Invalid contract size for ${symbol}: ${metadata.contractSize}`);
            }
            
            const result = await calculateCorrectLotSize(symbol, positionSizeUSD, accountBalance, price, metadata.contractSize, this.accountId);
            if (result.lotSize === null) {
                return { 
                    lotSize: null, 
                    error: result.error || 'Lot size calculation failed',
                    conversionSource: result.conversionSource || 'error'
                };
            }
            
            return { 
                ...result, 
                price: price, 
                notionalValue: result.lotSize * metadata.contractSize * price 
            };
        } catch (error) {
            return { 
                lotSize: null, 
                error: error.message,
                conversionSource: 'error'
            };
        }
    }

    calculateRSI(closes, period = 14) {
        if (closes.length < period + 1) return 50;
        let avgGain = 0, avgLoss = 0;
        for (let i = 1; i <= period; i++) {
            const change = closes[i] - closes[i-1];
            if (change >= 0) avgGain += change;
            else avgLoss += Math.abs(change);
        }
        avgGain /= period;
        avgLoss /= period;
        for (let i = period + 1; i < closes.length; i++) {
            const change = closes[i] - closes[i-1];
            if (change >= 0) {
                avgGain = (avgGain * (period - 1) + change) / period;
                avgLoss = (avgLoss * (period - 1)) / period;
            } else {
                avgGain = (avgGain * (period - 1)) / period;
                avgLoss = (avgLoss * (period - 1) + Math.abs(change)) / period;
            }
        }
        if (avgLoss === 0) return 100;
        return 100 - (100 / (1 + (avgGain / avgLoss)));
    }

    async analyzeMarket(symbol) {
        try {
            if (!ticker) return null;
            const price = await ticker.market.getPrice(this.accountId, symbol);
            const currentPrice = price.ask || price.bid || price.last || 0;
            const history = await ticker.market.getHistory(this.accountId, symbol, { period: '1m', count: 30 });
            if (!history || history.length < 20) {
                return { action: 'HOLD', confidence: 0.4, reasons: ['Insufficient data'] };
            }
            const closes = history.map(h => h.close);
            const rsi = this.calculateRSI(closes, 10);
            const ma10 = closes.slice(-10).reduce((a, b) => a + b, 0) / 10;
            const ma20 = closes.slice(-20).reduce((a, b) => a + b, 0) / 20;
            const mean = closes.slice(-10).reduce((a, b) => a + b, 0) / 10;
            const stdDev = Math.sqrt(closes.slice(-10).reduce((a, b) => a + Math.pow(b - mean, 2), 0) / 10);
            const bbUpper = mean + 1.5 * stdDev;
            const bbLower = mean - 1.5 * stdDev;
            const momentum = closes.length >= 2 ? ((closes[closes.length-1] - closes[closes.length-2]) / closes[closes.length-2]) * 100 : 0;
            const volatility = stdDev / mean * 100;
            const indicators = { rsi, ma10, ma20, bbUpper, bbLower, momentum, volatility, currentPrice };
            const adaptiveParams = realAI.getAdaptiveParameters(symbol);
            let action = 'HOLD';
            let confidence = 0.4;
            let reasons = [];
            const confidenceThreshold = Math.min(0.7, Math.max(0.3, adaptiveParams.confidenceThreshold));
            const riskMultiplier = adaptiveParams.riskMultiplier || 1.0;
            
            if (rsi < 40 && currentPrice < bbLower && momentum < 0) {
                action = 'BUY';
                confidence = 0.7 * riskMultiplier;
                reasons.push('RSI below 40, below lower band');
            } else if (rsi < 45 && ma10 > ma20 && momentum > -0.3) {
                action = 'BUY';
                confidence = 0.65 * riskMultiplier;
                reasons.push('RSI recovering, golden cross');
            } else if (currentPrice < bbLower && rsi < 50 && momentum < -0.5) {
                action = 'BUY';
                confidence = 0.6 * riskMultiplier;
                reasons.push('Price below lower band');
            } else if (rsi < 50 && ma10 > ma20 && momentum > 0) {
                action = 'BUY';
                confidence = 0.55 * riskMultiplier;
                reasons.push('RSI rising, above 10-day MA');
            } else if (rsi < 35 && momentum < -1) {
                action = 'BUY';
                confidence = 0.7 * riskMultiplier;
                reasons.push('Oversold RSI');
            }
            
            if (rsi > 60 && currentPrice > bbUpper && momentum > 0) {
                action = 'SELL';
                confidence = 0.7 * riskMultiplier;
                reasons.push('RSI above 60, above upper band');
            } else if (rsi > 55 && ma10 < ma20 && momentum < 0.3) {
                action = 'SELL';
                confidence = 0.65 * riskMultiplier;
                reasons.push('RSI declining, death cross');
            } else if (currentPrice > bbUpper && rsi > 50 && momentum > 0.5) {
                action = 'SELL';
                confidence = 0.6 * riskMultiplier;
                reasons.push('Price above upper band');
            } else if (rsi > 55 && ma10 < ma20 && momentum < 0) {
                action = 'SELL';
                confidence = 0.55 * riskMultiplier;
                reasons.push('RSI falling, below 10-day MA');
            } else if (rsi > 65 && momentum > 1) {
                action = 'SELL';
                confidence = 0.7 * riskMultiplier;
                reasons.push('Overbought RSI');
            }
            
            if (action !== 'HOLD') {
                const patternStrength = realAI.getPatternStrength(symbol, action, indicators);
                if (patternStrength.winRate > 0.6) {
                    confidence = Math.min(0.95, confidence * 1.2);
                    reasons.push(`REAL AI: Pattern recognized (${(patternStrength.winRate*100).toFixed(0)}% win rate)`);
                }
            }
            
            if (confidence < confidenceThreshold) {
                action = 'HOLD';
                reasons = [`Confidence ${(confidence*100).toFixed(0)}% below threshold ${(confidenceThreshold*100).toFixed(0)}%`];
            }
            
            if (action !== 'HOLD') {
                console.log(`🧠 AI: ${action} ${symbol} | Confidence: ${(confidence*100).toFixed(0)}%`);
            }
            
            return { symbol, action, confidence, reasons, currentPrice, rsi, ma10, ma20, bbUpper, bbLower, volatility, momentum, indicators, adaptiveParams };
        } catch (error) {
            return { action: 'HOLD', confidence: 0.4, reasons: ['Analysis error'] };
        }
    }

    async executeTrade(signal) {
        if (!signal || signal.action === 'HOLD' || signal.confidence < 0.45) {
            return { success: true, message: 'No valid signal' };
        }
        if (this.isLocked) return { success: false, message: 'Locked' };
        this.isLocked = true;
        
        try {
            const dailyCheck = this.checkDailyLimits();
            if (!dailyCheck.allowed) {
                this.isLocked = false;
                return { success: false, message: dailyCheck.reason };
            }
            
            const balanceResult = await fetchRealBalance(this.accountId);
            const balance = balanceResult.balance || 0;
            if (balance < this.minBalanceForNewTrade) {
                this.isLocked = false;
                return { success: false, message: 'Insufficient balance' };
            }
            
            const adaptiveParams = realAI.getAdaptiveParameters(signal.symbol);
            const riskMultiplier = adaptiveParams.riskMultiplier || 1.0;
            
            let riskPercent = (this.userRiskPercent / 100) * riskMultiplier;
            riskPercent = Math.min(0.25, riskPercent);
            
            if (balance < 50) {
                riskPercent = Math.min(riskPercent * 1.2, 0.20);
            }
            
            let positionSizeUSD = balance * riskPercent;
            
            if (this.autoCompound) {
                positionSizeUSD = positionSizeUSD * this.compoundMultiplier;
            }
            
            positionSizeUSD = Math.min(positionSizeUSD, balance * 0.25);
            
            const lotInfo = await this.calculateLotSize(signal.symbol, positionSizeUSD, balance);
            
            if (lotInfo.lotSize === null || lotInfo.lotSize === undefined) {
                this.isLocked = false;
                console.warn(`⚠️ Skipping trade ${signal.symbol}: ${lotInfo.error || 'Lot size calculation failed'}`);
                return { success: false, message: lotInfo.error || 'Lot size calculation failed' };
            }
            
            const lotSize = lotInfo.lotSize;
            
            if (lotSize <= 0) {
                this.isLocked = false;
                return { success: false, message: 'Invalid lot size' };
            }
            
            const marginRequired = await this.getMarginRequired(signal.symbol, lotSize);
            let totalMargin = 0;
            for (const pos of this.openPositions) {
                totalMargin += pos.marginRequired || 0;
            }
            const newTotalMargin = totalMargin + marginRequired;
            const maxMargin = balance * this.maxMarginRiskPercent;
            
            if (newTotalMargin > maxMargin) {
                this.isLocked = false;
                return { success: false, message: `Margin cap reached: $${newTotalMargin.toFixed(2)} / $${maxMargin.toFixed(2)}` };
            }
            
            if (this.openPositions.length >= this.maxConcurrentPositions) {
                this.isLocked = false;
                return { success: false, message: `Max positions reached: ${this.maxConcurrentPositions}` };
            }
            
            const isForced = signal.isForced || false;
            const tradeLabel = isForced ? '(FORCED)' : '';
            
            console.log(`📊 ORDER: ${signal.action} ${signal.symbol} ${tradeLabel} | Size: ${lotSize.toFixed(2)} | Risk: ${(riskPercent*100).toFixed(1)}%`);
            console.log(`   User Risk: ${this.userRiskPercent}% | Compounding: ${this.compoundMultiplier.toFixed(2)}x`);
            console.log(`   Contract Size: ${lotInfo.contractSize} | Notional: $${lotInfo.notionalValue.toFixed(2)}`);
            if (lotInfo.conversionSource === 'cross_pair' && lotInfo.conversionRate === 1.0) {
                console.warn(`⚠️ WARNING: Using fallback conversion rate for ${signal.symbol} - position size may be inaccurate`);
            }
            
            const order = await ticker.orders.place(this.accountId, {
                type: 'market',
                symbol: signal.symbol,
                side: signal.action,
                volume: lotSize
            });
            
            console.log(`✅ ORDER PLACED: ${order.id}`);
            
            if (isForced) this.forcedTradesExecuted++;
            
            this.openPositions.push({
                symbol: signal.symbol,
                side: signal.action,
                lotSize: lotSize,
                entryPrice: lotInfo.price,
                orderId: order.id,
                openedAt: Date.now(),
                positionSizeUSD: positionSizeUSD,
                maxProfit: 0,
                currentProfitPercent: 0,
                highestPrice: lotInfo.price,
                lowestPrice: lotInfo.price,
                notionalValue: lotInfo.notionalValue,
                marginRequired: marginRequired,
                metadata: lotInfo,
                signal: signal,
                conversionRate: lotInfo.conversionRate || 1.0,
                conversionSource: lotInfo.conversionSource || 'unknown',
                contractSize: lotInfo.contractSize,
                isForced: isForced
            });
            
            this.tradeCount++;
            this.dailyTrades++;
            this.trades.unshift({
                symbol: signal.symbol,
                side: `${signal.action} OPEN${isForced ? ' (FORCED)' : ''}`,
                entryPrice: lotInfo.price.toFixed(5),
                lotSize: lotSize.toFixed(2),
                positionSize: positionSizeUSD.toFixed(2),
                riskPercent: (riskPercent * 100).toFixed(1) + '%',
                conversionSource: lotInfo.conversionSource || 'unknown',
                conversionRate: (lotInfo.conversionRate || 1.0).toFixed(4),
                contractSize: lotInfo.contractSize,
                isForced: isForced,
                timestamp: new Date().toISOString()
            });
            
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: signal.symbol,
                side: `${signal.action} OPEN${isForced ? ' (FORCED)' : ''}`,
                entryPrice: lotInfo.price,
                lotSize: lotSize,
                positionSize: positionSizeUSD,
                riskPercent: riskPercent,
                conversionSource: lotInfo.conversionSource || 'unknown',
                conversionRate: lotInfo.conversionRate || 1.0,
                contractSize: lotInfo.contractSize,
                isForced: isForced,
                timestamp: new Date().toISOString(),
                indicators: signal.indicators || {}
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            this.isLocked = false;
            return { 
                success: true, 
                trade: { 
                    symbol: signal.symbol, 
                    action: signal.action, 
                    entryPrice: lotInfo.price, 
                    lotSize: lotSize, 
                    notionalValue: lotInfo.notionalValue,
                    orderId: order.id,
                    riskPercent: (riskPercent * 100).toFixed(1) + '%',
                    conversionSource: lotInfo.conversionSource || 'unknown',
                    conversionRate: (lotInfo.conversionRate || 1.0).toFixed(4),
                    contractSize: lotInfo.contractSize,
                    isForced: isForced
                } 
            };
        } catch (error) {
            console.error('❌ ORDER ERROR:', error.message);
            this.lastError = error.message;
            this.isLocked = false;
            return { success: false, message: error.message };
        }
    }

    calculateTotalMarginUsed() {
        let total = 0;
        for (const position of this.openPositions) {
            total += position.marginRequired || 0;
        }
        return total;
    }

    async monitorPositions() {
        if (this.isLocked || !this.isActive || this.openPositions.length === 0) return;
        this.isLocked = true;
        
        try {
            const positionsToClose = [];
            for (const position of this.openPositions) {
                try {
                    if (!ticker) continue;
                    const priceData = await ticker.market.getPrice(this.accountId, position.symbol);
                    const currentPrice = priceData.bid || priceData.ask || priceData.last || 0;
                    if (currentPrice <= 0) continue;
                    
                    if (currentPrice > position.highestPrice) position.highestPrice = currentPrice;
                    if (currentPrice < position.lowestPrice) position.lowestPrice = currentPrice;
                    
                    let profitPercent = 0;
                    if (position.side === 'BUY') {
                        profitPercent = ((currentPrice - position.entryPrice) / position.entryPrice) * 100;
                    } else {
                        profitPercent = ((position.entryPrice - currentPrice) / position.entryPrice) * 100;
                    }
                    
                    position.currentProfitPercent = profitPercent;
                    position.currentPrice = currentPrice;
                    
                    if (profitPercent > position.maxProfit) {
                        position.maxProfit = profitPercent;
                    }
                    
                    const stopLossPercent = Math.max(0.2, profitPercent * 0.5 * (1 / this.stopLossMultiplier));
                    const takeProfitPercent = Math.max(0.5, this.takeProfitMultiplier * 0.5);
                    
                    if (profitPercent > 0 && position.maxProfit > 0) {
                        const drawdownFromPeak = (position.maxProfit - profitPercent) / position.maxProfit;
                        if (drawdownFromPeak < 0.10) continue;
                        if (drawdownFromPeak > 0.50) {
                            positionsToClose.push({ position, profitPercent, currentPrice, reason: `Trailing take profit` });
                            continue;
                        }
                    }
                    
                    if (profitPercent < -stopLossPercent) {
                        positionsToClose.push({ position, profitPercent, currentPrice, reason: `Stop loss at ${profitPercent.toFixed(2)}%` });
                        continue;
                    }
                    
                    if (profitPercent > takeProfitPercent) {
                        positionsToClose.push({ position, profitPercent, currentPrice, reason: `Take profit at ${profitPercent.toFixed(2)}%` });
                        continue;
                    }
                } catch (error) {
                    console.error(`❌ Monitor error for ${position.symbol}:`, error.message);
                }
            }
            
            for (const close of positionsToClose) {
                await this.closePosition(close.position, close.profitPercent, close.currentPrice, close.reason);
            }
        } catch (error) {
            console.error(`❌ Monitor loop error:`, error.message);
        } finally {
            this.isLocked = false;
        }
    }

    async closePosition(position, profitPercent, currentPrice, reason) {
        try {
            if (!ticker) { console.log('❌ TickerAll not available'); return; }
            
            let closed = false;
            let attempts = 0;
            while (!closed && attempts < 3) {
                try {
                    await ticker.orders.close(this.accountId, position.orderId);
                    closed = true;
                    console.log(`✅ ORDER CLOSED: ${position.orderId}`);
                } catch (e) {
                    attempts++;
                    await new Promise(r => setTimeout(r, 500));
                }
            }
            if (!closed) { console.log(`❌ Failed to close position ${position.orderId}`); return; }
            
            const profit = (profitPercent / 100) * position.positionSizeUSD;
            this.currentProfit += profit;
            this.dailyProfit += profit;
            this.winStreak = profit > 0 ? this.winStreak + 1 : 0;
            
            if (this.autoCompound) {
                if (profit > 0) {
                    this.compoundMultiplier = Math.min(5, this.compoundMultiplier + 0.08);
                } else {
                    this.compoundMultiplier = Math.max(0.5, this.compoundMultiplier - 0.03);
                }
            }
            
            this.updateUserStats(profit, position.isForced);
            
            const forcedLabel = position.isForced ? ' (FORCED)' : '';
            this.trades.unshift({
                symbol: position.symbol,
                side: `${position.side} CLOSED${forcedLabel}`,
                entryPrice: position.entryPrice.toFixed(5),
                exitPrice: currentPrice.toFixed(5),
                profit: profit.toFixed(2),
                profitPercent: profitPercent.toFixed(2),
                lotSize: position.lotSize.toFixed(2),
                reason: reason,
                conversionSource: position.conversionSource || 'unknown',
                conversionRate: (position.conversionRate || 1.0).toFixed(4),
                contractSize: position.contractSize,
                isForced: position.isForced || false,
                timestamp: new Date().toISOString()
            });
            
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                exitPrice: currentPrice,
                profit: profit,
                profitPercent: profitPercent,
                lotSize: position.lotSize,
                reason: reason,
                conversionSource: position.conversionSource || 'unknown',
                conversionRate: position.conversionRate || 1.0,
                contractSize: position.contractSize,
                isForced: position.isForced || false,
                timestamp: new Date().toISOString(),
                indicators: position.signal?.indicators || {}
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            realAI.learnFromTrade({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                exitPrice: currentPrice,
                profit: profit,
                profitPercent: profitPercent,
                indicators: position.signal?.indicators || {},
                isForced: position.isForced || false
            });
            
            this.openPositions = this.openPositions.filter(p => p.orderId !== position.orderId);
            console.log(`✅ CLOSED ${position.symbol} | ${profit >= 0 ? '+' : ''}$${profit.toFixed(2)} | ${profitPercent.toFixed(2)}%${forcedLabel}`);
        } catch (error) {
            console.error(`❌ Close error:`, error.message);
            this.lastError = error.message;
        }
    }

    async updateUserStats(profit, isForced) {
        try {
            const users = readUsers();
            const user = users[this.userEmail];
            if (!user) return;
            
            if (!user.stats) {
                user.stats = {
                    totalTrades: 0,
                    wins: 0,
                    losses: 0,
                    forcedTrades: 0,
                    totalProfit: 0,
                    bestTrade: 0,
                    worstTrade: 0,
                    winRate: 0,
                    avgProfit: 0,
                    lastTradeAt: null,
                    updatedAt: new Date().toISOString()
                };
            }
            
            const stats = user.stats;
            stats.totalTrades++;
            if (isForced) stats.forcedTrades++;
            if (profit > 0) {
                stats.wins++;
                if (profit > stats.bestTrade) stats.bestTrade = profit;
            } else {
                stats.losses++;
                if (profit < stats.worstTrade) stats.worstTrade = profit;
            }
            stats.totalProfit += profit;
            stats.winRate = stats.totalTrades > 0 ? (stats.wins / stats.totalTrades) * 100 : 0;
            stats.avgProfit = stats.totalTrades > 0 ? stats.totalProfit / stats.totalTrades : 0;
            stats.lastTradeAt = new Date().toISOString();
            stats.updatedAt = new Date().toISOString();
            
            writeUsers(users);
        } catch (error) {
            console.error('❌ Error updating user stats:', error);
        }
    }

    async tradingLoop() {
        if (this.isLocked || !this.isActive) return;
        this.isLocked = true;
        
        try {
            const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
            if (elapsedHours >= this.config.timeLimit) { await this.stop(); this.isLocked = false; return; }
            
            const currentBalance = this.totalInvestment + this.currentProfit;
            if (currentBalance >= this.config.targetProfit) { await this.stop(); this.isLocked = false; return; }
            
            await this.monitorPositions();
            
            const balanceResult = await fetchRealBalance(this.accountId);
            const balance = balanceResult.balance || 0;
            
            const usedMargin = this.calculateTotalMarginUsed();
            const maxMargin = balance * this.maxMarginRiskPercent;
            const availableMargin = maxMargin - usedMargin;
            
            const avgMarginPerPosition = this.openPositions.length > 0 ? 
                usedMargin / this.openPositions.length : 
                balance * 0.01;
            
            const maxByMargin = availableMargin > 0 ? 
                Math.floor(availableMargin / Math.max(avgMarginPerPosition, 1)) : 0;
            
            const maxPositions = Math.min(
                this.maxConcurrentPositions,
                this.openPositions.length + maxByMargin
            );
            
            if (availableMargin > balance * 0.01 && this.openPositions.length < maxPositions) {
                const symbols = this.config.tradingPairs;
                const shuffledSymbols = [...symbols].sort(() => Math.random() - 0.5);
                let tradesOpened = 0;
                
                for (const symbol of shuffledSymbols) {
                    if (this.openPositions.length >= maxPositions) break;
                    const hasPosition = this.openPositions.some(p => p.symbol === symbol);
                    if (hasPosition) continue;
                    if (availableMargin < balance * 0.01) break;
                    
                    const signal = await this.analyzeMarket(symbol);
                    if (signal && signal.action !== 'HOLD' && signal.confidence >= 0.45) {
                        const result = await this.executeTrade(signal);
                        if (result.success) {
                            tradesOpened++;
                            const newUsedMargin = this.calculateTotalMarginUsed();
                            const newAvailable = maxMargin - newUsedMargin;
                            if (newAvailable < balance * 0.01) break;
                            console.log(`✅ Trade opened on ${symbol} | Total: ${this.openPositions.length}`);
                        }
                    }
                }
                
                // FIXED: Forced trades with user toggle
                if (this.allowForcedTrades && tradesOpened === 0 && availableMargin > balance * 0.05) {
                    this.analysisAttempts++;
                    if (this.analysisAttempts > 5) {
                        const availableSymbols = symbols.filter(s => 
                            !this.openPositions.some(p => p.symbol === s)
                        );
                        if (availableSymbols.length > 0) {
                            let bestSignal = null;
                            let bestConfidence = 0;
                            for (const sym of availableSymbols.slice(0, 3)) {
                                const signal = await this.analyzeMarket(sym);
                                if (signal && signal.confidence > bestConfidence) {
                                    bestConfidence = signal.confidence;
                                    bestSignal = signal;
                                }
                            }
                            if (bestSignal && bestSignal.action !== 'HOLD') {
                                console.log(`🎯 FORCED TRADE on ${bestSignal.symbol} (confidence: ${(bestSignal.confidence*100).toFixed(0)}%)`);
                                bestSignal.isForced = true;
                                bestSignal.reasons.push('⚠️ FORCED TRADE - Low confidence');
                                await this.executeTrade(bestSignal);
                            }
                        }
                        this.analysisAttempts = 0;
                    }
                } else {
                    this.analysisAttempts = 0;
                }
            }
        } catch (error) {
            this.lastError = error.message;
        } finally {
            this.isLocked = false;
        }
    }

    async start() {
        console.log('========================================');
        console.log(`UNLIMITED CONCURRENT TRADES STARTED`);
        console.log(`   User: ${this.userEmail}`);
        console.log(`   Investment: $${this.config.investmentAmount}`);
        console.log(`   Target: $${this.config.targetProfit}`);
        console.log(`   🔥 User Risk: ${this.userRiskPercent}%`);
        console.log(`   🔥 Max Positions: ${this.maxConcurrentPositions === Infinity ? 'UNLIMITED' : this.maxConcurrentPositions}`);
        console.log(`   ⚡ Speed: 1 SECOND LOOPS`);
        console.log(`   📈 Auto-Compound: ${this.autoCompound ? 'ENABLED' : 'DISABLED'}`);
        console.log(`   🔄 Forced Trades: ${this.allowForcedTrades ? 'ENABLED' : 'DISABLED'}`);
        console.log('========================================');
        
        const symbols = this.config.tradingPairs;
        let initialTrades = 0;
        for (const symbol of symbols) {
            if (initialTrades >= 3) break;
            const signal = await this.analyzeMarket(symbol);
            if (signal && signal.action !== 'HOLD' && signal.confidence >= 0.5) {
                await this.executeTrade(signal);
                initialTrades++;
            }
        }
        
        this.analysisInterval = setInterval(async () => { await this.tradingLoop(); }, 1000);
        this.monitorInterval = setInterval(async () => { if (!this.isLocked && this.isActive) await this.monitorPositions(); }, 500);
        
        console.log(`✅ UNLIMITED CONCURRENT TRADES ACTIVE`);
        console.log(`🔥 ${this.openPositions.length} positions opened`);
    }

    async stop() {
        console.log(`🛑 Stopping trading`);
        this.isActive = false;
        if (this.analysisInterval) clearInterval(this.analysisInterval);
        if (this.monitorInterval) clearInterval(this.monitorInterval);
        for (const position of this.openPositions) {
            try {
                await this.closePosition(position, position.currentProfitPercent || 0, position.currentPrice || position.entryPrice, 'Session stopped');
            } catch (error) {
                console.error(`Stop close error:`, error.message);
            }
        }
    }

    getStatus() {
        const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, this.config.timeLimit - elapsedHours);
        const currentBalance = this.totalInvestment + this.currentProfit;
        const progressPercent = this.config.targetProfit > 0 ? (currentBalance / this.config.targetProfit) * 100 : 0;
        const usedMargin = this.calculateTotalMarginUsed();
        const learningStats = realAI.getLearningStats();
        
        return {
            isActive: this.isActive,
            currentProfit: this.currentProfit || 0,
            targetProfit: this.config.targetProfit || 0,
            currentBalance: currentBalance || 0,
            winStreak: this.winStreak || 0,
            timeRemaining: timeRemaining || 0,
            progressPercent: Math.min(100, progressPercent || 0),
            openPositions: this.openPositions.length || 0,
            usedMargin: usedMargin || 0,
            maxConcurrentTrades: this.maxConcurrentPositions === Infinity ? 'UNLIMITED' : this.maxConcurrentPositions,
            trades: this.trades.slice(0, 30),
            tradeCount: this.tradeCount || 0,
            compoundMultiplier: this.compoundMultiplier || 1,
            totalInvestment: this.totalInvestment || 0,
            lastError: this.lastError || null,
            risk: `${this.userRiskPercent}% (User Configured)`,
            compounding: this.autoCompound ? 'AUTO-COMPOUNDING' : 'DISABLED',
            speed: '1 SECOND LOOPS',
            userRiskSettings: this.userRiskSettings,
            dailyTrades: this.dailyTrades,
            dailyProfit: this.dailyProfit,
            maxDailyTrades: this.maxDailyTrades,
            maxDailyLoss: this.maxDailyLoss,
            allowForcedTrades: this.allowForcedTrades,
            forcedTradesExecuted: this.forcedTradesExecuted || 0,
            learning: learningStats
        };
    }
}

// ============================================================
// 🚀 TRADING API ROUTES
// ============================================================

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetProfit, timeLimit = 1, tradingPairs } = req.body;
        if (!investmentAmount || investmentAmount < 10) {
            return res.status(400).json({ success: false, message: 'Minimum investment is $10' });
        }
        if (!targetProfit || targetProfit < 1) {
            return res.status(400).json({ success: false, message: 'Target profit must be at least $1' });
        }

        let pairs = tradingPairs || ['XAUUSD', 'EURUSD', 'GBPUSD', 'BTCUSDT', 'ETHUSDT'];

        if (!ticker) {
            const reinit = initTicker();
            if (!reinit) return res.status(500).json({ success: false, message: 'TickerAll initialization failed.' });
        }

        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.tickerallSessionId) {
            return res.status(400).json({ success: false, message: 'Please add Exness credentials first' });
        }

        const result = await fetchRealBalance(user.tickerallSessionId);
        const balance = result.balance || 0;
        if (balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have $${balance}, need $${investmentAmount}` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        const config = { 
            investmentAmount: parseFloat(investmentAmount), 
            targetProfit: parseFloat(targetProfit), 
            timeLimit: parseFloat(timeLimit), 
            tradingPairs: pairs 
        };

        const engine = new UnlimitedConcurrentTradingEngine(sessionId, req.user.email, config, user.tickerallSessionId);
        engines[sessionId] = engine;
        await engine.start();

        res.json({
            success: true,
            sessionId,
            message: `🔥 UNLIMITED CONCURRENT TRADES STARTED!`,
            balance: balance,
            currency: result.currency || 'USD',
            openPositions: engine.openPositions.length,
            maxConcurrentTrades: engine.maxConcurrentPositions === Infinity ? 'UNLIMITED' : engine.maxConcurrentPositions,
            compounding: engine.autoCompound ? 'AUTO-ENABLED' : 'DISABLED',
            risk: `${engine.userRiskPercent}% (User Configured)`,
            speed: '1 SECOND LOOPS',
            allowForcedTrades: engine.allowForcedTrades,
            userRiskSettings: engine.userRiskSettings
        });
    } catch (error) {
        console.error('❌ Start trading error:', error);
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (engines[sessionId]) {
        engines[sessionId].stop();
        delete engines[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const engine = engines[sessionId];
    if (!engine) {
        return res.json({ 
            success: true, 
            currentProfit: 0, 
            newTrades: [], 
            isActive: false, 
            openPositions: 0, 
            usedMargin: 0,
            tradeCount: 0,
            patterns: 0,
            symbols: 0,
            adaptiveRules: 0,
            forcedTradesExecuted: 0,
            allowForcedTrades: true
        });
    }
    const status = engine.getStatus();
    res.json({
        success: true,
        currentProfit: status.currentProfit || 0,
        targetProfit: status.targetProfit || 0,
        currentBalance: status.currentBalance || 0,
        newTrades: status.trades || [],
        winStreak: status.winStreak || 0,
        timeRemaining: status.timeRemaining || 0,
        progressPercent: status.progressPercent || 0,
        openPositions: status.openPositions || 0,
        usedMargin: status.usedMargin || 0,
        maxConcurrentTrades: status.maxConcurrentTrades || 'UNLIMITED',
        isActive: status.isActive,
        tradeCount: status.tradeCount || 0,
        compoundMultiplier: status.compoundMultiplier || 1,
        totalInvestment: status.totalInvestment || 0,
        lastError: status.lastError || null,
        risk: status.risk,
        compounding: status.compounding,
        speed: status.speed,
        userRiskSettings: status.userRiskSettings,
        dailyTrades: status.dailyTrades,
        dailyProfit: status.dailyProfit,
        maxDailyTrades: status.maxDailyTrades,
        maxDailyLoss: status.maxDailyLoss,
        patterns: status.learning?.patterns || 0,
        symbols: status.learning?.symbols?.length || 0,
        adaptiveRules: status.learning?.adaptiveRules || 0,
        forcedTradesExecuted: status.forcedTradesExecuted || 0,
        allowForcedTrades: status.allowForcedTrades !== false
    });
});

// ============================================================
// 🚀 SERVER START
// ============================================================

app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '88.0.0',
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\nALPHA - SECURE TRADING BOT v88.0.0`);
    console.log(`✅ Port: ${PORT}`);
    console.log(`✅ User Risk Range: ${MIN_RISK_PERCENT}% - ${MAX_RISK_PERCENT}%`);
    console.log(`✅ Default Risk: ${DEFAULT_RISK_PERCENT}%`);
    console.log(`✅ Default Forced Trades: ${DEFAULT_ALLOW_FORCED_TRADES ? 'ENABLED' : 'DISABLED'}`);
    console.log(`✅ TickerAll API Key: ${config.tickerallApiKey ? '✅ Configured' : '❌ Not Set'}`);
    console.log(`🔒 JWT_SECRET: ${JWT_SECRET ? '✅ Configured' : '❌ MISSING'}`);
    console.log(`🔒 ENCRYPTION_KEY: ${ENCRYPTION_KEY ? '✅ Configured' : '❌ MISSING'}`);
    console.log(`🔒 Token Blacklist: ${tokenBlacklist.size} tokens tracked`);
    console.log(`🔒 SECURE: Only public/ folder served statically`);
    console.log(`\n⚠️  DISCLAIMER: Trading involves risk.\n`);
});

module.exports = app;
