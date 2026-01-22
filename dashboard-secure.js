const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== SECURITY CONFIGURATION =====

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https://cdn.discordapp.com"],
            connectSrc: ["'self'"]
        }
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 uploads per hour
    message: 'Too many uploads, please try again later.'
});

// Input validation and sanitization
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return validator.escape(input.trim()).substring(0, 2000); // Max 2000 chars
}

function validateHexColor(color) {
    return /^#[0-9A-F]{6}$/i.test(color) ? color : '#FF69B4';
}

function validateURL(url) {
    try {
        if (!url) return '';
        const parsedUrl = new URL(url);
        // Only allow http/https
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return '';
        }
        return validator.isURL(url, { require_protocol: true }) ? url : '';
    } catch {
        return '';
    }
}

// ===== OAUTH CONFIGURATION =====

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Validate required environment variables
if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !SESSION_SECRET) {
    console.error('❌ Missing required environment variables!');
    console.error('Required: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, SESSION_SECRET');
    process.exit(1);
}

// Session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId', // Don't use default name
    cookie: { 
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'lax'
    }
}));

// Passport configuration
passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: DISCORD_CALLBACK_URL,
    scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
    // Don't store access token in session for security
    return done(null, {
        id: profile.id,
        username: profile.username,
        discriminator: profile.discriminator,
        avatar: profile.avatar,
        guilds: profile.guilds
    });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

// Body parsing with size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Static files
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory securely
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { mode: 0o755 });
}

// ===== FILE UPLOAD CONFIGURATION =====

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // Use crypto for secure random filename
        const crypto = require('crypto');
        const randomName = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${randomName}${ext}`);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // Strict file type checking
        const allowedMimes = ['image/gif', 'image/jpeg', 'image/jpg', 'image/png'];
        const allowedExts = ['.gif', '.jpg', '.jpeg', '.png'];
        
        const ext = path.extname(file.originalname).toLowerCase();
        const mimeType = file.mimetype.toLowerCase();
        
        if (allowedMimes.includes(mimeType) && allowedExts.includes(ext)) {
            return cb(null, true);
        }
        cb(new Error('Invalid file type. Only GIF, JPG, PNG allowed.'));
    }
});

// ===== DATA STORAGE =====

let uploadedGifs = [];
let stickyConfigs = {}; // { guildId: { channelId: { config } } }
let discordClient = null;

function setDiscordClient(client) {
    discordClient = client;
}

function getStickyConfigs() {
    return stickyConfigs;
}

// ===== AUTHENTICATION MIDDLEWARE =====

function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'Not authenticated' });
}

// Check if user has access to guild
function hasGuildAccess(req, res, next) {
    const guildId = req.params.guildId;
    const userGuilds = req.user.guilds || [];
    
    const guild = userGuilds.find(g => g.id === guildId);
    if (!guild) {
        return res.status(403).json({ error: 'No access to this guild' });
    }
    
    // Check admin permission
    if ((guild.permissions & 0x8) !== 0x8) {
        return res.status(403).json({ error: 'Admin permission required' });
    }
    
    // Check if bot is in guild
    if (!discordClient || !discordClient.guilds.cache.has(guildId)) {
        return res.status(404).json({ error: 'Bot not in this guild' });
    }
    
    next();
}

// ===== ROUTES =====

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// ===== AUTH ROUTES =====

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
    passport.authenticate('discord', { 
        failureRedirect: '/',
        failureMessage: true
    }),
    (req, res) => {
        res.redirect('/');
    }
);

app.get('/auth/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// ===== API ROUTES =====

app.get('/api/user', isAuth, (req, res) => {
    res.json({
        id: req.user.id,
        username: sanitizeInput(req.user.username),
        avatar: req.user.avatar ? 
            `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png` : 
            'https://cdn.discordapp.com/embed/avatars/0.png'
    });
});

app.get('/api/guilds', isAuth, (req, res) => {
    try {
        if (!discordClient) {
            return res.status(503).json({ error: 'Bot offline' });
        }
        
        const userGuilds = req.user.guilds || [];
        const mutualGuilds = userGuilds
            .filter(g => {
                const botGuild = discordClient.guilds.cache.get(g.id);
                return botGuild && (g.permissions & 0x8) === 0x8;
            })
            .map(g => {
                const botGuild = discordClient.guilds.cache.get(g.id);
                return {
                    id: g.id,
                    name: sanitizeInput(g.name),
                    icon: g.icon ? `https://cdn.discordapp.com/icons/${g.id}/${g.icon}.png` : null,
                    memberCount: botGuild ? botGuild.memberCount : 0
                };
            });
        
        res.json(mutualGuilds);
    } catch (error) {
        console.error('Error fetching guilds:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/guilds/:guildId/channels', isAuth, hasGuildAccess, (req, res) => {
    try {
        const guild = discordClient.guilds.cache.get(req.params.guildId);
        
        const channels = guild.channels.cache
            .filter(c => c.type === 0)
            .map(c => ({
                id: c.id,
                name: sanitizeInput(c.name),
                hasSticky: !!(stickyConfigs[req.params.guildId] && stickyConfigs[req.params.guildId][c.id])
            }));
        
        res.json(channels);
    } catch (error) {
        console.error('Error fetching channels:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/guilds/:guildId/channels/:channelId/config', isAuth, hasGuildAccess, (req, res) => {
    const config = stickyConfigs[req.params.guildId]?.[req.params.channelId];
    if (!config) {
        return res.status(404).json({ error: 'No config' });
    }
    res.json(config);
});

app.post('/api/guilds/:guildId/channels/:channelId/config', isAuth, hasGuildAccess, (req, res) => {
    try {
        // Validate and sanitize inputs
        const title = sanitizeInput(req.body.title);
        const description = sanitizeInput(req.body.description);
        const buttonText = sanitizeInput(req.body.buttonText);
        const responseMessage = sanitizeInput(req.body.responseMessage || '');
        const color = validateHexColor(req.body.color);
        
        // Sticky GIF settings
        const stickyMode = ['random', 'cycle', 'single', 'keyword'].includes(req.body.stickyMode) ? req.body.stickyMode : 
                          (['random', 'cycle', 'single', 'keyword'].includes(req.body.mode) ? req.body.mode : 'random');
        const stickyGifs = Array.isArray(req.body.stickyGifs) ? 
            req.body.stickyGifs.map(gif => validateURL(gif)).filter(url => url) : 
            (Array.isArray(req.body.gifs) ? req.body.gifs.map(gif => validateURL(gif)).filter(url => url) : []);
        const stickyKeywords = sanitizeInput(req.body.stickyKeywords || '');
        
        // Button GIF settings (separate from sticky)
        const buttonMode = ['random', 'cycle', 'single', 'keyword'].includes(req.body.buttonMode) ? req.body.buttonMode : 'random';
        const buttonGifs = Array.isArray(req.body.buttonGifs) ? 
            req.body.buttonGifs.map(gif => validateURL(gif)).filter(url => url) : [];
        const buttonKeywords = sanitizeInput(req.body.buttonKeywords || '');
        
        if (!title || !description || !buttonText) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        if (title.length > 256 || description.length > 2048 || buttonText.length > 80) {
            return res.status(400).json({ error: 'Text too long' });
        }
        
        if (!stickyConfigs[req.params.guildId]) {
            stickyConfigs[req.params.guildId] = {};
        }
        
        stickyConfigs[req.params.guildId][req.params.channelId] = {
            title,
            description,
            buttonText,
            color,
            responseMessage,
            // Sticky message settings
            stickyGifs,
            stickyMode,
            stickyKeywords,
            stickyCurrentIndex: 0,
            // Button response settings
            buttonGifs,
            buttonMode,
            buttonKeywords,
            buttonCurrentIndex: 0,
            // Backwards compatibility
            gifs: stickyGifs,
            mode: stickyMode,
            currentIndex: 0
        };
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error saving config:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/guilds/:guildId/channels/:channelId/config', isAuth, hasGuildAccess, (req, res) => {
    if (stickyConfigs[req.params.guildId]) {
        delete stickyConfigs[req.params.guildId][req.params.channelId];
    }
    res.json({ success: true });
});

// ===== GIF MANAGEMENT =====

app.get('/api/gifs', isAuth, (req, res) => {
    // Only return user's own GIFs
    const userGifs = uploadedGifs.filter(gif => gif.uploadedBy === req.user.id);
    res.json(userGifs);
});

app.post('/api/upload', isAuth, uploadLimiter, upload.single('gif'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const gifData = {
            id: Date.now() + Math.random(), // More unique ID
            filename: req.file.filename,
            originalname: sanitizeInput(req.file.originalname),
            url: `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`,
            uploadedAt: new Date().toISOString(),
            uploadedBy: req.user.id
        };
        
        uploadedGifs.push(gifData);
        res.json(gifData);
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.delete('/api/gifs/:id', isAuth, (req, res) => {
    try {
        const id = parseFloat(req.params.id);
        const index = uploadedGifs.findIndex(g => g.id === id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Not found' });
        }
        
        const gif = uploadedGifs[index];
        
        // Verify ownership
        if (gif.uploadedBy !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        // Safely delete file
        const filePath = path.join('uploads', path.basename(gif.filename));
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        
        uploadedGifs.splice(index, 1);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// ===== ERROR HANDLING =====

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ===== START SERVER =====

function startWebServer() {
    app.listen(PORT, () => {
        console.log(`🌐 Dashboard: http://localhost:${PORT}`);
        console.log('🔒 Security features enabled');
    });
}

module.exports = { startWebServer, setDiscordClient, getStickyConfigs };
