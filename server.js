const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const emailService = require('./emailService');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const expressLayouts = require('express-ejs-layouts');
const fs = require('fs');
const { createServer } = require('http');
const { Server } = require('socket.io');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Créer le serveur HTTP et Socket.IO
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Configuration des sessions
app.use(session({
    secret: process.env.SESSION_SECRET || 'ivote_secret_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Configuration de la base de données
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ivote_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Création du pool de connexions
let pool;

async function createPool() {
    pool = mysql.createPool(dbConfig);

    try {
        const connection = await pool.getConnection();
        console.log('✅ Connecté à la base de données MySQL');
        connection.release();
    } catch (error) {
        console.error('❌ Erreur de connexion à MySQL:', error);
        process.exit(1);
    }
}

// Configuration EJS avec layouts
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');
app.use(expressLayouts);
app.set('layout', 'layouts/main');

// Créer le dossier uploads s'il n'existe pas
const uploadsDir = __dirname + '/public/uploads';
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('📁 Dossier uploads créé:', uploadsDir);
}

// Servir les fichiers statiques uploadés
app.use('/uploads', express.static('public/uploads'));

// Middleware pour injecter les données utilisateur
app.use(async (req, res, next) => {
    if (req.session.userId) {
        try {
            const [users] = await pool.execute(
                'SELECT id, prenom, nom, email, created_at FROM users WHERE id = ?',
                [req.session.userId]
            );
            if (users.length > 0) {
                req.user = users[0];
            }
        } catch (error) {
            console.error('Erreur lors de la récupération de l\'utilisateur:', error);
        }
    }
    next();
});

// Middleware d'authentification
const requireAuth = (req, res, next) => {
    if (req.session.userId && req.user) {
        next();
    } else {
        res.redirect('/');
    }
};

// Fonctions utilitaires
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getExpirationDate() {
    const expires = new Date();
    expires.setHours(expires.getHours() + 24);
    return expires;
}

async function cleanExpiredRegistrations() {
    try {
        const [result] = await pool.execute(
            'DELETE FROM pending_registrations WHERE expires_at < NOW()'
        );
        if (result.affectedRows > 0) {
            console.log(`🧹 ${result.affectedRows} inscription(s) expirée(s) nettoyée(s)`);
        }
    } catch (error) {
        console.error('❌ Erreur lors du nettoyage des inscriptions expirées:', error);
    }
}



// Middleware pour ajouter le compteur de notifications à TOUTES les vues
app.use(async (req, res, next) => {
    // Injecter les données utilisateur
    if (req.session.userId) {
        try {
            const [users] = await pool.execute(
                'SELECT id, prenom, nom, email, created_at FROM users WHERE id = ?',
                [req.session.userId]
            );
            if (users.length > 0) {
                req.user = users[0];

                // Récupérer le compteur de notifications pour cet utilisateur
                const [unreadResult] = await pool.execute(
                    'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
                    [req.session.userId]
                );

                // Rendre disponible dans toutes les vues
                res.locals.unreadNotificationCount = unreadResult[0]?.count || 0;
            }
        } catch (error) {
            console.error('Erreur lors de la récupération de l\'utilisateur:', error);
            res.locals.unreadNotificationCount = 0;
        }
    } else {
        // Si pas connecté, mettre 0
        res.locals.unreadNotificationCount = 0;
    }
    next();
});

// ==================== ROUTES STATIQUES ====================

app.get('/', (req, res) => {
    if (req.session.userId && req.user) {
        res.redirect('/dashboard');
    } else {
        res.sendFile(__dirname + '/public/acceuil.html');
    }
});

app.get('/inscription', (req, res) => {
    res.sendFile(__dirname + '/public/inscription.html');
});

app.get('/verify-email', (req, res) => {
    res.sendFile(__dirname + '/public/verify-email.html');
});

app.get('/verification-success', (req, res) => {
    res.sendFile(__dirname + '/public/verification-success.html');
});

app.get('/waiting-verification', (req, res) => {
    res.sendFile(__dirname + '/public/waiting-verification.html');
});

app.get('/reset-password', (req, res) => {
    res.sendFile(__dirname + '/public/reset-password.html');
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(__dirname + '/public/forgot-password.html');
});

// ==================== ROUTES DASHBOARD ====================

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;

        // Récupérer l'utilisateur
        const [users] = await pool.execute(
            'SELECT id, prenom, nom, email, created_at FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            req.session.destroy();
            return res.redirect('/');
        }

        const user = users[0];

        // Récupérer les statistiques de l'utilisateur
        const [statsResult] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM votes WHERE user_id = ?) as total_votes,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'active') as active_polls,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'closed') as completed_polls,
                (SELECT COUNT(*) FROM polls WHERE created_by = ?) as total_polls_created,
                (SELECT COUNT(*) FROM room_members WHERE user_id = ?) as total_rooms_joined,
                (SELECT COUNT(*) FROM rooms WHERE owner_id = ?) as total_rooms_owned
        `, [userId, userId, userId, userId, userId, userId]);

        const stats = statsResult[0];

        // Récupérer les sondages actifs de l'utilisateur (limités à 3)
        const [activePolls] = await pool.execute(`
            SELECT p.id, p.title, p.question, p.end_time, p.created_at,
                   (SELECT COUNT(*) FROM votes WHERE poll_id = p.id) as vote_count
            FROM polls p
            WHERE p.created_by = ? AND p.status = 'active'
            ORDER BY p.created_at DESC
            LIMIT 3
        `, [userId]);

        // Récupérer les activités récentes (derniers 7 jours)
        const [recentActivity] = await pool.execute(`
            SELECT 
                DATE(voted_at) as activity_date,
                COUNT(*) as vote_count
            FROM votes
            WHERE user_id = ?
                AND voted_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(voted_at)
            ORDER BY activity_date ASC
        `, [userId]);

        // Formater les données pour le graphique
        const last7Days = [];
        const voteCounts = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            const dayName = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'][date.getDay()];

            last7Days.push(dayName);

            const activity = recentActivity.find(a => {
                const activityDate = new Date(a.activity_date).toISOString().split('T')[0];
                return activityDate === dateStr;
            });

            voteCounts.push(activity ? activity.vote_count : 0);
        }

        res.render('dashboard/dashboard', {
            title: 'Tableau de bord',
            page: 'dashboard',
            user: {
                name: `${user.prenom} ${user.nom}`,
                email: user.email,
                prenom: user.prenom,
                nom: user.nom,
                joinDate: new Date(user.created_at).toLocaleDateString('fr-FR')
            },
            stats: {
                totalVotes: stats.total_votes || 0,
                activePolls: stats.active_polls || 0,
                completedPolls: stats.completed_polls || 0,
                totalPollsCreated: stats.total_polls_created || 0,
                totalRoomsJoined: stats.total_rooms_joined || 0,
                totalRoomsOwned: stats.total_rooms_owned || 0
            },
            activePolls: activePolls || [],
            chartData: {
                labels: last7Days,
                data: voteCounts
            }
        });
    } catch (error) {
        console.error('❌ Erreur lors du chargement du dashboard:', error);
        res.status(500).send('Erreur lors du chargement du dashboard');
    }
});

app.get('/vote', requireAuth, (req, res) => {
    res.render('dashboard/vote', {
        title: 'Voter',
        page: 'vote',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

app.get('/poll/create', requireAuth, (req, res) => {
    res.render('dashboard/create-poll', {
        title: 'Créer un sondage',
        page: 'create-poll',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

app.get('/rooms', requireAuth, (req, res) => {
    res.render('dashboard/rooms', {
        title: 'Rooms',
        page: 'rooms',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

app.get('/results', requireAuth, (req, res) => {
    res.render('dashboard/results', {
        title: 'Résultats',
        page: 'results',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

app.get('/settings', requireAuth, (req, res) => {
    res.render('dashboard/settings', {
        title: 'Paramètres',
        page: 'settings',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Erreur lors de la déconnexion:', err);
        }
        res.redirect('/');
    });
});

// Route Explorer
app.get('/explorer', requireAuth, (req, res) => {
    res.render('dashboard/explorer', {
        title: 'Explorer',
        page: 'explorer',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

// Route Statistiques
app.get('/statistics', requireAuth, (req, res) => {
    res.render('dashboard/statistics', {
        title: 'Statistiques',
        page: 'statistics',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

// Route Notifications - CORRECTION
app.get('/notifications', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Vérifier/Créer les tables nécessaires
        await createNetworkTables();

        // Récupérer les notifications
        const [notifications] = await pool.execute(`
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50
        `, [userId]);

        // Récupérer le nombre de notifications non lues
        const [unreadResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        const unreadCount = unreadResult[0]?.count || 0;

        // Récupérer le nombre d'abonnés pour la navigation
        const [followersCountResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM followers WHERE following_id = ?',
            [userId]
        );

        res.render('dashboard/notifications', {
            title: 'Notifications',
            page: 'notifications',
            user: {
                id: userId,
                name: `${req.user.prenom} ${req.user.nom}`,
                email: req.user.email,
                prenom: req.user.prenom,
                nom: req.user.nom,
                joinDate: req.user.created_at
                    ? new Date(req.user.created_at).toLocaleDateString('fr-FR')
                    : new Date().toLocaleDateString('fr-FR')
            },
            notifications: notifications || [],
            unreadCount: unreadCount,
            hasUnread: unreadCount > 0,
            followersCount: followersCountResult[0]?.count || 0,
            unreadNotificationCount: unreadCount  // ✅ AJOUT DE CETTE LIGNE
        });

    } catch (error) {
        console.error('Erreur notifications:', error);
        res.status(500).send('Erreur serveur');
    }
});


// Route Recherche
app.get('/search', requireAuth, (req, res) => {
    const query = req.query.q || '';
    res.render('dashboard/search', {
        title: `Résultats pour "${query}"`,
        page: 'search',
        query: query,
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

// ==================== ROUTES API ====================

// Route d'inscription
app.post('/api/register', async (req, res) => {
    console.log('📨 Nouvelle inscription reçue:', { ...req.body, password: '***' });

    const { prenom, nom, countryCode, telephone, email, password, confirmPassword, terms } = req.body;

    const errors = [];
    const nameRegex = /^[a-zA-ZÀ-ÿ\s'-]+$/;
    const phoneRegex = /^[0-9\s]{9,15}$/;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!prenom || !nameRegex.test(prenom)) errors.push('Prénom invalide');
    if (!nom || !nameRegex.test(nom)) errors.push('Nom invalide');
    if (!telephone || !phoneRegex.test(telephone.replace(/\s/g, ''))) errors.push('Numéro de téléphone invalide');
    if (!email || !emailRegex.test(email)) errors.push('Email invalide');
    if (!password || password.length < 8) errors.push('Le mot de passe doit contenir au moins 8 caractères');
    if (password !== confirmPassword) errors.push('Les mots de passe ne correspondent pas');
    if (!terms || (terms !== true && terms !== 'true' && terms !== 1 && terms !== '1')) errors.push('Vous devez accepter les conditions');

    if (errors.length > 0) {
        console.log('❌ Erreurs de validation:', errors);
        return res.status(400).json({ success: false, errors });
    }

    try {
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE email = ? OR telephone = ?',
            [email, telephone]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                errors: ['Cet email ou numéro de téléphone est déjà utilisé']
            });
        }

        const [existingPending] = await pool.execute(
            'SELECT id, expires_at FROM pending_registrations WHERE email = ?',
            [email]
        );

        if (existingPending.length > 0) {
            const pending = existingPending[0];
            const expiresAt = new Date(pending.expires_at);
            const now = new Date();

            if (now < expiresAt) {
                return res.status(400).json({
                    success: false,
                    errors: ['Une inscription est déjà en attente pour cet email. Vérifiez vos emails.']
                });
            } else {
                await pool.execute(
                    'DELETE FROM pending_registrations WHERE id = ?',
                    [pending.id]
                );
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = generateVerificationToken();
        const expiresAt = getExpirationDate();

        const [result] = await pool.execute(
            `INSERT INTO pending_registrations 
            (prenom, nom, country_code, telephone, email, password, verification_token, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [prenom, nom, countryCode, telephone, email, hashedPassword, verificationToken, expiresAt]
        );

        const pendingId = result.insertId;

        await pool.execute(
            'INSERT INTO registration_audit (email, action) VALUES (?, ?)',
            [email, 'pending']
        );

        console.log(`✅ Inscription en attente créée (ID: ${pendingId}) pour: ${email}`);

        const emailResult = await emailService.sendVerificationEmail(email, verificationToken, prenom);

        if (!emailResult.success) {
            console.warn(`⚠️ Inscription en attente mais email non envoyé: ${email}`);
        }

        res.status(201).json({
            success: true,
            message: 'Inscription en attente. Veuillez vérifier votre email.',
            pendingId: pendingId,
            emailSent: emailResult.success,
            expiresAt: expiresAt.toISOString()
        });

    } catch (error) {
        console.error('❌ Erreur lors de l\'inscription en attente:', error);
        res.status(500).json({
            success: false,
            errors: ['Erreur serveur. Veuillez réessayer plus tard.']
        });
    }
});

// Route de vérification d'email
app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'Token manquant'
        });
    }

    try {
        const [pendingRows] = await pool.execute(
            `SELECT * FROM pending_registrations 
             WHERE verification_token = ?`,
            [token]
        );

        if (pendingRows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Token invalide ou inscription expirée'
            });
        }

        const pendingUser = pendingRows[0];
        const now = new Date();
        const expiresAt = new Date(pendingUser.expires_at);

        if (now > expiresAt) {
            await pool.execute(
                'DELETE FROM pending_registrations WHERE id = ?',
                [pendingUser.id]
            );

            await pool.execute(
                'INSERT INTO registration_audit (email, action) VALUES (?, ?)',
                [pendingUser.email, 'expired']
            );

            return res.status(400).json({
                success: false,
                message: 'Le lien de vérification a expiré. Veuillez vous réinscrire.'
            });
        }

        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE email = ? OR telephone = ?',
            [pendingUser.email, pendingUser.telephone]
        );

        if (existingUsers.length > 0) {
            await pool.execute(
                'DELETE FROM pending_registrations WHERE id = ?',
                [pendingUser.id]
            );

            return res.status(400).json({
                success: false,
                message: 'Cet email ou numéro de téléphone est déjà utilisé.'
            });
        }

        const [userResult] = await pool.execute(
            `INSERT INTO users 
            (prenom, nom, country_code, telephone, email, password, verified_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [
                pendingUser.prenom,
                pendingUser.nom,
                pendingUser.country_code,
                pendingUser.telephone,
                pendingUser.email,
                pendingUser.password
            ]
        );

        const userId = userResult.insertId;

        await pool.execute(
            'DELETE FROM pending_registrations WHERE id = ?',
            [pendingUser.id]
        );

        await pool.execute(
            'INSERT INTO registration_audit (email, action) VALUES (?, ?)',
            [pendingUser.email, 'verified']
        );

        console.log(`✅ Utilisateur créé (ID: ${userId}) après vérification: ${pendingUser.email}`);

        await emailService.sendWelcomeEmail(pendingUser.email, pendingUser.prenom);

        res.json({
            success: true,
            message: 'Compte vérifié et créé avec succès !',
            user: {
                id: userId,
                email: pendingUser.email,
                prenom: pendingUser.prenom,
                nom: pendingUser.nom
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors de la vérification:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la vérification'
        });
    }
});

// Route de connexion
app.post('/api/login', async (req, res) => {
    console.log('🔑 Tentative de connexion reçue:', { email: req.body.email, password: '***' });

    const { email, password, remember } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email et mot de passe requis'
        });
    }

    try {
        const [users] = await pool.execute(
            'SELECT id, prenom, nom, email, password, verified_at, created_at FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            console.log('❌ Utilisateur non trouvé:', email);
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        const user = users[0];

        if (!user.verified_at) {
            return res.status(403).json({
                success: false,
                message: 'Veuillez vérifier votre email avant de vous connecter'
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            console.log('❌ Mot de passe incorrect pour:', email);
            return res.status(401).json({
                success: false,
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Créer la session
        req.session.userId = user.id;
        req.session.userEmail = user.email;
        req.session.userName = `${user.prenom} ${user.nom}`;
        req.user = user;

        if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        }

        console.log('✅ Connexion réussie pour:', email);
        console.log('   Session créée:', req.session.userId);

        const tokenPayload = {
            id: user.id,
            email: user.email,
            prenom: user.prenom,
            nom: user.nom
        };

        const token = jwt.sign(
            tokenPayload,
            process.env.JWT_SECRET || 'votre_secret_jwt',
            { expiresIn: remember ? '30d' : '24h' }
        );

        res.json({
            success: true,
            message: 'Connexion réussie',
            token: token,
            redirect: '/dashboard',
            user: {
                id: user.id,
                prenom: user.prenom,
                nom: user.nom,
                email: user.email,
                created_at: user.created_at
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors de la connexion:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la connexion'
        });
    }
});

// Route pour vérifier le statut d'authentification
app.get('/api/auth/status', (req, res) => {
    res.json({
        isAuthenticated: !!req.session.userId,
        user: req.session.userId ? {
            id: req.session.userId,
            email: req.session.userEmail,
            name: req.session.userName
        } : null
    });
});

// Route pour vérifier le statut d'une inscription en attente
app.post('/api/check-pending-status', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email requis' });
    }

    try {
        const [pendingRows] = await pool.execute(
            `SELECT id, created_at, expires_at 
             FROM pending_registrations 
             WHERE email = ?`,
            [email]
        );

        if (pendingRows.length === 0) {
            return res.json({
                exists: false,
                message: 'Aucune inscription en attente trouvée'
            });
        }

        const pending = pendingRows[0];
        const now = new Date();
        const expiresAt = new Date(pending.expires_at);
        const isValid = now < expiresAt;

        res.json({
            exists: true,
            isValid: isValid,
            created_at: pending.created_at,
            expires_at: pending.expires_at,
            expires_in: Math.max(0, Math.floor((expiresAt - now) / 1000 / 60))
        });

    } catch (error) {
        console.error('Erreur lors de la vérification du statut:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour renvoyer un email de vérification
app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email requis' });
    }

    try {
        const [pendingRows] = await pool.execute(
            'SELECT id, prenom, verification_token, expires_at FROM pending_registrations WHERE email = ?',
            [email]
        );

        if (pendingRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Aucune inscription en attente trouvée avec cet email'
            });
        }

        const pending = pendingRows[0];
        const now = new Date();
        const expiresAt = new Date(pending.expires_at);

        if (now > expiresAt) {
            return res.status(400).json({
                success: false,
                message: 'L\'inscription a expiré. Veuillez vous réinscrire.'
            });
        }

        const newToken = generateVerificationToken();
        const newExpiresAt = getExpirationDate();

        await pool.execute(
            `UPDATE pending_registrations 
             SET verification_token = ?, expires_at = ? 
             WHERE id = ?`,
            [newToken, newExpiresAt, pending.id]
        );

        const emailResult = await emailService.sendVerificationEmail(
            email,
            newToken,
            pending.prenom
        );

        if (emailResult.success) {
            res.json({
                success: true,
                message: 'Email de vérification renvoyé',
                expiresAt: newExpiresAt.toISOString()
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Erreur lors de l\'envoi de l\'email'
            });
        }

    } catch (error) {
        console.error('❌ Erreur lors du renvoi:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour vérifier si un utilisateur existe
app.post('/api/check-user-exists', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email requis' });
    }

    try {
        const [users] = await pool.execute(
            'SELECT id, email, prenom, created_at FROM users WHERE email = ?',
            [email]
        );

        res.json({
            exists: users.length > 0,
            user: users.length > 0 ? users[0] : null
        });

    } catch (error) {
        console.error('Erreur lors de la vérification de l\'utilisateur:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route "Mot de passe oublié"
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'Email requis'
        });
    }

    console.log('🔑 Demande de réinitialisation pour:', email);

    try {
        const [users] = await pool.execute(
            'SELECT id, email, prenom FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            console.log('ℹ️ Email non trouvé, réponse générique envoyée');
            return res.json({
                success: true,
                message: 'Si cet email existe, vous recevrez un lien de réinitialisation'
            });
        }

        const user = users[0];

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        console.log('📝 Création token pour:', email);
        console.log('   Token hash:', tokenHash.substring(0, 20) + '...');
        console.log('   Expire à:', expiresAt);

        await pool.execute(
            'DELETE FROM password_reset_tokens WHERE user_id = ?',
            [user.id]
        );

        await pool.execute(
            `INSERT INTO password_reset_tokens 
            (user_id, token_hash, expires_at) 
            VALUES (?, ?, ?)`,
            [user.id, tokenHash, expiresAt]
        );

        const appUrl = process.env.APP_URL || 'http://localhost:3000';
        const resetLink = `${appUrl}/reset-password?token=${resetToken}`;

        console.log('📧 Tentative d\'envoi email à:', email);
        console.log('   Lien de réinitialisation:', resetLink);

        const emailResult = await emailService.sendPasswordResetEmail(email, resetLink, user.prenom);

        if (emailResult.success) {
            console.log('✅ Email envoyé avec succès');
            res.json({
                success: true,
                message: 'Si cet email existe, vous recevrez un lien de réinitialisation'
            });
        } else {
            console.warn('⚠️ Email non envoyé:', emailResult.error);

            await pool.execute(
                'DELETE FROM password_reset_tokens WHERE token_hash = ?',
                [tokenHash]
            );

            res.status(500).json({
                success: false,
                message: 'Erreur lors de l\'envoi de l\'email. Veuillez réessayer.'
            });
        }

    } catch (error) {
        console.error('❌ Erreur lors de la demande de réinitialisation:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route de vérification de token de réinitialisation
app.get('/api/verify-reset-token', async (req, res) => {
    const { token } = req.query;

    console.log('🔐 Vérification token:', token ? token.substring(0, 20) + '...' : 'null');

    if (!token) {
        return res.status(400).json({
            success: false,
            valid: false,
            message: 'Token manquant'
        });
    }

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        console.log('🔍 Recherche token hash:', tokenHash.substring(0, 20) + '...');

        const [tokens] = await pool.execute(
            `SELECT prt.*, u.email 
             FROM password_reset_tokens prt
             JOIN users u ON prt.user_id = u.id
             WHERE prt.token_hash = ? AND prt.expires_at > NOW() AND prt.used = 0`,
            [tokenHash]
        );

        console.log('📊 Tokens trouvés:', tokens.length);

        if (tokens.length === 0) {
            return res.json({
                success: true,
                valid: false,
                message: 'Token invalide ou expiré'
            });
        }

        res.json({
            success: true,
            valid: true,
            message: 'Token valide',
            expiresAt: tokens[0].expires_at
        });

    } catch (error) {
        console.error('❌ Erreur lors de la vérification du token:', error);
        res.status(500).json({
            success: false,
            valid: false,
            message: 'Erreur serveur'
        });
    }
});

// Route de réinitialisation du mot de passe
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body;

    console.log('🔄 Réinitialisation mot de passe reçue');

    if (!token || !newPassword || !confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'Tous les champs sont requis'
        });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'Les mots de passe ne correspondent pas'
        });
    }

    if (newPassword.length < 8) {
        return res.status(400).json({
            success: false,
            message: 'Le mot de passe doit contenir au moins 8 caractères'
        });
    }

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        console.log('🔍 Vérification token pour réinitialisation:', tokenHash.substring(0, 20) + '...');

        const [tokens] = await pool.execute(
            `SELECT prt.*, u.email, u.id as user_id
             FROM password_reset_tokens prt
             JOIN users u ON prt.user_id = u.id
             WHERE prt.token_hash = ? AND prt.expires_at > NOW() AND prt.used = 0`,
            [tokenHash]
        );

        if (tokens.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Lien invalide ou expiré'
            });
        }

        const resetToken = tokens[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, resetToken.user_id]
        );

        await pool.execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = ?',
            [resetToken.id]
        );

        console.log(`✅ Mot de passe réinitialisé pour: ${resetToken.email}`);

        res.json({
            success: true,
            message: 'Mot de passe réinitialisé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors de la réinitialisation:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour nettoyer manuellement les inscriptions expirées
app.post('/api/clean-expired', async (req, res) => {
    try {
        await cleanExpiredRegistrations();
        res.json({ success: true, message: 'Nettoyage terminé' });
    } catch (error) {
        console.error('❌ Erreur lors du nettoyage:', error);
        res.status(500).json({ success: false, message: 'Erreur lors du nettoyage' });
    }
});

// Route pour vérifier le statut de la base de données
app.get('/api/health', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT 1');
        res.json({
            status: 'healthy',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ==================== ROUTES POUR LES SONDAGES ET VOTES ====================

// Route pour récupérer les catégories
app.get('/api/categories', async (req, res) => {
    try {
        const [categories] = await pool.execute(
            'SELECT * FROM poll_categories ORDER BY name'
        );

        res.json({
            success: true,
            categories: categories
        });
    } catch (error) {
        console.error('❌ Erreur lors de la récupération des catégories:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour créer un sondage/vote
app.post('/api/polls', requireAuth, async (req, res) => {
    const {
        title,
        question,
        description,
        options,
        duration_hours,
        duration_minutes,
        poll_category,
        poll_type,
        category_id,
        is_anonymous,
        is_public,
        allow_images,
        password
    } = req.body;

    if (!title || !question || !options || !Array.isArray(options) || options.length < 2) {
        return res.status(400).json({
            success: false,
            message: 'Titre, question et au moins 2 options sont requises'
        });
    }

    // Validation du type
    if (!['sondage', 'vote'].includes(poll_category)) {
        return res.status(400).json({
            success: false,
            message: 'Type de création invalide'
        });
    }

    try {
        // Calculer la date de fin
        const now = new Date();
        let endTime = new Date(now);

        if (duration_hours) endTime.setHours(endTime.getHours() + parseInt(duration_hours));
        if (duration_minutes) endTime.setMinutes(endTime.getMinutes() + parseInt(duration_minutes));

        // Si aucune durée spécifiée, mettre 24h par défaut
        if (!duration_hours && !duration_minutes) {
            endTime.setHours(endTime.getHours() + 24);
        }

        // Créer le sondage/vote
        const [pollResult] = await pool.execute(
            `INSERT INTO polls 
            (title, question, description, end_time, created_by, status, 
             poll_category, poll_type, category_id, is_anonymous, is_public, allow_images, password) 
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
            [
                title,
                question,
                description || null,
                endTime,
                req.user.id,
                poll_category,
                poll_type || 'single',
                category_id || null,
                is_anonymous || false,
                is_public !== undefined ? is_public : true,
                allow_images || false,
                password || null
            ]
        );

        const pollId = pollResult.insertId;

        // Ajouter les options
        for (const [index, option] of options.entries()) {
            let imageUrl = null;

            // Si une image en base64 est fournie, la sauvegarder
            if (allow_images && option.image && option.image.startsWith('data:image')) {
                try {
                    // Extraire les données base64
                    const matches = option.image.match(/^data:image\/(\w+);base64,(.+)$/);
                    if (matches) {
                        const ext = matches[1];
                        const data = matches[2];
                        const buffer = Buffer.from(data, 'base64');

                        // Créer un nom de fichier unique
                        const filename = `option_${pollId}_${index}_${Date.now()}.${ext}`;
                        const filepath = __dirname + '/public/uploads/' + filename;

                        // Sauvegarder le fichier
                        await fs.promises.writeFile(filepath, buffer);

                        imageUrl = `/uploads/${filename}`;
                        console.log(`📸 Image sauvegardée: ${filename}`);
                    }
                } catch (imageError) {
                    console.error('❌ Erreur lors de la sauvegarde de l\'image:', imageError);
                }
            }

            await pool.execute(
                `INSERT INTO poll_options 
                (poll_id, option_text, option_image, option_order) 
                VALUES (?, ?, ?, ?)`,
                [
                    pollId,
                    option.text || option,
                    imageUrl,
                    index
                ]
            );
        }

        console.log(`✅ ${poll_category === 'vote' ? 'Vote' : 'Sondage'} créé (ID: ${pollId}) par: ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: poll_category === 'vote' ? 'Vote officiel créé avec succès' : 'Sondage créé avec succès',
            poll_id: pollId,
            end_time: endTime
        });

    } catch (error) {
        console.error('❌ Erreur lors de la création:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la création'
        });
    }
});

// Route pour récupérer tous les sondages/votes
app.get('/api/polls', requireAuth, async (req, res) => {
    try {
        const [polls] = await pool.execute(`
            SELECT p.*, 
                   pc.name as category_name,
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   (SELECT COUNT(*) FROM poll_options po WHERE po.poll_id = p.id) as options_count,
                   (SELECT COUNT(DISTINCT user_id) FROM votes WHERE poll_id = p.id) as total_votes,
                   CASE 
                       WHEN p.created_by = ? THEN 1
                       ELSE 0
                   END as is_creator
            FROM polls p
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            JOIN users u ON p.created_by = u.id
            WHERE (p.is_public = 1 OR p.created_by = ?)
            ORDER BY p.end_time DESC, p.created_at DESC
        `, [req.user.id, req.user.id]);

        // Pour chaque sondage/vote, récupérer les options et vérifier si l'utilisateur a déjà voté
        const pollsWithDetails = await Promise.all(polls.map(async (poll) => {
            const [options] = await pool.execute(`
                SELECT id, option_text, option_image 
                FROM poll_options 
                WHERE poll_id = ? 
                ORDER BY option_order
            `, [poll.id]);

            const [hasVoted] = await pool.execute(`
                SELECT COUNT(*) as count 
                FROM votes 
                WHERE poll_id = ? AND user_id = ?
            `, [poll.id, req.user.id]);

            return {
                ...poll,
                options,
                has_voted: hasVoted[0].count > 0,
                is_active: new Date(poll.end_time) > new Date() && poll.status === 'active'
            };
        }));

        res.json({
            success: true,
            polls: pollsWithDetails
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des sondages:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour voter
app.post('/api/vote', requireAuth, async (req, res) => {
    const { poll_id, options } = req.body;

    if (!poll_id || !options || !Array.isArray(options) || options.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'Données de vote invalides'
        });
    }

    try {
        // Vérifier si le sondage/vote existe et est actif
        const [pollRows] = await pool.execute(`
            SELECT p.*, u.id as creator_id 
            FROM polls p
            JOIN users u ON p.created_by = u.id
            WHERE p.id = ? AND p.status = 'active'
        `, [poll_id]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé ou terminé'
            });
        }

        const poll = pollRows[0];

        // Vérifier si l'utilisateur est le créateur
        if (poll.creator_id === req.user.id) {
            // Si c'est un vote officiel, le créateur ne peut pas voter
            if (poll.poll_category === 'vote') {
                return res.status(403).json({
                    success: false,
                    message: 'En tant que créateur d\'un vote officiel, vous ne pouvez pas participer'
                });
            }
            // Si c'est un sondage, le créateur peut voter
            console.log(`⚠️ Le créateur vote dans son propre sondage (ID: ${poll_id})`);
        }

        // Vérifier si le vote est encore ouvert
        const now = new Date();
        const endTime = new Date(poll.end_time);

        if (now > endTime) {
            await pool.execute(
                'UPDATE polls SET status = ? WHERE id = ?',
                ['closed', poll_id]
            );
            return res.status(400).json({
                success: false,
                message: 'Le ' + (poll.poll_category === 'vote' ? 'vote' : 'sondage') + ' est terminé'
            });
        }

        // Vérifier si l'utilisateur a déjà voté
        const [existingVotes] = await pool.execute(`
            SELECT COUNT(*) as count 
            FROM votes 
            WHERE poll_id = ? AND user_id = ?
        `, [poll_id, req.user.id]);

        if (existingVotes[0].count > 0) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté pour ce ' + (poll.poll_category === 'vote' ? 'vote' : 'sondage')
            });
        }

        // Vérifier le type de vote
        if (poll.poll_type === 'single' && options.length > 1) {
            return res.status(400).json({
                success: false,
                message: 'Ce ' + (poll.poll_category === 'vote' ? 'vote' : 'sondage') + ' ne permet qu\'un seul choix'
            });
        }

        // Vérifier que les options appartiennent bien au sondage/vote
        for (const optionId of options) {
            const [optionRows] = await pool.execute(`
                SELECT id FROM poll_options 
                WHERE id = ? AND poll_id = ?
            `, [optionId, poll_id]);

            if (optionRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Option de vote invalide'
                });
            }
        }

        // Enregistrer le(s) vote(s)
        for (const optionId of options) {
            await pool.execute(`
                INSERT INTO votes (poll_id, user_id, option_selected)
                VALUES (?, ?, ?)
            `, [poll_id, req.user.id, optionId]);
        }

        console.log(`✅ Vote enregistré (Poll: ${poll_id}, User: ${req.user.id}, Type: ${poll.poll_category})`);

        res.json({
            success: true,
            message: 'Votre vote a été enregistré avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors du vote:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de l\'enregistrement du vote'
        });
    }
});

// Route pour récupérer les résultats d'un sondage/vote
app.get('/api/polls/:id/results', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    try {
        // Vérifier les permissions
        const [pollCheck] = await pool.execute(`
            SELECT p.*, u.id as creator_id 
            FROM polls p
            JOIN users u ON p.created_by = u.id
            WHERE p.id = ?
        `, [pollId]);

        if (pollCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé'
            });
        }

        const poll = pollCheck[0];

        // Vérifier si l'utilisateur peut voir les résultats
        if (poll.status === 'active' && poll.created_by !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Les résultats ne sont disponibles qu\'après la fin du ' + (poll.poll_category === 'vote' ? 'vote' : 'sondage')
            });
        }

        // Récupérer les informations complètes
        const [pollRows] = await pool.execute(`
            SELECT p.*, 
                   pc.name as category_name,
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   (SELECT COUNT(DISTINCT user_id) FROM votes WHERE poll_id = p.id) as total_votes
            FROM polls p
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            JOIN users u ON p.created_by = u.id
            WHERE p.id = ?
        `, [pollId]);

        const pollWithDetails = pollRows[0];

        // Récupérer les options avec le nombre de votes
        const [options] = await pool.execute(`
            SELECT po.*, 
                   (SELECT COUNT(*) FROM votes v WHERE v.poll_id = po.poll_id AND v.option_selected = po.id) as vote_count
            FROM poll_options po
            WHERE po.poll_id = ?
            ORDER BY po.option_order
        `, [pollId]);

        pollWithDetails.options = options;

        res.json({
            success: true,
            poll: pollWithDetails
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des résultats:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour fermer un sondage/vote
app.post('/api/polls/:id/close', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    try {
        // Vérifier que l'utilisateur est bien le créateur
        const [pollRows] = await pool.execute(`
            SELECT created_by, poll_category, title FROM polls WHERE id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé'
            });
        }

        if (pollRows[0].created_by !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas autorisé à fermer ce sondage/vote'
            });
        }

        // Fermer le sondage/vote
        await pool.execute(`
            UPDATE polls SET status = 'closed' WHERE id = ?
        `, [pollId]);

        console.log(`🔒 ${pollRows[0].poll_category === 'vote' ? 'Vote' : 'Sondage'} fermé: "${pollRows[0].title}" (ID: ${pollId}) par: ${req.user.email}`);

        res.json({
            success: true,
            message: (pollRows[0].poll_category === 'vote' ? 'Vote' : 'Sondage') + ' fermé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors de la fermeture:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour supprimer un sondage/vote
app.delete('/api/polls/:id', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    try {
        // Vérifier que l'utilisateur est bien le créateur
        const [pollRows] = await pool.execute(`
            SELECT created_by, poll_category, title FROM polls WHERE id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé'
            });
        }

        const poll = pollRows[0];

        if (poll.created_by !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas autorisé à supprimer ce sondage/vote'
            });
        }

        // Supprimer les votes associés
        await pool.execute('DELETE FROM votes WHERE poll_id = ?', [pollId]);

        // Supprimer les options
        await pool.execute('DELETE FROM poll_options WHERE poll_id = ?', [pollId]);

        // Supprimer les sessions
        await pool.execute('DELETE FROM poll_sessions WHERE poll_id = ?', [pollId]);

        // Supprimer le sondage/vote
        await pool.execute('DELETE FROM polls WHERE id = ?', [pollId]);

        console.log(`🗑️ ${poll.poll_category === 'vote' ? 'Vote' : 'Sondage'} supprimé: "${poll.title}" (ID: ${pollId}) par: ${req.user.email}`);

        res.json({
            success: true,
            message: (poll.poll_category === 'vote' ? 'Vote' : 'Sondage') + ' supprimé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors de la suppression:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour modifier un sondage/vote
app.put('/api/polls/:id', requireAuth, async (req, res) => {
    const pollId = req.params.id;
    const { title, question, description, category_id } = req.body;

    try {
        // Vérifier que l'utilisateur est bien le créateur
        const [pollRows] = await pool.execute(`
            SELECT created_by, status, poll_category FROM polls WHERE id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé'
            });
        }

        if (pollRows[0].created_by !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas autorisé à modifier ce sondage/vote'
            });
        }

        // Vérifier que le sondage/vote n'est pas déjà commencé
        if (pollRows[0].status !== 'active') {
            return res.status(400).json({
                success: false,
                message: 'Impossible de modifier un ' + (pollRows[0].poll_category === 'vote' ? 'vote' : 'sondage') + ' déjà commencé ou terminé'
            });
        }

        // Mettre à jour
        await pool.execute(`
            UPDATE polls 
            SET title = ?, question = ?, description = ?, category_id = ?
            WHERE id = ?
        `, [title, question, description || null, category_id || null, pollId]);

        console.log(`✏️ ${pollRows[0].poll_category === 'vote' ? 'Vote' : 'Sondage'} modifié (ID: ${pollId}) par: ${req.user.email}`);

        res.json({
            success: true,
            message: (pollRows[0].poll_category === 'vote' ? 'Vote' : 'Sondage') + ' modifié avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors de la modification:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Tâche cron pour fermer automatiquement les sondages/votes expirés
setInterval(async () => {
    try {
        const [expiredPolls] = await pool.execute(`
            SELECT id, title, poll_category FROM polls 
            WHERE status = 'active' AND end_time < NOW()
        `);

        for (const poll of expiredPolls) {
            await pool.execute(`
                UPDATE polls SET status = 'closed' WHERE id = ?
            `, [poll.id]);

            console.log(`🔄 ${poll.poll_category === 'vote' ? 'Vote' : 'Sondage'} expiré fermé: "${poll.title}" (ID: ${poll.id})`);
        }

        if (expiredPolls.length > 0) {
            console.log(`🔄 ${expiredPolls.length} sondage(s)/vote(s) automatiquement fermé(s)`);
        }
    } catch (error) {
        console.error('❌ Erreur lors de la fermeture automatique:', error);
    }
}, 60000); // Vérifie toutes les minutes

// Démarrer le serveur
async function startServer() {
    await createPool();

    await cleanExpiredRegistrations();

    setInterval(cleanExpiredRegistrations, 60 * 60 * 1000);

    const emailConnected = await emailService.verifyConnection();

    app.listen(PORT, () => {
        console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
        console.log(`📝 Page de connexion: http://localhost:${PORT}/`);
        console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
        console.log(`🗳️  Page de vote: http://localhost:${PORT}/vote`);
        console.log(`📝 Page d'inscription: http://localhost:${PORT}/inscription`);
        console.log(`📧 Vérification email: ${emailConnected ? '✅ Activée' : '⚠️ Simulation'}`);
        console.log(`📁 Dossier uploads: ${uploadsDir}`);
        console.log(`🔄 Fermeture automatique des sondages/votes: ✅ Activée`);
    });
}

startServer().catch(console.error);
// ==================== FONCTIONS UTILITAIRES POUR LE RÉSEAU ====================

// Fonction pour créer les tables réseau si elles n'existent pas
async function createNetworkTables() {
    try {
        // Vérifier si la table followers existe
        const [tables] = await pool.execute(`
            SHOW TABLES LIKE 'followers'
        `);

        if (tables.length === 0) {
            await pool.execute(`
                CREATE TABLE followers (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    follower_id INT NOT NULL,
                    following_id INT NOT NULL,
                    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_follow (follower_id, following_id),
                    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Table followers créée');
        }
    } catch (error) {
        console.error('Erreur création tables réseau:', error);
    }
}

// Fonction pour créer une notification
async function createNotification(userId, type, message, fromUserId = null, relatedId = null) {
    try {
        const [result] = await pool.execute(
            `INSERT INTO notifications 
            (user_id, from_user_id, type, message, related_id) 
            VALUES (?, ?, ?, ?, ?)`,
            [userId, fromUserId, type, message, relatedId]
        );
        return result.insertId;
    } catch (error) {
        console.error('Erreur création notification:', error);
        return null;
    }
}

// ==================== ROUTES RÉSEAU SOCIAL ====================

// Route Network - Page principale
app.get('/network', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Vérifier/Créer les tables nécessaires
        await createNetworkTables();

        // Récupérer les suggestions d'amis (utilisateurs non suivis)
        const [suggestions] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email, 
                   u.created_at as join_date
            FROM users u
            WHERE u.id != ?
              AND u.verified_at IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM followers f 
                WHERE f.follower_id = ? 
                  AND f.following_id = u.id
              )
            ORDER BY RAND()
            LIMIT 10
        `, [userId, userId]);

        // Récupérer les abonnements (personnes que je suis)
        const [following] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email,
                   f.status, f.created_at as followed_at, f.id as follow_id
            FROM followers f
            JOIN users u ON f.following_id = u.id
            WHERE f.follower_id = ?
            ORDER BY f.created_at DESC
        `, [userId]);

        // Récupérer les abonnés (personnes qui me suivent)
        const [followers] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email,
                   f.status, f.created_at as followed_at, f.id as follow_id
            FROM followers f
            JOIN users u ON f.follower_id = u.id
            WHERE f.following_id = ?
            ORDER BY f.created_at DESC
        `, [userId]);

        // Récupérer les notifications non lues pour la nav
        const [unreadResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        const unreadCount = unreadResult[0]?.count || 0;

        res.render('dashboard/network', {
            title: 'Réseau',
            page: 'network',
            user: {
                id: userId,
                name: `${req.user.prenom} ${req.user.nom}`,
                email: req.user.email,
                prenom: req.user.prenom,
                nom: req.user.nom,
                joinDate: req.user.created_at
                    ? new Date(req.user.created_at).toLocaleDateString('fr-FR')
                    : new Date().toLocaleDateString('fr-FR')
            },
            suggestions: suggestions || [],
            following: following || [],
            followers: followers || [],
            unreadNotificationCount: unreadCount
        });

    } catch (error) {
        console.error('Erreur réseau:', error);
        res.status(500).send('Erreur serveur');
    }
});

// API: Recherche d'utilisateurs
app.get('/api/network/users/search', requireAuth, async (req, res) => {
    try {
        const searchTerm = req.query.q || '';
        const userId = req.user.id;

        if (!searchTerm || searchTerm.length < 2) {
            return res.json({ success: true, users: [] });
        }

        const searchPattern = `%${searchTerm}%`;

        const [users] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email, 
                   u.created_at as join_date,
                   EXISTS(
                       SELECT 1 FROM followers f 
                       WHERE f.follower_id = ? 
                         AND f.following_id = u.id
                   ) as is_following,
                   (SELECT f.status FROM followers f 
                    WHERE f.follower_id = ? 
                      AND f.following_id = u.id LIMIT 1) as follow_status
            FROM users u
            WHERE u.id != ?
              AND u.verified_at IS NOT NULL
              AND (u.prenom LIKE ? OR u.nom LIKE ? OR u.email LIKE ?)
            ORDER BY u.prenom, u.nom
            LIMIT 20
        `, [userId, userId, userId, searchPattern, searchPattern, searchPattern]);

        res.json({
            success: true,
            users: users
        });

    } catch (error) {
        console.error('Erreur recherche:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// API: Envoyer une demande d'abonnement
app.post('/api/network/follow/request', requireAuth, async (req, res) => {
    try {
        const { following_id, message } = req.body;
        const follower_id = req.user.id;

        if (!following_id) {
            return res.status(400).json({
                success: false,
                message: 'ID utilisateur requis'
            });
        }

        // Vérifier que l'utilisateur existe
        const [userRows] = await pool.execute(
            'SELECT id, prenom, nom FROM users WHERE id = ?',
            [following_id]
        );

        if (userRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        const targetUser = userRows[0];

        // Vérifier si une demande existe déjà
        const [existingRows] = await pool.execute(`
            SELECT id, status FROM followers 
            WHERE follower_id = ? AND following_id = ?
        `, [follower_id, following_id]);

        let followId;

        if (existingRows.length > 0) {
            const existing = existingRows[0];

            if (existing.status === 'pending') {
                return res.status(400).json({
                    success: false,
                    message: 'Demande déjà envoyée'
                });
            } else if (existing.status === 'accepted') {
                return res.status(400).json({
                    success: false,
                    message: 'Vous êtes déjà abonné'
                });
            } else {
                // Mettre à jour la demande rejetée
                await pool.execute(`
                    UPDATE followers 
                    SET status = 'pending', message = ?, updated_at = NOW()
                    WHERE id = ?
                `, [message || null, existing.id]);
                followId = existing.id;
            }
        } else {
            // Créer une nouvelle demande
            const [result] = await pool.execute(`
                INSERT INTO followers (follower_id, following_id, status, message)
                VALUES (?, ?, 'pending', ?)
            `, [follower_id, following_id, message || null]);

            followId = result.insertId;
        }

        // Créer une notification pour l'utilisateur cible
        const notificationMessage = `${req.user.prenom} ${req.user.nom} vous a envoyé une demande d'abonnement`;
        await createNotification(
            following_id,
            'follow_request',
            notificationMessage,
            follower_id,
            followId
        );

        console.log(`✅ Demande d'abonnement envoyée: ${follower_id} → ${following_id}`);

        res.json({
            success: true,
            message: 'Demande d\'abonnement envoyée',
            follow_id: followId
        });

    } catch (error) {
        console.error('Erreur demande abonnement:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// API: Accepter une demande d'abonnement
app.post('/api/network/follow/accept', requireAuth, async (req, res) => {
    try {
        const { follow_id } = req.body;

        if (!follow_id) {
            return res.status(400).json({
                success: false,
                message: 'ID demande requis'
            });
        }

        // Vérifier la demande
        const [followRows] = await pool.execute(`
            SELECT f.*, u.prenom, u.nom 
            FROM followers f
            JOIN users u ON f.follower_id = u.id
            WHERE f.id = ? AND f.following_id = ?
        `, [follow_id, req.user.id]);

        if (followRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Demande non trouvée'
            });
        }

        const follow = followRows[0];

        // Mettre à jour le statut
        await pool.execute(`
            UPDATE followers SET status = 'accepted' WHERE id = ?
        `, [follow_id]);

        // Créer une notification pour le demandeur
        const notificationMessage = `${req.user.prenom} ${req.user.nom} a accepté votre demande d'abonnement`;
        await createNotification(
            follow.follower_id,
            'follow_accepted',
            notificationMessage,
            req.user.id,
            follow_id
        );

        console.log(`✅ Demande d'abonnement acceptée: ${follow.follower_id} → ${req.user.id}`);

        res.json({
            success: true,
            message: 'Demande d\'abonnement acceptée'
        });

    } catch (error) {
        console.error('Erreur acceptation:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// API: Refuser une demande d'abonnement
app.post('/api/network/follow/reject', requireAuth, async (req, res) => {
    try {
        const { follow_id } = req.body;

        if (!follow_id) {
            return res.status(400).json({
                success: false,
                message: 'ID demande requis'
            });
        }

        // Vérifier la demande
        const [followRows] = await pool.execute(`
            SELECT f.* FROM followers f
            WHERE f.id = ? AND f.following_id = ?
        `, [follow_id, req.user.id]);

        if (followRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Demande non trouvée'
            });
        }

        // Mettre à jour le statut
        await pool.execute(`
            UPDATE followers SET status = 'rejected' WHERE id = ?
        `, [follow_id]);

        console.log(`❌ Demande d'abonnement refusée: ${follow_id}`);

        res.json({
            success: true,
            message: 'Demande d\'abonnement refusée'
        });

    } catch (error) {
        console.error('Erreur refus:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// API: Se désabonner
app.post('/api/network/follow/unfollow', requireAuth, async (req, res) => {
    try {
        const { following_id } = req.body;

        if (!following_id) {
            return res.status(400).json({
                success: false,
                message: 'ID utilisateur requis'
            });
        }

        // Supprimer l'abonnement
        await pool.execute(`
            DELETE FROM followers 
            WHERE follower_id = ? AND following_id = ?
        `, [req.user.id, following_id]);

        console.log(`🔕 Désabonnement: ${req.user.id} → ${following_id}`);

        res.json({
            success: true,
            message: 'Vous êtes désabonné'
        });

    } catch (error) {
        console.error('Erreur désabonnement:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// API: Supprimer un abonné
app.delete('/api/network/followers/:follower_id', requireAuth, async (req, res) => {
    try {
        const follower_id = req.params.follower_id;

        if (!follower_id) {
            return res.status(400).json({
                success: false,
                message: 'ID abonné requis'
            });
        }

        // Vérifier si l'abonné existe
        const [checkRows] = await pool.execute(`
            SELECT id FROM followers 
            WHERE follower_id = ? AND following_id = ?
        `, [follower_id, req.user.id]);

        if (checkRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Abonné non trouvé'
            });
        }

        // Supprimer l'abonnement
        await pool.execute(`
            DELETE FROM followers 
            WHERE follower_id = ? AND following_id = ?
        `, [follower_id, req.user.id]);

        console.log(`🗑️ Abonné supprimé: ${follower_id} → ${req.user.id}`);

        res.json({
            success: true,
            message: 'Abonné supprimé'
        });

    } catch (error) {
        console.error('Erreur suppression abonné:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// API: Obtenir les statistiques de réseau
app.get('/api/network/stats', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [followingCount] = await pool.execute(`
            SELECT COUNT(*) as count FROM followers 
            WHERE follower_id = ? AND status = 'accepted'
        `, [userId]);

        const [followersCount] = await pool.execute(`
            SELECT COUNT(*) as count FROM followers 
            WHERE following_id = ? AND status = 'accepted'
        `, [userId]);

        const [pendingCount] = await pool.execute(`
            SELECT COUNT(*) as count FROM followers 
            WHERE following_id = ? AND status = 'pending'
        `, [userId]);

        res.json({
            success: true,
            stats: {
                following: followingCount[0].count || 0,
                followers: followersCount[0].count || 0,
                pending: pendingCount[0].count || 0
            }
        });

    } catch (error) {
        console.error('Erreur stats réseau:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// API: Obtenir les détails d'un utilisateur
app.get('/api/network/user/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.params.id;

        const [userRows] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email, 
                   u.created_at as join_date,
                   (SELECT COUNT(*) FROM followers WHERE follower_id = u.id AND status = 'accepted') as following_count,
                   (SELECT COUNT(*) FROM followers WHERE following_id = u.id AND status = 'accepted') as followers_count
            FROM users u
            WHERE u.id = ? AND u.verified_at IS NOT NULL
        `, [userId]);

        if (userRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        const user = userRows[0];

        // Vérifier la relation
        const [relationRows] = await pool.execute(`
            SELECT status FROM followers 
            WHERE follower_id = ? AND following_id = ?
        `, [req.user.id, userId]);

        user.relation = relationRows.length > 0 ? relationRows[0].status : null;

        res.json({
            success: true,
            user: user
        });

    } catch (error) {
        console.error('Erreur détails utilisateur:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});
// ==================== FONCTIONS UTILITAIRES ====================

// Fonction pour créer la table notifications si elle n'existe pas
async function createNotificationsTable() {
    try {
        const [tables] = await pool.execute(`
            SHOW TABLES LIKE 'notifications'
        `);

        if (tables.length === 0) {
            await pool.execute(`
                CREATE TABLE notifications (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    from_user_id INT,
                    type VARCHAR(50) NOT NULL,
                    message TEXT NOT NULL,
                    related_id INT,
                    is_read BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id),
                    INDEX idx_is_read (is_read),
                    INDEX idx_created_at (created_at),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            `);
            console.log('✅ Table notifications créée');
        }
    } catch (error) {
        console.error('❌ Erreur création table notifications:', error);
    }
}

// Fonction pour créer toutes les tables réseau
async function createNetworkTables() {
    try {
        // Créer la table followers si elle n'existe pas
        const [followerTables] = await pool.execute(`
            SHOW TABLES LIKE 'followers'
        `);

        if (followerTables.length === 0) {
            await pool.execute(`
                CREATE TABLE followers (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    follower_id INT NOT NULL,
                    following_id INT NOT NULL,
                    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_follow (follower_id, following_id),
                    INDEX idx_follower_id (follower_id),
                    INDEX idx_following_id (following_id),
                    INDEX idx_status (status),
                    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            `);
            console.log('✅ Table followers créée');
        }

        // Créer la table notifications si elle n'existe pas
        await createNotificationsTable();

    } catch (error) {
        console.error('❌ Erreur création tables réseau:', error);
    }
}

// Fonction pour créer une notification (améliorée)
async function createNotification(userId, type, message, fromUserId = null, relatedId = null) {
    try {
        const [result] = await pool.execute(
            `INSERT INTO notifications 
            (user_id, from_user_id, type, message, related_id, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())`,
            [userId, fromUserId, type, message, relatedId]
        );

        console.log(`📧 Notification créée pour l'utilisateur ${userId}: ${type}`);
        return result.insertId;
    } catch (error) {
        console.error('❌ Erreur création notification:', error);
        return null;
    }
}

// ==================== ROUTES NOTIFICATIONS ====================

// IMPORTANT: Placez les routes spécifiques AVANT les routes paramétrées

// Page principale des notifications
app.get('/notifications', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = 20;
        const offset = 0;

        // Vérifier/Créer les tables nécessaires
        await createNetworkTables();

        // Récupérer les notifications
        const [notifications] = await pool.execute(`
            SELECT n.*, 
                   u.prenom as from_prenom,
                   u.nom as from_nom,
                   u.email as from_email
            FROM notifications n
            LEFT JOIN users u ON n.from_user_id = u.id
            WHERE n.user_id = ?
            ORDER BY n.is_read ASC, n.created_at DESC
            LIMIT ? OFFSET ?
        `, [userId, limit, offset]);

        // Compter les notifications non lues
        const [unreadResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        // Compter le total des notifications
        const [totalResult] = await pool.execute(
            'SELECT COUNT(*) as total FROM notifications WHERE user_id = ?',
            [userId]
        );

        const unreadCount = unreadResult[0]?.count || 0;
        const totalCount = totalResult[0]?.total || 0;

        // Récupérer les notifications non lues pour la nav
        const [navUnreadResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        const navUnreadCount = navUnreadResult[0]?.count || 0;

        res.render('dashboard/notifications', {
            title: 'Notifications',
            page: 'notifications',
            user: {
                id: userId,
                name: `${req.user.prenom} ${req.user.nom}`,
                email: req.user.email,
                prenom: req.user.prenom,
                nom: req.user.nom
            },
            notifications: notifications || [],
            unreadCount: unreadCount,
            totalCount: totalCount,
            unreadNotificationCount: navUnreadCount
        });

    } catch (error) {
        console.error('❌ Erreur chargement notifications:', error);
        res.status(500).send('Erreur serveur');
    }
});

// ==================== API NOTIFICATIONS ====================

// ==================== ROUTES API NOTIFICATIONS ====================

// CRITIQUE: LES ROUTES SPÉCIFIQUES DOIVENT ÊTRE AVANT LES ROUTES PARAMÉTRÉES

// 1. Route pour obtenir les statistiques des notifications
app.get('/api/notifications/stats', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [unreadResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        const [totalResult] = await pool.execute(
            'SELECT COUNT(*) as total FROM notifications WHERE user_id = ?',
            [userId]
        );

        const [pendingFollows] = await pool.execute(`
            SELECT COUNT(*) as pending FROM followers 
            WHERE following_id = ? AND status = 'pending'
        `, [userId]);

        res.json({
            success: true,
            stats: {
                unread: unreadResult[0]?.count || 0,
                total: totalResult[0]?.total || 0,
                pendingFollows: pendingFollows[0]?.pending || 0
            }
        });

    } catch (error) {
        console.error('❌ Erreur stats notifications:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 2. Route pour obtenir les notifications (pagination)
app.get('/api/notifications', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 20;
        const offset = parseInt(req.query.offset) || 0;

        const [notifications] = await pool.execute(`
            SELECT n.*, 
                   u.prenom as from_prenom,
                   u.nom as from_nom,
                   u.email as from_email
            FROM notifications n
            LEFT JOIN users u ON n.from_user_id = u.id
            WHERE n.user_id = ?
            ORDER BY n.is_read ASC, n.created_at DESC
            LIMIT ? OFFSET ?
        `, [userId, limit, offset]);

        const [totalResult] = await pool.execute(
            'SELECT COUNT(*) as total FROM notifications WHERE user_id = ?',
            [userId]
        );

        res.json({
            success: true,
            notifications: notifications || [],
            total: totalResult[0]?.total || 0
        });

    } catch (error) {
        console.error('❌ Erreur récupération notifications:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la récupération des notifications'
        });
    }
});

// 3. Route pour marquer TOUTES les notifications comme lues
app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        await pool.execute(`
            UPDATE notifications 
            SET is_read = 1, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND is_read = 0
        `, [userId]);

        console.log(`✅ Toutes les notifications marquées comme lues pour l'utilisateur: ${userId}`);

        res.json({
            success: true,
            message: 'Toutes les notifications ont été marquées comme lues'
        });

    } catch (error) {
        console.error('❌ Erreur marquer tout comme lu:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors du marquage'
        });
    }
});

// 4. Route pour accepter une demande d'abonnement depuis les notifications
app.post('/api/notifications/follow/accept', requireAuth, async (req, res) => {
    try {
        const { follow_id, notification_id } = req.body;
        const userId = req.user.id;

        console.log('📝 Acceptation depuis notification:', { follow_id, notification_id, userId });

        if (!follow_id) {
            return res.status(400).json({
                success: false,
                message: 'ID demande requis'
            });
        }

        // Vérifier que la notification appartient à l'utilisateur (si fournie)
        if (notification_id) {
            const [notifCheck] = await pool.execute(
                'SELECT id, user_id FROM notifications WHERE id = ?',
                [notification_id]
            );

            if (notifCheck.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Notification non trouvée'
                });
            }

            // Vérifier que la notification appartient bien à l'utilisateur
            if (notifCheck[0].user_id !== userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Non autorisé à modifier cette notification'
                });
            }
        }

        // Vérifier la demande de suivi
        const [followRows] = await pool.execute(`
            SELECT f.*, 
                   fu.prenom as follower_prenom,
                   fu.nom as follower_nom
            FROM followers f
            JOIN users fu ON f.follower_id = fu.id
            WHERE f.id = ? AND f.following_id = ?
        `, [follow_id, userId]);

        if (followRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Demande de suivi non trouvée'
            });
        }

        const follow = followRows[0];

        // Vérifier le statut actuel
        if (follow.status === 'accepted') {
            return res.status(400).json({
                success: false,
                message: 'Cette demande est déjà acceptée'
            });
        }

        if (follow.status === 'rejected') {
            return res.status(400).json({
                success: false,
                message: 'Cette demande a déjà été refusée'
            });
        }

        // Mettre à jour le statut de suivi
        await pool.execute(`
            UPDATE followers 
            SET status = 'accepted', updated_at = NOW() 
            WHERE id = ?
        `, [follow_id]);

        // Créer une notification pour l'utilisateur qui a envoyé la demande
        const notificationMessage = `${req.user.prenom} ${req.user.nom} a accepté votre demande d'abonnement`;
        await createNotification(
            follow.follower_id,
            'follow_accepted',
            notificationMessage,
            userId,
            follow_id
        );

        // Marquer la notification originale comme lue (si elle existe)
        if (notification_id) {
            await pool.execute(`
                UPDATE notifications 
                SET is_read = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `, [notification_id]);
        }

        console.log(`✅ Demande d'abonnement acceptée depuis notification: ${follow_id}`);

        res.json({
            success: true,
            message: 'Demande d\'abonnement acceptée',
            follow: {
                id: follow_id,
                status: 'accepted',
                follower: {
                    id: follow.follower_id,
                    name: `${follow.follower_prenom} ${follow.follower_nom}`
                }
            },
            notification_id: notification_id
        });

    } catch (error) {
        console.error('❌ Erreur acceptation depuis notification:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de l\'acceptation'
        });
    }
});

// 5. Route pour refuser une demande d'abonnement depuis les notifications
app.post('/api/notifications/follow/reject', requireAuth, async (req, res) => {
    try {
        const { follow_id, notification_id } = req.body;
        const userId = req.user.id;

        console.log('📝 Refus depuis notification:', { follow_id, notification_id, userId });

        if (!follow_id) {
            return res.status(400).json({
                success: false,
                message: 'ID demande requis'
            });
        }

        // Vérifier que la notification appartient à l'utilisateur (si fournie)
        if (notification_id) {
            const [notifCheck] = await pool.execute(
                'SELECT id, user_id FROM notifications WHERE id = ?',
                [notification_id]
            );

            if (notifCheck.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Notification non trouvée'
                });
            }

            // Vérifier que la notification appartient bien à l'utilisateur
            if (notifCheck[0].user_id !== userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Non autorisé à modifier cette notification'
                });
            }
        }

        // Vérifier la demande de suivi
        const [followRows] = await pool.execute(`
            SELECT f.*, fu.prenom, fu.nom
            FROM followers f
            JOIN users fu ON f.follower_id = fu.id
            WHERE f.id = ? AND f.following_id = ?
        `, [follow_id, userId]);

        if (followRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Demande de suivi non trouvée'
            });
        }

        const follow = followRows[0];

        // Vérifier le statut actuel
        if (follow.status === 'rejected') {
            return res.status(400).json({
                success: false,
                message: 'Cette demande a déjà été refusée'
            });
        }

        // Mettre à jour le statut de suivi
        await pool.execute(`
            UPDATE followers 
            SET status = 'rejected', updated_at = NOW() 
            WHERE id = ?
        `, [follow_id]);

        // Marquer la notification comme lue (si elle existe)
        if (notification_id) {
            await pool.execute(`
                UPDATE notifications 
                SET is_read = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `, [notification_id]);
        }

        console.log(`❌ Demande d'abonnement refusée depuis notification: ${follow_id}`);

        res.json({
            success: true,
            message: 'Demande d\'abonnement refusée',
            follow: {
                id: follow_id,
                status: 'rejected',
                follower: {
                    id: follow.follower_id,
                    name: `${follow.prenom} ${follow.nom}`
                }
            },
            notification_id: notification_id
        });

    } catch (error) {
        console.error('❌ Erreur refus depuis notification:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors du refus'
        });
    }
});

// 6. Route pour obtenir le compteur de notifications (pour la navbar)
app.get('/api/notifications/count', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [result] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
            [userId]
        );

        res.json({
            success: true,
            count: result[0]?.count || 0
        });

    } catch (error) {
        console.error('❌ Erreur compteur notifications:', error);
        res.status(500).json({
            success: false,
            count: 0
        });
    }
});

// ==================== ROUTES PARAMÉTRÉES (DOIVENT ÊTRE APRÈS LES ROUTES SPÉCIFIQUES) ====================

// 7. Route pour marquer UNE notification comme lue
app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
    try {
        const notificationId = req.params.id;
        const userId = req.user.id;

        console.log('📝 Marquer comme lu:', { notificationId, userId });

        if (!notificationId) {
            return res.status(400).json({
                success: false,
                message: 'ID notification requis'
            });
        }

        // Vérifier que la notification appartient à l'utilisateur
        const [checkRows] = await pool.execute(
            'SELECT id, is_read FROM notifications WHERE id = ? AND user_id = ?',
            [notificationId, userId]
        );

        if (checkRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Notification non trouvée'
            });
        }

        // Vérifier si déjà lue
        const notification = checkRows[0];
        if (notification.is_read) {
            return res.json({
                success: true,
                message: 'Notification déjà marquée comme lue'
            });
        }

        // Mettre à jour comme lue
        await pool.execute(`
            UPDATE notifications 
            SET is_read = 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [notificationId]);

        console.log(`✅ Notification marquée comme lue: ${notificationId}`);

        res.json({
            success: true,
            message: 'Notification marquée comme lue'
        });

    } catch (error) {
        console.error('❌ Erreur marquer comme lu:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors du marquage comme lu'
        });
    }
});

// 8. Route pour supprimer UNE notification
app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
    try {
        const notificationId = req.params.id;
        const userId = req.user.id;

        console.log('🗑️ Suppression notification:', { notificationId, userId });

        if (!notificationId) {
            return res.status(400).json({
                success: false,
                message: 'ID notification requis'
            });
        }

        // Vérifier que la notification appartient à l'utilisateur
        const [checkRows] = await pool.execute(
            'SELECT id, is_read FROM notifications WHERE id = ? AND user_id = ?',
            [notificationId, userId]
        );

        if (checkRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Notification non trouvée'
            });
        }

        // Supprimer la notification
        await pool.execute(`
            DELETE FROM notifications 
            WHERE id = ? AND user_id = ?
        `, [notificationId, userId]);

        console.log(`🗑️ Notification supprimée: ${notificationId}`);

        res.json({
            success: true,
            message: 'Notification supprimée'
        });

    } catch (error) {
        console.error('❌ Erreur suppression notification:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la suppression'
        });
    }
});

/// ==================== ROUTES PROFIL ====================

// Route pour la page profil
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Récupérer les informations de base de l'utilisateur
        const [userRows] = await pool.execute(
            'SELECT id, prenom, nom, email, country_code, telephone, created_at, verified_at FROM users WHERE id = ?',
            [userId]
        );

        if (userRows.length === 0) {
            return res.redirect('/dashboard');
        }

        const user = userRows[0];

        // Récupérer les statistiques
        const [pollsCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM polls WHERE created_by = ?',
            [userId]
        );

        const [votesCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM votes WHERE user_id = ?',
            [userId]
        );

        const [followersCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM followers WHERE following_id = ? AND status = "accepted"',
            [userId]
        );

        const [followingCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM followers WHERE follower_id = ? AND status = "accepted"',
            [userId]
        );

        // Récupérer les sondages récents (limit 5)
        const [recentPolls] = await pool.execute(`
            SELECT p.*, pc.name as category_name,
                   (SELECT COUNT(*) FROM votes v WHERE v.poll_id = p.id) as total_votes
            FROM polls p
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            WHERE p.created_by = ?
            ORDER BY p.created_at DESC
            LIMIT 5
        `, [userId]);

        // Récupérer les votes récents (limit 5)
        const [recentVotes] = await pool.execute(`
            SELECT v.*, 
                   p.title as poll_title, 
                   p.question as poll_question,
                   CONCAT(u.prenom, ' ', u.nom) as poll_creator_name,
                   po.option_text as selected_option
            FROM votes v
            JOIN polls p ON v.poll_id = p.id
            JOIN poll_options po ON v.option_selected = po.id
            JOIN users u ON p.created_by = u.id
            WHERE v.user_id = ?
            ORDER BY v.voted_at DESC
            LIMIT 5
        `, [userId]);

        res.render('dashboard/profile', {
            title: 'Mon Profil',
            page: 'profile',
            user: {
                id: user.id,
                name: `${user.prenom} ${user.nom}`,
                email: user.email,
                prenom: user.prenom,
                nom: user.nom,
                country_code: user.country_code || '+33',
                telephone: user.telephone || '',
                verified: user.verified_at !== null,
                joinDate: user.created_at ? new Date(user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
            },
            stats: {
                createdPolls: pollsCount[0]?.count || 0,
                totalVotes: votesCount[0]?.count || 0,
                followers: followersCount[0]?.count || 0,
                following: followingCount[0]?.count || 0
            },
            recentPolls: recentPolls || [],
            recentVotes: recentVotes || []
        });

    } catch (error) {
        console.error('❌ Erreur lors du chargement du profil:', error);
        res.status(500).send('Erreur lors du chargement du profil');
    }
});

// Route pour la page d'édition de profil
app.get('/profile/edit', requireAuth, async (req, res) => {
    try {
        const [userRows] = await pool.execute(
            'SELECT id, prenom, nom, email, country_code, telephone, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (userRows.length === 0) {
            return res.redirect('/profile');
        }

        const user = userRows[0];

        res.render('dashboard/edit-profile', {
            title: 'Modifier Profil',
            page: 'edit-profile',
            user: {
                id: user.id,
                name: `${user.prenom} ${user.nom}`,
                email: user.email,
                prenom: user.prenom,
                nom: user.nom,
                countryCode: user.country_code || '+33',
                telephone: user.telephone || '',
                joinDate: user.created_at ? new Date(user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors du chargement de l\'édition du profil:', error);
        res.status(500).send('Erreur serveur');
    }
});

// ==================== API PROFIL ====================

// API: Mettre à jour le profil
app.post('/api/profile/update', requireAuth, async (req, res) => {
    const {
        prenom,
        nom,
        email,
        telephone,
        countryCode,
        currentPassword,
        newPassword,
        confirmPassword
    } = req.body;

    const userId = req.user.id;
    const errors = [];
    const updates = [];

    try {
        // Validation de base
        if (!prenom || prenom.length < 2) {
            errors.push('Le prénom doit contenir au moins 2 caractères');
        }

        if (!nom || nom.length < 2) {
            errors.push('Le nom doit contenir au moins 2 caractères');
        }

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            errors.push('Email invalide');
        }

        if (errors.length > 0) {
            return res.status(400).json({
                success: false,
                errors: errors
            });
        }

        // Vérifier si l'email est déjà utilisé par un autre utilisateur
        const [emailCheck] = await pool.execute(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            [email, userId]
        );

        if (emailCheck.length > 0) {
            return res.status(400).json({
                success: false,
                errors: ['Cet email est déjà utilisé par un autre compte']
            });
        }

        // Préparer les champs à mettre à jour
        const updateFields = [];
        const updateValues = [];

        if (prenom !== req.user.prenom) {
            updateFields.push('prenom = ?');
            updateValues.push(prenom);
            updates.push('prenom');
        }

        if (nom !== req.user.nom) {
            updateFields.push('nom = ?');
            updateValues.push(nom);
            updates.push('nom');
        }

        if (email !== req.user.email) {
            updateFields.push('email = ?');
            updateValues.push(email);
            updates.push('email');
        }

        if (telephone && telephone !== req.user.telephone) {
            updateFields.push('telephone = ?');
            updateValues.push(telephone);
            updates.push('telephone');
        }

        if (countryCode && countryCode !== req.user.country_code) {
            updateFields.push('country_code = ?');
            updateValues.push(countryCode);
            updates.push('country_code');
        }

        // Gestion du changement de mot de passe
        let passwordChanged = false;
        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({
                    success: false,
                    errors: ['Le mot de passe actuel est requis pour changer de mot de passe']
                });
            }

            if (newPassword !== confirmPassword) {
                return res.status(400).json({
                    success: false,
                    errors: ['Les nouveaux mots de passe ne correspondent pas']
                });
            }

            if (newPassword.length < 8) {
                return res.status(400).json({
                    success: false,
                    errors: ['Le mot de passe doit contenir au moins 8 caractères']
                });
            }

            // Vérifier le mot de passe actuel
            const [userRows] = await pool.execute(
                'SELECT password FROM users WHERE id = ?',
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    errors: ['Utilisateur non trouvé']
                });
            }

            const passwordMatch = await bcrypt.compare(currentPassword, userRows[0].password);

            if (!passwordMatch) {
                return res.status(400).json({
                    success: false,
                    errors: ['Mot de passe actuel incorrect']
                });
            }

            // Hasher le nouveau mot de passe
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            updateFields.push('password = ?');
            updateValues.push(hashedPassword);
            passwordChanged = true;
        }

        // Si des champs à mettre à jour
        if (updateFields.length > 0) {
            updateValues.push(userId);

            // Vérifier si la colonne updated_at existe
            let query;
            try {
                // Tenter de construire la requête avec updated_at
                query = `
                    UPDATE users 
                    SET ${updateFields.join(', ')}, updated_at = NOW()
                    WHERE id = ?
                `;
                await pool.execute(query, updateValues);
            } catch (error) {
                if (error.code === 'ER_BAD_FIELD_ERROR' && error.sqlMessage.includes('updated_at')) {
                    // Si la colonne n'existe pas, utiliser une requête sans updated_at
                    console.log('⚠️ Colonne updated_at non trouvée, utilisation de requête alternative');
                    query = `
                        UPDATE users 
                        SET ${updateFields.join(', ')}
                        WHERE id = ?
                    `;
                    await pool.execute(query, updateValues);
                } else {
                    throw error; // Relancer les autres erreurs
                }
            }

            console.log(`✅ Profil mis à jour pour l'utilisateur ID: ${userId}`);

            // Mettre à jour la session si le nom a changé
            if (updates.includes('prenom') || updates.includes('nom')) {
                req.session.userName = `${prenom} ${nom}`;
                req.user.prenom = prenom;
                req.user.nom = nom;
                req.user.email = email;
            }

            // Si l'email a changé, mettre à jour la session
            if (updates.includes('email')) {
                req.session.userEmail = email;
            }

            res.json({
                success: true,
                message: passwordChanged ?
                    'Profil et mot de passe mis à jour avec succès' :
                    'Profil mis à jour avec succès',
                updates: updates,
                passwordChanged: passwordChanged
            });

        } else {
            res.json({
                success: false,
                message: 'Aucune modification détectée',
                updates: []
            });
        }

    } catch (error) {
        console.error('❌ Erreur lors de la mise à jour du profil:', error);

        // Gérer spécifiquement l'erreur de colonne manquante
        if (error.code === 'ER_BAD_FIELD_ERROR' && error.sqlMessage.includes('updated_at')) {
            res.status(500).json({
                success: false,
                errors: ['Erreur de base de données : colonne updated_at manquante. Veuillez contacter l\'administrateur.'],
                technical: 'La colonne updated_at n\'existe pas dans la table users'
            });
        } else {
            res.status(500).json({
                success: false,
                errors: ['Erreur serveur lors de la mise à jour']
            });
        }
    }
});
// API: Obtenir la liste des abonnés de l'utilisateur connecté
app.get('/api/network/user/followers', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [followers] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email,
                   f.status, f.created_at as followed_at, f.id as follow_id
            FROM followers f
            JOIN users u ON f.follower_id = u.id
            WHERE f.following_id = ? AND f.status = 'accepted'
            ORDER BY u.prenom, u.nom
        `, [userId]);

        res.json({
            success: true,
            followers: followers || []
        });

    } catch (error) {
        console.error('Erreur récupération followers:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur',
            followers: []
        });
    }
});
// API: Obtenir la liste des abonnements de l'utilisateur connecté
app.get('/api/network/user/following', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [following] = await pool.execute(`
            SELECT u.id, u.prenom, u.nom, u.email,
                   f.status, f.created_at as followed_at, f.id as follow_id
            FROM followers f
            JOIN users u ON f.following_id = u.id
            WHERE f.follower_id = ? AND f.status = 'accepted'
            ORDER BY u.prenom, u.nom
        `, [userId]);

        res.json({
            success: true,
            following: following || []
        });

    } catch (error) {
        console.error('Erreur récupération following:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur',
            following: []
        });
    }
});
// ==================== ROUTES ROOMS COMPLÈTES ====================

// Middleware pour vérifier si l'utilisateur est propriétaire OU admin de la room
const isRoomOwner = async (req, res, next) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier si propriétaire OU admin
        const [roomRows] = await pool.execute(
            `SELECT r.owner_id, rm.role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const isOwner = roomRows[0].owner_id === userId;
        const isAdmin = roomRows[0].role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé. Vous devez être propriétaire ou administrateur de cette room.'
            });
        }

        // Ajouter l'info sur le rôle pour les routes suivantes
        req.isRoomOwner = isOwner;
        req.isRoomAdmin = isAdmin;

        next();
    } catch (error) {
        console.error('Erreur vérification propriétaire/admin:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
};

// Middleware pour vérifier si l'utilisateur est membre de la room
const isRoomMember = async (req, res, next) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier aussi si c'est le propriétaire
        const [roomRows] = await pool.execute(
            'SELECT owner_id FROM rooms WHERE id = ?',
            [roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        // Le propriétaire est automatiquement membre
        if (roomRows[0].owner_id === userId) {
            return next();
        }

        const [memberRows] = await pool.execute(
            'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, userId]
        );

        if (memberRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous devez être membre de cette room'
            });
        }

        next();
    } catch (error) {
        console.error('Erreur vérification membre:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
};

// Route pour créer une room
app.post('/api/rooms', requireAuth, async (req, res) => {
    try {
        const { name, description, room_type, max_members } = req.body;
        const userId = req.user.id;

        if (!name || name.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Le nom de la room est requis'
            });
        }

        // Vérifier la limite de membres
        const maxMembers = Math.min(Math.max(parseInt(max_members) || 100, 2), 1000);

        const [result] = await pool.execute(
            `INSERT INTO rooms 
            (name, description, room_type, owner_id, max_members) 
            VALUES (?, ?, ?, ?, ?)`,
            [name.trim(), description || null, room_type || 'public', userId, maxMembers]
        );

        const roomId = result.insertId;

        // Ajouter le créateur comme admin
        await pool.execute(
            `INSERT INTO room_members (room_id, user_id, role) 
            VALUES (?, ?, 'admin')`,
            [roomId, userId]
        );

        // Mettre à jour le compteur de membres
        await pool.execute(
            'UPDATE rooms SET current_members = 1 WHERE id = ?',
            [roomId]
        );

        // Si c'est une room privée, générer un code d'accès
        if (room_type === 'private') {
            const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
            await pool.execute(
                `INSERT INTO room_access_codes 
                (room_id, code, created_by) 
                VALUES (?, ?, ?)`,
                [roomId, accessCode, userId]
            );
        }

        console.log(`✅ Room créée: "${name}" (ID: ${roomId}) par: ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: 'Room créée avec succès',
            room_id: roomId
        });

    } catch (error) {
        console.error('❌ Erreur création room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la création'
        });
    }
});

// Route pour récupérer les rooms
app.get('/api/rooms', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const { filter = 'all', page = 1, limit = 9 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereClause = 'WHERE r.status != "archived"';
        let params = [];

        switch (filter) {
            case 'my':
                whereClause += ' AND (r.owner_id = ? OR EXISTS (SELECT 1 FROM room_members rm WHERE rm.room_id = r.id AND rm.user_id = ?))';
                params.push(userId, userId);
                break;
            case 'public':
                whereClause += ' AND r.room_type = "public"';
                break;
            case 'private':
                whereClause += ' AND r.room_type = "private"';
                break;
            case 'active':
                whereClause += ' AND r.status = "active"';
                break;
            case 'closed':
                whereClause += ' AND r.status = "closed"';
                break;
        }

        // Compter le total
        const [countRows] = await pool.execute(
            `SELECT COUNT(*) as total FROM rooms r ${whereClause}`,
            params
        );

        const total = countRows[0].total;
        const totalPages = Math.ceil(total / parseInt(limit));

        // Récupérer les rooms
        let query = `
            SELECT r.*, 
                    CONCAT(u.prenom, ' ', u.nom) as owner_name,
                    u.email as owner_email,
                    EXISTS(SELECT 1 FROM room_members rm WHERE rm.room_id = r.id AND rm.user_id = ?) as is_member,
                    (r.owner_id = ?) as is_owner
             FROM rooms r
             JOIN users u ON r.owner_id = u.id
             ${whereClause}
             ORDER BY r.created_at DESC
             LIMIT ? OFFSET ?
        `;

        // Construire les paramètres de la requête
        const queryParams = [...params, userId, userId, parseInt(limit), parseInt(offset)];

        const [rooms] = await pool.execute(query, queryParams);

        res.json({
            success: true,
            rooms: rooms,
            total: total,
            totalPages: totalPages,
            currentPage: parseInt(page)
        });

    } catch (error) {
        console.error('❌ Erreur récupération rooms:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour rejoindre une room
app.post('/api/rooms/:id/join', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { access_code } = req.body;

        // Vérifier si la room existe
        const [roomRows] = await pool.execute(
            `SELECT r.*, 
                    r.current_members as member_count
             FROM rooms r 
             WHERE r.id = ? AND r.status = 'active'`,
            [roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée ou inactive'
            });
        }

        const room = roomRows[0];

        // Vérifier si déjà membre
        const [memberRows] = await pool.execute(
            'SELECT id, role FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, userId]
        );

        if (memberRows.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Vous êtes déjà membre de cette room'
            });
        }

        // Vérifier la capacité
        if (room.member_count >= room.max_members) {
            return res.status(400).json({
                success: false,
                message: 'La room est pleine'
            });
        }

        // Si room privée, vérifier le code
        if (room.room_type === 'private') {
            if (!access_code) {
                return res.status(400).json({
                    success: false,
                    message: 'Code d\'accès requis pour les rooms privées'
                });
            }

            const [codeRows] = await pool.execute(
                `SELECT * FROM room_access_codes 
                 WHERE room_id = ? AND code = ? AND is_active = 1`,
                [roomId, access_code.toUpperCase()]
            );

            if (codeRows.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Code d\'accès invalide'
                });
            }

            // Incrémenter le compteur d'utilisation
            await pool.execute(
                'UPDATE room_access_codes SET use_count = use_count + 1 WHERE id = ?',
                [codeRows[0].id]
            );
        }

        // Ajouter le membre
        await pool.execute(
            'INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, "member")',
            [roomId, userId]
        );

        // Mettre à jour le compteur
        await pool.execute(
            'UPDATE rooms SET current_members = current_members + 1 WHERE id = ?',
            [roomId]
        );

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, userId, `${req.user.prenom} ${req.user.nom} a rejoint la room`]
        );

        console.log(`✅ Utilisateur ${userId} a rejoint la room ${roomId}`);

        res.json({
            success: true,
            message: 'Vous avez rejoint la room avec succès',
            room_id: roomId
        });

    } catch (error) {
        console.error('❌ Erreur rejoindre room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour quitter une room
app.post('/api/rooms/:id/leave', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier si c'est le propriétaire
        const [ownerRows] = await pool.execute(
            'SELECT owner_id FROM rooms WHERE id = ?',
            [roomId]
        );

        if (ownerRows.length > 0 && ownerRows[0].owner_id === userId) {
            return res.status(400).json({
                success: false,
                message: 'Le propriétaire ne peut pas quitter la room. Transférez la propriété d\'abord.'
            });
        }

        // Supprimer le membre
        const [result] = await pool.execute(
            'DELETE FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, userId]
        );

        if (result.affectedRows > 0) {
            // Mettre à jour le compteur
            await pool.execute(
                'UPDATE rooms SET current_members = GREATEST(current_members - 1, 0) WHERE id = ?',
                [roomId]
            );

            // Créer un message système
            await pool.execute(
                `INSERT INTO room_messages 
                (room_id, user_id, message, message_type) 
                VALUES (?, ?, ?, 'system')`,
                [roomId, userId, `${req.user.prenom} ${req.user.nom} a quitté la room`]
            );

            console.log(`✅ Utilisateur ${userId} a quitté la room ${roomId}`);

            res.json({
                success: true,
                message: 'Vous avez quitté la room'
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

    } catch (error) {
        console.error('❌ Erreur quitter room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour les détails d'une room
app.get('/api/rooms/:id', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        const [roomRows] = await pool.execute(
            `SELECT r.*, 
                    CONCAT(u.prenom, ' ', u.nom) as owner_name,
                    u.email as owner_email,
                    EXISTS(SELECT 1 FROM room_members rm WHERE rm.room_id = r.id AND rm.user_id = ?) as is_member,
                    (r.owner_id = ?) as is_owner,
                    COALESCE(rm.role, 'owner') as user_role
             FROM rooms r
             JOIN users u ON r.owner_id = u.id
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, userId, userId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = roomRows[0];

        // Récupérer les membres
        const [members] = await pool.execute(
            `SELECT rm.*, 
                    CONCAT(u.prenom, ' ', u.nom) as user_name,
                    u.email as user_email
             FROM room_members rm
             JOIN users u ON rm.user_id = u.id
             WHERE rm.room_id = ?
             ORDER BY 
                CASE WHEN rm.user_id = ? THEN 0 ELSE 1 END,
                CASE rm.role 
                    WHEN 'admin' THEN 0 
                    ELSE 1 
                END,
                rm.joined_at ASC`,
            [roomId, room.owner_id]
        );

        // Ajouter le propriétaire à la liste des membres s'il n'y est pas déjà
        const isOwnerInMembers = members.some(m => m.user_id === room.owner_id);
        if (!isOwnerInMembers) {
            const [ownerRow] = await pool.execute(
                `SELECT ?, 
                        CONCAT(u.prenom, ' ', u.nom) as user_name,
                        u.email as user_email,
                        'admin' as role,
                        r.created_at as joined_at
                 FROM rooms r
                 JOIN users u ON r.owner_id = u.id
                 WHERE r.id = ?`,
                [room.owner_id, roomId]
            );
            if (ownerRow.length > 0) {
                members.unshift({
                    user_id: room.owner_id,
                    user_name: ownerRow[0].user_name,
                    user_email: ownerRow[0].user_email,
                    role: 'admin',
                    joined_at: ownerRow[0].joined_at
                });
            }
        }

        // Récupérer les messages récents
        const [messages] = await pool.execute(
            `SELECT m.*, 
                    CONCAT(u.prenom, ' ', u.nom) as user_name
             FROM room_messages m
             JOIN users u ON m.user_id = u.id
             WHERE m.room_id = ?
             ORDER BY m.created_at DESC
             LIMIT 50`,
            [roomId]
        );

        // Récupérer les sondages actifs
        const [polls] = await pool.execute(
            `SELECT p.*, 
                    CONCAT(u.prenom, ' ', u.nom) as creator_name,
                    (SELECT COUNT(*) FROM room_poll_votes WHERE poll_id = p.id) as total_votes,
                    EXISTS(SELECT 1 FROM room_poll_votes WHERE poll_id = p.id AND user_id = ?) as has_voted
             FROM room_polls p
             JOIN users u ON p.created_by = u.id
             WHERE p.room_id = ? AND p.status = 'active'
             ORDER BY p.created_at DESC
             LIMIT 5`,
            [userId, roomId]
        );

        // Récupérer le code d'accès si room privée
        let accessCode = null;
        if (room.room_type === 'private' && room.is_owner) {
            const [codeRows] = await pool.execute(
                'SELECT code FROM room_access_codes WHERE room_id = ? AND is_active = 1 LIMIT 1',
                [roomId]
            );
            if (codeRows.length > 0) {
                accessCode = codeRows[0].code;
            }
        }

        res.json({
            success: true,
            room: room,
            members: members,
            messages: messages.reverse(), // Plus ancien au plus récent
            polls: polls,
            access_code: accessCode
        });

    } catch (error) {
        console.error('❌ Erreur détails room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour créer un sondage dans une room
app.post('/api/rooms/:id/polls', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { title, question, poll_type = 'single', options, closes_at, is_anonymous = false } = req.body;

        if (!title || !question || !options || !Array.isArray(options) || options.length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Titre, question et au moins 2 options sont requis'
            });
        }

        // Vérifier la room
        const [roomRows] = await pool.execute(
            'SELECT id, status FROM rooms WHERE id = ? AND status = "active"',
            [roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room inactive ou non trouvée'
            });
        }

        // Calculer la date de fermeture
        let closesAt = null;
        if (closes_at) {
            closesAt = new Date(closes_at);
        } else {
            closesAt = new Date();
            closesAt.setHours(closesAt.getHours() + 24); // 24h par défaut
        }

        // Créer le sondage
        const [pollResult] = await pool.execute(
            `INSERT INTO room_polls 
            (room_id, title, question, created_by, poll_type, closes_at, is_anonymous) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [roomId, title, question, userId, poll_type, closesAt, is_anonymous]
        );

        const pollId = pollResult.insertId;

        // Ajouter les options
        for (let i = 0; i < options.length; i++) {
            await pool.execute(
                'INSERT INTO room_poll_options (poll_id, option_text, option_order) VALUES (?, ?, ?)',
                [pollId, options[i], i]
            );
        }

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type, related_poll_id) 
            VALUES (?, ?, ?, 'poll_created', ?)`,
            [roomId, userId, `${req.user.prenom} ${req.user.nom} a créé un sondage: "${title}"`, pollId]
        );

        console.log(`✅ Sondage créé dans la room ${roomId}: "${title}"`);

        res.status(201).json({
            success: true,
            message: 'Sondage créé avec succès',
            poll_id: pollId
        });

    } catch (error) {
        console.error('❌ Erreur création sondage room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour voter dans un sondage de room (CORRIGÉE)
app.post('/api/rooms/polls/:pollId/vote', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;
        const { option_ids } = req.body; // Changé de option_id à option_ids

        if (!option_ids || !Array.isArray(option_ids) || option_ids.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Options requises'
            });
        }

        // Récupérer le sondage
        const [pollRows] = await pool.execute(`
            SELECT p.*, r.id as room_id 
             FROM room_polls p
             JOIN rooms r ON p.room_id = r.id
             WHERE p.id = ? AND p.status = 'active' 
             AND (p.closes_at IS NULL OR p.closes_at > NOW())`,
            [pollId]
        );

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé ou terminé'
            });
        }

        const poll = pollRows[0];

        // Vérifier l'appartenance à la room
        const [memberRows] = await pool.execute(
            'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
            [poll.room_id, userId]
        );

        if (memberRows.length === 0) {
            // Vérifier si c'est le propriétaire
            const [ownerRows] = await pool.execute(
                'SELECT owner_id FROM rooms WHERE id = ?',
                [poll.room_id]
            );

            if (ownerRows.length === 0 || ownerRows[0].owner_id !== userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Vous devez être membre de la room'
                });
            }
        }

        // Pour un vote unique, vérifier si déjà voté
        if (poll.poll_type === 'single') {
            const [voteRows] = await pool.execute(
                'SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [pollId, userId]
            );

            if (voteRows.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Vous avez déjà voté pour ce sondage'
                });
            }
        }

        // Pour un vote multiple, vérifier les options sélectionnées
        const validOptionIds = [];
        for (const optionId of option_ids) {
            const [optionRows] = await pool.execute(
                'SELECT id FROM room_poll_options WHERE id = ? AND poll_id = ?',
                [optionId, pollId]
            );

            if (optionRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: `Option invalide: ${optionId}`
                });
            }
            validOptionIds.push(optionId);
        }

        // Enregistrer les votes
        for (const optionId of validOptionIds) {
            await pool.execute(
                'INSERT INTO room_poll_votes (poll_id, user_id, option_id) VALUES (?, ?, ?)',
                [pollId, userId, optionId]
            );

            // Mettre à jour le compteur de votes
            await pool.execute(
                'UPDATE room_poll_options SET vote_count = COALESCE(vote_count, 0) + 1 WHERE id = ?',
                [optionId]
            );
        }

        // Créer un message système (si non anonyme)
        if (!poll.is_anonymous) {
            const [optionTextRows] = await pool.execute(
                'SELECT option_text FROM room_poll_options WHERE id = ?',
                [validOptionIds[0]]
            );

            if (optionTextRows.length > 0) {
                const optionText = validOptionIds.length > 1
                    ? `${validOptionIds.length} options`
                    : `"${optionTextRows[0].option_text}"`;

                await pool.execute(
                    `INSERT INTO room_messages 
                    (room_id, user_id, message, message_type, related_poll_id) 
                    VALUES (?, ?, ?, 'poll_vote', ?)`,
                    [poll.room_id, userId,
                    `${req.user.prenom} ${req.user.nom} a voté pour ${optionText}`,
                        pollId]
                );
            }
        }

        // Récupérer les résultats mis à jour pour Socket.IO
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as vote_count
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [pollId]);

        const total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.vote_count) || 0), 0);

        // Émettre l'événement Socket.IO
        io.to(`poll_${pollId}`).emit('vote-update', {
            poll_id: pollId,
            results: {
                options: options,
                total_votes: total_votes
            }
        });

        console.log(`✅ Vote enregistré pour le sondage ${pollId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès',
            results: {
                options: options,
                total_votes: total_votes
            }
        });

    } catch (error) {
        console.error('❌ Erreur vote room:', error);

        // Gérer les erreurs de contrainte unique
        if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté pour cette option'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour les messages d'une room
app.get('/api/rooms/:id/messages', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const { before, limit = 50 } = req.query;

        let whereClause = 'WHERE m.room_id = ?';
        let params = [roomId];

        if (before) {
            whereClause += ' AND m.created_at < ?';
            params.push(new Date(before));
        }

        const [messages] = await pool.execute(
            `SELECT m.*, 
                    CONCAT(u.prenom, ' ', u.nom) as user_name,
                    p.title as poll_title
             FROM room_messages m
             JOIN users u ON m.user_id = u.id
             LEFT JOIN room_polls p ON m.related_poll_id = p.id
             ${whereClause}
             ORDER BY m.created_at DESC
             LIMIT ?`,
            [...params, parseInt(limit)]
        );

        res.json({
            success: true,
            messages: messages.reverse() // Plus ancien au plus récent
        });

    } catch (error) {
        console.error('❌ Erreur messages room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour envoyer un message
app.post('/api/rooms/:id/messages', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { message } = req.body;

        if (!message || message.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Message requis'
            });
        }

        // Vérifier la room
        const [roomRows] = await pool.execute(
            'SELECT status FROM rooms WHERE id = ?',
            [roomId]
        );

        if (roomRows.length === 0 || roomRows[0].status !== 'active') {
            return res.status(400).json({
                success: false,
                message: 'Room inactive'
            });
        }

        const [result] = await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'chat')`,
            [roomId, userId, message.trim()]
        );

        // Récupérer le message créé
        const [messageRows] = await pool.execute(
            `SELECT m.*, 
                    CONCAT(u.prenom, ' ', u.nom) as user_name
             FROM room_messages m
             JOIN users u ON m.user_id = u.id
             WHERE m.id = ?`,
            [result.insertId]
        );

        res.json({
            success: true,
            message: messageRows[0]
        });

    } catch (error) {
        console.error('❌ Erreur envoi message:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour mettre à jour une room
app.put('/api/rooms/:id', requireAuth, isRoomOwner, async (req, res) => {
    try {
        const roomId = req.params.id;
        const { name, description, status, max_members, room_type } = req.body;

        // Construire la requête dynamiquement
        const updates = [];
        const params = [];

        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name.trim());
        }

        if (description !== undefined) {
            updates.push('description = ?');
            params.push(description || null);
        }

        if (status !== undefined && ['active', 'closed', 'archived'].includes(status)) {
            updates.push('status = ?');
            params.push(status);
        }

        if (max_members !== undefined) {
            const maxMembers = Math.min(Math.max(parseInt(max_members), 2), 1000);
            updates.push('max_members = ?');
            params.push(maxMembers);
        }

        if (room_type !== undefined && ['public', 'private'].includes(room_type)) {
            updates.push('room_type = ?');
            params.push(room_type);

            // Si changement de public à privé, générer un code d'accès
            const [currentRoom] = await pool.execute(
                'SELECT room_type FROM rooms WHERE id = ?',
                [roomId]
            );

            if (currentRoom.length > 0 && currentRoom[0].room_type === 'public' && room_type === 'private') {
                const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
                await pool.execute(
                    `INSERT INTO room_access_codes 
                    (room_id, code, created_by) 
                    VALUES (?, ?, ?)`,
                    [roomId, accessCode, req.user.id]
                );
            }
        }

        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Aucune modification'
            });
        }

        params.push(roomId);

        await pool.execute(
            `UPDATE rooms SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        // Créer un message système pour les changements importants
        if (status) {
            await pool.execute(
                `INSERT INTO room_messages 
                (room_id, user_id, message, message_type) 
                VALUES (?, ?, ?, 'system')`,
                [roomId, req.user.id,
                    `La room a été ${status === 'active' ? 'réactivée' : status === 'closed' ? 'fermée' : 'archivée'} par ${req.user.prenom} ${req.user.nom}`]
            );
        }

        res.json({
            success: true,
            message: 'Room mise à jour avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur mise à jour room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour récupérer le code d'accès actuel d'une room
app.get('/api/rooms/:id/access-code/current', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier que l'utilisateur est propriétaire ou admin
        const [roomRows] = await pool.execute(
            `SELECT r.*,  COALESCE(rm.role, 'owner') as user_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [userId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = roomRows[0];

        // Vérifier que c'est le propriétaire ou un admin
        if (room.owner_id !== userId && room.user_role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        // Si la room n'est pas privée, pas de code
        if (room.room_type !== 'private') {
            return res.json({
                success: true,
                message: 'Cette room est publique',
                code: null
            });
        }

        // Récupérer le code d'accès actif
        const [codeRows] = await pool.execute(
            'SELECT code, use_count, created_at FROM room_access_codes WHERE room_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1',
            [roomId]
        );

        if (codeRows.length === 0) {
            return res.json({
                success: false,
                message: 'Aucun code d\'accès actif trouvé',
                code: null
            });
        }

        res.json({
            success: true,
            code: codeRows[0].code,
            use_count: codeRows[0].use_count || 0,
            created_at: codeRows[0].created_at
        });

    } catch (error) {
        console.error('❌ Erreur récupération code d\'accès:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES POUR LES PAGES ====================

// Page de détails de room (pour utilisateurs normaux)
app.get('/room/:id/details', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier si l'utilisateur est membre
        const [memberRows] = await pool.execute(
            `SELECT r.*, rm.role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, roomId]
        );

        if (memberRows.length === 0) {
            // Si pas membre, vérifier si la room est publique
            const [publicRoom] = await pool.execute(
                'SELECT * FROM rooms WHERE id = ? AND room_type = "public" AND status = "active"',
                [roomId]
            );

            if (publicRoom.length === 0) {
                return res.redirect('/rooms?error=not_member');
            }

            return res.render('dashboard/room-details', {
                title: `Détails: ${publicRoom[0].name}`,
                page: 'rooms',
                user: req.user,
                room: publicRoom[0],
                isMember: false,
                user_role: 'guest'
            });
        }

        const room = memberRows[0];
        const userRole = room.owner_id === userId ? 'owner' : (room.role || 'member');

        res.render('dashboard/room-details', {
            title: `Détails: ${room.name}`,
            page: 'rooms',
            user: req.user,
            room: room,
            isMember: true,
            user_role: userRole
        });

    } catch (error) {
        console.error('❌ Erreur page détails:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user
        });
    }
});

// Page de gestion de room (admin seulement)
app.get('/room/:id/manage', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier d'abord si l'utilisateur est membre ou propriétaire de la room
        const [memberCheck] = await pool.execute(
            `SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?
             UNION
             SELECT 1 FROM rooms WHERE id = ? AND owner_id = ?`,
            [roomId, userId, roomId, userId]
        );

        if (memberCheck.length === 0) {
            return res.status(403).render('error', {
                title: 'Accès Refusé',
                message: 'Vous devez être membre de cette room pour y accéder.',
                user: req.user,
                page: 'error',
                status: 403
            });
        }

        // Vérifier que l'utilisateur est propriétaire ou admin
        const [roomRows] = await pool.execute(
            `SELECT r.*, 
                    CONCAT(u.prenom, ' ', u.nom) as owner_name,
                    COALESCE(rm.role, 'owner') as user_role
             FROM rooms r
             JOIN users u ON r.owner_id = u.id
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).render('error', {
                title: 'Erreur',
                message: 'Room non trouvée',
                user: req.user,
                page: 'error',
                status: 404
            });
        }

        const room = roomRows[0];

        // Vérifier les permissions (admin ou owner seulement)
        if (room.user_role !== 'owner' && room.user_role !== 'admin') {
            return res.status(403).render('error', {
                title: 'Accès Refusé',
                message: 'Seuls les administrateurs peuvent accéder à cette page.',
                user: req.user,
                page: 'error',
                status: 403
            });
        }

        res.render('dashboard/room-manage', {
            title: `Gérer: ${room.name}`,
            page: 'rooms',
            user: req.user,
            room: room
        });

    } catch (error) {
        console.error('❌ Erreur page gestion:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user,
            page: 'error',
            status: 500
        });
    }
});

// Page de chat (room principale)
app.get('/room/:id', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier l'appartenance
        const [memberRows] = await pool.execute(
            `SELECT r.*, COALESCE(rm.role, 'owner') as user_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, roomId]
        );

        if (memberRows.length === 0) {
            return res.redirect(`/room/${roomId}/details`);
        }

        const room = memberRows[0];

        res.render('dashboard/room-chat', {
            title: `Chat: ${room.name}`,
            page: 'rooms',
            user: req.user,
            room: {
                id: roomId,
                name: room.name,
                description: room.description,
                type: room.room_type,
                status: room.status,
                owner_id: room.owner_id,
                role: room.user_role
            }
        });

    } catch (error) {
        console.error('❌ Erreur page room:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user
        });
    }
});

// Page des sondages d'une room
app.get('/room/:id/polls', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier que l'utilisateur est membre
        const [memberRows] = await pool.execute(
            `SELECT r.*, COALESCE(rm.role, 'owner') as user_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND r.status != 'archived'`,
            [userId, roomId]
        );

        if (memberRows.length === 0) {
            return res.redirect(`/room/${roomId}/details`);
        }

        const room = memberRows[0];
        const isAdmin = room.user_role === 'owner' || room.user_role === 'admin';

        res.render('dashboard/room-polls', {
            title: `Sondages: ${room.name}`,
            page: 'rooms',
            user: req.user,
            room: {
                id: roomId,
                name: room.name,
                role: room.user_role
            },
            isAdmin: isAdmin
        });

    } catch (error) {
        console.error('❌ Erreur page sondages:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user
        });
    }
});

// Page de vue utilisateur d'une room (détails pour utilisateurs)
app.get('/room/:id/user-view', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Récupérer les informations de la room
        const [roomRows] = await pool.execute(
            'SELECT * FROM rooms WHERE id = ? AND status != \'archived\'',
            [roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).render('error', {
                title: 'Erreur',
                message: 'Room non trouvée',
                user: req.user,
                page: 'error',
                status: 404
            });
        }

        const room = roomRows[0];

        // Vérifier si l'utilisateur est membre ou propriétaire
        const [memberCheck] = await pool.execute(
            `SELECT rm.role FROM room_members rm WHERE rm.room_id = ? AND rm.user_id = ?
             UNION
             SELECT 'owner' as role FROM rooms WHERE id = ? AND owner_id = ?`,
            [roomId, userId, roomId, userId]
        );

        const isMember = memberCheck.length > 0;
        const userRole = isMember ? memberCheck[0].role : null;

        // Si la room est privée et l'utilisateur n'est pas membre, bloquer l'accès
        if (room.room_type === 'private' && !isMember) {
            return res.status(403).render('error', {
                title: 'Accès Refusé',
                message: 'Erreur de chargement : Accès refusé. Cette room est privée.',
                user: req.user,
                page: 'error',
                status: 403
            });
        }

        // Si l'utilisateur n'est pas membre d'une room publique, permettre la vue limitée
        if (!isMember) {
            // Récupérer les informations du propriétaire
            const [ownerInfo] = await pool.execute(
                'SELECT id, prenom, nom, email FROM users WHERE id = ?',
                [room.owner_id]
            );

            return res.render('dashboard/room-user-details', {
                title: `${room.name} - Détails`,
                page: 'rooms',
                user: req.user,
                room: {
                    id: roomId,
                    name: room.name,
                    description: room.description,
                    room_type: room.room_type,
                    status: room.status,
                    max_members: room.max_members,
                    current_members: 0,
                    created_at: room.created_at,
                    user_role: 'guest',
                    owner_id: room.owner_id
                },
                owner: ownerInfo.length > 0 ? ownerInfo[0] : null,
                isMember: false
            });
        }

        // L'utilisateur est membre, afficher les détails complets
        // Récupérer le nombre de membres
        const [membersCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM room_members WHERE room_id = ?',
            [roomId]
        );

        // Récupérer les informations du propriétaire
        const [ownerInfo] = await pool.execute(
            'SELECT id, prenom, nom, email FROM users WHERE id = ?',
            [room.owner_id]
        );

        res.render('dashboard/room-user-details', {
            title: `${room.name} - Détails`,
            page: 'rooms',
            user: req.user,
            room: {
                id: roomId,
                name: room.name,
                description: room.description,
                room_type: room.room_type,
                status: room.status,
                max_members: room.max_members,
                current_members: membersCount[0].count + 1, // +1 pour le propriétaire
                created_at: room.created_at,
                user_role: userRole || 'member',
                owner_id: room.owner_id
            },
            owner: ownerInfo.length > 0 ? ownerInfo[0] : null,
            isMember: true
        });

    } catch (error) {
        console.error('❌ Erreur page user-view:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user,
            page: 'error',
            status: 500
        });
    }
});

// Page des rooms (liste principale)
app.get('/rooms', requireAuth, async (req, res) => {
    try {
        // Récupérer les catégories pour les filtres
        const [categories] = await pool.execute(
            'SELECT * FROM poll_categories ORDER BY name'
        );

        res.render('dashboard/rooms', {
            title: 'Rooms',
            page: 'rooms',
            user: req.user,
            categories: categories
        });

    } catch (error) {
        console.error('❌ Erreur page rooms:', error);
        res.status(500).render('error', {
            title: 'Erreur',
            message: 'Erreur serveur',
            user: req.user
        });
    }
});

// Route pour récupérer le propriétaire d'une room
app.get('/api/rooms/:id/owner', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;

        const [ownerRows] = await pool.execute(
            `SELECT u.id, u.prenom, u.nom, u.email 
             FROM rooms r
             JOIN users u ON r.owner_id = u.id
             WHERE r.id = ?`,
            [roomId]
        );

        if (ownerRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        res.json({
            success: true,
            owner: {
                id: ownerRows[0].id,
                name: `${ownerRows[0].prenom} ${ownerRows[0].nom}`,
                email: ownerRows[0].email
            }
        });

    } catch (error) {
        console.error('❌ Erreur récupération propriétaire:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour les détails des membres d'une room
app.get('/api/rooms/:id/members', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier si l'utilisateur a accès à la room
        const [accessRows] = await pool.execute(
            `SELECT r.room_type 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)`,
            [userId, roomId, userId]
        );

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        const [members] = await pool.execute(`
            SELECT rm.*, 
                   CONCAT(u.prenom, ' ', u.nom) as user_name,
                   u.email,
                   (SELECT 1 FROM room_messages WHERE room_id = ? AND user_id = rm.user_id ORDER BY created_at DESC LIMIT 1) as is_online
            FROM room_members rm
            JOIN users u ON rm.user_id = u.id
            WHERE rm.room_id = ?
            ORDER BY rm.role DESC, rm.joined_at ASC
        `, [roomId, roomId]);

        // Ajouter le propriétaire s'il n'est pas dans la liste
        const [ownerRows] = await pool.execute(
            'SELECT owner_id FROM rooms WHERE id = ?',
            [roomId]
        );

        if (ownerRows.length > 0) {
            const ownerId = ownerRows[0].owner_id;
            const isOwnerInMembers = members.some(m => m.user_id === ownerId);

            if (!isOwnerInMembers) {
                const [ownerData] = await pool.execute(`
                    SELECT r.owner_id as user_id, 
                            CONCAT(u.prenom, ' ', u.nom) as user_name,
                            u.email,
                            'admin' as role,
                            r.created_at as joined_at
                     FROM rooms r
                     JOIN users u ON r.owner_id = u.id
                     WHERE r.id = ?`,
                    [roomId]
                );
                if (ownerData.length > 0) {
                    members.unshift(ownerData[0]);
                }
            }
        }

        // Marquer comme en ligne si activité récente (dans les 5 dernières minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        members.forEach(member => {
            member.is_online = member.is_online ?
                new Date(member.is_online) > fiveMinutesAgo : false;
        });

        res.json({
            success: true,
            members: members
        });

    } catch (error) {
        console.error('❌ Erreur récupération membres:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== WEBSOCKET POUR LES ROOMS ====================

// Configuration WebSocket pour les rooms
const roomWebSockets = new Map();

function setupRoomWebSocket(server) {
    const io = require('socket.io')(server);

    io.on('connection', (socket) => {
        console.log('✅ Nouvelle connexion WebSocket:', socket.id);

        // Rejoindre une room
        socket.on('join_room', (roomId) => {
            socket.join(`room_${roomId}`);
            console.log(`✅ Socket ${socket.id} a rejoint room_${roomId}`);

            // Stocker la room de l'utilisateur
            socket.roomId = roomId;

            // Notifier les autres membres
            socket.to(`room_${roomId}`).emit('member_online', {
                user_id: socket.userId,
                user_name: socket.userName
            });
        });

        // Quitter une room
        socket.on('leave_room', (roomId) => {
            socket.leave(`room_${roomId}`);
            console.log(`❌ Socket ${socket.id} a quitté room_${roomId}`);

            // Notifier les autres membres
            socket.to(`room_${roomId}`).emit('member_offline', {
                user_id: socket.userId
            });
        });

        // Nouveau message
        socket.on('new_message', async (data) => {
            const { room_id, message } = data;

            try {
                // Sauvegarder le message en base de données
                const [result] = await pool.execute(
                    `INSERT INTO room_messages 
                    (room_id, user_id, message, message_type) 
                    VALUES (?, ?, ?, 'chat')`,
                    [room_id, socket.userId, message]
                );

                // Récupérer le message complet
                const [messageRows] = await pool.execute(
                    `SELECT m.*, 
                            CONCAT(u.prenom, ' ', u.nom) as user_name
                     FROM room_messages m
                     JOIN users u ON m.user_id = u.id
                     WHERE m.id = ?`,
                    [result.insertId]
                );

                // Diffuser le message à tous les membres de la room
                io.to(`room_${room_id}`).emit('new_message', messageRows[0]);

            } catch (error) {
                console.error('❌ Erreur WebSocket message:', error);
            }
        });

        // En train d'écrire
        socket.on('typing', (data) => {
            const { room_id } = data;
            socket.to(`room_${room_id}`).emit('user_typing', {
                user_id: socket.userId,
                user_name: socket.userName
            });
        });

        // Arrêt d'écriture
        socket.on('stop_typing', (data) => {
            const { room_id } = data;
            socket.to(`room_${room_id}`).emit('user_stop_typing', {
                user_id: socket.userId
            });
        });

        // Nouveau sondage créé
        socket.on('poll_created', (data) => {
            const { room_id, poll } = data;
            io.to(`room_${room_id}`).emit('new_poll', poll);
        });

        // Vote dans un sondage
        socket.on('poll_vote', (data) => {
            const { room_id, poll_id, option_id } = data;
            io.to(`room_${room_id}`).emit('poll_vote_update', {
                poll_id: poll_id,
                option_id: option_id
            });
        });

        // Déconnexion
        socket.on('disconnect', () => {
            console.log('❌ Déconnexion WebSocket:', socket.id);

            if (socket.roomId) {
                // Notifier que l'utilisateur est hors ligne
                io.to(`room_${socket.roomId}`).emit('member_offline', {
                    user_id: socket.userId
                });
            }
        });
    });

    // Middleware pour authentifier les WebSockets
    io.use((socket, next) => {
        // Vous devriez valider le token JWT ici
        const token = socket.handshake.auth.token;
        if (token) {
            // Décoder le token et récupérer l'utilisateur
            // socket.userId = decoded.userId;
            // socket.userName = decoded.userName;
            next();
        } else {
            next(new Error('Authentication error'));
        }
    });
}

// ==================== TÂCHES AUTOMATIQUES ====================

// Tâche cron pour fermer les sondages expirés
setInterval(async () => {
    try {
        const [expiredPolls] = await pool.execute(`
            SELECT p.id, p.room_id, p.title
            FROM room_polls p
            WHERE p.status = 'active' 
            AND p.closes_at < NOW()
        `);

        for (const poll of expiredPolls) {
            await pool.execute(
                'UPDATE room_polls SET status = "closed" WHERE id = ?',
                [poll.id]
            );

            // Créer un message système
            await pool.execute(
                `INSERT INTO room_messages 
                (room_id, user_id, message, message_type, related_poll_id) 
                VALUES (?, 1, ?, 'system', ?)`,
                [poll.room_id, `Le sondage "${poll.title}" est maintenant terminé`, poll.id]
            );

            console.log(`🔄 Sondage expiré fermé: "${poll.title}" (ID: ${poll.id})`);
        }
    } catch (error) {
        console.error('Erreur fermeture automatique sondages:', error);
    }
}, 60000); // Vérifie toutes les minutes

// Nettoyage des messages anciens (plus de 30 jours)
setInterval(async () => {
    try {
        const [result] = await pool.execute(
            'DELETE FROM room_messages WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)'
        );

        if (result.affectedRows > 0) {
            console.log(`🧹 ${result.affectedRows} messages anciens nettoyés`);
        }
    } catch (error) {
        console.error('Erreur nettoyage messages:', error);
    }
}, 24 * 60 * 60 * 1000); // Toutes les 24 heures

// ==================== ROUTES SUPPLEMENTAIRES ====================

// Route pour les statistiques d'une room
app.get('/api/rooms/:id/stats', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier l'accès
        const [accessRows] = await pool.execute(
            `SELECT r.room_type 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)`,
            [userId, roomId, userId]
        );

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        // Statistiques des membres
        const [memberStats] = await pool.execute(
            `SELECT 
                COUNT(*) as total_members
             FROM room_members 
             WHERE room_id = ?`,
            [roomId]
        );

        // Ajouter le propriétaire
        memberStats[0].total_members += 1;

        // Statistiques des messages
        const [messageStats] = await pool.execute(
            `SELECT 
                COUNT(*) as total_messages
             FROM room_messages 
             WHERE room_id = ?`,
            [roomId]
        );

        // Statistiques des sondages
        const [pollStats] = await pool.execute(
            `SELECT 
                COUNT(*) as total_polls,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_polls
             FROM room_polls 
             WHERE room_id = ?`,
            [roomId]
        );

        // Membres en ligne (activité dans les 5 dernières minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const [onlineStats] = await pool.execute(
            `SELECT COUNT(DISTINCT user_id) as online_members
             FROM room_messages 
             WHERE room_id = ? AND created_at > ?`,
            [roomId, fiveMinutesAgo]
        );

        res.json({
            success: true,
            stats: {
                members: memberStats[0],
                messages: messageStats[0],
                polls: pollStats[0],
                online_members: onlineStats[0].online_members
            }
        });

    } catch (error) {
        console.error('❌ Erreur statistiques room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour récupérer les sondages d'une room
app.get('/api/rooms/:id/polls', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier l'accès
        const [accessRows] = await pool.execute(
            `SELECT r.room_type 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)`,
            [userId, roomId, userId]
        );

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        const [polls] = await pool.execute(`
            SELECT p.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = p.id) as total_votes,
                   EXISTS(SELECT 1 FROM room_poll_votes WHERE poll_id = p.id AND user_id = ?) as has_voted
            FROM room_polls p
            JOIN users u ON p.created_by = u.id
            WHERE p.room_id = ?
            ORDER BY p.status = 'active' DESC, p.created_at DESC
            LIMIT 10
        `, [userId, roomId]);

        res.json({
            success: true,
            polls: polls
        });

    } catch (error) {
        console.error('❌ Erreur récupération sondages:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour fermer un sondage (version simplifiée)
app.post('/api/rooms/polls/:pollId/close-simple', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;

        // Vérifier que l'utilisateur est créateur ou admin/propriétaire
        const [pollRows] = await pool.execute(`
            SELECT p.*, r.owner_id, r.id as room_id
            FROM room_polls p
            JOIN rooms r ON p.room_id = r.id
            WHERE p.id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = pollRows[0];

        if (poll.created_by !== userId && poll.owner_id !== userId) {
            // Vérifier si admin
            const [adminRows] = await pool.execute(
                'SELECT role FROM room_members WHERE room_id = ? AND user_id = ? AND role = "admin"',
                [poll.room_id, userId]
            );

            if (adminRows.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Permission refusée'
                });
            }
        }

        // Fermer le sondage
        await pool.execute(
            'UPDATE room_polls SET status = "closed" WHERE id = ?',
            [pollId]
        );

        console.log(`🔒 Sondage ${pollId} fermé`);

        res.json({
            success: true,
            message: 'Sondage fermé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur fermeture sondage simple:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES POUR LE ROOM MANAGER ====================

// 1. Route pour inviter un utilisateur à une room (propriétaire/admin seulement)
app.post('/api/rooms/:id/invite', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { user_id } = req.body;

        if (!user_id) {
            return res.status(400).json({
                success: false,
                message: 'ID utilisateur requis'
            });
        }

        // Vérifier les permissions (propriétaire ou admin seulement)
        const [permissionRows] = await pool.execute(
            `SELECT rm.role, r.owner_id 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [userId, roomId]
        );

        if (permissionRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const isOwner = permissionRows[0].owner_id === userId;
        const isAdmin = permissionRows[0].role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Permission refusée. Seuls les propriétaires et administrateurs peuvent inviter.'
            });
        }

        // Vérifier si l'utilisateur existe
        const [userRows] = await pool.execute(
            'SELECT id, prenom, nom FROM users WHERE id = ?',
            [user_id]
        );

        if (userRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé'
            });
        }

        const user = userRows[0];

        // Vérifier si l'utilisateur est déjà membre
        const [memberRows] = await pool.execute(
            'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, user_id]
        );

        if (memberRows.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Cet utilisateur est déjà membre de la room'
            });
        }

        // Vérifier si c'est le propriétaire
        const [roomRows] = await pool.execute(
            'SELECT owner_id, current_members, max_members FROM rooms WHERE id = ?',
            [roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = roomRows[0];

        // Vérifier la capacité
        if (room.current_members >= room.max_members) {
            return res.status(400).json({
                success: false,
                message: 'La room a atteint sa capacité maximale'
            });
        }

        // Ajouter comme membre
        await pool.execute(
            'INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, "member")',
            [roomId, user_id]
        );

        // Mettre à jour le compteur
        await pool.execute(
            'UPDATE rooms SET current_members = current_members + 1 WHERE id = ?',
            [roomId]
        );

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, userId, `${req.user.prenom} ${req.user.nom} a invité ${user.prenom} ${user.nom} à rejoindre la room`]
        );

        console.log(`✅ Utilisateur ${user_id} invité à la room ${roomId}`);

        res.json({
            success: true,
            message: 'Utilisateur invité avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur invitation room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 2. Route pour promouvoir un membre en admin
app.post('/api/rooms/:roomId/members/:userId/promote', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const targetUserId = req.params.userId;
        const currentUserId = req.user.id;

        // Vérifier que le demandeur est propriétaire ou admin
        const [roomRows] = await pool.execute(
            `SELECT r.owner_id, rm.role as requester_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [currentUserId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const isOwner = roomRows[0].owner_id === currentUserId;
        const isAdmin = roomRows[0].requester_role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Seuls le propriétaire et les administrateurs peuvent promouvoir des membres'
            });
        }

        // Vérifier que la cible est bien membre
        const [memberRows] = await pool.execute(
            'SELECT id, role FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, targetUserId]
        );

        if (memberRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Membre non trouvé'
            });
        }

        // Vérifier le rôle actuel
        if (memberRows[0].role === 'admin') {
            return res.status(400).json({
                success: false,
                message: 'Cet utilisateur est déjà administrateur'
            });
        }

        // Promouvoir en admin
        await pool.execute(
            'UPDATE room_members SET role = "admin" WHERE room_id = ? AND user_id = ?',
            [roomId, targetUserId]
        );

        // Créer un message système
        const [targetUser] = await pool.execute(
            'SELECT prenom, nom FROM users WHERE id = ?',
            [targetUserId]
        );

        if (targetUser.length > 0) {
            await pool.execute(
                `INSERT INTO room_messages 
                (room_id, user_id, message, message_type) 
                VALUES (?, ?, ?, 'system')`,
                [roomId, currentUserId,
                    `${req.user.prenom} ${req.user.nom} a promu ${targetUser[0].prenom} ${targetUser[0].nom} au rang d'administrateur`]
            );
        }

        console.log(`✅ Utilisateur ${targetUserId} promu admin dans la room ${roomId}`);

        res.json({
            success: true,
            message: 'Membre promu administrateur avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur promotion membre:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 3. Route pour rétrograder un admin en membre
app.post('/api/rooms/:roomId/members/:userId/demote', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const targetUserId = req.params.userId;
        const currentUserId = req.user.id;

        // Vérifier que le demandeur est propriétaire ou admin
        const [roomRows] = await pool.execute(
            `SELECT r.owner_id, rm.role as requester_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [currentUserId, roomId]
        );

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const isOwner = roomRows[0].owner_id === currentUserId;
        const isAdmin = roomRows[0].requester_role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Seuls le propriétaire et les administrateurs peuvent rétrograder des administrateurs'
            });
        }

        // Vérifier que la cible est bien admin
        const [memberRows] = await pool.execute(
            'SELECT id, role FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, targetUserId]
        );

        if (memberRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Membre non trouvé'
            });
        }

        // Vérifier le rôle actuel
        if (memberRows[0].role !== 'admin') {
            return res.status(400).json({
                success: false,
                message: 'Cet utilisateur n\'est pas administrateur'
            });
        }

        // Rétrograder en membre
        await pool.execute(
            'UPDATE room_members SET role = "member" WHERE room_id = ? AND user_id = ?',
            [roomId, targetUserId]
        );

        // Créer un message système
        const [targetUser] = await pool.execute(
            'SELECT prenom, nom FROM users WHERE id = ?',
            [targetUserId]
        );

        if (targetUser.length > 0) {
            await pool.execute(
                `INSERT INTO room_messages 
                (room_id, user_id, message, message_type) 
                VALUES (?, ?, ?, 'system')`,
                [roomId, currentUserId,
                    `${req.user.prenom} ${req.user.nom} a rétrogradé ${targetUser[0].prenom} ${targetUser[0].nom} au rang de membre`]
            );
        }

        console.log(`✅ Utilisateur ${targetUserId} rétrogradé membre dans la room ${roomId}`);

        res.json({
            success: true,
            message: 'Administrateur rétrogradé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur rétrogradation membre:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 4. Route pour supprimer un membre
app.delete('/api/rooms/:roomId/members/:userId', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const targetUserId = req.params.userId;
        const currentUserId = req.user.id;

        // Vérifier les permissions
        const [permissionRows] = await pool.execute(
            `SELECT r.owner_id, rm.role as current_user_role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [currentUserId, roomId]
        );

        if (permissionRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const isOwner = permissionRows[0].owner_id === currentUserId;
        const isAdmin = permissionRows[0].current_user_role === 'admin';
        const isTargetSelf = targetUserId === currentUserId;

        // Règles de permission :
        // - Propriétaire peut supprimer n'importe qui sauf lui-même
        // - Admin peut supprimer seulement les membres (pas d'autres admins ou propriétaire)
        // - Un utilisateur peut se supprimer lui-même (quitter)

        if (isTargetSelf) {
            // C'est l'utilisateur lui-même qui veut partir
            // Vérifier que ce n'est pas le propriétaire
            if (isOwner) {
                return res.status(400).json({
                    success: false,
                    message: 'Le propriétaire ne peut pas quitter la room. Transférez la propriété d\'abord.'
                });
            }
        } else {
            // Quelqu'un d'autre
            if (!isOwner && !isAdmin) {
                return res.status(403).json({
                    success: false,
                    message: 'Permission refusée'
                });
            }

            // Vérifier le rôle de la cible
            if (targetUserId == permissionRows[0].owner_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Vous ne pouvez pas supprimer le propriétaire'
                });
            }

            // Admin ne peut pas supprimer d'autres admins (seul le propriétaire peut)
            if (isAdmin && !isOwner) {
                const [targetRoleRows] = await pool.execute(
                    'SELECT role FROM room_members WHERE room_id = ? AND user_id = ?',
                    [roomId, targetUserId]
                );

                if (targetRoleRows.length > 0 && targetRoleRows[0].role === 'admin') {
                    return res.status(403).json({
                        success: false,
                        message: 'Les administrateurs ne peuvent pas supprimer d\'autres administrateurs'
                    });
                }
            }
        }

        // Supprimer le membre
        const [result] = await pool.execute(
            'DELETE FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, targetUserId]
        );

        if (result.affectedRows > 0) {
            // Mettre à jour le compteur
            await pool.execute(
                'UPDATE rooms SET current_members = GREATEST(current_members - 1, 0) WHERE id = ?',
                [roomId]
            );

            // Créer un message système
            const [targetUser] = await pool.execute(
                'SELECT prenom, nom FROM users WHERE id = ?',
                [targetUserId]
            );

            if (targetUser.length > 0) {
                const message = isTargetSelf
                    ? `${targetUser[0].prenom} ${targetUser[0].nom} a quitté la room`
                    : `${req.user.prenom} ${req.user.nom} a exclu ${targetUser[0].prenom} ${targetUser[0].nom} de la room`;

                await pool.execute(
                    `INSERT INTO room_messages 
                    (room_id, user_id, message, message_type) 
                    VALUES (?, ?, ?, 'system')`,
                    [roomId, currentUserId, message]
                );
            }

            console.log(`✅ Utilisateur ${targetUserId} supprimé de la room ${roomId}`);

            res.json({
                success: true,
                message: isTargetSelf ? 'Vous avez quitté la room' : 'Membre exclu avec succès'
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'Membre non trouvé'
            });
        }

    } catch (error) {
        console.error('❌ Erreur suppression membre:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 5. Route pour récupérer le code d'accès
app.get('/api/rooms/:id/access-code', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier que l'utilisateur est propriétaire ou admin
        const [permissionRows] = await pool.execute(
            `SELECT r.room_type, r.owner_id, rm.role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [userId, roomId]
        );

        if (permissionRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = permissionRows[0];

        // Vérifier les permissions
        const isOwner = room.owner_id === userId;
        const isAdmin = room.role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Permission refusée'
            });
        }

        // Si room publique, pas de code
        if (room.room_type === 'public') {
            return res.json({
                success: true,
                code: null,
                message: 'Cette room est publique, aucun code d\'accès n\'est nécessaire'
            });
        }

        // Récupérer le code actif
        const [codeRows] = await pool.execute(
            'SELECT code FROM room_access_codes WHERE room_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1',
            [roomId]
        );

        if (codeRows.length === 0) {
            // Générer un nouveau code
            const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
            await pool.execute(
                `INSERT INTO room_access_codes 
                (room_id, code, created_by) 
                VALUES (?, ?, ?)`,
                [roomId, accessCode, userId]
            );

            return res.json({
                success: true,
                code: accessCode,
                message: 'Code généré avec succès'
            });
        }

        res.json({
            success: true,
            code: codeRows[0].code
        });

    } catch (error) {
        console.error('❌ Erreur récupération code:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 6. Route pour régénérer le code d'accès
app.post('/api/rooms/:id/regenerate-code', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier que l'utilisateur est propriétaire ou admin
        const [permissionRows] = await pool.execute(
            `SELECT r.room_type, r.owner_id, rm.role
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ?`,
            [userId, roomId]
        );

        if (permissionRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = permissionRows[0];

        // Vérifier les permissions
        const isOwner = room.owner_id === userId;
        const isAdmin = room.role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Permission refusée'
            });
        }

        // Si room publique, pas de code
        if (room.room_type === 'public') {
            return res.status(400).json({
                success: false,
                message: 'Les rooms publiques n\'ont pas de code d\'accès'
            });
        }

        // Désactiver l'ancien code
        await pool.execute(
            'UPDATE room_access_codes SET is_active = 0 WHERE room_id = ? AND is_active = 1',
            [roomId]
        );

        // Générer un nouveau code
        const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await pool.execute(
            `INSERT INTO room_access_codes 
            (room_id, code, created_by) 
            VALUES (?, ?, ?)`,
            [roomId, accessCode, userId]
        );

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, userId, `${req.user.prenom} ${req.user.nom} a régénéré le code d'accès`]
        );

        console.log(`✅ Code régénéré pour la room ${roomId}: ${accessCode}`);

        res.json({
            success: true,
            code: accessCode,
            message: 'Code régénéré avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur régénération code:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 7. Route pour mettre à jour le type d'accès
app.put('/api/rooms/:id/access-type', requireAuth, isRoomOwner, async (req, res) => {
    try {
        const roomId = req.params.id;
        const { room_type } = req.body;

        if (!room_type || !['public', 'private'].includes(room_type)) {
            return res.status(400).json({
                success: false,
                message: 'Type de room invalide'
            });
        }

        // Vérifier le type actuel
        const [currentRoom] = await pool.execute(
            'SELECT room_type FROM rooms WHERE id = ?',
            [roomId]
        );

        if (currentRoom.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        // Si pas de changement
        if (currentRoom[0].room_type === room_type) {
            return res.status(400).json({
                success: false,
                message: 'Le type de room est déjà configuré ainsi'
            });
        }

        // Mettre à jour le type
        await pool.execute(
            'UPDATE rooms SET room_type = ? WHERE id = ?',
            [room_type, roomId]
        );

        // Si changement de public à privé, générer un code
        if (room_type === 'private') {
            const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
            await pool.execute(
                `INSERT INTO room_access_codes 
                (room_id, code, created_by) 
                VALUES (?, ?, ?)`,
                [roomId, accessCode, req.user.id]
            );
        }

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, req.user.id,
                `${req.user.prenom} ${req.user.nom} a changé la room en ${room_type === 'public' ? 'publique' : 'privée'}`]
        );

        console.log(`✅ Type d'accès changé pour la room ${roomId}: ${room_type}`);

        res.json({
            success: true,
            message: `Room configurée en ${room_type === 'public' ? 'publique' : 'privée'}`
        });

    } catch (error) {
        console.error('❌ Erreur changement type accès:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 8. Route pour rechercher des utilisateurs (abonnés/abonnements)
app.get('/api/users/search', requireAuth, async (req, res) => {
    try {
        const query = req.query.q || '';
        const userId = req.user.id;

        if (query.length < 2) {
            return res.json({
                success: true,
                users: []
            });
        }

        // Rechercher les utilisateurs (sauf soi-même)
        const searchTerm = `%${query}%`;
        const [users] = await pool.execute(
            `SELECT id, prenom, nom, email 
             FROM users 
             WHERE id != ? 
             AND (prenom LIKE ? OR nom LIKE ? OR email LIKE ?)
             LIMIT 10`,
            [userId, searchTerm, searchTerm, searchTerm]
        );

        res.json({
            success: true,
            users: users
        });

    } catch (error) {
        console.error('❌ Erreur recherche utilisateurs:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 9. Route pour récupérer les abonnés (followers) - Utilise les membres des rooms partagées
app.get('/api/network/followers', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Récupérer les utilisateurs qui partagent au moins une room avec l'utilisateur courant
        const [followers] = await pool.execute(`
            SELECT DISTINCT u.id, u.prenom, u.nom, u.email
            FROM users u
            INNER JOIN room_members rm1 ON u.id = rm1.user_id
            INNER JOIN room_members rm2 ON rm1.room_id = rm2.room_id
            WHERE rm2.user_id = ? AND u.id != ?
            ORDER BY u.prenom, u.nom
            LIMIT 50
        `, [userId, userId]);

        res.json({
            success: true,
            followers: followers
        });

    } catch (error) {
        console.error('❌ Erreur récupération followers:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 10. Route pour récupérer les abonnements (following) - Utilise les membres des rooms partagées
app.get('/api/network/following', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Récupérer les utilisateurs des rooms où l'utilisateur est membre
        const [following] = await pool.execute(`
            SELECT DISTINCT u.id, u.prenom, u.nom, u.email
            FROM users u
            INNER JOIN room_members rm ON u.id = rm.user_id
            INNER JOIN rooms r ON rm.room_id = r.id
            WHERE r.owner_id = ? AND u.id != ? AND r.status != 'archived'
            UNION
            SELECT DISTINCT u.id, u.prenom, u.nom, u.email
            FROM users u
            INNER JOIN room_members rm1 ON u.id = rm1.user_id
            INNER JOIN room_members rm2 ON rm1.room_id = rm2.room_id
            WHERE rm2.user_id = ? AND u.id != ?
            ORDER BY prenom, nom
            LIMIT 50
        `, [userId, userId, userId, userId]);

        res.json({
            success: true,
            following: following
        });

    } catch (error) {
        console.error('❌ Erreur récupération following:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 11. Route pour supprimer tous les messages d'une room
app.delete('/api/rooms/:id/messages', requireAuth, isRoomOwner, async (req, res) => {
    try {
        const roomId = req.params.id;

        // Supprimer tous les messages
        const [result] = await pool.execute(
            'DELETE FROM room_messages WHERE room_id = ?',
            [roomId]
        );

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, req.user.id,
                `${req.user.prenom} ${req.user.nom} a supprimé tous les messages de la room`]
        );

        console.log(`🗑️ ${result.affectedRows} messages supprimés de la room ${roomId}`);

        res.json({
            success: true,
            message: `${result.affectedRows} messages supprimés`,
            count: result.affectedRows
        });

    } catch (error) {
        console.error('❌ Erreur suppression messages:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 12. Route pour supprimer tous les membres (sauf propriétaire)
app.delete('/api/rooms/:id/members', requireAuth, isRoomOwner, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Compter combien de membres seront supprimés
        const [countRows] = await pool.execute(
            'SELECT COUNT(*) as count FROM room_members WHERE room_id = ?',
            [roomId]
        );

        const countToDelete = countRows[0].count;

        // Supprimer tous les membres (sauf propriétaire)
        await pool.execute(
            'DELETE FROM room_members WHERE room_id = ?',
            [roomId]
        );

        // Réinitialiser le compteur (juste le propriétaire reste)
        await pool.execute(
            'UPDATE rooms SET current_members = 1 WHERE id = ?',
            [roomId]
        );

        // Créer un message système
        await pool.execute(
            `INSERT INTO room_messages 
            (room_id, user_id, message, message_type) 
            VALUES (?, ?, ?, 'system')`,
            [roomId, userId,
                `${req.user.prenom} ${req.user.nom} a exclu tous les membres de la room (${countToDelete} membres)`]
        );

        console.log(`👥 ${countToDelete} membres supprimés de la room ${roomId}`);

        res.json({
            success: true,
            message: `${countToDelete} membres exclus`,
            count: countToDelete
        });

    } catch (error) {
        console.error('❌ Erreur suppression membres:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 13. Route pour supprimer définitivement une room
app.delete('/api/rooms/:id', requireAuth, isRoomOwner, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // D'abord, archiver la room
        await pool.execute(
            'UPDATE rooms SET status = "archived" WHERE id = ?',
            [roomId]
        );

        console.log(`🗑️ Room ${roomId} archivée par l'utilisateur ${userId}`);

        res.json({
            success: true,
            message: 'Room supprimée avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur suppression room:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES ROOM POLLS (CORRIGÉES) ====================

// Page de gestion des sondages d'une room
app.get('/room/:id/polls', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        const [rooms] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ? AND r.status != 'archived'
        `, [userId, roomId]);

        if (rooms.length === 0) {
            return res.redirect('/rooms');
        }

        const room = rooms[0];

        res.render('dashboard/room-polls', {
            title: `Sondages - ${room.name}`,
            page: 'rooms',
            user: {
                id: userId,
                name: `${req.user.prenom} ${req.user.nom}`,
                email: req.user.email,
                prenom: req.user.prenom,
                nom: req.user.nom,
                joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
            },
            room: {
                id: room.id,
                name: room.name,
                description: room.description,
                role: room.role
            }
        });
    } catch (error) {
        console.error('Erreur chargement page sondages:', error);
        res.status(500).send('Erreur serveur');
    }
});

// Créer un sondage dans une room (admin only) - CORRIGÉ
app.post('/api/rooms/:roomId/polls', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        const { title, question, description, poll_type, options, closes_at, is_anonymous } = req.body;

        // Vérifier si l'utilisateur est admin de la room (propriétaire ou admin)
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent créer des sondages'
            });
        }

        // Validation
        if (!title || !question || !options || options.length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Titre, question et au moins 2 options sont requis'
            });
        }

        // Créer le sondage
        const [pollResult] = await pool.execute(`
            INSERT INTO room_polls 
            (room_id, title, question, description, created_by, poll_type, is_anonymous, closes_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [roomId, title, question, description || null, userId, poll_type || 'single', is_anonymous ? 1 : 0, closes_at || null]);

        const pollId = pollResult.insertId;

        // Ajouter les options
        for (let i = 0; i < options.length; i++) {
            await pool.execute(`
                INSERT INTO room_poll_options (poll_id, option_text, option_order)
                VALUES (?, ?, ?)
            `, [pollId, options[i], i]);
        }

        // Créer un message système dans la room
        await pool.execute(`
            INSERT INTO room_messages (room_id, user_id, message, message_type, related_poll_id)
            VALUES (?, ?, ?, 'poll_created', ?)
        `, [roomId, userId, `${req.user.prenom} ${req.user.nom} a créé un sondage: "${title}"`, pollId]);

        // Récupérer le sondage créé avec les options
        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   r.name as room_name
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        const [pollOptions] = await pool.execute(`
            SELECT * FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
        `, [pollId]);

        const poll = polls[0];
        poll.options = pollOptions;

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('poll-created', {
            room_id: roomId,
            poll: poll
        });

        console.log(`✅ Sondage créé: ${pollId} dans room ${roomId}`);

        res.json({
            success: true,
            message: 'Sondage créé avec succès',
            poll: poll
        });

    } catch (error) {
        console.error('Erreur création sondage:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Récupérer tous les sondages d'une room pour la gestion - CORRIGÉ avec filtres
app.get('/api/rooms/:roomId/polls-management', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;

        // Récupérer les paramètres de filtrage
        const { status, sort, search, type, anon, startDate, endDate, page = 1, limit = 10 } = req.query;

        // Vérifier si l'utilisateur est membre de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 
                CASE WHEN r.owner_id = ? THEN 'owner' ELSE NULL END
            ) as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, userId, roomId]);

        if (roomInfo.length === 0 || !roomInfo[0].user_role) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        // Construire la requête dynamique avec filtres
        let whereClause = 'WHERE rp.room_id = ?';
        const queryParams = [roomId];

        // Filtre par statut
        if (status && status !== 'all') {
            whereClause += ' AND rp.status = ?';
            queryParams.push(status);
        }

        // Filtre par type de vote
        if (type && type !== 'all') {
            whereClause += ' AND rp.poll_type = ?';
            queryParams.push(type);
        }

        // Filtre par anonymat
        if (anon && anon !== 'all') {
            if (anon === 'anonymous') {
                whereClause += ' AND rp.is_anonymous = 1';
            } else if (anon === 'public') {
                whereClause += ' AND rp.is_anonymous = 0';
            }
        }

        // Filtre par recherche
        if (search && search.trim() !== '') {
            whereClause += ' AND (rp.title LIKE ? OR rp.question LIKE ?)';
            queryParams.push(`%${search}%`, `%${search}%`);
        }

        // Filtre par dates
        if (startDate) {
            whereClause += ' AND DATE(rp.created_at) >= ?';
            queryParams.push(startDate);
        }
        if (endDate) {
            whereClause += ' AND DATE(rp.created_at) <= ?';
            queryParams.push(endDate);
        }

        // Construire ORDER BY dynamique
        let orderClause = '';
        switch (sort) {
            case 'oldest':
                orderClause = 'ORDER BY rp.created_at ASC';
                break;
            case 'votes':
                orderClause = 'ORDER BY voter_count DESC, rp.created_at DESC';
                break;
            case 'title':
                orderClause = 'ORDER BY rp.title ASC';
                break;
            case 'newest':
            default:
                orderClause = 'ORDER BY CASE WHEN rp.status = \'active\' THEN 0 ELSE 1 END, rp.created_at DESC';
                break;
        }

        // Récupérer tous les sondages avec les votes
        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   r.name as room_name,
                   (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = rp.id) as voter_count
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            JOIN rooms r ON rp.room_id = r.id
            ${whereClause}
            ${orderClause}
        `, queryParams);

        // Pour chaque sondage, récupérer les options avec les votes
        for (let poll of polls) {
            const [options] = await pool.execute(`
                SELECT 
                    rpo.*,
                    COUNT(rpv.id) as vote_count
                FROM room_poll_options rpo
                LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
                WHERE rpo.poll_id = ?
                GROUP BY rpo.id
                ORDER BY rpo.option_order
            `, [poll.id]);

            // Vérifier si l'utilisateur a déjà voté
            const [userVotes] = await pool.execute(`
                SELECT COUNT(*) as has_voted
                FROM room_poll_votes
                WHERE poll_id = ? AND user_id = ?
            `, [poll.id, userId]);

            poll.options = options;
            poll.has_voted = userVotes[0].has_voted > 0;

            // Calculer le total des votes
            poll.total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.vote_count) || 0), 0);
        }

        // Calculer les statistiques
        const stats = {
            total: polls.length,
            active: polls.filter(p => p.status === 'active').length,
            totalVotes: polls.reduce((sum, p) => sum + (p.total_votes || 0), 0),
            yourVotes: polls.filter(p => p.has_voted).length
        };

        res.json({
            success: true,
            polls: polls,
            total: polls.length,
            currentPage: parseInt(page),
            totalPages: Math.ceil(polls.length / parseInt(limit)),
            stats: stats
        });

    } catch (error) {
        console.error('Erreur récupération sondages:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Récupérer les détails d'un sondage - CORRIGÉ
app.get('/api/rooms/:roomId/polls/:pollId', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const roomId = req.params.roomId;
        const userId = req.user.id;

        // Vérifier si l'utilisateur est membre de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   r.name as room_name
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ? AND rp.room_id = ?
        `, [pollId, roomId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];

        // Récupérer les options avec les votes
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as vote_count
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [pollId]);

        poll.options = options;
        poll.total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.vote_count) || 0), 0);

        res.json({
            success: true,
            poll: poll
        });

    } catch (error) {
        console.error('Erreur récupération sondage:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Récupérer les résultats détaillés d'un sondage - CORRIGÉ
app.get('/api/rooms/:roomId/polls/:pollId/results', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const roomId = req.params.roomId;
        const userId = req.user.id;

        // Vérifier si l'utilisateur est membre de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            WHERE rp.id = ? AND rp.room_id = ?
        `, [pollId, roomId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];

        // Récupérer les options avec les votes
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as vote_count
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [pollId]);

        poll.options = options;
        poll.total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.vote_count) || 0), 0);

        // Si non anonyme, récupérer la liste des votants
        if (!poll.is_anonymous) {
            const [voters] = await pool.execute(`
                SELECT rpv.*, 
                       CONCAT(u.prenom, ' ', u.nom) as user_name,
                       rpo.option_text as selected_option
                FROM room_poll_votes rpv
                JOIN users u ON rpv.user_id = u.id
                JOIN room_poll_options rpo ON rpv.option_id = rpo.id
                WHERE rpv.poll_id = ?
                ORDER BY rpv.voted_at DESC
            `, [pollId]);

            poll.voters = voters;
        }

        res.json({
            success: true,
            poll: poll
        });

    } catch (error) {
        console.error('Erreur récupération résultats:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Voter pour un sondage (déjà corrigée plus haut)
// Cette route est déjà corrigée dans la section supérieure

// Fermer un sondage (admin only) - CORRIGÉ
app.post('/api/rooms/polls/:pollId/close-simple', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;

        // Récupérer le sondage et vérifier les permissions
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent fermer un sondage'
            });
        }

        // Fermer le sondage
        await pool.execute(
            'UPDATE room_polls SET status = \'closed\' WHERE id = ?',
            [pollId]
        );

        // Émettre l'événement Socket.IO
        io.to(`poll_${pollId}`).emit('poll-closed', {
            poll_id: pollId,
            poll_title: poll.title
        });

        io.to(`room_${roomId}`).emit('poll-closed', {
            poll_id: pollId,
            poll_title: poll.title
        });

        console.log(`🔒 Sondage ${pollId} fermé par user ${userId}`);

        res.json({
            success: true,
            message: 'Sondage fermé avec succès'
        });

    } catch (error) {
        console.error('Erreur fermeture sondage:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer un sondage de room (admin only) - NOUVELLE ROUTE DÉDIÉE
app.delete('/api/rooms/polls/:pollId/delete', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;

        // Récupérer le sondage et vérifier les permissions
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.owner_id, COALESCE(rm.role, 
                CASE WHEN r.owner_id = ? THEN 'owner' ELSE NULL END
            ) as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const userRole = roomInfo[0].user_role;
        const isOwner = roomInfo[0].owner_id === userId;

        if (!isOwner && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent supprimer un sondage'
            });
        }

        // Supprimer le sondage (les votes et options seront supprimés en cascade grâce aux FK)
        await pool.execute(
            'DELETE FROM room_polls WHERE id = ?',
            [pollId]
        );

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('poll-deleted', {
            poll_id: pollId,
            poll_title: poll.title
        });

        console.log(`🗑️ Sondage room ${pollId} supprimé par user ${userId}`);

        res.json({
            success: true,
            message: 'Sondage supprimé avec succès'
        });

    } catch (error) {
        console.error('Erreur suppression sondage room:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Voter pour un sondage - NOUVELLE ROUTE
app.post('/api/rooms/polls/:pollId/vote', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;
        const { option_ids } = req.body;

        // Valider les options
        if (!option_ids || !Array.isArray(option_ids) || option_ids.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Veuillez sélectionner au moins une option'
            });
        }

        // Récupérer le sondage
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id, r.owner_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier si le sondage est actif
        if (poll.status !== 'active') {
            return res.status(400).json({
                success: false,
                message: 'Ce sondage est fermé'
            });
        }

        // Vérifier si le sondage a expiré
        if (poll.closes_at && new Date(poll.closes_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'Ce sondage a expiré'
            });
        }

        // Vérifier que l'utilisateur est membre de la room
        const [memberCheck] = await pool.execute(`
            SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?
            UNION
            SELECT 1 FROM rooms WHERE id = ? AND owner_id = ?
        `, [roomId, userId, roomId, userId]);

        if (memberCheck.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous devez être membre de la room pour voter'
            });
        }

        // Vérifier si l'utilisateur a déjà voté
        const [existingVotes] = await pool.execute(`
            SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?
        `, [pollId, userId]);

        // Pour les sondages à choix unique, empêcher le double vote
        if (poll.poll_type === 'single' && existingVotes.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté pour ce sondage'
            });
        }

        // Pour les sondages à choix multiple, supprimer les anciens votes si nécessaire
        if (poll.poll_type === 'multiple' && existingVotes.length > 0) {
            // Supprimer les anciens votes pour permettre de modifier son vote
            await pool.execute(
                'DELETE FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [pollId, userId]
            );
        }

        // Vérifier que les options existent
        const [validOptions] = await pool.execute(`
            SELECT id FROM room_poll_options WHERE poll_id = ? AND id IN (${option_ids.map(() => '?').join(',')})
        `, [pollId, ...option_ids]);

        if (validOptions.length !== option_ids.length) {
            return res.status(400).json({
                success: false,
                message: 'Une ou plusieurs options sont invalides'
            });
        }

        // Pour choix unique, ne garder que la première option
        const optionsToInsert = poll.poll_type === 'single' ? [option_ids[0]] : option_ids;

        // Insérer les votes
        for (const optionId of optionsToInsert) {
            await pool.execute(`
                INSERT INTO room_poll_votes (poll_id, user_id, option_id)
                VALUES (?, ?, ?)
            `, [pollId, userId, optionId]);
        }

        // Récupérer l'option sélectionnée (pour le message)
        const [selectedOption] = await pool.execute(
            'SELECT option_text FROM room_poll_options WHERE id = ?',
            [optionsToInsert[0]]
        );

        // Créer un message système
        await pool.execute(`
            INSERT INTO room_messages (room_id, user_id, message, message_type, related_poll_id)
            VALUES (?, ?, ?, 'poll_vote', ?)
        `, [roomId, userId, `${req.user.prenom} ${req.user.nom} a voté pour "${selectedOption[0].option_text}"`, pollId]);

        // Récupérer les résultats mis à jour
        const [updatedOptions] = await pool.execute(`
            SELECT 
                rpo.id,
                rpo.option_text,
                COUNT(rpv.id) as vote_count
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [pollId]);

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('vote-update', {
            poll_id: pollId,
            results: updatedOptions,
            voter: `${req.user.prenom} ${req.user.nom}`
        });

        io.to(`poll_${pollId}`).emit('vote-update', {
            poll_id: pollId,
            results: updatedOptions,
            voter: `${req.user.prenom} ${req.user.nom}`
        });

        console.log(`✅ Vote enregistré: user ${userId} pour sondage ${pollId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès',
            results: updatedOptions
        });

    } catch (error) {
        console.error('Erreur vote:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer un sondage (admin only) - CORRIGÉ
app.delete('/api/polls/:id', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.id;
        const userId = req.user.id;

        // Récupérer le sondage et vérifier les permissions
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent supprimer un sondage'
            });
        }

        // Supprimer le sondage (les votes et options seront supprimés en cascade)
        await pool.execute(
            'DELETE FROM room_polls WHERE id = ?',
            [pollId]
        );

        console.log(`🗑️ Sondage ${pollId} supprimé par user ${userId}`);

        res.json({
            success: true,
            message: 'Sondage supprimé avec succès'
        });

    } catch (error) {
        console.error('Erreur suppression sondage:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ==================== SOCKET.IO CONFIGURATION ====================

io.on('connection', (socket) => {
    console.log('👤 Nouvelle connexion Socket.IO:', socket.id);

    // Rejoindre une room
    socket.on('join-room', (data) => {
        const { room_id } = data;
        socket.join(`room_${room_id}`);
        console.log(`👤 Socket ${socket.id} a rejoint la room ${room_id}`);
    });

    // Quitter une room
    socket.on('leave-room', (data) => {
        const { room_id } = data;
        socket.leave(`room_${room_id}`);
        console.log(`👤 Socket ${socket.id} a quitté la room ${room_id}`);
    });

    // Rejoindre une room de sondage
    socket.on('join-poll-room', (data) => {
        const { poll_id, room_id } = data;
        socket.join(`poll_${poll_id}`);
        socket.join(`room_${room_id}`);
        console.log(`📊 Socket ${socket.id} a rejoint le sondage ${poll_id}`);
    });

    // Quitter une room de sondage
    socket.on('leave-poll-room', (data) => {
        const { poll_id } = data;
        socket.leave(`poll_${poll_id}`);
        console.log(`📊 Socket ${socket.id} a quitté le sondage ${poll_id}`);
    });

    // Déconnexion
    socket.on('disconnect', () => {
        console.log('👤 Déconnexion Socket.IO:', socket.id);
    });
});



// ==================== ROUTES API MANQUANTES POUR ROOM-DETAILS ====================

// 1. Route pour récupérer les votes/sondages d'une room (pour la page details)
app.get('/api/rooms/:id/votes', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier l'accès à la room
        const [accessRows] = await pool.execute(
            `SELECT r.room_type 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)`,
            [userId, roomId, userId]
        );

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        // Récupérer les sondages actifs avec leurs options
        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = rp.id) as total_votes
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            WHERE rp.room_id = ? AND rp.status = 'active'
            ORDER BY rp.created_at DESC
        `, [roomId]);

        // Pour chaque sondage, récupérer les options avec les votes
        for (let poll of polls) {
            const [options] = await pool.execute(`
                SELECT 
                    rpo.*,
                    COUNT(rpv.id) as votes
                FROM room_poll_options rpo
                LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
                WHERE rpo.poll_id = ?
                GROUP BY rpo.id
                ORDER BY rpo.option_order
            `, [poll.id]);

            poll.options = options;

            // Vérifier si l'utilisateur a voté
            const [userVotes] = await pool.execute(
                'SELECT option_id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [poll.id, userId]
            );

            poll.user_has_voted = userVotes.length > 0;
            poll.user_vote = userVotes.length > 0 ? userVotes[0].option_id : null;
        }

        res.json({
            success: true,
            votes: polls // Renommé "votes" pour correspondre au frontend
        });

    } catch (error) {
        console.error('❌ Erreur récupération votes:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

/// Load user votes
app.get('/api/rooms/:id/user-votes', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Récupérer tous les votes de l'utilisateur dans cette room
        const [votes] = await pool.execute(`
            SELECT rpv.poll_id as vote_id, rpv.option_id
            FROM room_poll_votes rpv
            JOIN room_polls rp ON rpv.poll_id = rp.id
            WHERE rp.room_id = ? AND rpv.user_id = ?
        `, [roomId, userId]);

        // Organiser les votes par poll_id
        const userVotes = {};
        votes.forEach(vote => {
            if (!userVotes[vote.vote_id]) {
                userVotes[vote.vote_id] = [];
            }
            userVotes[vote.vote_id].push(vote.option_id);
        });

        res.json({
            success: true,
            votes: votes,
            organized: userVotes
        });

    } catch (error) {
        console.error('❌ Erreur récupération votes utilisateur:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur',
            votes: []
        });
    }
});
// 3. Route pour créer un vote/sondage (alias de la route polls pour compatibilité)
app.post('/api/rooms/:id/votes/create', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { title, question, options, duration, multiple_choice } = req.body;

        // Vérifier que l'utilisateur est admin
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent créer des votes'
            });
        }

        // Validation
        if (!title || !question || !options || options.length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Titre, question et au moins 2 options sont requis'
            });
        }

        // Calculer la date de fermeture
        let closesAt = null;
        if (duration) {
            closesAt = new Date();
            closesAt.setSeconds(closesAt.getSeconds() + parseInt(duration));
        }

        // Créer le sondage
        const [pollResult] = await pool.execute(`
            INSERT INTO room_polls 
            (room_id, title, question, created_by, poll_type, is_anonymous, closes_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            roomId,
            title,
            question,
            userId,
            multiple_choice ? 'multiple' : 'single',
            0,
            closesAt
        ]);

        const pollId = pollResult.insertId;

        // Ajouter les options
        for (let i = 0; i < options.length; i++) {
            await pool.execute(`
                INSERT INTO room_poll_options (poll_id, option_text, option_order)
                VALUES (?, ?, ?)
            `, [pollId, options[i], i]);
        }

        // Créer un message système
        await pool.execute(`
            INSERT INTO room_messages (room_id, user_id, message, message_type, related_poll_id)
            VALUES (?, ?, ?, 'poll_created', ?)
        `, [roomId, userId, `${req.user.prenom} ${req.user.nom} a créé un vote: "${title}"`, pollId]);

        // Récupérer le vote créé avec les options
        const [votes] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            WHERE rp.id = ?
        `, [pollId]);

        const [pollOptions] = await pool.execute(`
            SELECT *, 0 as votes FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
        `, [pollId]);

        const vote = votes[0];
        vote.options = pollOptions;
        vote.total_votes = 0;
        vote.multiple_choice = multiple_choice ? 1 : 0;

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('vote-created', {
            room_id: roomId,
            vote: vote
        });

        console.log(`✅ Vote créé: ${pollId} dans room ${roomId}`);

        res.json({
            success: true,
            message: 'Vote créé avec succès',
            vote: vote
        });

    } catch (error) {
        console.error('❌ Erreur création vote:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 4. Route pour voter (compatible avec le frontend room-details)
app.post('/api/votes/:voteId/vote', requireAuth, async (req, res) => {
    try {
        const voteId = req.params.voteId; // C'est en fait un poll_id
        const userId = req.user.id;
        const { option_ids } = req.body;

        if (!option_ids || !Array.isArray(option_ids) || option_ids.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Options requises'
            });
        }

        // Récupérer le sondage
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id 
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ? AND rp.status = 'active' 
            AND (rp.closes_at IS NULL OR rp.closes_at > NOW())
        `, [voteId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Vote non trouvé ou terminé'
            });
        }

        const poll = polls[0];

        // Vérifier l'appartenance à la room
        const [memberRows] = await pool.execute(
            'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
            [poll.room_id, userId]
        );

        if (memberRows.length === 0) {
            // Vérifier si c'est le propriétaire
            const [ownerRows] = await pool.execute(
                'SELECT owner_id FROM rooms WHERE id = ?',
                [poll.room_id]
            );

            if (ownerRows.length === 0 || ownerRows[0].owner_id !== userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Vous devez être membre de la room'
                });
            }
        }

        // Vérifier si déjà voté
        const [existingVotes] = await pool.execute(
            'SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
            [voteId, userId]
        );

        if (existingVotes.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté'
            });
        }

        // Vérifier que les options appartiennent au sondage
        for (const optionId of option_ids) {
            const [optionRows] = await pool.execute(
                'SELECT id FROM room_poll_options WHERE id = ? AND poll_id = ?',
                [optionId, voteId]
            );

            if (optionRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: `Option invalide: ${optionId}`
                });
            }
        }

        // Enregistrer les votes
        for (const optionId of option_ids) {
            await pool.execute(
                'INSERT INTO room_poll_votes (poll_id, user_id, option_id) VALUES (?, ?, ?)',
                [voteId, userId, optionId]
            );
        }

        // Récupérer les résultats mis à jour
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as votes
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [voteId]);

        const total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0);

        // Émettre l'événement Socket.IO
        io.to(`room_${poll.room_id}`).emit('vote-update', {
            vote_id: voteId,
            results: {
                options: options,
                total_votes: total_votes
            }
        });

        console.log(`✅ Vote enregistré pour le sondage ${voteId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès',
            results: {
                options: options,
                total_votes: total_votes
            }
        });

    } catch (error) {
        console.error('❌ Erreur vote:', error);

        if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 5. Route pour récupérer les résultats d'un vote
app.get('/api/votes/:voteId/results', requireAuth, async (req, res) => {
    try {
        const voteId = req.params.voteId;

        // Récupérer les options avec les votes
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as votes
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [voteId]);

        const total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0);

        res.json({
            success: true,
            options: options,
            total_votes: total_votes
        });

    } catch (error) {
        console.error('❌ Erreur résultats vote:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// 6. Route pour fermer un vote (admin only)
app.post('/api/votes/:voteId/close', requireAuth, async (req, res) => {
    try {
        const voteId = req.params.voteId;
        const userId = req.user.id;

        // Récupérer le sondage et vérifier les permissions
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [voteId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Vote non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent fermer un vote'
            });
        }

        // Fermer le vote
        await pool.execute(
            'UPDATE room_polls SET status = \'closed\' WHERE id = ?',
            [voteId]
        );

        // Créer un message système
        await pool.execute(`
            INSERT INTO room_messages (room_id, user_id, message, message_type, related_poll_id)
            VALUES (?, ?, ?, 'system', ?)
        `, [roomId, userId, `${req.user.prenom} ${req.user.nom} a fermé le vote "${poll.title}"`, voteId]);

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('vote-closed', {
            vote_id: voteId,
            vote_title: poll.title
        });

        console.log(`🔒 Vote ${voteId} fermé par user ${userId}`);

        res.json({
            success: true,
            message: 'Vote fermé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur fermeture vote:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

console.log('✅ Routes API room-details ajoutées');

// ==================== ROUTES API SUPPLEMENTAIRES ====================

// Route pour récupérer les votes d'une room
app.get('/api/rooms/:id/votes', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier l'accès à la room
        const [accessRows] = await pool.execute(
            `SELECT r.room_type 
             FROM rooms r
             LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
             WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)`,
            [userId, roomId, userId]
        );

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès non autorisé'
            });
        }

        // Récupérer les votes ACTIFS avec leurs options
        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = rp.id) as total_votes,
                   rp.poll_type as multiple_choice
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            WHERE rp.room_id = ? AND rp.status = 'active'
            ORDER BY rp.created_at DESC
        `, [roomId]);

        // Pour chaque sondage, récupérer les options avec les votes
        for (let poll of polls) {
            const [options] = await pool.execute(`
                SELECT 
                    rpo.id,
                    rpo.option_text as text,
                    rpo.option_order,
                    COUNT(rpv.id) as votes
                FROM room_poll_options rpo
                LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
                WHERE rpo.poll_id = ?
                GROUP BY rpo.id, rpo.option_text, rpo.option_order
                ORDER BY rpo.option_order
            `, [poll.id]);

            poll.options = options;

            // Vérifier si l'utilisateur a voté
            const [userVotes] = await pool.execute(
                'SELECT option_id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [poll.id, userId]
            );

            poll.user_has_voted = userVotes.length > 0;
            poll.user_vote = userVotes.length > 0 ? userVotes.map(v => v.option_id) : [];
        }

        res.json({
            success: true,
            votes: polls
        });

    } catch (error) {
        console.error('❌ Erreur récupération votes:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour rouvrir un vote
app.post('/api/votes/:voteId/reopen', requireAuth, async (req, res) => {
    try {
        const voteId = req.params.voteId;
        const userId = req.user.id;

        // Récupérer le sondage et vérifier les permissions
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [voteId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Vote non trouvé'
            });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [roomInfo] = await pool.execute(`
            SELECT r.*, COALESCE(rm.role, 'owner') as user_role
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ?
        `, [userId, roomId]);

        if (roomInfo.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas membre de cette room'
            });
        }

        const userRole = roomInfo[0].user_role;
        if (userRole !== 'owner' && userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Seuls les administrateurs peuvent rouvrir un vote'
            });
        }

        // Rouvrir le vote
        await pool.execute(
            'UPDATE room_polls SET status = \'active\' WHERE id = ?',
            [voteId]
        );

        // Créer un message système
        await pool.execute(`
            INSERT INTO room_messages (room_id, user_id, message, message_type, related_poll_id)
            VALUES (?, ?, ?, 'system', ?)
        `, [roomId, userId, `${req.user.prenom} ${req.user.nom} a rouvert le vote "${poll.title}"`, voteId]);

        // Émettre l'événement Socket.IO
        io.to(`room_${roomId}`).emit('vote-reopened', {
            vote_id: voteId,
            vote_title: poll.title
        });

        console.log(`🔄 Vote ${voteId} rouvert par user ${userId}`);

        res.json({
            success: true,
            message: 'Vote rouvert avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur réouverture vote:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour voter (version corrigée)
app.post('/api/votes/:voteId/vote', requireAuth, async (req, res) => {
    try {
        const voteId = req.params.voteId;
        const userId = req.user.id;
        const { option_ids } = req.body;

        if (!option_ids || !Array.isArray(option_ids) || option_ids.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Veuillez sélectionner au moins une option'
            });
        }

        // Récupérer le sondage
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id, rp.poll_type as multiple_choice
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ? AND rp.status = 'active'
        `, [voteId]);

        if (polls.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Vote non trouvé ou inactif'
            });
        }

        const poll = polls[0];
        const isMultiple = poll.multiple_choice === 'multiple';

        // Vérifier l'appartenance à la room
        const [memberRows] = await pool.execute(
            'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
            [poll.room_id, userId]
        );

        const isOwner = await pool.execute(
            'SELECT owner_id FROM rooms WHERE id = ? AND owner_id = ?',
            [poll.room_id, userId]
        );

        if (memberRows.length === 0 && isOwner[0].length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Vous devez être membre de la room pour voter'
            });
        }

        // Vérifier si déjà voté (sauf pour votes multiples)
        if (!isMultiple) {
            const [existingVotes] = await pool.execute(
                'SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [voteId, userId]
            );

            if (existingVotes.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Vous avez déjà voté pour ce sondage'
                });
            }
        }

        // Vérifier que les options appartiennent au sondage
        for (const optionId of option_ids) {
            const [optionRows] = await pool.execute(
                'SELECT id FROM room_poll_options WHERE id = ? AND poll_id = ?',
                [optionId, voteId]
            );

            if (optionRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: `Option invalide: ${optionId}`
                });
            }
        }

        // Pour les votes multiples, supprimer d'abord les votes existants
        if (isMultiple) {
            await pool.execute(
                'DELETE FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [voteId, userId]
            );
        }

        // Enregistrer les votes
        for (const optionId of option_ids) {
            await pool.execute(
                'INSERT INTO room_poll_votes (poll_id, user_id, option_id) VALUES (?, ?, ?)',
                [voteId, userId, optionId]
            );
        }

        // Récupérer les résultats mis à jour
        const [options] = await pool.execute(`
            SELECT 
                rpo.*,
                COUNT(rpv.id) as votes
            FROM room_poll_options rpo
            LEFT JOIN room_poll_votes rpv ON rpo.id = rpv.option_id
            WHERE rpo.poll_id = ?
            GROUP BY rpo.id
            ORDER BY rpo.option_order
        `, [voteId]);

        const total_votes = options.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0);

        // Émettre l'événement Socket.IO
        io.to(`room_${poll.room_id}`).emit('vote-update', {
            vote_id: voteId,
            results: {
                options: options,
                total_votes: total_votes
            }
        });

        console.log(`✅ Vote enregistré pour le sondage ${voteId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès',
            results: {
                options: options,
                total_votes: total_votes
            }
        });

    } catch (error) {
        console.error('❌ Erreur vote:', error);

        if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
            return res.status(400).json({
                success: false,
                message: 'Vous avez déjà voté pour cette option'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES POUR UTILISATEURS NORMAUX DE ROOMS ====================

// Route pour récupérer les détails d'une room (version utilisateur normal)
app.get('/api/rooms/:id/details-user', requireAuth, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Vérifier si l'utilisateur est membre ou si la room est publique
        const [roomRows] = await pool.execute(`
            SELECT r.*, 
                   CONCAT(u.prenom, ' ', u.nom) as owner_name,
                   (r.owner_id = ?) as is_owner,
                   (r.owner_id = ? OR EXISTS (
                       SELECT 1 FROM room_members rm 
                       WHERE rm.room_id = r.id AND rm.user_id = ?
                   )) as is_member,
                   r.room_type as type,
                   CASE 
                       WHEN r.room_type = 'private' AND r.owner_id = ? THEN 'owner'
                       WHEN r.room_type = 'private' AND EXISTS (
                           SELECT 1 FROM room_members rm 
                           WHERE rm.room_id = r.id AND rm.user_id = ?
                       ) THEN 'member'
                       WHEN r.room_type = 'public' THEN 'guest'
                       ELSE 'none'
                   END as access_status
            FROM rooms r
            JOIN users u ON r.owner_id = u.id
            WHERE r.id = ? AND r.status != 'archived'
        `, [userId, userId, userId, userId, userId, roomId]);

        if (roomRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Room non trouvée'
            });
        }

        const room = roomRows[0];

        // Vérifier l'accès
        if (room.type === 'private' && room.access_status === 'none') {
            return res.status(403).json({
                success: false,
                message: 'Accès refusé. Cette room est privée.'
            });
        }

        // Récupérer les membres de la room
        const [members] = await pool.execute(`
            SELECT 
                u.id,
                CONCAT(u.prenom, ' ', u.nom) as name,
                u.email,
                CASE 
                    WHEN r.owner_id = u.id THEN 'owner'
                    ELSE COALESCE(rm.role, 'member')
                END as role,
                rm.joined_at,
                (SELECT COUNT(*) FROM room_messages m 
                 WHERE m.room_id = ? AND m.user_id = u.id 
                 AND m.created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)) > 0 as is_online
            FROM users u
            LEFT JOIN room_members rm ON u.id = rm.user_id AND rm.room_id = ?
            JOIN rooms r ON r.id = ?
            WHERE r.id = ? AND (r.owner_id = u.id OR rm.user_id IS NOT NULL)
            ORDER BY 
                CASE WHEN r.owner_id = u.id THEN 0 ELSE 1 END,
                rm.joined_at ASC
        `, [roomId, roomId, roomId, roomId]);

        // Récupérer tous les sondages (actifs et fermés)
        const [polls] = await pool.execute(`
            SELECT 
                p.*,
                CONCAT(u.prenom, ' ', u.nom) as creator_name,
                (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = p.id) as total_votes,
                (SELECT COUNT(*) FROM room_poll_votes WHERE poll_id = p.id AND user_id = ?) as user_voted,
                CASE 
                    WHEN p.status = 'active' AND (p.closes_at IS NULL OR p.closes_at > NOW()) THEN 'active'
                    ELSE 'closed'
                END as vote_status
            FROM room_polls p
            JOIN users u ON p.created_by = u.id
            WHERE p.room_id = ?
            ORDER BY 
                CASE WHEN vote_status = 'active' THEN 0 ELSE 1 END,
                p.created_at DESC
        `, [userId, roomId]);

        // Pour chaque sondage, récupérer les options
        for (let poll of polls) {
            const [options] = await pool.execute(`
                SELECT 
                    o.*,
                    COUNT(v.id) as votes,
                    (SELECT COUNT(*) FROM room_poll_votes 
                     WHERE poll_id = ? AND option_id = o.id AND user_id = ?) as user_selected
                FROM room_poll_options o
                LEFT JOIN room_poll_votes v ON o.id = v.option_id
                WHERE o.poll_id = ?
                GROUP BY o.id
                ORDER BY o.option_order
            `, [poll.id, userId, poll.id]);

            poll.options = options;
            poll.user_has_voted = poll.user_voted > 0;

            // Calculer les pourcentages
            if (poll.total_votes > 0) {
                poll.options.forEach(option => {
                    option.percentage = Math.round((option.votes / poll.total_votes) * 100);
                });
            }
        }

        // Récupérer les statistiques
        const [stats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM room_messages WHERE room_id = ?) as total_messages,
                (SELECT COUNT(*) FROM room_members WHERE room_id = ?) + 1 as total_members,
                (SELECT COUNT(*) FROM room_polls WHERE room_id = ?) as total_polls,
                (SELECT COUNT(*) FROM room_polls WHERE room_id = ? AND status = 'active') as active_polls
        `, [roomId, roomId, roomId, roomId]);

        res.json({
            success: true,
            room: {
                id: room.id,
                name: room.name,
                description: room.description || 'Aucune description',
                type: room.type,
                status: room.status,
                owner_name: room.owner_name,
                created_at: room.created_at,
                current_members: room.current_members,
                max_members: room.max_members,
                is_member: room.is_member,
                is_owner: room.is_owner
            },
            members: members,
            polls: polls,
            stats: stats[0],
            user: {
                id: userId,
                name: `${req.user.prenom} ${req.user.nom}`
            }
        });

    } catch (error) {
        console.error('❌ Erreur détails room utilisateur:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour voter dans un sondage (version simplifiée)
app.post('/api/rooms/polls/:pollId/vote-simple', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;
        const { option_ids } = req.body; // Peut être un tableau pour votes multiples

        if (!option_ids || (Array.isArray(option_ids) && option_ids.length === 0)) {
            return res.status(400).json({
                success: false,
                message: 'Veuillez sélectionner une option'
            });
        }

        // Récupérer le sondage
        const [pollRows] = await pool.execute(`
            SELECT p.*, r.id as room_id, r.room_type
            FROM room_polls p
            JOIN rooms r ON p.room_id = r.id
            WHERE p.id = ? AND p.status = 'active'
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé ou terminé'
            });
        }

        const poll = pollRows[0];

        // Vérifier l'accès à la room
        const [accessRows] = await pool.execute(`
            SELECT 1 
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)
        `, [userId, poll.room_id, userId]);

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès refusé'
            });
        }

        // Pour les votes uniques, vérifier si déjà voté
        if (poll.poll_type === 'single') {
            const [existingVote] = await pool.execute(
                'SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [pollId, userId]
            );

            if (existingVote.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Vous avez déjà voté pour ce sondage'
                });
            }
        }

        // Pour les votes multiples, supprimer d'abord les anciens votes
        // IMPORTANT: Supprimer TOUS les votes existants pour permettre de changer de vote
        await pool.execute(
            'DELETE FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
            [pollId, userId]
        );

        // Enregistrer les votes
        const options = Array.isArray(option_ids) ? option_ids : [option_ids];

        // Pour choix unique, ne garder que la première option
        const optionsToInsert = poll.poll_type === 'single' ? [options[0]] : options;

        for (const optionId of optionsToInsert) {
            // Vérifier que l'option appartient au sondage
            const [optionRows] = await pool.execute(
                'SELECT id FROM room_poll_options WHERE id = ? AND poll_id = ?',
                [optionId, pollId]
            );

            if (optionRows.length === 0) {
                continue; // Ignorer les options invalides
            }

            // Utiliser INSERT pour chaque option (le DELETE précédent a libéré les contraintes)
            await pool.execute(
                'INSERT INTO room_poll_votes (poll_id, user_id, option_id) VALUES (?, ?, ?)',
                [pollId, userId, optionId]
            );
        }

        // Récupérer les résultats mis à jour
        const [results] = await pool.execute(`
            SELECT 
                o.*,
                COUNT(v.id) as votes,
                (SELECT COUNT(*) FROM room_poll_votes 
                 WHERE poll_id = ? AND option_id = o.id AND user_id = ?) as user_selected
            FROM room_poll_options o
            LEFT JOIN room_poll_votes v ON o.id = v.option_id
            WHERE o.poll_id = ?
            GROUP BY o.id
            ORDER BY o.option_order
        `, [pollId, userId, pollId]);

        const total_votes = results.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0);

        // Calculer les pourcentages
        const optionsWithPercentage = results.map(option => ({
            ...option,
            percentage: total_votes > 0 ? Math.round((option.votes / total_votes) * 100) : 0
        }));

        // Émettre l'événement WebSocket
        io.to(`room_${poll.room_id}`).emit('poll-update', {
            poll_id: pollId,
            results: {
                options: optionsWithPercentage,
                total_votes: total_votes
            }
        });

        console.log(`✅ Vote enregistré pour le sondage ${pollId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès',
            results: {
                options: optionsWithPercentage,
                total_votes: total_votes,
                user_has_voted: true
            }
        });

    } catch (error) {
        console.error('❌ Erreur vote simplifié:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour récupérer les résultats d'un sondage en temps réel
app.get('/api/rooms/polls/:pollId/live-results', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;

        const [pollRows] = await pool.execute(`
            SELECT p.*, r.id as room_id
            FROM room_polls p
            JOIN rooms r ON p.room_id = r.id
            WHERE p.id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        const poll = pollRows[0];

        // Vérifier l'accès à la room
        const [accessRows] = await pool.execute(`
            SELECT 1 
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
            WHERE r.id = ? AND (r.room_type = 'public' OR rm.id IS NOT NULL OR r.owner_id = ?)
        `, [userId, poll.room_id, userId]);

        if (accessRows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Accès refusé'
            });
        }

        // Récupérer les résultats
        const [results] = await pool.execute(`
            SELECT 
                o.*,
                COUNT(v.id) as votes,
                (SELECT COUNT(*) FROM room_poll_votes 
                 WHERE poll_id = ? AND option_id = o.id AND user_id = ?) as user_selected
            FROM room_poll_options o
            LEFT JOIN room_poll_votes v ON o.id = v.option_id
            WHERE o.poll_id = ?
            GROUP BY o.id
            ORDER BY o.option_order
        `, [pollId, userId, pollId]);

        const total_votes = results.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0);

        // Calculer les pourcentages
        const optionsWithPercentage = results.map(option => ({
            ...option,
            percentage: total_votes > 0 ? Math.round((option.votes / total_votes) * 100) : 0
        }));

        res.json({
            success: true,
            results: {
                options: optionsWithPercentage,
                total_votes: total_votes
            }
        });

    } catch (error) {
        console.error('❌ Erreur résultats live:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES POUR LA PAGE EXPLORER ====================

// Route pour récupérer tous les sondages/votes publics pour Explorer
// Route pour récupérer tous les sondages/votes pour Explorer
app.get('/api/explorer/polls', requireAuth, async (req, res) => {
    try {
        const [polls] = await pool.execute(`
            SELECT p.*, 
                   pc.name as category_name,
                   pc.icon as category_icon,
                   pc.color as category_color,
                   CASE 
                       WHEN p.is_anonymous = 1 THEN 'Anonyme'
                       ELSE CONCAT(u.prenom, ' ', u.nom)
                   END as creator_name,
                   CASE 
                       WHEN p.is_anonymous = 0 THEN u.id
                       ELSE NULL
                   END as creator_id,
                   (SELECT COUNT(*) FROM poll_options po WHERE po.poll_id = p.id) as options_count,
                   (SELECT COUNT(DISTINCT user_id) FROM votes WHERE poll_id = p.id) as total_votes,
                   (SELECT COUNT(*) FROM poll_views WHERE poll_id = p.id) as total_views,
                   CASE 
                       WHEN p.created_by = ? THEN 1
                       ELSE 0
                   END as is_creator,
                   CASE 
                       WHEN p.end_time > NOW() AND p.status = 'active' THEN 1
                       ELSE 0
                   END as is_active
            FROM polls p
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            JOIN users u ON p.created_by = u.id
            ORDER BY p.created_at DESC
        `, [req.user.id]);

        // Pour chaque sondage/vote, récupérer les détails
        const pollsWithDetails = await Promise.all(polls.map(async (poll) => {
            // Récupérer les options
            const [options] = await pool.execute(`
                SELECT id, option_text, option_image 
                FROM poll_options 
                WHERE poll_id = ? 
                ORDER BY option_order
            `, [poll.id]);

            // Vérifier si l'utilisateur a voté
            const [hasVoted] = await pool.execute(`
                SELECT COUNT(*) as count 
                FROM votes 
                WHERE poll_id = ? AND user_id = ?
            `, [poll.id, req.user.id]);

            // Récupérer les réactions
            const [reactions] = await pool.execute(`
                SELECT reaction_type, COUNT(*) as count
                FROM poll_reactions
                WHERE poll_id = ?
                GROUP BY reaction_type
            `, [poll.id]);

            // Vérifier si l'utilisateur a réagi
            const [userReaction] = await pool.execute(`
                SELECT reaction_type
                FROM poll_reactions
                WHERE poll_id = ? AND user_id = ?
            `, [poll.id, req.user.id]);

            // Récupérer le nombre de commentaires
            const [commentsCount] = await pool.execute(`
                SELECT COUNT(*) as count
                FROM poll_comments
                WHERE poll_id = ? AND is_deleted = 0
            `, [poll.id]);

            // Enregistrer la vue (seulement si ce n'est pas le créateur)
            if (poll.is_creator !== 1) {
                await pool.execute(`
                    INSERT IGNORE INTO poll_views (poll_id, user_id)
                    VALUES (?, ?)
                `, [poll.id, req.user.id]);
            }

            return {
                ...poll,
                options,
                has_voted: hasVoted[0].count > 0,
                reactions: reactions,
                user_reaction: userReaction[0]?.reaction_type || null,
                comments_count: commentsCount[0].count,
                time_remaining: poll.is_active ? Math.max(0, Math.floor((new Date(poll.end_time) - new Date()) / 1000)) : 0
            };
        }));

        res.json({
            success: true,
            polls: pollsWithDetails
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des sondages Explorer:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour ajouter une réaction
app.post('/api/polls/:id/react', requireAuth, async (req, res) => {
    const pollId = req.params.id;
    const { reaction_type } = req.body;

    const validReactions = ['like', 'love', 'wow', 'haha', 'sad', 'angry'];
    if (!validReactions.includes(reaction_type)) {
        return res.status(400).json({
            success: false,
            message: 'Type de réaction invalide'
        });
    }

    try {
        // Vérifier si l'utilisateur a déjà réagi
        const [existing] = await pool.execute(`
            SELECT id, reaction_type FROM poll_reactions
            WHERE poll_id = ? AND user_id = ?
        `, [pollId, req.user.id]);

        if (existing.length > 0) {
            if (existing[0].reaction_type === reaction_type) {
                // Supprimer la réaction
                await pool.execute(`
                    DELETE FROM poll_reactions
                    WHERE poll_id = ? AND user_id = ?
                `, [pollId, req.user.id]);

                res.json({
                    success: true,
                    action: 'removed',
                    message: 'Réaction supprimée'
                });
            } else {
                // Modifier la réaction
                await pool.execute(`
                    UPDATE poll_reactions
                    SET reaction_type = ?
                    WHERE poll_id = ? AND user_id = ?
                `, [reaction_type, pollId, req.user.id]);

                res.json({
                    success: true,
                    action: 'updated',
                    message: 'Réaction modifiée'
                });
            }
        } else {
            // Ajouter une nouvelle réaction
            await pool.execute(`
                INSERT INTO poll_reactions (poll_id, user_id, reaction_type)
                VALUES (?, ?, ?)
            `, [pollId, req.user.id, reaction_type]);

            res.json({
                success: true,
                action: 'added',
                message: 'Réaction ajoutée'
            });
        }

    } catch (error) {
        console.error('❌ Erreur lors de la réaction:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour ajouter un commentaire
app.post('/api/polls/:id/comment', requireAuth, async (req, res) => {
    const pollId = req.params.id;
    const { comment_text, parent_comment_id } = req.body;

    if (!comment_text || comment_text.trim().length === 0) {
        return res.status(400).json({
            success: false,
            message: 'Le commentaire ne peut pas être vide'
        });
    }

    try {
        const [result] = await pool.execute(`
            INSERT INTO poll_comments (poll_id, user_id, parent_comment_id, comment_text)
            VALUES (?, ?, ?, ?)
        `, [pollId, req.user.id, parent_comment_id || null, comment_text.trim()]);

        // Récupérer le commentaire créé avec les infos utilisateur
        const [comment] = await pool.execute(`
            SELECT pc.*, CONCAT(u.prenom, ' ', u.nom) as user_name
            FROM poll_comments pc
            JOIN users u ON pc.user_id = u.id
            WHERE pc.id = ?
        `, [result.insertId]);

        res.json({
            success: true,
            message: 'Commentaire ajouté',
            comment: comment[0]
        });

    } catch (error) {
        console.error('❌ Erreur lors de l\'ajout du commentaire:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour récupérer les commentaires
app.get('/api/polls/:id/comments', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    try {
        const [comments] = await pool.execute(`
            SELECT pc.*, 
                   CONCAT(u.prenom, ' ', u.nom) as user_name,
                   CASE WHEN pc.user_id = ? THEN 1 ELSE 0 END as is_owner
            FROM poll_comments pc
            JOIN users u ON pc.user_id = u.id
            WHERE pc.poll_id = ? AND pc.is_deleted = 0
            ORDER BY pc.created_at DESC
        `, [req.user.id, pollId]);

        res.json({
            success: true,
            comments: comments
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des commentaires:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour partager un sondage
app.post('/api/polls/:id/share', requireAuth, async (req, res) => {
    const pollId = req.params.id;
    const { share_message, shared_to_user_id } = req.body;

    try {
        await pool.execute(`
            INSERT INTO poll_shares (poll_id, user_id, shared_to_user_id, share_message)
            VALUES (?, ?, ?, ?)
        `, [pollId, req.user.id, shared_to_user_id || null, share_message || null]);

        res.json({
            success: true,
            message: 'Sondage partagé avec succès'
        });

    } catch (error) {
        console.error('❌ Erreur lors du partage:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// Route pour récupérer les résultats (seulement après la fin)
app.get('/api/polls/:id/results-explorer', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    try {
        const [pollRows] = await pool.execute(`
            SELECT * FROM polls WHERE id = ?
        `, [pollId]);

        if (pollRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage/vote non trouvé'
            });
        }

        const poll = pollRows[0];
        const now = new Date();
        const endTime = new Date(poll.end_time);

        // Vérifier si le sondage est terminé
        if (now < endTime && poll.status === 'active') {
            return res.status(403).json({
                success: false,
                message: 'Les résultats seront disponibles après la fin du ' + (poll.poll_category === 'vote' ? 'vote' : 'sondage')
            });
        }

        // Récupérer les résultats
        const [options] = await pool.execute(`
            SELECT po.*, 
                   (SELECT COUNT(*) FROM votes v WHERE v.poll_id = po.poll_id AND v.option_selected = po.id) as vote_count
            FROM poll_options po
            WHERE po.poll_id = ?
            ORDER BY vote_count DESC, po.option_order
        `, [pollId]);

        res.json({
            success: true,
            results: options,
            total_votes: poll.total_votes || 0
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des résultats:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ==================== ROUTES POUR LES STATISTIQUES ====================

// Route pour récupérer les statistiques générales
app.get('/api/statistics/general', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        console.log(`📊 Chargement des statistiques pour l'utilisateur ${userId}`);

        // Statistiques de l'utilisateur
        const [userStats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM polls WHERE created_by = ?) as total_polls_created,
                (SELECT COUNT(*) FROM votes WHERE user_id = ?) as total_votes_cast,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'active') as active_polls,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'closed') as closed_polls,
                (SELECT COUNT(*) FROM poll_comments pc 
                 JOIN polls p ON pc.poll_id = p.id 
                 WHERE p.created_by = ?) as total_comments,
                (SELECT COUNT(*) FROM poll_reactions pr 
                 JOIN polls p ON pr.poll_id = p.id 
                 WHERE p.created_by = ?) as total_reactions,
                (SELECT COUNT(*) FROM poll_shares ps 
                 JOIN polls p ON ps.poll_id = p.id 
                 WHERE p.created_by = ?) as total_shares,
                (SELECT COUNT(*) FROM poll_views pv 
                 JOIN polls p ON pv.poll_id = p.id 
                 WHERE p.created_by = ?) as total_views
        `, [userId, userId, userId, userId, userId, userId, userId, userId]);

        // Statistiques générales de la plateforme
        const [platformStats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM polls) as total_polls,
                (SELECT COUNT(*) FROM votes) as total_votes,
                (SELECT COUNT(*) FROM polls WHERE status = 'active') as active_polls_total,
                (SELECT COUNT(*) FROM polls WHERE poll_category = 'vote') as total_votes_official,
                (SELECT COUNT(*) FROM polls WHERE poll_category = 'sondage') as total_polls_survey,
                (SELECT COUNT(*) FROM poll_comments) as total_comments_platform,
                (SELECT COUNT(*) FROM poll_reactions) as total_reactions_platform,
                (SELECT COUNT(*) FROM poll_shares) as total_shares_platform
        `);

        // Types de sondages/votes
        const [pollTypes] = await pool.execute(`
            SELECT 
                poll_category as type,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM polls), 2) as percentage
            FROM polls
            GROUP BY poll_category
            ORDER BY count DESC
        `);

        // Activité récente (7 derniers jours)
        const [recentActivity] = await pool.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as polls_created,
                (SELECT COUNT(*) FROM votes v WHERE DATE(v.voted_at) = DATE(p.created_at)) as votes_cast
            FROM polls p
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        `);

        // Catégories populaires
        const [popularCategories] = await pool.execute(`
            SELECT 
                pc.name,
                COUNT(p.id) as poll_count,
                COALESCE(SUM((SELECT COUNT(*) FROM votes v WHERE v.poll_id = p.id)), 0) as total_votes
            FROM poll_categories pc
            LEFT JOIN polls p ON pc.id = p.category_id
            GROUP BY pc.id, pc.name
            ORDER BY poll_count DESC
            LIMIT 10
        `);

        // Top sondages/votes par participation
        const [topPolls] = await pool.execute(`
            SELECT 
                p.id,
                p.title,
                p.question,
                p.poll_category,
                (SELECT COUNT(*) FROM votes WHERE poll_id = p.id) as vote_count,
                (SELECT COUNT(*) FROM poll_options WHERE poll_id = p.id) as options_count,
                (SELECT COUNT(*) FROM poll_comments WHERE poll_id = p.id AND is_deleted = 0) as comments_count,
                CONCAT(u.prenom, ' ', u.nom) as creator_name
            FROM polls p
            JOIN users u ON p.created_by = u.id
            ORDER BY vote_count DESC
            LIMIT 5
        `);

        // Participation de l'utilisateur
        const [userParticipation] = await pool.execute(`
            SELECT 
                DATE(voted_at) as vote_date,
                COUNT(*) as votes_per_day
            FROM votes 
            WHERE user_id = ?
                AND voted_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(voted_at)
            ORDER BY vote_date
        `, [userId]);

        // Statistiques de performance des sondages de l'utilisateur
        const [userPollPerformance] = await pool.execute(`
            SELECT 
                p.id,
                p.title,
                p.poll_category,
                p.status,
                p.created_at,
                p.end_time,
                (SELECT COUNT(*) FROM votes WHERE poll_id = p.id) as total_votes,
                (SELECT COUNT(*) FROM poll_comments WHERE poll_id = p.id AND is_deleted = 0) as total_comments,
                (SELECT COUNT(*) FROM poll_reactions WHERE poll_id = p.id) as total_reactions,
                (SELECT COUNT(*) FROM poll_shares WHERE poll_id = p.id) as total_shares
            FROM polls p
            WHERE p.created_by = ?
            ORDER BY total_votes DESC
            LIMIT 10
        `, [userId]);

        // Calculer le classement de l'utilisateur
        const [userRanking] = await pool.execute(`
            SELECT 
                u.id,
                CONCAT(u.prenom, ' ', u.nom) as user_name,
                COUNT(p.id) as polls_count,
                COALESCE(SUM((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as total_votes,
                ROW_NUMBER() OVER (ORDER BY COALESCE(SUM((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) DESC) as ranking
            FROM users u
            LEFT JOIN polls p ON u.id = p.created_by
            GROUP BY u.id, u.prenom, u.nom
            ORDER BY total_votes DESC
        `);

        const userRank = userRanking.find(row => row.id === userId)?.ranking || 1;

        // Récupérer les réactions par type
        const [reactionsByType] = await pool.execute(`
            SELECT 
                pr.reaction_type,
                COUNT(*) as count
            FROM poll_reactions pr
            JOIN polls p ON pr.poll_id = p.id
            WHERE p.created_by = ?
            GROUP BY pr.reaction_type
            ORDER BY count DESC
        `, [userId]);

        res.json({
            success: true,
            data: {
                user_stats: userStats[0] || {
                    total_polls_created: 0,
                    total_votes_cast: 0,
                    active_polls: 0,
                    closed_polls: 0,
                    total_comments: 0,
                    total_reactions: 0,
                    total_shares: 0,
                    total_views: 0
                },
                platform_stats: platformStats[0] || {
                    total_users: 0,
                    total_polls: 0,
                    total_votes: 0,
                    active_polls_total: 0,
                    total_votes_official: 0,
                    total_polls_survey: 0,
                    total_comments_platform: 0,
                    total_reactions_platform: 0,
                    total_shares_platform: 0
                },
                poll_types: pollTypes || [],
                recent_activity: recentActivity || [],
                popular_categories: popularCategories || [],
                top_polls: topPolls || [],
                user_participation: userParticipation || [],
                user_poll_performance: userPollPerformance || [],
                user_ranking: userRank,
                reactions_by_type: reactionsByType || []
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des statistiques:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors du chargement des statistiques',
            error: error.message
        });
    }
});

// Route pour récupérer les statistiques détaillées d'un sondage
app.get('/api/statistics/poll/:id', requireAuth, async (req, res) => {
    const pollId = req.params.id;

    console.log(`📊 Chargement des statistiques pour le sondage ${pollId}`);

    try {
        // Informations de base du sondage
        const [pollInfo] = await pool.execute(`
            SELECT 
                p.*,
                CONCAT(u.prenom, ' ', u.nom) as creator_name,
                pc.name as category_name,
                (SELECT COUNT(*) FROM votes WHERE poll_id = p.id) as total_votes
            FROM polls p
            JOIN users u ON p.created_by = u.id
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            WHERE p.id = ?
        `, [pollId]);

        if (pollInfo.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sondage non trouvé'
            });
        }

        // Statistiques des options
        const [optionStats] = await pool.execute(`
            SELECT 
                po.id,
                po.option_text,
                po.option_image,
                po.option_order,
                COUNT(v.id) as vote_count,
                ROUND(
                    COUNT(v.id) * 100.0 / NULLIF(
                        (SELECT COUNT(*) FROM votes WHERE poll_id = ?), 0
                    ), 2
                ) as percentage
            FROM poll_options po
            LEFT JOIN votes v ON po.id = v.option_selected
            WHERE po.poll_id = ?
            GROUP BY po.id, po.option_text, po.option_image, po.option_order
            ORDER BY vote_count DESC
        `, [pollId, pollId]);

        // Participation par heure
        const [hourlyParticipation] = await pool.execute(`
            SELECT 
                HOUR(voted_at) as hour,
                COUNT(*) as vote_count
            FROM votes
            WHERE poll_id = ?
            GROUP BY HOUR(voted_at)
            ORDER BY hour
        `, [pollId]);

        // Évolution des votes dans le temps
        const [voteTimeline] = await pool.execute(`
            SELECT 
                DATE(voted_at) as vote_date,
                HOUR(voted_at) as vote_hour,
                COUNT(*) as vote_count
            FROM votes
            WHERE poll_id = ?
            GROUP BY DATE(voted_at), HOUR(voted_at)
            ORDER BY vote_date, vote_hour
        `, [pollId]);

        // Réactions au sondage
        const [reactionStats] = await pool.execute(`
            SELECT 
                reaction_type,
                COUNT(*) as count
            FROM poll_reactions
            WHERE poll_id = ?
            GROUP BY reaction_type
            ORDER BY count DESC
        `, [pollId]);

        // Partages du sondage
        const [shareStats] = await pool.execute(`
            SELECT 
                DATE(created_at) as share_date,
                COUNT(*) as share_count
            FROM poll_shares
            WHERE poll_id = ?
            GROUP BY DATE(created_at)
            ORDER BY share_date
        `, [pollId]);

        // Analyse des commentaires
        const [commentStats] = await pool.execute(`
            SELECT 
                DATE(pc.created_at) as comment_date,
                COUNT(*) as comment_count
            FROM poll_comments pc
            WHERE pc.poll_id = ? AND pc.is_deleted = 0
            GROUP BY DATE(pc.created_at)
            ORDER BY comment_date
        `, [pollId]);

        // Taux de participation
        const [totalUsers] = await pool.execute('SELECT COUNT(*) as count FROM users');
        const totalVotes = pollInfo[0].total_votes || 0;
        const participationRate = totalUsers[0]?.count > 0
            ? ((totalVotes / totalUsers[0].count) * 100).toFixed(2)
            : '0.00';

        res.json({
            success: true,
            data: {
                poll_info: pollInfo[0],
                option_stats: optionStats,
                hourly_participation: hourlyParticipation,
                vote_timeline: voteTimeline,
                reaction_stats: reactionStats,
                share_stats: shareStats,
                comment_stats: commentStats,
                participation_rate: participationRate
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des statistiques du sondage:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur',
            error: error.message
        });
    }
});

// Route pour les statistiques de performance
app.get('/api/statistics/performance', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        console.log(`📈 Chargement des statistiques de performance pour l'utilisateur ${userId}`);

        // Performance des sondages par catégorie
        const [categoryPerformance] = await pool.execute(`
            SELECT 
                COALESCE(pc.name, 'Non catégorisé') as category_name,
                COUNT(p.id) as poll_count,
                COALESCE(SUM((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as total_votes,
                ROUND(COALESCE(AVG((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0), 2) as avg_votes_per_poll,
                COALESCE(MAX((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as max_votes,
                COALESCE(MIN((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as min_votes,
                ROUND(
                    SUM(CASE WHEN p.status = 'closed' THEN 1 ELSE 0 END) * 100.0 / COUNT(p.id), 2
                ) as completion_rate
            FROM polls p
            LEFT JOIN poll_categories pc ON p.category_id = pc.id
            WHERE p.created_by = ?
            GROUP BY pc.name
            ORDER BY total_votes DESC
        `, [userId]);

        // Tendances temporelles
        const [timeTrends] = await pool.execute(`
            SELECT 
                DATE_FORMAT(p.created_at, '%Y-%m') as month,
                COUNT(p.id) as polls_created,
                COALESCE(SUM((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as total_votes,
                ROUND(COALESCE(AVG((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0), 2) as avg_votes_per_poll,
                ROUND(
                    SUM(CASE WHEN p.poll_category = 'vote' THEN 1 ELSE 0 END) * 100.0 / COUNT(p.id), 2
                ) as official_vote_percentage
            FROM polls p
            WHERE p.created_by = ?
                AND p.created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(p.created_at, '%Y-%m')
            ORDER BY month
        `, [userId]);

        // Engagement des utilisateurs
        const [userEngagement] = await pool.execute(`
            SELECT 
                p.id,
                p.title,
                p.poll_category,
                (SELECT COUNT(DISTINCT user_id) FROM votes WHERE poll_id = p.id) as unique_voters,
                (SELECT COUNT(*) FROM poll_comments WHERE poll_id = p.id AND is_deleted = 0) as total_comments,
                (SELECT COUNT(*) FROM poll_reactions WHERE poll_id = p.id) as total_reactions,
                (SELECT COUNT(*) FROM poll_shares WHERE poll_id = p.id) as total_shares
            FROM polls p
            WHERE p.created_by = ?
            ORDER BY unique_voters DESC
            LIMIT 10
        `, [userId]);

        // Statistiques comparatives
        const [comparativeStats] = await pool.execute(`
            SELECT 
                'Vos sondages' as source,
                COUNT(p.id) as total_polls,
                ROUND(COALESCE(AVG((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0), 2) as avg_votes,
                COALESCE(MAX((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as max_votes,
                COALESCE(MIN((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as min_votes,
                ROUND(
                    SUM(CASE WHEN p.status = 'closed' THEN 1 ELSE 0 END) * 100.0 / COUNT(p.id), 2
                ) as completion_rate
            FROM polls p
            WHERE p.created_by = ?
            
            UNION ALL
            
            SELECT 
                'Plateforme (moyenne)' as source,
                COUNT(p.id) as total_polls,
                ROUND(COALESCE(AVG((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0), 2) as avg_votes,
                COALESCE(MAX((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as max_votes,
                COALESCE(MIN((SELECT COUNT(*) FROM votes WHERE poll_id = p.id)), 0) as min_votes,
                ROUND(
                    SUM(CASE WHEN p.status = 'closed' THEN 1 ELSE 0 END) * 100.0 / COUNT(p.id), 2
                ) as completion_rate
            FROM polls p
            WHERE p.created_by != ?
        `, [userId, userId]);

        res.json({
            success: true,
            data: {
                category_performance: categoryPerformance || [],
                time_trends: timeTrends || [],
                user_engagement: userEngagement || [],
                comparative_stats: comparativeStats || []
            }
        });

    } catch (error) {
        console.error('❌ Erreur lors de la récupération des statistiques de performance:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur',
            error: error.message
        });
    }
});

// Route pour exporter les statistiques (version simplifiée)
app.get('/api/statistics/export/:type', requireAuth, async (req, res) => {
    try {
        const exportType = req.params.type;
        const userId = req.user.id;

        console.log(`📤 Export des statistiques au format ${exportType} pour l'utilisateur ${userId}`);

        // Récupérer les statistiques générales
        const [userStats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM polls WHERE created_by = ?) as total_polls_created,
                (SELECT COUNT(*) FROM votes WHERE user_id = ?) as total_votes_cast,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'active') as active_polls,
                (SELECT COUNT(*) FROM polls WHERE created_by = ? AND status = 'closed') as closed_polls
        `, [userId, userId, userId, userId]);

        // Récupérer les sondages de l'utilisateur
        const [userPolls] = await pool.execute(`
            SELECT 
                p.id,
                p.title,
                p.question,
                p.poll_category,
                p.status,
                p.created_at,
                p.end_time,
                (SELECT COUNT(*) FROM votes WHERE poll_id = p.id) as total_votes,
                (SELECT COUNT(*) FROM poll_comments WHERE poll_id = p.id) as total_comments
            FROM polls p
            WHERE p.created_by = ?
            ORDER BY p.created_at DESC
        `, [userId]);

        const exportData = {
            export_date: new Date().toISOString(),
            user_id: userId,
            user_name: req.user.prenom + ' ' + req.user.nom,
            user_stats: userStats[0] || {},
            polls: userPolls || [],
            generated_at: new Date().toISOString()
        };

        if (exportType === 'json') {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename=statistiques-${userId}-${Date.now()}.json`);
            res.json(exportData);
        } else if (exportType === 'csv') {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=statistiques-${userId}-${Date.now()}.csv`);

            // Convertir en CSV simplifié
            let csvContent = 'Section,Paramètre,Valeur\n';
            csvContent += `Utilisateur,ID,${exportData.user_id}\n`;
            csvContent += `Utilisateur,Nom,${exportData.user_name}\n`;
            csvContent += `Utilisateur,Date d'export,${exportData.export_date}\n`;
            csvContent += `Statistiques,Sondages créés,${exportData.user_stats.total_polls_created || 0}\n`;
            csvContent += `Statistiques,Votes reçus,${exportData.user_stats.total_votes_cast || 0}\n`;
            csvContent += `Statistiques,Sondages actifs,${exportData.user_stats.active_polls || 0}\n`;
            csvContent += `Statistiques,Sondages terminés,${exportData.user_stats.closed_polls || 0}\n`;

            // Ajouter les sondages
            csvContent += '\nSondages,ID,Titre,Question,Catégorie,Statut,Créé le,Termine le,Votes,Commentaires\n';
            exportData.polls.forEach(poll => {
                csvContent += `Sondage,${poll.id},"${poll.title}","${poll.question}",${poll.poll_category},${poll.status},${poll.created_at},${poll.end_time},${poll.total_votes},${poll.total_comments}\n`;
            });

            res.send(csvContent);
        } else {
            res.json({
                success: true,
                message: 'Format non pris en charge. Utilisez "json" ou "csv"',
                data: exportData
            });
        }

    } catch (error) {
        console.error('❌ Erreur lors de l\'exportation:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur lors de l\'exportation',
            error: error.message
        });
    }
});

// Route pour vérifier la santé des statistiques
app.get('/api/statistics/health', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [basicStats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM polls WHERE created_by = ?) as polls_count,
                (SELECT COUNT(*) FROM votes WHERE user_id = ?) as votes_count
        `, [userId, userId]);

        res.json({
            success: true,
            status: 'healthy',
            user_id: userId,
            polls_count: basicStats[0]?.polls_count || 0,
            votes_count: basicStats[0]?.votes_count || 0,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Erreur de santé des statistiques:', error);
        res.status(500).json({
            success: false,
            status: 'unhealthy',
            error: error.message
        });
    }
});
