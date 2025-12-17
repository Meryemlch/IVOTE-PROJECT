const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const emailService = require('./emailService');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const expressLayouts = require('express-ejs-layouts');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
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
// Configuration EJS avec layouts (ORDRE IMPORTANT!)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layouts/main'); // Layout par défaut
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

// ==================== ROUTES STATIQUES ====================

app.get('/', (req, res) => {
    if (req.session.userId && req.user) {
        res.redirect('/dashboard');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'connexion.html'));
    }
});

app.get('/inscription', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'inscription.html'));
});

app.get('/verify-email', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify-email.html'));
});

app.get('/verification-success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verification-success.html'));
});

app.get('/waiting-verification', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'waiting-verification.html'));
});

app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// ==================== ROUTES DASHBOARD ====================

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const [users] = await pool.execute(
            'SELECT id, prenom, nom, email, created_at FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (users.length === 0) {
            req.session.destroy();
            return res.redirect('/');
        }

        const user = users[0];
        
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
                totalVotes: 0,
                activePolls: 0,
                completedPolls: 0
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

// Route Notifications
app.get('/notifications', requireAuth, (req, res) => {
    res.render('dashboard/notifications', {
        title: 'Notifications',
        page: 'notifications',
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

// Route Sondages (remplace /poll/create)
app.get('/polls', requireAuth, (req, res) => {
    res.render('dashboard/polls', {
        title: 'Mes Sondages',
        page: 'polls',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR')
        }
    });
});

// Route Profil
app.get('/profile', requireAuth, (req, res) => {
    res.render('dashboard/profile', {
        title: 'Mon Profil',
        page: 'profile',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR'),
            telephone: req.user.telephone || 'Non renseigné',
            countryCode: req.user.country_code || '+33'
        }
    });
});

// Route Édition Profil
app.get('/profile/edit', requireAuth, (req, res) => {
    res.render('dashboard/edit-profile', {
        title: 'Modifier Profil',
        page: 'edit-profile',
        user: {
            name: `${req.user.prenom} ${req.user.nom}`,
            email: req.user.email,
            prenom: req.user.prenom,
            nom: req.user.nom,
            joinDate: req.user.created_at ? new Date(req.user.created_at).toLocaleDateString('fr-FR') : new Date().toLocaleDateString('fr-FR'),
            telephone: req.user.telephone || '',
            countryCode: req.user.country_code || '+33'
        }
    });
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
        req.user = user; // Ajouter l'utilisateur à la requête
        
        if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        }

        console.log('✅ Connexion réussie pour:', email);
        console.log('   Session créée:', req.session.userId);

        // Créer un token JWT également si nécessaire
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
        console.log(`📝 Page d'inscription: http://localhost:${PORT}/inscription`);
        console.log(`⏳ Page d'attente: http://localhost:${PORT}/waiting-verification`);
        console.log(`📧 Vérification email: ${emailConnected ? '✅ Activée' : '⚠️ Simulation'}`);
        console.log(`🔐 Système de session: ✅ Activé`);
        console.log(`🏗️  Structure EJS avec layouts: ✅ Activé`);
        console.log(`📊 Routes dashboard: /dashboard, /vote, /poll/create, /rooms, /results, /settings`);
        console.log(`📁 Layout principal: views/layouts/main.ejs`);
    });
}

startServer().catch(console.error);