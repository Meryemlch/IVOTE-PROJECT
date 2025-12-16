const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const emailService = require('./emailService');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

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
    
    // Tester la connexion
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connecté à la base de données MySQL');
        connection.release();
    } catch (error) {
        console.error('❌ Erreur de connexion à MySQL:', error);
        process.exit(1);
    }
}

// Fonction pour générer un token sécurisé
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Calculer la date d'expiration (24 heures)
function getExpirationDate() {
    const expires = new Date();
    expires.setHours(expires.getHours() + 24);
    return expires;
}

// Nettoyer les inscriptions expirées (cron job)
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

// Routes

// Page d'inscription
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'connexion.html'));
});

// Page de vérification email
app.get('/verify-email', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify-email.html'));
});

// Page de confirmation
app.get('/verification-success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verification-success.html'));
});

// Page d'attente de vérification
app.get('/waiting-verification', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'waiting-verification.html'));
});

// Route d'inscription (Nouvelle logique)
app.post('/api/register', async (req, res) => {
    console.log('📨 Nouvelle inscription reçue:', { ...req.body, password: '***' });
    
    const { prenom, nom, countryCode, telephone, email, password, confirmPassword, terms } = req.body;

    // Validation côté serveur
    const errors = [];

    // Validation des noms
    const nameRegex = /^[a-zA-ZÀ-ÿ\s'-]+$/;
    if (!prenom || !nameRegex.test(prenom)) {
        errors.push('Prénom invalide');
    }
    if (!nom || !nameRegex.test(nom)) {
        errors.push('Nom invalide');
    }

    // Validation téléphone
    const phoneRegex = /^[0-9\s]{9,15}$/;
    if (!telephone || !phoneRegex.test(telephone.replace(/\s/g, ''))) {
        errors.push('Numéro de téléphone invalide');
    }

    // Validation email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        errors.push('Email invalide');
    }

    // Validation mot de passe
    if (!password || password.length < 8) {
        errors.push('Le mot de passe doit contenir au moins 8 caractères');
    }
    if (password !== confirmPassword) {
        errors.push('Les mots de passe ne correspondent pas');
    }

    // Validation des termes
    if (!terms || (terms !== true && terms !== 'true' && terms !== 1 && terms !== '1')) {
        errors.push('Vous devez accepter les conditions');
    }

    if (errors.length > 0) {
        console.log('❌ Erreurs de validation:', errors);
        return res.status(400).json({ success: false, errors });
    }

    try {
        // Vérifier si l'email est déjà dans les utilisateurs vérifiés
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

        // Vérifier si une inscription en attente existe déjà
        const [existingPending] = await pool.execute(
            'SELECT id, expires_at FROM pending_registrations WHERE email = ?',
            [email]
        );

        if (existingPending.length > 0) {
            const pending = existingPending[0];
            const expiresAt = new Date(pending.expires_at);
            const now = new Date();
            
            if (now < expiresAt) {
                // Inscription encore valide
                return res.status(400).json({ 
                    success: false, 
                    errors: ['Une inscription est déjà en attente pour cet email. Vérifiez vos emails.'] 
                });
            } else {
                // Inscription expirée, on la supprime
                await pool.execute(
                    'DELETE FROM pending_registrations WHERE id = ?',
                    [pending.id]
                );
            }
        }

        // Hachage du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Générer le token de vérification
        const verificationToken = generateVerificationToken();
        const expiresAt = getExpirationDate();

        // Enregistrer dans pending_registrations (pas dans users)
        const [result] = await pool.execute(
            `INSERT INTO pending_registrations 
            (prenom, nom, country_code, telephone, email, password, verification_token, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [prenom, nom, countryCode, telephone, email, hashedPassword, verificationToken, expiresAt]
        );

        const pendingId = result.insertId;

        // Enregistrer l'action d'audit
        await pool.execute(
            'INSERT INTO registration_audit (email, action) VALUES (?, ?)',
            [email, 'pending']
        );

        console.log(`✅ Inscription en attente créée (ID: ${pendingId}) pour: ${email}`);

        // Envoyer l'email de vérification
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

// Route de vérification d'email (Nouvelle logique)
app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).json({ 
            success: false, 
            message: 'Token manquant' 
        });
    }

    try {
        // Vérifier si le token existe dans pending_registrations
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

        // Vérifier si le token est expiré
        if (now > expiresAt) {
            // Supprimer l'inscription expirée
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

        // Vérifier si l'email ou téléphone existe déjà dans users (cas rare)
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE email = ? OR telephone = ?',
            [pendingUser.email, pendingUser.telephone]
        );

        if (existingUsers.length > 0) {
            // Supprimer l'inscription en attente
            await pool.execute(
                'DELETE FROM pending_registrations WHERE id = ?',
                [pendingUser.id]
            );
            
            return res.status(400).json({ 
                success: false, 
                message: 'Cet email ou numéro de téléphone est déjà utilisé.' 
            });
        }

        // Créer l'utilisateur dans la table users
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

        // Supprimer l'inscription en attente
        await pool.execute(
            'DELETE FROM pending_registrations WHERE id = ?',
            [pendingUser.id]
        );

        // Enregistrer l'action d'audit
        await pool.execute(
            'INSERT INTO registration_audit (email, action) VALUES (?, ?)',
            [pendingUser.email, 'verified']
        );

        console.log(`✅ Utilisateur créé (ID: ${userId}) après vérification: ${pendingUser.email}`);

        // Envoyer un email de bienvenue
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
            expires_in: Math.max(0, Math.floor((expiresAt - now) / 1000 / 60)) // en minutes
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
        // Vérifier si l'inscription en attente existe
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

        // Vérifier si l'inscription est encore valide
        if (now > expiresAt) {
            return res.status(400).json({ 
                success: false, 
                message: 'L\'inscription a expiré. Veuillez vous réinscrire.' 
            });
        }

        // Générer un nouveau token
        const newToken = generateVerificationToken();
        const newExpiresAt = getExpirationDate();

        // Mettre à jour le token
        await pool.execute(
            `UPDATE pending_registrations 
             SET verification_token = ?, expires_at = ? 
             WHERE id = ?`,
            [newToken, newExpiresAt, pending.id]
        );

        // Envoyer le nouvel email
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

// Route pour vérifier si un utilisateur existe
app.post('/api/check-user-exists', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email requis' });
    }

    try {
        const [users] = await pool.execute(
            'SELECT id, email, prenom FROM users WHERE email = ?',
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

// ============================
// ROUTES DE RÉINITIALISATION DE MOT DE PASSE
// ============================

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
        // Hasher le token pour le comparer
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

    // Validation
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
        // Hasher le token pour le comparer
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        console.log('🔍 Vérification token pour réinitialisation:', tokenHash.substring(0, 20) + '...');

        // Vérifier le token
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

        // Hasher le nouveau mot de passe
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Mettre à jour le mot de passe de l'utilisateur
        await pool.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, resetToken.user_id]
        );

        // Marquer le token comme utilisé
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

// Démarrer le serveur
async function startServer() {
    await createPool();
    
    // Nettoyer les inscriptions expirées au démarrage
    await cleanExpiredRegistrations();
    
    // Nettoyer toutes les heures
    setInterval(cleanExpiredRegistrations, 60 * 60 * 1000);
    
    // Tester la connexion email
    const emailConnected = await emailService.verifyConnection();
    
    app.listen(PORT, () => {
        console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
        console.log(`📝 Page d'inscription: http://localhost:${PORT}/`);
        console.log(`⏳ Page d'attente: http://localhost:${PORT}/waiting-verification`);
        console.log(`📧 Vérification email: ${emailConnected ? '✅ Activée' : '⚠️ Simulation'}`);
    });
}

startServer().catch(console.error);
//_________________________________________________________________________________________
// Route de connexion (Nouvelle route)
app.post('/api/login', async (req, res) => {
    console.log('🔑 Tentative de connexion reçue:', { email: req.body.email, password: '***' });
    
    const { email, password, remember } = req.body;

    // Validation basique
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email et mot de passe requis' 
        });
    }

    try {
        // Rechercher l'utilisateur dans la base de données
        const [users] = await pool.execute(
            'SELECT id, prenom, nom, email, password, verified_at FROM users WHERE email = ?',
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

        // Vérifier si le compte est vérifié
        if (!user.verified_at) {
            return res.status(403).json({ 
                success: false, 
                message: 'Veuillez vérifier votre email avant de vous connecter' 
            });
        }

        // Vérifier le mot de passe
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            console.log('❌ Mot de passe incorrect pour:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Email ou mot de passe incorrect' 
            });
        }

        // Créer une session JWT (ou autre système de session)
        const tokenPayload = {
            id: user.id,
            email: user.email,
            prenom: user.prenom,
            nom: user.nom
        };

        // Créer un token JWT
        const jwt = require('jsonwebtoken');
        const token = jwt.sign(
            tokenPayload, 
            process.env.JWT_SECRET || 'votre_secret_jwt',
            { expiresIn: remember ? '30d' : '24h' } // "Remember me" pour 30 jours
        );

        console.log('✅ Connexion réussie pour:', email);

        // Réponse de succès
        res.json({
            success: true,
            message: 'Connexion réussie',
            token: token,
            user: {
                id: user.id,
                prenom: user.prenom,
                nom: user.nom,
                email: user.email
            },
            remember: remember || false
        });

    } catch (error) {
        console.error('❌ Erreur lors de la connexion:', error);
        res.status(500).json({
            success: false,
            message: 'Erreur serveur lors de la connexion'
        });
    }
});


// Page de réinitialisation de mot de passe
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Page "Mot de passe oublié" (optionnel)
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

//_____________________________________________________________________________________
// Route "Mot de passe oublié" - AJOUTEZ SI MANQUANTE
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
        // Vérifier si l'utilisateur existe
        const [users] = await pool.execute(
            'SELECT id, email, prenom FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            // Pour la sécurité, ne pas révéler que l'email n'existe pas
            console.log('ℹ️ Email non trouvé, réponse générique envoyée');
            return res.json({ 
                success: true, 
                message: 'Si cet email existe, vous recevrez un lien de réinitialisation' 
            });
        }

        const user = users[0];
        
        // Générer un token de réinitialisation
        const crypto = require('crypto');
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        
        // Date d'expiration (1 heure)
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        console.log('📝 Création token pour:', email);
        console.log('   Token hash:', tokenHash.substring(0, 20) + '...');
        console.log('   Expire à:', expiresAt);

        // Supprimer les anciens tokens pour cet utilisateur
        await pool.execute(
            'DELETE FROM password_reset_tokens WHERE user_id = ?',
            [user.id]
        );

        // Stocker le token dans la base de données
        await pool.execute(
            `INSERT INTO password_reset_tokens 
            (user_id, token_hash, expires_at) 
            VALUES (?, ?, ?)`,
            [user.id, tokenHash, expiresAt]
        );

        // Envoyer l'email de réinitialisation
        const appUrl = process.env.APP_URL || 'http://localhost:3000';
        const resetLink = `${appUrl}/reset-password?token=${resetToken}`;
        
        console.log('📧 Tentative d\'envoi email à:', email);
        console.log('   Lien de réinitialisation:', resetLink);
        
        // Utiliser votre service email
        const emailResult = await emailService.sendPasswordResetEmail(email, resetLink, user.prenom);

        if (emailResult.success) {
            console.log('✅ Email envoyé avec succès');
            res.json({
                success: true,
                message: 'Si cet email existe, vous recevrez un lien de réinitialisation'
            });
        } else {
            console.warn('⚠️ Email non envoyé:', emailResult.error);
            
            // Supprimer le token si l'email n'a pas pu être envoyé
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