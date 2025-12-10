const nodemailer = require('nodemailer');
require('dotenv').config();

class EmailService {
    constructor() {
        // Configuration SMTP améliorée avec fallback
        const emailConfig = {
            host: process.env.EMAIL_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.EMAIL_PORT) || 587,
            secure: process.env.EMAIL_PORT === '465', // true pour le port 465
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            // Options supplémentaires pour meilleure compatibilité
            tls: {
                rejectUnauthorized: false
            },
            // Timeout augmenté
            connectionTimeout: 10000, // 10 secondes
            greetingTimeout: 10000,
            socketTimeout: 10000
        };

        console.log('📧 Configuration email:', {
            host: emailConfig.host,
            port: emailConfig.port,
            user: emailConfig.auth.user ? 'Défini' : 'Non défini'
        });

        this.transporter = nodemailer.createTransport(emailConfig);
    }

    // Tester la connexion SMTP
    async verifyConnection() {
        try {
            await this.transporter.verify();
            console.log('✅ Serveur SMTP connecté avec succès');
            return true;
        } catch (error) {
            console.error('❌ Erreur de connexion SMTP:', error.message);
            
            // Afficher des conseils de dépannage
            if (error.code === 'EAUTH') {
                console.log('🔍 Conseil: Vérifiez vos identifiants SMTP dans .env');
                console.log('🔍 Pour Gmail, utilisez un mot de passe d\'application:');
                console.log('   https://myaccount.google.com/apppasswords');
            } else if (error.code === 'ECONNECTION') {
                console.log('🔍 Conseil: Vérifiez vos paramètres SMTP (host/port)');
            }
            
            return false;
        }
    }

    // Envoyer un email de vérification
    async sendVerificationEmail(email, token, prenom) {
        // Vérifier si les variables d'environnement sont définies
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            console.warn('⚠️ Variables SMTP non configurées. Email simulé.');
            console.log(`📧 [SIMULATION] Email de vérification pour: ${email}`);
            console.log(`📧 [SIMULATION] Token: ${token}`);
            console.log(`📧 [SIMULATION] Lien: ${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${token}`);
            
            return {
                success: true,
                simulated: true,
                message: 'Email simulé (SMTP non configuré)'
            };
        }

        const appUrl = process.env.APP_URL || 'http://localhost:3000';
        const verificationLink = `${appUrl}/verify-email?token=${token}`;
        
        const mailOptions = {
            from: process.env.EMAIL_FROM || `"iVOTE" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Vérification de votre email - iVOTE',
            html: `
                <!DOCTYPE html>
<html>
<head>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; 
            line-height: 1.6; 
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px 20px; 
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 36px;
            font-weight: 800;
            letter-spacing: 2px;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 14px;
            letter-spacing: 1px;
            opacity: 0.9;
        }
        .illustration {
            text-align: center;
            padding: 40px 20px 20px;
            background: white;
        }
        .illustration img {
            max-width: 280px;
            height: auto;
        }
        .content { 
            background: white; 
            padding: 20px 40px 40px;
        }
        .content h2 {
            font-size: 24px;
            color: #1a1a1a;
            margin-bottom: 20px;
        }
        .content p {
            margin: 15px 0;
            font-size: 16px;
            color: #4a4a4a;
        }
        .highlight {
            color: #667eea;
            font-weight: 600;
        }
        .button { 
            display: inline-block; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 16px 48px; 
            text-decoration: none; 
            border-radius: 50px; 
            margin: 20px 0;
            font-weight: 700;
            font-size: 16px;
            box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
        }
        .warning-box {
            background: linear-gradient(135deg, #fff3cd 0%, #ffe8a1 100%);
            border-left: 4px solid #ffc107;
            border-radius: 8px;
            padding: 18px 20px;
            margin: 25px 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .warning-icon {
            font-size: 24px;
        }
        .warning-text {
            color: #856404;
            font-size: 14px;
            font-weight: 600;
        }
        .divider {
            margin: 30px 0;
            text-align: center;
            position: relative;
        }
        .divider::before {
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            width: 100%;
            height: 1px;
            background: linear-gradient(90deg, transparent, #e0e0e0, transparent);
        }
        .divider-text {
            background: white;
            padding: 0 15px;
            color: #999;
            font-size: 13px;
            position: relative;
        }
        .token-box {
            background: #f8f9fa;
            border: 2px dashed #e0e0e0;
            padding: 20px;
            border-radius: 12px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 20px 0;
        }
        .link-label {
            color: #666;
            font-size: 13px;
            margin-bottom: 8px;
            font-weight: 600;
        }
        .link-text {
            color: #667eea;
            line-height: 1.6;
        }
        .info-box {
            background: #f0f4ff;
            border-radius: 8px;
            padding: 18px 20px;
            margin: 25px 0;
            color: #4a5568;
            font-size: 14px;
        }
        .footer { 
            background: #f8f9fa;
            margin-top: 0; 
            padding: 30px 40px; 
            border-top: 1px solid #e9ecef; 
            color: #6c757d; 
            font-size: 13px;
            text-align: center;
        }
        .footer-links {
            margin: 15px 0;
        }
        .footer-link {
            color: #667eea;
            text-decoration: none;
            margin: 0 12px;
            font-weight: 600;
        }
        .social-icons {
            margin: 20px 0;
        }
        .social-icon {
            display: inline-block;
            width: 36px;
            height: 36px;
            margin: 0 6px;
            background: #667eea;
            border-radius: 50%;
            line-height: 36px;
            color: white;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>iVOTE</h1>
            <p>VOTEZ EN TOUTE SÉCURITÉ</p>
        </div>
        
        <div class="illustration">
            <img src="images/Confirmed-rafiki.svg" alt="Confirmation" />
        </div>
        
        <div class="content">
            <h2>Bonjour ${prenom} ! 👋</h2>
            <p>Bienvenue sur <span class="highlight">iVOTE</span> ! Nous sommes ravis de vous compter parmi nous.</p>
            <p>Pour activer votre compte et commencer à voter en toute sécurité, nous devons vérifier votre adresse email.</p>
            
            <div style="text-align: center;">
                <a href="${verificationLink}" class="button">
                    ✓ Confirmer mon adresse email
                </a>
            </div>
            
            <div class="warning-box">
                <div class="warning-icon">⏰</div>
                <div class="warning-text">
                    Ce lien de vérification expire dans 10 minutes pour votre sécurité
                </div>
            </div>
            
            <div class="divider">
                <span class="divider-text">OU</span>
            </div>
            
            <p>Si le bouton ne fonctionne pas, vous pouvez copier-coller ce lien dans votre navigateur :</p>
            <div class="token-box">
                <div class="link-label">Lien de vérification :</div>
                <div class="link-text">${verificationLink}</div>
            </div>
            
            <div class="info-box">
                <strong>🔒 Sécurité :</strong> Si vous n'avez pas créé de compte sur iVOTE, vous pouvez ignorer cet email en toute sécurité.
            </div>
        </div>
        
        <div class="footer">
            <div class="social-icons">
                <a href="#" class="social-icon">f</a>
                <a href="#" class="social-icon">𝕏</a>
                <a href="#" class="social-icon">in</a>
            </div>
            
            <div class="footer-links">
                <a href="#" class="footer-link">Centre d'aide</a>
                <a href="#" class="footer-link">Conditions</a>
                <a href="#" class="footer-link">Confidentialité</a>
            </div>
            
            <p>© ${new Date().getFullYear()} iVOTE. Tous droits réservés.</p>
            <p>Cet email a été envoyé automatiquement, merci de ne pas y répondre.</p>
        </div>
    </div>
</body>
</html>
            `,
            // Version texte pour les clients qui ne supportent pas HTML
            text: `
                Bonjour ${prenom},
                
                Merci de vous être inscrit sur iVOTE !
                
                Pour vérifier votre email, veuillez cliquer sur le lien suivant :
                ${verificationLink}
                
                Ce lien expirera dans 24 heures.
                
                Si vous n'avez pas créé de compte sur iVOTE, vous pouvez ignorer cet email.
                
                © ${new Date().getFullYear()} iVOTE
            `
        };

        try {
            console.log(`📧 Tentative d'envoi d'email à: ${email}`);
            const info = await this.transporter.sendMail(mailOptions);
            console.log(`✅ Email envoyé à: ${email}`);
            console.log(`📧 Message ID: ${info.messageId}`);
            
            return { 
                success: true, 
                messageId: info.messageId,
                simulated: false
            };
        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi de l\'email:', error.message);
            console.error('❌ Détails:', error);
            
            // Fallback: simuler l'email si l'envoi échoue
            console.log(`📧 [FALLBACK] Email simulé pour: ${email}`);
            console.log(`📧 [FALLBACK] Lien de vérification: ${verificationLink}`);
            
            return { 
                success: false, 
                error: error.message,
                simulated: true,
                fallbackLink: verificationLink
            };
        }
    }

    // Envoyer un email de bienvenue (simplifié)
    async sendWelcomeEmail(email, prenom) {
        console.log(`📧 Email de bienvenue simulé pour: ${email}`);
        return { success: true, simulated: true };
    }
}

module.exports = new EmailService();