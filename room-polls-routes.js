
// ==================== ROOM POLLS ROUTES ====================

// Middleware pour vérifier si l'utilisateur est membre d'une room
async function isRoomMember(req, res, next) {
    try {
        const roomId = req.params.id || req.params.roomId;
        const userId = req.user.id;

        const [members] = await pool.execute(
            'SELECT role FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, userId]
        );

        if (members.length === 0) {
            return res.status(403).json({ success: false, message: 'Vous n\'êtes pas membre de cette room' });
        }

        req.roomMember = members[0];
        next();
    } catch (error) {
        console.error('Erreur vérification membre room:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
}

// Middleware pour vérifier si l'utilisateur est admin/owner de la room
async function isRoomAdmin(req, res, next) {
    try {
        const roomId = req.params.id || req.params.roomId;
        const userId = req.user.id;

        const [members] = await pool.execute(
            'SELECT role FROM room_members WHERE room_id = ? AND user_id = ? AND role = \'admin\'',
            [roomId, userId]
        );

        if (members.length === 0) {
            return res.status(403).json({ success: false, message: 'Seuls les administrateurs peuvent effectuer cette action' });
        }

        next();
    } catch (error) {
        console.error('Erreur vérification admin room:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
}

// Page de gestion des sondages d'une room
app.get('/room/:id/polls', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        // Récupérer les informations de la room
        const [rooms] = await pool.execute(`
            SELECT r.*, rm.role
            FROM rooms r
            JOIN room_members rm ON r.id = rm.room_id
            WHERE r.id = ? AND rm.user_id = ?
        `, [roomId, userId]);

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

// Créer un sondage dans une room (admin only)
app.post('/api/rooms/:roomId/polls', requireAuth, isRoomMember, isRoomAdmin, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;
        const { title, question, description, poll_type, options, closes_at, is_anonymous } = req.body;

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

// Récupérer tous les sondages d'une room pour la gestion
app.get('/api/rooms/:roomId/polls-management', requireAuth, isRoomMember, async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const userId = req.user.id;

        // Récupérer tous les sondages
        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name,
                   r.name as room_name,
                   (SELECT COUNT(DISTINCT user_id) FROM room_poll_votes WHERE poll_id = rp.id) as voter_count
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.room_id = ?
            ORDER BY rp.created_at DESC
        `, [roomId]);

        // Pour chaque sondage, récupérer les options et vérifier si l'utilisateur a voté
        for (let poll of polls) {
            const [options] = await pool.execute(`
                SELECT * FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
            `, [poll.id]);

            const [votes] = await pool.execute(`
                SELECT * FROM room_poll_votes WHERE poll_id = ? AND user_id = ?
            `, [poll.id, userId]);

            poll.options = options;
            poll.has_voted = votes.length > 0;
        }

        res.json({
            success: true,
            polls: polls
        });

    } catch (error) {
        console.error('Erreur récupération sondages:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Récupérer les détails d'un sondage
app.get('/api/rooms/:roomId/polls/:pollId', requireAuth, isRoomMember, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const roomId = req.params.roomId;

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
            return res.status(404).json({ success: false, message: 'Sondage non trouvé' });
        }

        const poll = polls[0];

        // Récupérer les options
        const [options] = await pool.execute(`
            SELECT * FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
        `, [pollId]);

        poll.options = options;

        res.json({
            success: true,
            poll: poll
        });

    } catch (error) {
        console.error('Erreur récupération sondage:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Récupérer les résultats détaillés d'un sondage
app.get('/api/rooms/:roomId/polls/:pollId/results', requireAuth, isRoomMember, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const roomId = req.params.roomId;

        const [polls] = await pool.execute(`
            SELECT rp.*, 
                   CONCAT(u.prenom, ' ', u.nom) as creator_name
            FROM room_polls rp
            JOIN users u ON rp.created_by = u.id
            WHERE rp.id = ? AND rp.room_id = ?
        `, [pollId, roomId]);

        if (polls.length === 0) {
            return res.status(404).json({ success: false, message: 'Sondage non trouvé' });
        }

        const poll = polls[0];

        // Récupérer les options avec les votes
        const [options] = await pool.execute(`
            SELECT * FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
        `, [pollId]);

        poll.options = options;
        poll.total_votes = options.reduce((sum, opt) => sum + (opt.vote_count || 0), 0);

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

// Voter pour un sondage
app.post('/api/rooms/polls/:pollId/vote', requireAuth, async (req, res) => {
    try {
        const pollId = req.params.pollId;
        const userId = req.user.id;
        const { option_id } = req.body;

        if (!option_id) {
            return res.status(400).json({ success: false, message: 'Option requise' });
        }

        // Récupérer le sondage
        const [polls] = await pool.execute(`
            SELECT rp.*, r.id as room_id
            FROM room_polls rp
            JOIN rooms r ON rp.room_id = r.id
            WHERE rp.id = ?
        `, [pollId]);

        if (polls.length === 0) {
            return res.status(404).json({ success: false, message: 'Sondage non trouvé' });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est membre de la room
        const [members] = await pool.execute(
            'SELECT role FROM room_members WHERE room_id = ? AND user_id = ?',
            [roomId, userId]
        );

        if (members.length === 0) {
            return res.status(403).json({ success: false, message: 'Vous n\'êtes pas membre de cette room' });
        }

        // Vérifier si le sondage est actif
        if (poll.status !== 'active') {
            return res.status(400).json({ success: false, message: 'Ce sondage est fermé' });
        }

        // Vérifier si l'utilisateur a déjà voté (pour vote unique)
        if (poll.poll_type === 'single') {
            const [existingVotes] = await pool.execute(
                'SELECT id FROM room_poll_votes WHERE poll_id = ? AND user_id = ?',
                [pollId, userId]
            );

            if (existingVotes.length > 0) {
                return res.status(400).json({ success: false, message: 'Vous avez déjà voté pour ce sondage' });
            }
        }

        // Enregistrer le vote
        await pool.execute(`
            INSERT INTO room_poll_votes (poll_id, user_id, option_id)
            VALUES (?, ?, ?)
        `, [pollId, userId, option_id]);

        // Récupérer les résultats mis à jour
        const [options] = await pool.execute(`
            SELECT * FROM room_poll_options WHERE poll_id = ? ORDER BY option_order
        `, [pollId]);

        const total_votes = options.reduce((sum, opt) => sum + (opt.vote_count || 0), 0);

        // Émettre l'événement Socket.IO pour mise à jour en temps réel
        io.to(`poll_${pollId}`).emit('vote-update', {
            poll_id: pollId,
            results: {
                options: options,
                total_votes: total_votes
            }
        });

        console.log(`✅ Vote enregistré pour sondage ${pollId} par user ${userId}`);

        res.json({
            success: true,
            message: 'Vote enregistré avec succès'
        });

    } catch (error) {
        console.error('Erreur enregistrement vote:', error);

        // Gérer l'erreur de contrainte unique (déjà voté)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ success: false, message: 'Vous avez déjà voté pour ce sondage' });
        }

        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Fermer un sondage (admin only)
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
            return res.status(404).json({ success: false, message: 'Sondage non trouvé' });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [members] = await pool.execute(
            'SELECT role FROM room_members WHERE room_id = ? AND user_id = ? AND role = \'admin\'',
            [roomId, userId]
        );

        if (members.length === 0) {
            return res.status(403).json({ success: false, message: 'Seuls les administrateurs peuvent fermer un sondage' });
        }

        // Fermer le sondage
        await pool.execute(`
            UPDATE room_polls SET status = 'closed' WHERE id = ?
        `, [pollId]);

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

// Supprimer un sondage (admin only)
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
            return res.status(404).json({ success: false, message: 'Sondage non trouvé' });
        }

        const poll = polls[0];
        const roomId = poll.room_id;

        // Vérifier que l'utilisateur est admin de la room
        const [members] = await pool.execute(
            'SELECT role FROM room_members WHERE room_id = ? AND user_id = ? AND role = \'admin\'',
            [roomId, userId]
        );

        if (members.length === 0) {
            return res.status(403).json({ success: false, message: 'Seuls les administrateurs peuvent supprimer un sondage' });
        }

        // Supprimer le sondage (les votes et options seront supprimés en cascade)
        await pool.execute(`
            DELETE FROM room_polls WHERE id = ?
        `, [pollId]);

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

// ==================== DÉMARRAGE DU SERVEUR ====================

// Initialiser la connexion à la base de données puis démarrer le serveur
createPool().then(() => {
    httpServer.listen(PORT, () => {
        console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
        console.log(`⚡ Socket.IO activé`);
    });
}).catch(error => {
    console.error('❌ Erreur lors du démarrage:', error);
    process.exit(1);
});
