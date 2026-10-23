const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'anaAndNesrin42494249Alla$$$';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const dbURI = 'mongodb+srv://nesrinallalen_db_user:<db_password>@cluster0.6bviy5m.mongodb.net/';
mongoose.connect(dbURI)
    .then(() => console.log('Connected to MongoDB!'))
    .catch(err => console.error(err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' } 
});
const User = mongoose.model('User', userSchema);
const postSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], 
    comments: [{
        username: { type: String, required: true },
        text: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
    }]
});
const Post = mongoose.model('Post', postSchema);
const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send('Access Denied. Please log in.');

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid Session Token.');
    }
};
const requireRole = (allowedRoles) => {
    return async (req, res, next) => {
        try {
            const user = await User.findOne({ username: req.user.username });
    
            if (!user || !allowedRoles.includes(user.role)) {
                return res.status(403).send('Access Denied: You do not have permission to post.');
            }
            
            next();
        } catch (err) {
            res.status(500).send('Server authorization error.');
        }
    };
};

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const userExists = await User.findOne({ username });
        if (userExists) return res.status(400).send('Username already taken.');

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).send('Registration successful!');
    } catch (err) {
        res.status(500).send('Registration error.');
    }
});
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('User not found.');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Incorrect password.');

        const token = jwt.sign({ id: user._index, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        res.cookie('token', token, { httpOnly: true });
        res.status(200).send('Logged in successfully!');
    } catch (err) {
        res.status(500).send('Login error.');
    }
});

app.get('/profile', verifyToken, (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Dashboard</title></head>
        <body>
            <h1>Welcome to your Dashboard, ${req.user.username}!</h1>
            <p>This is secure, private information meant only for you.</p>
            <button onclick="window.location.href='/logout'">Log Out</button>
        </body>
        </html>
    `);
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.send('Logged out! <a href="http://localhost:3000/login.html">Login again</a>');
});
app.post('/api/posts', verifyToken, requireRole(['creator', 'admin']), async (req, res) => {
    try {
        const { content } = req.body;
        
        const newPost = new Post({
            username: req.user.username, 
            content: content
        });
        
        await newPost.save();
        res.status(201).send('Post published successfully!');
    } catch (err) {
        res.status(500).send('Failed to save post.');
    }
});

app.get('/api/posts', verifyToken, async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).send('Failed to load posts.');
    }
});

app.use(express.static(__dirname));
app.get('/api/admin/users', verifyToken, requireRole(['admin']), async (req, res) => {
    try {
        const users = await User.find({}, 'username role');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch user list.' });
    }
});

app.put('/api/admin/update-role', verifyToken, requireRole(['admin']), async (req, res) => {
    try {
        const { username, newRole } = req.body;
        if (username === req.user.username) {
            return res.status(400).send('You cannot change your own role.');
        }
        if (!['user', 'creator', 'admin'].includes(newRole)) {
            return res.status(400).send('Invalid role specified.');
        }

        const updatedUser = await User.findOneAndUpdate(
            { username: username },
            { role: newRole },
            { new: true } 
        );

        if (!updatedUser) return res.status(404).send('User not found.');

        res.status(200).send(`Successfully updated @${username} to ${newRole}!`);
    } catch (err) {
        res.status(500).send('Server error while updating role.');
    }
});

app.get('/admin', verifyToken, requireRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});
app.post('/api/posts/:id/like', verifyToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).send('Post not found.');
        const userId = req.user.id; 
        const likeIndex = post.likes.indexOf(userId);

        if (likeIndex === -1) {
            post.likes.push(userId);
            await post.save();
            return res.status(200).json({ message: 'Liked', likeCount: post.likes.length });
        } else {
            post.likes.splice(likeIndex, 1);
            await post.save();
            return res.status(200).json({ message: 'Unliked', likeCount: post.likes.length });
        }
    } catch (err) {
        res.status(500).send('Server error processing like.');
    }
});

app.post('/api/posts/:id/comment', verifyToken, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || !text.trim()) return res.status(400).send('Comment cannot be empty.');

        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).send('Post not found.');
        post.comments.push({
            username: req.user.username,
            text: text
        });

        await post.save();
        res.status(201).json(post.comments);
    } catch (err) {
        res.status(500).send('Server error processing comment.');
    }
});


app.listen(PORT, () => console.log(`Server live at http://localhost:${PORT}`));
