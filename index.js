const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");

// Load environment variables from .env file
dotenv.config();
const app = express();
const port = process.env.PORT || 5000;
const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);


// Middleware
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.pkaqrby.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: false,
        deprecationErrors: true,
    }
});

let articlesCollection, usersCollection, publishersCollection, plansCollection

// Database connection check middleware
app.use((req, res, next) => {
    if (!articlesCollection) {
        return res.status(503).json({
            message: "Database is connecting. Please try again in a moment."
        });
    }
    next();
});

async function verifyFirebaseToken(req, res, next) {
    const authHeader = req.headers?.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: "Unauthorized Token" })
    }
    const idToken = authHeader.split(' ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken;
        next()
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" })
    }
}

async function run() {
    try {
        // Connect the client to the server
        await client.connect();

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        // Initialize collections (GLOBAL)
        const db = client.db("newspaperDB");
        articlesCollection = db.collection("articles");
        usersCollection = db.collection("users");
        publishersCollection = db.collection("publishers");
        plansCollection = db.collection("plans");

        console.log("Database collections initialized successfully");

        // Start server AFTER database is connected
        app.listen(port, () => {
            console.log(`Server is up and running on port ${port}`);
        });

    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
}

run().catch(console.dir);

// ================== USERS ROUTES ================== //

//  Add or update user (when user registers/login via Firebase)
app.post('/users', async (req, res) => {
    try {
        const { uid, name, email, photoURL } = req.body;
        if (!uid || !email) {
            return res.status(400).json({ message: 'UID and email are required' });
        }

        const existingUser = await usersCollection.findOne({ uid });

        if (existingUser) {
            // Update existing user info
            await usersCollection.updateOne(
                { uid },
                { $set: { name, email, photoURL } }
            );
            return res.status(200).json({ message: 'User updated successfully' });
        } else {
            // Add new user
            const newUser = {
                uid,
                name,
                email,
                photoURL: photoURL || '',
                role: 'user',      // default role
                premiumTaken: null, // for subscription
                createdAt: new Date()
            };
            await usersCollection.insertOne(newUser);
            return res.status(201).json({ message: 'User created successfully' });
        }
    } catch (error) {
        console.error('Add/Update user error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get all users (for Admin Dashboard )
app.get('/users', verifyFirebaseToken, async (req, res) => {
    try {
        const userEmail = req.query.email;

        if (userEmail) {
            const user = await usersCollection.findOne({ email: userEmail });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            return res.status(200).json(user);
        }

        // Multiple users - admin only (for dashboard)
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        const users = await usersCollection.find().sort({ createdAt: -1 }).toArray();
        res.status(200).json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: error.message });
    }
});


// ================== STRIPE PAYMENT ROUTES ================== //

// Create Payment Intent
app.post('/create-payment-intent', verifyFirebaseToken, async (req, res) => {
    try {
        const { plan } = req.body;
        const userEmail = req.user.email;

        const plans = {
            '1 minute': { amount: 10 },
            '5 days': { amount: 500 },
            '10 days': { amount: 800 }
        };

        const selectedPlan = plans[plan];
        if (!selectedPlan) {
            return res.status(400).json({ message: 'Invalid plan' });
        }


        const paymentIntent = await stripe.paymentIntents.create({
            amount: selectedPlan.amount,
            currency: 'usd',
            metadata: {
                userEmail: userEmail,
                plan: plan
            }
        });

        res.json({
            clientSecret: paymentIntent.client_secret,
            amount: selectedPlan.amount
        });
    } catch (error) {
        console.error('Payment intent error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Confirm Payment and Activate Premium
app.post('/confirm-payment', verifyFirebaseToken, async (req, res) => {
    try {
        const { paymentIntentId } = req.body;
        const userEmail = req.user.email;

        // Retrieve payment intent to verify it succeeded
        const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

        if (paymentIntent.status !== 'succeeded') {
            return res.status(400).json({ message: 'Payment not successful' });
        }

        // Get plan from metadata
        const plan = paymentIntent.metadata.plan;

        // Calculate expiry date
        let expiryDate = new Date();
        if (plan === '1 minute') {
            expiryDate.setMinutes(expiryDate.getMinutes() + 1);
        } else if (plan === '5 days') {
            expiryDate.setDate(expiryDate.getDate() + 5);
        } else if (plan === '10 days') {
            expiryDate.setDate(expiryDate.getDate() + 10);
        }

        // Update user premium status
        await usersCollection.updateOne(
            { email: userEmail },
            { $set: { premiumTaken: expiryDate } }
        );

        res.json({
            success: true,
            message: 'Payment confirmed and premium activated!',
            expiryDate: expiryDate
        });

    } catch (error) {
        console.error('Confirm payment error:', error);
        res.status(500).json({ message: error.message });
    }
});

// PREMIUM ARTICLES ROUTE
app.get('/articles/premium', verifyFirebaseToken, async (req, res) => {
    try {
        const user = await usersCollection.findOne({ email: req.user.email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.premiumTaken || new Date() > new Date(user.premiumTaken)) {
            return res.status(403).json({ message: 'Premium subscription required' });
        }

        const articles = await articlesCollection.find({
            isPremium: true,
            status: 'approved'
        }).toArray();

        res.json(articles);
    } catch (error) {
        console.error('Premium articles error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get single user by UID
app.get('/users/:uid', verifyFirebaseToken, async (req, res) => {
    try {
        const { uid } = req.params;
        if (!uid) return res.status(400).json({ message: "UID is required" });

        const user = await usersCollection.findOne({ uid });
        if (!user) return res.status(404).json({ message: "User not found" });

        res.status(200).json(user);
    } catch (error) {
        console.error('Get user by UID error:', error);
        res.status(500).json({ message: error.message });
    }
});

//  Make admin / update role
app.put('/users/:id/role', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        // Only admin can update roles
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role' });
        }

        const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role } }
        );

        if (result.modifiedCount === 1) {
            res.status(200).json({ message: `User role updated to ${role}` });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({ message: error.message });
    }
});

//  NEW: Delete user (Admin only)
app.delete('/users/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if ID is valid
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid user ID' });
        }

        // Only admin can delete users
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        // Check if user exists
        const userToDelete = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (!userToDelete) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Prevent admin from deleting themselves
        if (userToDelete.uid === req.user.uid) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }

        // Delete user from database
        const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 1) {
            res.json({
                message: 'User deleted successfully',
                deletedUser: {
                    id: userToDelete._id,
                    email: userToDelete.email,
                    name: userToDelete.name
                }
            });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error while deleting user' });
    }
});

// Admin: Get all articles (with pagination + search/filter)
app.get('/admin/articles', verifyFirebaseToken, async (req, res) => {
    try {
        // check admin
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        let query = {};

        // Search by title
        if (req.query.search) {
            query.title = { $regex: req.query.search, $options: 'i' };
        }

        // Filter by status
        if (req.query.status) {
            query.status = req.query.status;
        }

        // Pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const total = await articlesCollection.countDocuments(query);
        const articles = await articlesCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

        res.status(200).json({
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
            articles
        });
    } catch (error) {
        console.error('Admin get articles error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Update article status by admin
app.patch('/admin/articles/:id/status', verifyFirebaseToken, async (req, res) => {
    try {
        // check admin
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        const { id } = req.params;
        const { status, declineReason } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid article ID' });
        }

        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }

        const article = await articlesCollection.findOne({ _id: new ObjectId(id) });
        if (!article) {
            return res.status(404).json({ message: 'Article not found' });
        }

        // Prepare update data
        const updateData = { status };
        if (status === 'rejected' && declineReason) {
            updateData.declineReason = declineReason;
        } else if (status === 'approved') {
            updateData.declineReason = null; // Clear decline reason if approved
        }

        await articlesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        res.json({
            message: `Article status updated to ${status}`,
            declineReason: status === 'rejected' ? declineReason : null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
    }
});
// ================== PREMIUM ARTICLE TOGGLE ROUTE ================== //
app.patch('/admin/articles/:id/premium', verifyFirebaseToken, async (req, res) => {
    try {
        // Check if requester is admin
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        const { id } = req.params;
        const { isPremium } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid article ID' });
        }

        if (typeof isPremium !== 'boolean') {
            return res.status(400).json({ message: 'isPremium must be a boolean value' });
        }

        // Check if article exists
        const article = await articlesCollection.findOne({ _id: new ObjectId(id) });
        if (!article) {
            return res.status(404).json({ message: 'Article not found' });
        }

        // Update premium status
        const result = await articlesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { isPremium: isPremium } }
        );

        if (result.modifiedCount === 1) {
            res.json({
                message: `Article ${isPremium ? 'marked as premium' : 'removed from premium'} successfully`,
                isPremium: isPremium
            });
        } else {
            res.status(404).json({ message: 'Article not found or no changes made' });
        }

    } catch (error) {
        console.error('Toggle premium status error:', error);
        res.status(500).json({ message: error.message });
    }
});
// Admin: Delete any article
app.delete('/admin/articles/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid article ID" });
        }

        // Check if requester is admin
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: "Forbidden: Admins only" });
        }

        // Check if article exists
        const article = await articlesCollection.findOne({ _id: new ObjectId(id) });
        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        // Delete the article
        await articlesCollection.deleteOne({ _id: new ObjectId(id) });

        res.json({
            message: "Article deleted successfully",
            deletedArticle: {
                id: article._id,
                title: article.title,
                status: article.status
            }
        });
    } catch (error) {
        console.error('Admin delete article error:', error);
        res.status(500).json({ message: "Server error while deleting article" });
    }
});

//  Add Publisher (Admin Only)
app.post('/publishers', verifyFirebaseToken, async (req, res) => {
    try {
        // check if requester is admin
        const requester = await usersCollection.findOne({ uid: req.user.uid });
        if (!requester || requester.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: Admins only' });
        }

        const { name, logo } = req.body;
        if (!name || !logo) {
            return res.status(400).json({ message: "Name and logo are required" });
        }

        const newPublisher = { name, logo, createdAt: new Date() };
        const result = await publishersCollection.insertOne(newPublisher);
        res.status(201).json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

//  Get All Publishers (Public, for dropdown + home page)
app.get('/publishers', async (req, res) => {
    try {
        const result = await publishersCollection.find().toArray();
        res.json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
// ================== STATS ROUTE ==================
app.get('/stats', async (req, res) => {
    try {
        const totalUsers = await usersCollection.countDocuments();

        // Normal users: premiumTaken null or expired
        const normalUsers = await usersCollection.countDocuments({
            $or: [
                { premiumTaken: null },
                { premiumTaken: { $lt: new Date() } }
            ]
        });

        // Premium users: premiumTaken valid (not expired)
        const premiumUsers = await usersCollection.countDocuments({
            premiumTaken: { $gte: new Date() }
        });

        res.json({
            totalUsers,
            normalUsers,
            premiumUsers
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: error.message });
    }
});
// ================== ARTICLE ROUTES ================== //
app.get('/articles/trending', async (req, res) => {
    try {
        const articles = await articlesCollection.find({ status: 'approved' })
            .sort({ views: -1 })
            .limit(6)
            .toArray();
        res.json(articles);
    } catch (error) {
        console.error('Trending articles error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Backend route for filtered articles
app.get('/articles', async (req, res) => {
    try {
        let query = { status: 'approved' };

        // Search by title
        if (req.query.search) {
            query.title = { $regex: req.query.search, $options: 'i' };
        }

        // Filter by publisher
        if (req.query.publisher) {
            query.publisher = req.query.publisher;
        }

        // Filter by tags
        if (req.query.tags) {
            const tagsArray = req.query.tags.split(',');
            query.tags = { $in: tagsArray };
        }

        const articles = await articlesCollection.find(query).toArray();
        res.json(articles);
    } catch (error) {
        console.error('Get articles error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Add a new endpoint to get all unique publishers for filter dropdown
app.get('/articles/publishers', async (req, res) => {
    try {
        const publishers = await articlesCollection.distinct("publisher", { status: 'approved' });
        res.json(publishers);
    } catch (error) {
        console.error('Get publishers error:', error);
        res.status(500).json({ message: error.message });
    }
});

app.get('/tags', async (req, res) => {
    try {
        const tags = await articlesCollection.distinct("tags", { status: 'approved' });

        const normalizedTags = tags
            .filter(Boolean)
            .flatMap(tag => Array.isArray(tag) ? tag : [tag]);

        const uniqueTags = [...new Set(normalizedTags)];
        res.json(uniqueTags);
    } catch (error) {
        console.error("Tags API Error:", error);
        res.status(500).json({ message: error.message });
    }
});

// ================== ARTICLE DETAILS ROUTE ================== //
app.get('/articles/:id', async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid article ID" });
        }

        const article = await articlesCollection.findOne({
            _id: new ObjectId(id),
            status: 'approved'
        });

        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        // Increment views
        await articlesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $inc: { views: 1 } }
        );

        res.json(article);

    } catch (error) {
        console.error('Article details error:', error);
        res.status(500).json({ message: error.message });
    }
});

// articles add 
app.post('/articles', verifyFirebaseToken, async (req, res) => {
    try {
        const { title, image, publisher, tags, description } = req.body;

        // Validation
        if (!title || !image || !publisher || !tags || !description) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const article = {
            title,
            image,
            publisher,
            tags: Array.isArray(tags) ? tags : [tags],
            description,
            status: 'pending',
            author: req.user.email,
            authorId: req.user.uid,
            createdAt: new Date(),
            views: 0,
            isPremium: false,
            declineReason: null
        };

        const result = await articlesCollection.insertOne(article);
        res.status(201).json({
            message: "Article submitted successfully! Waiting for admin approval.",
            articleId: result.insertedId
        });

    } catch (error) {
        console.error('Add article error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get user's articles with decline reason
app.get('/my-articles', verifyFirebaseToken, async (req, res) => {
    try {
        const articles = await articlesCollection.find({
            authorId: req.user.uid
        }).sort({ createdAt: -1 }).toArray();
        res.json(articles);
    } catch (error) {
        console.error('Get my-articles error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Delete article
app.delete('/article/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid article ID" });
        }

        const article = await articlesCollection.findOne({
            _id: new ObjectId(id),
            authorId: req.user.uid
        });

        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        // Only allow delete if article is pending or declined
        if (article.status === 'approved') {
            return res.status(400).json({ message: "Cannot delete approved articles" });
        }

        await articlesCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "Article deleted successfully" });

    } catch (error) {
        console.error('Delete article error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Update article
app.put('/articles/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, tags } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid article ID" });
        }

        const article = await articlesCollection.findOne({
            _id: new ObjectId(id),
            authorId: req.user.uid
        });

        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        // Only allow update if article is pending or declined
        if (article.status === 'approved') {
            return res.status(400).json({ message: "Cannot update approved articles" });
        }

        const updateData = {
            title,
            description,
            tags: Array.isArray(tags) ? tags : [tags],
            updatedAt: new Date()
        };

        await articlesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        res.json({ message: "Article updated successfully" });

    } catch (error) {
        console.error('Update article error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get article by ID (details view)
app.get('/my-article/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid article ID" });
        }

        const article = await articlesCollection.findOne({
            _id: new ObjectId(id),
            authorId: req.user.uid
        });

        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        res.json(article);
    } catch (error) {
        console.error('Get my-article error:', error);
        res.status(500).json({ message: error.message });
    }
});
// Plans Route
app.get("/plans", async (req, res) => {
    try {
        const result = await plansCollection.find().toArray(); // Added ()
        res.status(200).json(result);
    }
    catch (error) {
        console.error("Get plans error:", error);
        res.status(500).json({ message: error.message });
    }
});
// Sample route
app.get('/', (req, res) => {
    res.json({ message: 'Newspaper FullStack Server is running smoothly!' });
});