require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Configuration
const config = {
    port: process.env.PORT || 3000,
    mongoUri: process.env.MONGODB_URI,
    jwtSecret: process.env.JWT_SECRET,
    systemUserId: process.env.SYSTEM_USER_ID,
    dailyRequestLimit: parseInt(process.env.DAILY_REQUEST_LIMIT) || 3000,
    url: process.env.URL || 'http://localhost'
};

const app = express();

// Dummy Recipes
const dummyRecipes = [
    {
        title: "Classic Spaghetti",
        description: "Traditional Italian pasta dish",
        items: ["spaghetti", "tomato sauce", "ground beef", "garlic", "olive oil"],
        cookingTime: 30,
        category: "Main Course",
        image: "https://images.immediate.co.uk/production/volatile/sites/30/2020/08/chorizo-mozarella-gnocchi-bake-cropped-9ab73a3.jpg",
        userId: config.systemUserId,
        isSystem: true
    },
    {
        title: "Chocolate Chip Cookies",
        description: "Soft and chewy cookies",
        items: ["flour", "sugar", "butter", "chocolate chips", "eggs"],
        cookingTime: 25,
        category: "Dessert",
        image: "https://images.immediate.co.uk/production/volatile/sites/30/2020/08/chorizo-mozarella-gnocchi-bake-cropped-9ab73a3.jpg",
        userId: config.systemUserId,
        isSystem: true
    },
    {
        title: "Apple Pie",
        description: "Classic American dessert",
        items: ["apples", "flour", "sugar", "butter", "cinnamon"],
        cookingTime: 75,
        category: "Dessert",
        image: "https://images.immediate.co.uk/production/volatile/sites/30/2020/08/chorizo-mozarella-gnocchi-bake-cropped-9ab73a3.jpg",
        userId: config.systemUserId,
        isSystem: true
    }
];

// Middleware
app.use(express.json());

// MongoDB Connection
const connectDB = async () => {
    try {
        await mongoose.connect(config.mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('MongoDB connected successfully');
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

// Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const recipeSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, default: '' },
    items: [{ type: String }],
    cookingTime: { type: Number, required: true },
    category: { type: String, required: true },
    image: { type: String, default: '' },
    userId: { type: String, required: true },
    isSystem: { type: Boolean, default: false }
});
const Recipe = mongoose.model('Recipe', recipeSchema);

const tokenUsageSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    requestCount: { type: Number, default: 0 },
    lastReset: { type: Date, default: Date.now }
});
const TokenUsage = mongoose.model('TokenUsage', tokenUsageSchema);

// Rate Limiting Middleware
const rateLimitMiddleware = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const decoded = jwt.verify(token, config.jwtSecret);
        req.user = decoded;

        let usage = await TokenUsage.findOne({ token });
        const now = new Date();

        if (!usage) {
            usage = new TokenUsage({ token, requestCount: 0, lastReset: now });
        } else if (isNewDay(usage.lastReset)) {
            usage.requestCount = 0;
            usage.lastReset = now;
        }

        if (usage.requestCount >= config.dailyRequestLimit) {
            return res.status(429).json({
                error: 'Daily request limit exceeded',
                limit: config.dailyRequestLimit,
                remaining: 0
            });
        }

        usage.requestCount += 1;
        await usage.save();

        res.set('X-Rate-Limit-Limit', config.dailyRequestLimit);
        res.set('X-Rate-Limit-Remaining', config.dailyRequestLimit - usage.requestCount);
        res.set('X-Rate-Limit-Reset', getNextResetTime(usage.lastReset));

        next();
    } catch (error) {
        res.status(403).json({ error: 'Invalid token' });
    }
};

// Helper Functions
const isNewDay = (lastReset) => {
    const now = new Date();
    const resetDate = new Date(lastReset);
    return now.getDate() !== resetDate.getDate() ||
        now.getMonth() !== resetDate.getMonth() ||
        now.getFullYear() !== resetDate.getFullYear();
};

const getNextResetTime = (lastReset) => {
    const reset = new Date(lastReset);
    reset.setDate(reset.getDate() + 1);
    reset.setHours(0, 0, 0, 0);
    return reset.toISOString();
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) throw new Error('Username and password required');

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            throw new Error('Invalid credentials');
        }

        const token = jwt.sign({ id: user._id, username: user.username }, config.jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(error.message === 'Invalid credentials' ? 401 : 500).json({ error: error.message });
    }
});

app.post('/api/recipes', rateLimitMiddleware, async (req, res) => {
    try {
        const { title, description, items, cookingTime, category, image } = req.body;
        if (!title || !category || !items || !cookingTime) {
            throw new Error('Missing required fields');
        }

        const recipe = new Recipe({
            title,
            description,
            items: Array.isArray(items) ? items : [],
            cookingTime: parseInt(cookingTime),
            category,
            image,
            userId: req.user.id,
            isSystem: false
        });

        await recipe.save();
        res.status(201).json(recipe);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/recipes', rateLimitMiddleware, async (req, res) => {
    try {
        const recipes = await Recipe.find({
            $or: [{ userId: req.user.id }, { isSystem: true }]
        });
        res.json(recipes);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/recipes/:id', rateLimitMiddleware, async (req, res) => {
    try {
        const recipe = await Recipe.findOne({
            _id: req.params.id,
            $or: [{ userId: req.user.id }, { isSystem: true }]
        });
        if (!recipe) throw new Error('Recipe not found');
        res.json(recipe);
    } catch (error) {
        res.status(error.message === 'Recipe not found' ? 404 : 500).json({ error: error.message });
    }
});

app.get('/api/recipes/filter', rateLimitMiddleware, async (req, res) => {
    try {
        const { name } = req.query;
        if (!name) throw new Error('Name query parameter is required');

        const recipes = await Recipe.find({
            $or: [{ userId: req.user.id }, { isSystem: true }],
            title: { $regex: name, $options: 'i' }
        });
        res.json(recipes);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/recipes/:id', rateLimitMiddleware, async (req, res) => {
    try {
        const recipe = await Recipe.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id, isSystem: false },
            { $set: req.body },
            { new: true, runValidators: true }
        );
        if (!recipe) throw new Error('Recipe not found or cannot be updated (system recipe)');
        res.json(recipe);
    } catch (error) {
        res.status(error.message.includes('not found') ? 404 : 400).json({ error: error.message });
    }
});

app.delete('/api/recipes/:id', rateLimitMiddleware, async (req, res) => {
    try {
        const recipe = await Recipe.findOneAndDelete({
            _id: req.params.id,
            userId: req.user.id,
            isSystem: false
        });
        if (!recipe) throw new Error('Recipe not found or cannot be deleted (system recipe)');
        res.status(204).send();
    } catch (error) {
        res.status(error.message.includes('not found') ? 404 : 500).json({ error: error.message });
    }
});

// Initialize Data
const insertDummyData = async () => {
    try {
        await Recipe.deleteMany({ userId: config.systemUserId });
        await Recipe.insertMany(dummyRecipes);
        console.log('Dummy data inserted successfully');
    } catch (error) {
        console.error('Error inserting dummy data:', error);
    }
};

// Start Server
const startServer = async () => {
    await connectDB();
    app.listen(config.port, () => {
        console.log(`Server running at ${config.url}:${config.port}`);
        insertDummyData();
    });
};

startServer();