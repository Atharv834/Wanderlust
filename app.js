// ============================================
// SECURE WANDERLUST APPLICATION
// Application Security Engineer: Comprehensive Refactoring
// ============================================

require('dotenv').config(); // Load environment variables first

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const Listing = require("./models/list.js");
const Review = require("./models/reviews.js"); // FIXED: Missing import
const path = require("path");
const methodOverride = require("method-override");
const ejsMate = require("ejs-mate");
const ExpressError = require("./ExpressError");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const User = require("./models/user.js");

// ============================================
// SECURITY MIDDLEWARE IMPORTS
// ============================================
const helmet = require("helmet"); // Security headers
const mongoSanitize = require("express-mongo-sanitize"); // NoSQL injection prevention
const rateLimit = require("express-rate-limit"); // DDoS protection
const xss = require("xss-clean"); // XSS sanitization
const Joi = require("joi"); // Input validation

// ============================================
// DATABASE CONNECTION WITH ERROR HANDLING
// ============================================
const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/wanderlust';

async function connectDB() {
    try {
        await mongoose.connect(MONGO_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("✅ Secure database connection established");
    } catch (err) {
        console.error("❌ Database connection failed:", err.message);
        process.exit(1); // Exit on critical failure
    }
}

connectDB();

// ============================================
// SECURITY MIDDLEWARE CONFIGURATION
// ============================================

// 1. Helmet - Secure HTTP headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "https://images.unsplash.com", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

// 2. Rate Limiting - Prevent brute force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: "Too many requests from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// 3. NoSQL Injection Protection
app.use(mongoSanitize({
    replaceWith: '_', // Replace prohibited characters
}));

// 4. XSS Protection
app.use(xss());

// ============================================
// VIEW ENGINE & MIDDLEWARE SETUP
// ============================================
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Limit payload size
app.use(express.json({ limit: '10kb' })); // JSON body parser with size limit
app.use(methodOverride("_method"));
app.engine('ejs', ejsMate);
app.use(express.static(path.join(__dirname, "/public")));

// ============================================
// SESSION CONFIGURATION (SECURE)
// ============================================
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

if (!process.env.SESSION_SECRET) {
    console.warn("⚠️ WARNING: Using default session secret. Set SESSION_SECRET in .env");
}

const sessionOptions = {
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Changed to false for better security
    name: 'sessionId', // Obscure session cookie name
    cookie: {
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true, // Prevent XSS access to cookies
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict', // CSRF protection
    },
};

app.use(session(sessionOptions));
app.use(flash());
app.use(cookieParser(SESSION_SECRET)); // Sign cookies

// ============================================
// PASSPORT AUTHENTICATION SETUP
// ============================================
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// ============================================
// VALIDATION SCHEMAS (JOI)
// ============================================
const listingSchema = Joi.object({
    listing: Joi.object({
        title: Joi.string().required().trim().max(100),
        description: Joi.string().required().trim().max(1000),
        image: Joi.string().uri().allow('').optional(),
        price: Joi.number().required().min(0).max(1000000),
        location: Joi.string().required().trim().max(100),
        country: Joi.string().required().trim().max(100),
    }).required()
});

const reviewSchema = Joi.object({
    review: Joi.object({
        rating: Joi.number().required().min(1).max(5),
        comment: Joi.string().required().trim().max(500),
    }).required()
});

// Validation middleware factory
const validateInput = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body, { abortEarly: false });
        if (error) {
            const msg = error.details.map(el => el.message).join(', ');
            return next(new ExpressError(400, msg));
        }
        next();
    };
};

// MongoDB ObjectId validation
const isValidObjectId = (id) => {
    return mongoose.Types.ObjectId.isValid(id);
};

// ============================================
// FLASH MESSAGES MIDDLEWARE
// ============================================
app.use((req, res, next) => {
    res.locals.success = req.flash("success");
    res.locals.error = req.flash("error");
    res.locals.updated = req.flash("updated");
    res.locals.currentUser = req.user; // For authentication
    next();
});

// ============================================
// SECURE ROUTES
// ============================================

// Root route
app.get("/", (req, res, next) => {
    try {
        res.render("root.ejs");
    } catch (err) {
        next(err);
    }
});

// Secure cookie demo routes (sanitized)
app.get("/cookie", (req, res, next) => {
    try {
        res.cookie("MADEIn", "Bharat", { 
            httpOnly: true, 
            signed: true,
            sameSite: 'strict' 
        });
        res.cookie("ProudToBe", "Indian", { 
            httpOnly: true, 
            signed: true,
            sameSite: 'strict' 
        });
        res.send("Secure cookies set successfully");
    } catch (err) {
        next(err);
    }
});

app.get("/greet", (req, res, next) => {
    try {
        const signedCookies = req.signedCookies || {};
        const madeIn = signedCookies.MADEIn || "Anonymous";
        
        // Sanitize output to prevent XSS
        const sanitizedValue = madeIn.replace(/[<>"'&]/g, '');
        res.send(`Hello ${sanitizedValue}, how are you?`);
    } catch (err) {
        next(err);
    }
});

// ============================================
// LISTING ROUTES (SECURED)
// ============================================

// Index - View all listings
app.get("/listings", async (req, res, next) => {
    try {
        const alllistings = await Listing.find({}).lean(); // Use lean() for performance
        res.render("index.ejs", { alllistings });
    } catch (err) {
        next(err);
    }
});

// New listing form
app.get("/listings/new", (req, res, next) => {
    try {
        // TODO: Add authentication middleware
        res.render("new.ejs");
    } catch (err) {
        next(err);
    }
});

// Create new listing (SECURED)
app.post("/listings/", validateInput(listingSchema), async (req, res, next) => {
    try {
        // Input is already validated by Joi middleware
        const sanitizedData = {
            title: req.body.listing.title.trim(),
            description: req.body.listing.description.trim(),
            image: req.body.listing.image || undefined,
            price: parseFloat(req.body.listing.price),
            location: req.body.listing.location.trim(),
            country: req.body.listing.country.trim(),
        };

        const newListing = new Listing(sanitizedData);
        await newListing.save();
        
        req.flash("success", "New listing created successfully!");
        res.redirect("/listings");
    } catch (err) {
        next(err);
    }
});

// Show individual listing (SECURED)
app.get("/listings/:id", async (req, res, next) => {
    try {
        const { id } = req.params;

        // Validate MongoDB ObjectId
        if (!isValidObjectId(id)) {
            return next(new ExpressError(400, "Invalid listing ID format"));
        }

        const listing = await Listing.findById(id).populate('reviews').lean();

        if (!listing) {
            return next(new ExpressError(404, "Listing not found"));
        }

        res.render("show.ejs", { listing });
    } catch (err) {
        next(err);
    }
});

// Edit listing form (SECURED)
app.get("/listings/:id/edit", async (req, res, next) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return next(new ExpressError(400, "Invalid listing ID format"));
        }

        const listing = await Listing.findById(id).lean();

        if (!listing) {
            return next(new ExpressError(404, "Listing not found"));
        }

        res.render("edit.ejs", { listing });
    } catch (err) {
        next(err);
    }
});

// Update listing (SECURED)
app.put("/listings/:id/", validateInput(listingSchema), async (req, res, next) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return next(new ExpressError(400, "Invalid listing ID format"));
        }

        const sanitizedData = {
            title: req.body.listing.title.trim(),
            description: req.body.listing.description.trim(),
            image: req.body.listing.image || undefined,
            price: parseFloat(req.body.listing.price),
            location: req.body.listing.location.trim(),
            country: req.body.listing.country.trim(),
        };

        const updatedListing = await Listing.findByIdAndUpdate(
            id, 
            sanitizedData,
            { new: true, runValidators: true }
        );

        if (!updatedListing) {
            return next(new ExpressError(404, "Listing not found"));
        }

        req.flash("updated", "Listing updated successfully!");
        res.redirect(`/listings/${id}`);
    } catch (err) {
        next(err);
    }
});

// Delete listing (SECURED)
app.delete("/listings/:id/", async (req, res, next) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return next(new ExpressError(400, "Invalid listing ID format"));
        }

        const deletedListing = await Listing.findByIdAndDelete(id);

        if (!deletedListing) {
            return next(new ExpressError(404, "Listing not found"));
        }

        req.flash("error", "Listing deleted successfully!");
        res.redirect("/listings");
    } catch (err) {
        next(err);
    }
});

// ============================================
// REVIEW ROUTES (SECURED)
// ============================================

// Create review (SECURED)
app.post("/listings/:id/reviews", validateInput(reviewSchema), async (req, res, next) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return next(new ExpressError(400, "Invalid listing ID format"));
        }

        const listing = await Listing.findById(id);

        if (!listing) {
            return next(new ExpressError(404, "Listing not found"));
        }

        const sanitizedReview = {
            rating: parseInt(req.body.review.rating),
            comment: req.body.review.comment.trim(),
        };

        const newReview = new Review(sanitizedReview);
        listing.reviews.push(newReview);

        await newReview.save();
        await listing.save();

        req.flash("success", "Review submitted successfully!");
        res.redirect(`/listings/${id}`);
    } catch (err) {
        next(err);
    }
});

// ============================================
// ERROR HANDLING MIDDLEWARE
// ============================================

// 404 Handler
app.all("*", (req, res, next) => {
    next(new ExpressError(404, "Page Not Found"));
});

// Global Error Handler (NO STACK TRACE EXPOSURE)
app.use((err, req, res, next) => {
    const { status = 500, message = "Something went wrong" } = err;
    
    // Log full error for debugging (server-side only)
    console.error(`[ERROR ${status}]: `, err.message);
    
    // Development mode - show detailed errors
    if (process.env.NODE_ENV === 'development') {
        console.error(err.stack);
    }
    
    // Production mode - generic error message
    const userMessage = process.env.NODE_ENV === 'production' && status === 500
        ? "Internal Server Error"
        : message;
    
    res.status(status).render("error.ejs", { 
        message: userMessage,
        status: status 
    });
});

// ============================================
// SERVER STARTUP
// ============================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`✅ Secure Wanderlust server running on port ${PORT}`);
    console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app; // For testing