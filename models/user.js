const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const passportLocalMongoose = require("passport-local-mongoose");

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    createdAt: {
        type: Date,
        default: Date.now,
        immutable: true
    }
});

// Passport-Local Mongoose plugin adds username, hash and salt fields
// Provides additional methods for authentication
userSchema.plugin(passportLocalMongoose, {
    usernameField: 'email',
    limitAttempts: true,
    maxAttempts: 5,
    digestAlgorithm: 'sha256',
    encoding: 'hex',
    saltlen: 32,
    iterations: 25000,
    errorMessages: {
        UserExistsError: 'A user with this email is already registered'
    }
});

module.exports = mongoose.model("User", userSchema);
