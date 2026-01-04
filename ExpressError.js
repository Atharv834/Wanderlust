/**
 * Custom Express Error Class
 * Prevents stack trace leakage and standardizes error handling
 */
class ExpressError extends Error {
    constructor(status, message) {
        super();
        this.status = status;
        this.message = message;
        
        // Capture stack trace (development only)
        Error.captureStackTrace(this, this.constructor);
    }
}

module.exports = ExpressError;
