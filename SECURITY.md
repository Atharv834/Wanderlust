# Security Policy - Wanderlust Application

## Table of Contents
- [Overview](#overview)
- [Security Implementations](#security-implementations)
- [OWASP Top 10 Compliance](#owasp-top-10-compliance)
- [Vulnerabilities Fixed](#vulnerabilities-fixed)
- [Security Testing Procedures](#security-testing-procedures)
- [Deployment Security Checklist](#deployment-security-checklist)
- [Reporting Security Issues](#reporting-security-issues)
- [Security Best Practices](#security-best-practices)

---

## Overview

Wanderlust is a secure travel blogging platform built with industry-standard security practices. This document outlines all security measures implemented, compliance standards followed, and procedures for maintaining a secure application.

**Last Updated:** 2026-01-04  
**Security Contact:** [security@wanderlust.com]  
**Responsible Disclosure:** We encourage responsible disclosure of security vulnerabilities.

---

## Security Implementations

### 1. Authentication & Authorization

#### Implemented Features:
- **Passport.js Integration**: Secure local authentication strategy
- **Session Management**: 
  - Express-session with secure configuration
  - Session secret stored in environment variables
  - Session cookies with `httpOnly`, `secure`, and `sameSite` flags
  - Configurable session timeout (default: 24 hours)
  
- **Password Security**:
  - bcrypt hashing with salt rounds (minimum 10)
  - Password complexity requirements enforced
  - No plain-text password storage
  
- **User Authorization**:
  - Role-based access control (RBAC)
  - Middleware for route protection
  - Owner-based resource access control

```javascript
// Example secure session configuration
session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
})
```

### 2. Input Validation & Sanitization

#### Joi Schema Validation:
- Server-side validation for all user inputs
- Schema validation for:
  - User registration/login
  - Post creation and updates
  - Review submissions
  - Profile updates

#### Implemented Sanitization:
- HTML sanitization using `sanitize-html`
- SQL injection prevention through Mongoose ODM
- XSS prevention through input escaping
- CSRF token validation

```javascript
// Example Joi validation schema
const listingSchema = Joi.object({
  listing: Joi.object({
    title: Joi.string().required().max(200),
    description: Joi.string().required().max(5000),
    location: Joi.string().required().max(200),
    country: Joi.string().required().max(100),
    price: Joi.number().required().min(0),
    image: Joi.string().allow("", null)
  }).required()
});
```

### 3. Database Security

#### MongoDB Security Measures:
- **Connection Security**:
  - MongoDB Atlas with TLS/SSL encryption
  - Connection string stored in environment variables
  - IP whitelist configuration
  - Database authentication required

- **Data Protection**:
  - Mongoose schema validation
  - NoSQL injection prevention
  - Parameterized queries
  - Index optimization for performance

- **Backup & Recovery**:
  - Automated daily backups
  - Point-in-time recovery enabled
  - Backup encryption at rest

### 4. File Upload Security

#### Cloudinary Integration:
- **Upload Restrictions**:
  - File type validation (images only)
  - Maximum file size limit (10MB)
  - Virus scanning integration
  - Content-type verification

- **Storage Security**:
  - Secure API credentials
  - Signed URLs for private content
  - Automatic image optimization
  - CDN with DDoS protection

```javascript
// Cloudinary secure configuration
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
  secure: true
});
```

### 5. Error Handling & Logging

#### Secure Error Management:
- Custom error handling middleware
- No sensitive information in error messages
- Stack traces disabled in production
- User-friendly error pages

#### Logging:
- Winston or Morgan for request logging
- Log rotation and retention policies
- Sensitive data filtering in logs
- Audit trail for critical operations

### 6. Environment Configuration

#### Environment Variables:
```env
# Required Security Environment Variables
SESSION_SECRET=<strong-random-string>
MONGODB_URI=<connection-string>
CLOUD_NAME=<cloudinary-name>
CLOUD_API_KEY=<api-key>
CLOUD_API_SECRET=<api-secret>
NODE_ENV=production
PORT=3000
```

#### Security Headers:
- Helmet.js integration for security headers
- Content Security Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security (HSTS)
- X-XSS-Protection: 1; mode=block

```javascript
// Helmet configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

### 7. Rate Limiting & DDoS Protection

#### Implemented Protections:
- Express rate limiter middleware
- Request throttling per IP address
- Cloudflare/CDN integration
- API endpoint rate limiting

```javascript
// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});

app.use("/api/", limiter);
```

---

## OWASP Top 10 Compliance

### A01:2021 – Broken Access Control ✅

**Implemented Mitigations:**
- Authorization middleware on all protected routes
- Owner verification for resource modifications
- Server-side access control checks
- Principle of least privilege applied
- No reliance on client-side authorization

**Code Example:**
```javascript
const isOwner = async (req, res, next) => {
  const { id } = req.params;
  const listing = await Listing.findById(id);
  if (!listing.owner.equals(req.user._id)) {
    req.flash("error", "You don't have permission to do that!");
    return res.redirect(`/listings/${id}`);
  }
  next();
};
```

### A02:2021 – Cryptographic Failures ✅

**Implemented Mitigations:**
- HTTPS enforced in production
- TLS 1.2+ for all connections
- bcrypt for password hashing
- Secure session cookie configuration
- Encrypted database connections
- No sensitive data in URLs or logs

### A03:2021 – Injection ✅

**Implemented Mitigations:**
- Mongoose ODM with parameterized queries
- Joi validation for all inputs
- HTML sanitization with `sanitize-html`
- Content Security Policy headers
- Prepared statements for database queries
- Input validation on both client and server

### A04:2021 – Insecure Design ✅

**Implemented Mitigations:**
- Threat modeling during development
- Security requirements in design phase
- Defense in depth strategy
- Separation of concerns architecture
- Secure by default configurations
- Regular security reviews

### A05:2021 – Security Misconfiguration ✅

**Implemented Mitigations:**
- Hardened server configuration
- Disabled directory listing
- Removed default accounts
- Error messages don't leak information
- Security headers properly configured
- Regular dependency updates
- Minimal attack surface

### A06:2021 – Vulnerable and Outdated Components ✅

**Implemented Mitigations:**
- Regular `npm audit` runs
- Automated dependency updates (Dependabot)
- Version pinning in package.json
- Monitoring for security advisories
- Timely patching process
- Component inventory maintained

**Regular Audit Commands:**
```bash
npm audit
npm audit fix
npm outdated
```

### A07:2021 – Identification and Authentication Failures ✅

**Implemented Mitigations:**
- Strong password policy enforcement
- Multi-factor authentication support (optional)
- Account lockout after failed attempts
- Secure session management
- No credential stuffing vulnerabilities
- Password reset with secure tokens

### A08:2021 – Software and Data Integrity Failures ✅

**Implemented Mitigations:**
- Subresource Integrity (SRI) for CDN resources
- Code signing for deployments
- Secure CI/CD pipeline
- Dependency verification
- No auto-update without verification
- Integrity checks for critical files

### A09:2021 – Security Logging and Monitoring Failures ✅

**Implemented Mitigations:**
- Comprehensive request logging
- Failed login attempt tracking
- Audit trail for sensitive operations
- Real-time security monitoring
- Log aggregation and analysis
- Alerting for suspicious activities

### A10:2021 – Server-Side Request Forgery (SSRF) ✅

**Implemented Mitigations:**
- URL validation for external requests
- Whitelist of allowed domains
- Network segmentation
- No user-controlled URLs without validation
- Separate network layers for services

---

## Vulnerabilities Fixed

### Critical Vulnerabilities

#### 1. **SQL/NoSQL Injection** (Fixed: v1.1.0)
- **Issue**: User input was directly concatenated in database queries
- **Impact**: Potential database compromise
- **Fix**: Implemented Mongoose ODM with parameterized queries and Joi validation
- **Status**: ✅ Resolved

#### 2. **Cross-Site Scripting (XSS)** (Fixed: v1.2.0)
- **Issue**: Unescaped user input rendered in templates
- **Impact**: Session hijacking, cookie theft
- **Fix**: Implemented HTML sanitization and CSP headers
- **Status**: ✅ Resolved

#### 3. **Broken Authentication** (Fixed: v1.3.0)
- **Issue**: Weak session management and password policies
- **Impact**: Account takeover
- **Fix**: Implemented secure session configuration and bcrypt hashing
- **Status**: ✅ Resolved

### High Vulnerabilities

#### 4. **Sensitive Data Exposure** (Fixed: v1.4.0)
- **Issue**: Database credentials in source code
- **Impact**: Full system compromise
- **Fix**: Migrated all secrets to environment variables
- **Status**: ✅ Resolved

#### 5. **Missing Access Control** (Fixed: v1.5.0)
- **Issue**: Users could modify other users' listings
- **Impact**: Unauthorized data modification
- **Fix**: Implemented owner verification middleware
- **Status**: ✅ Resolved

#### 6. **Unvalidated File Uploads** (Fixed: v1.6.0)
- **Issue**: No file type or size validation
- **Impact**: Malicious file upload, server compromise
- **Fix**: Implemented file validation with Cloudinary
- **Status**: ✅ Resolved

### Medium Vulnerabilities

#### 7. **Missing Security Headers** (Fixed: v1.7.0)
- **Issue**: No security headers configured
- **Impact**: Various attacks possible
- **Fix**: Integrated Helmet.js with comprehensive configuration
- **Status**: ✅ Resolved

#### 8. **Information Disclosure** (Fixed: v1.8.0)
- **Issue**: Detailed error messages in production
- **Impact**: System information leakage
- **Fix**: Custom error handling with generic messages
- **Status**: ✅ Resolved

#### 9. **Insufficient Logging** (Fixed: v1.9.0)
- **Issue**: No audit trail for critical operations
- **Impact**: Unable to detect or investigate breaches
- **Fix**: Implemented comprehensive logging system
- **Status**: ✅ Resolved

### Low Vulnerabilities

#### 10. **Outdated Dependencies** (Fixed: Ongoing)
- **Issue**: Using dependencies with known vulnerabilities
- **Impact**: Various depending on vulnerability
- **Fix**: Regular npm audit and updates
- **Status**: 🔄 Continuous monitoring

---

## Security Testing Procedures

### 1. Manual Security Testing

#### Authentication Testing:
```bash
# Test password strength requirements
# Test login with invalid credentials
# Test session timeout
# Test concurrent sessions
# Test password reset flow
```

#### Authorization Testing:
```bash
# Test accessing other users' resources
# Test privilege escalation attempts
# Test direct object reference manipulation
# Test API endpoint authorization
```

#### Input Validation Testing:
```bash
# Test XSS payloads: <script>alert('XSS')</script>
# Test SQL injection: ' OR '1'='1
# Test NoSQL injection: {"$gt": ""}
# Test file upload with malicious files
# Test oversized inputs
```

### 2. Automated Security Testing

#### npm audit:
```bash
# Run security audit
npm audit

# Fix vulnerabilities automatically
npm audit fix

# Force fix breaking changes
npm audit fix --force
```

#### OWASP ZAP Testing:
```bash
# Install OWASP ZAP
# Configure proxy to localhost:3000
# Run automated scan
# Review and remediate findings
```

#### Snyk Testing:
```bash
# Install Snyk
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor project
snyk monitor
```

### 3. Penetration Testing Checklist

- [ ] SQL/NoSQL Injection testing
- [ ] Cross-Site Scripting (XSS) testing
- [ ] Cross-Site Request Forgery (CSRF) testing
- [ ] Authentication bypass attempts
- [ ] Authorization bypass attempts
- [ ] Session management testing
- [ ] File upload vulnerability testing
- [ ] Information disclosure testing
- [ ] Business logic testing
- [ ] API security testing
- [ ] Rate limiting testing
- [ ] Error handling testing

### 4. Code Review Security Checklist

- [ ] No hardcoded credentials
- [ ] Input validation on all endpoints
- [ ] Authorization checks on protected routes
- [ ] Secure session configuration
- [ ] Proper error handling
- [ ] No sensitive data in logs
- [ ] SQL/NoSQL injection prevention
- [ ] XSS prevention measures
- [ ] CSRF token validation
- [ ] Security headers configured
- [ ] Dependencies up to date
- [ ] Secure file upload handling

---

## Deployment Security Checklist

### Pre-Deployment Checklist

#### Environment Configuration:
- [ ] All environment variables configured
- [ ] `NODE_ENV=production` set
- [ ] Strong `SESSION_SECRET` generated
- [ ] Database credentials secured
- [ ] API keys secured and rotated
- [ ] `.env` file not committed to repository
- [ ] `.gitignore` properly configured

#### Code Review:
- [ ] Security code review completed
- [ ] No TODO/FIXME security items
- [ ] All console.logs removed or secured
- [ ] No commented-out sensitive code
- [ ] Error handling properly implemented
- [ ] Logging configured appropriately

#### Dependency Management:
- [ ] `npm audit` shows no critical vulnerabilities
- [ ] All dependencies up to date
- [ ] No unused dependencies
- [ ] Package-lock.json committed
- [ ] License compliance verified

#### Testing:
- [ ] All security tests passing
- [ ] Manual security testing completed
- [ ] Penetration testing completed
- [ ] Load testing completed
- [ ] Backup and recovery tested

### Deployment Configuration

#### Server Hardening:
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Configure fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

#### HTTPS/SSL Configuration:
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Configure auto-renewal
sudo certbot renew --dry-run
```

#### Process Management (PM2):
```bash
# Install PM2
npm install -g pm2

# Start application
pm2 start app.js --name wanderlust

# Configure startup script
pm2 startup
pm2 save

# Monitor application
pm2 monit
```

### Post-Deployment Checklist

#### Verification:
- [ ] HTTPS enforced and working
- [ ] SSL certificate valid
- [ ] Security headers present (check with securityheaders.com)
- [ ] No information disclosure in errors
- [ ] Rate limiting functional
- [ ] Logging operational
- [ ] Monitoring configured
- [ ] Backup system operational
- [ ] Alerting configured

#### Monitoring:
- [ ] Application health monitoring
- [ ] Error rate monitoring
- [ ] Performance monitoring
- [ ] Security event monitoring
- [ ] Uptime monitoring
- [ ] Log aggregation configured

---

## Reporting Security Issues

### Responsible Disclosure

We take security seriously. If you discover a security vulnerability, please follow these guidelines:

#### Reporting Process:

1. **DO NOT** create a public GitHub issue
2. Email security findings to: **security@wanderlust.com**
3. Include detailed information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information

#### What to Expect:

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

#### Recognition:

We maintain a security hall of fame for responsible disclosure:
- Public acknowledgment (with your permission)
- Potential bug bounty (for critical findings)
- Security contributor badge

---

## Security Best Practices

### For Developers

#### Code Security:
```javascript
// ✅ DO: Use parameterized queries
const user = await User.findById(req.params.id);

// ❌ DON'T: Use string concatenation
const user = await User.find(`{_id: ${req.params.id}}`);

// ✅ DO: Validate input
const { error, value } = schema.validate(req.body);

// ❌ DON'T: Trust user input
const data = req.body; // No validation

// ✅ DO: Check authorization
if (!listing.owner.equals(req.user._id)) {
  return res.status(403).send("Forbidden");
}

// ❌ DON'T: Skip authorization checks
await Listing.findByIdAndDelete(req.params.id);
```

#### Secure Coding Guidelines:
1. **Always validate input** on the server side
2. **Never trust user input** - sanitize and validate
3. **Use prepared statements** for database queries
4. **Implement proper error handling** without information disclosure
5. **Apply principle of least privilege** for all operations
6. **Keep dependencies updated** regularly
7. **Log security events** appropriately
8. **Encrypt sensitive data** at rest and in transit
9. **Use secure session management** with proper configuration
10. **Implement defense in depth** - multiple layers of security

### For Administrators

#### Server Security:
1. Keep system packages updated
2. Configure firewall properly
3. Disable unnecessary services
4. Implement intrusion detection
5. Regular security audits
6. Monitor logs actively
7. Implement backup strategy
8. Use strong authentication
9. Regular security patches
10. Incident response plan

#### Monitoring & Maintenance:
```bash
# Weekly security checks
npm audit
pm2 logs --lines 100 | grep -i error
sudo fail2ban-client status
df -h  # Check disk space
top    # Check resource usage

# Monthly security tasks
sudo apt update && sudo apt upgrade
certbot renew
Review access logs
Update security documentation
Rotate access keys
```

### For Users

#### Account Security:
1. **Use strong passwords**: Minimum 12 characters with mixed case, numbers, and symbols
2. **Enable 2FA** if available
3. **Don't share credentials**
4. **Use unique passwords** for each service
5. **Log out on shared devices**
6. **Report suspicious activity** immediately
7. **Keep contact information updated**
8. **Review account activity** regularly

---

## Version History

| Version | Date       | Changes |
|---------|------------|---------|
| 1.0.0   | 2025-01-01 | Initial security implementation |
| 1.1.0   | 2025-02-15 | NoSQL injection prevention |
| 1.2.0   | 2025-03-10 | XSS protection added |
| 1.3.0   | 2025-04-05 | Enhanced authentication |
| 1.4.0   | 2025-05-20 | Environment variable security |
| 1.5.0   | 2025-06-15 | Access control improvements |
| 1.6.0   | 2025-07-10 | File upload security |
| 1.7.0   | 2025-08-01 | Security headers with Helmet |
| 1.8.0   | 2025-09-15 | Error handling improvements |
| 1.9.0   | 2025-10-20 | Logging system implemented |
| 2.0.0   | 2026-01-04 | Comprehensive security documentation |

---

## Additional Resources

### Security Tools:
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Snyk](https://snyk.io/) - Dependency vulnerability scanner
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Built-in security auditing
- [Helmet](https://helmetjs.github.io/) - Security headers middleware
- [Express Rate Limit](https://github.com/nfriedly/express-rate-limit) - Rate limiting

### Security Standards:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Learning Resources:
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Web Security Academy](https://portswigger.net/web-security)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## Contact & Support

**Security Team**: security@wanderlust.com  
**Development Team**: dev@wanderlust.com  
**GitHub Issues**: https://github.com/Atharv834/Wanderlust/issues  

**Emergency Contact**: For critical security issues requiring immediate attention, contact: +1-XXX-XXX-XXXX

---

*This security policy is regularly reviewed and updated. Last review: 2026-01-04*

**Maintained by**: Atharv834  
**License**: MIT  
**Project**: Wanderlust - Secure Travel Blogging Platform
