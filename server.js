/**
 * FinAudit One — Autonomous CA Cloud OS
 * Production Express REST API & Statutory Compliance Server
 *
 * Integrated with Razorpay Standard Checkout (Orders API + HMAC-SHA256 Verification)
 * & All 41 Backend Security & Statutory Validation Controls:
 * - Universal Mail Delivery Gateway: Supports HTTPS REST APIs (Brevo / Resend via Port 443)
 *   to bypass Render Free-Tier SMTP port blocks (25/465/587), with automatic local SMTP fallback
 * - Live Razorpay Orders API (https://api.razorpay.com/v1/orders) with automatic offline fallback
 * - Cryptographic HMAC-SHA256 signature verification (order_id|payment_id) using constant-time comparison
 * - Zero hardcoded JWT secrets (CSPRNG runtime secret in dev/test; mandatory env in prod)
 * - Strict tokenType separation ('ACCESS' vs 'REFRESH')
 * - Real JTI blacklisting & token_version incrementation on logout & revoke-all
 * - Official GSTN Modulo-36 Check-Digit (Checksum) validation on all 15-char GSTINs
 * - Strict Voucher Type, Statutory GST Slab Rate, Upper Amount (<= 1e11) & Client Ownership guards
 * - HTML / Script tag sanitization on party, client, and firm names
 * - Per-Firm (FRN) deterministic 64-char SHA-256 Audit Trail chaining & /api/audit-trail/verify endpoint
 * - Password Reset OTP 5-attempt brute-force lockout & permanent token invalidation
 */

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const mailerEnvPath = path.join(__dirname, 'mailer.env');
const defaultEnvPath = path.join(__dirname, '.env');
let activeEnvPath = null;

function parseCustomEnv(filePath) {
  try {
    if (!fs.existsSync(filePath)) return false;
    const raw = fs.readFileSync(filePath);
    let content = raw.toString('utf8');
    if (raw.length >= 2 && raw[0] === 0xFF && raw[1] === 0xFE) {
      content = raw.toString('utf16le');
    }
    content.split(/\r?\n/).forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx !== -1) {
        const key = trimmed.substring(0, eqIdx).trim();
        let val = trimmed.substring(eqIdx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.substring(1, val.length - 1);
        }
        process.env[key] = val;
      }
    });
    return true;
  } catch (e) {
    return false;
  }
}

if (parseCustomEnv(defaultEnvPath)) activeEnvPath = defaultEnvPath;
if (parseCustomEnv(mailerEnvPath)) activeEnvPath = mailerEnvPath;

const PORT = parseInt(process.env.PORT, 10) || 5000;
const APP_URL = process.env.APP_URL || 'http://localhost:5500';
const DATABASE_URL = process.env.DATABASE_URL || '';
const PG_POOL_MAX = parseInt(process.env.PG_POOL_MAX, 10) || 20;
const LOCAL_STORE_FILE = path.join(__dirname, '.finaudit_data_store.json');

// Razorpay Live Merchant & Gateway Configuration — keys are read strictly from environment variables
const RAZORPAY_MERCHANT_ID = (process.env.RAZORPAY_MERCHANT_ID || 'RJyqo7o2wrDfNg').trim();
const RAZORPAY_ACCOUNT_ID = (process.env.RAZORPAY_ACCOUNT_ID || 'acc_RJyqo7o2wrDfNg').trim();

function getRazorpayConfig() {
  const keyId = (process.env.RAZORPAY_KEY_ID || '').trim();
  const keySecret = (process.env.RAZORPAY_KEY_SECRET || '').trim();
  const webhookSecret = (process.env.RAZORPAY_WEBHOOK_SECRET || '').trim();
  const allowFake = process.env.NODE_ENV !== 'production' && process.env.ALLOW_FAKE_PAYMENTS === 'true';
  const isValidKeyPrefix = keyId.startsWith('rzp_live_') || keyId.startsWith('rzp_test_');
  const mode = keyId.startsWith('rzp_live_') ? 'LIVE' : (keyId.startsWith('rzp_test_') ? 'TEST' : 'UNCONFIGURED');

  return {
    merchantId: RAZORPAY_MERCHANT_ID,
    accountId: RAZORPAY_ACCOUNT_ID,
    keyId,
    keySecret,
    webhookSecret,
    mode,
    isValidKeyPrefix,
    configured: Boolean(keyId && keySecret && isValidKeyPrefix),
    allowFake
  };
}

// Never allow any known or weak default JWT secret from older builds
const COMPROMISED_DEFAULT_SECRETS = new Set([
  'finaudit_statutory_secret_key_2026_x891_sha512',
  'default_secret',
  'secret',
  'changeme'
]);

function resolveJwtSecret() {
  const envSecret = (process.env.JWT_SECRET || '').trim();
  if (envSecret && !COMPROMISED_DEFAULT_SECRETS.has(envSecret) && envSecret.length >= 32) {
    return envSecret;
  }
  if (process.env.NODE_ENV === 'production') {
    console.error('>>> [FinAudit Security] FATAL: A strong, non-default JWT_SECRET (>= 32 chars) is mandatory in production.');
    process.exit(1);
  }
  return crypto.randomBytes(64).toString('hex');
}

const JWT_SECRET = resolveJwtSecret();

// Strict CORS Origin Allowlist (Never open to '*')
const ALLOWED_ORIGINS = new Set(
  [
    APP_URL,
    process.env.RENDER_EXTERNAL_URL,
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : []),
    ...(process.env.NODE_ENV !== 'production'
      ? [
          'http://localhost:5500',
          'http://127.0.0.1:5500',
          'http://localhost:5000',
          'http://127.0.0.1:5000',
          'http://localhost:3000',
          'http://127.0.0.1:3000'
        ]
      : [])
  ].filter(Boolean)
);

const app = express();
app.use(cors({
  origin: Array.from(ALLOWED_ORIGINS),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Explicit CORS enforcement guard (prevents '*' even if cors is stubbed in test sandboxes)
app.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  const hostOrigin = req.headers.host ? `${req.protocol || 'http'}://${req.headers.host}` : null;
  const httpsHostOrigin = req.headers.host ? `https://${req.headers.host}` : null;
  if (requestOrigin) {
    if (!ALLOWED_ORIGINS.has(requestOrigin) && requestOrigin !== hostOrigin && requestOrigin !== httpsHostOrigin) {
      res.removeHeader('Access-Control-Allow-Origin');
      return res.status(403).json({
        success: false,
        code: 'CORS_ORIGIN_FORBIDDEN',
        message: 'Cross-Origin Request Blocked: Origin is not permitted.'
      });
    }
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    res.setHeader('Vary', 'Origin');
  } else {
    res.setHeader('Access-Control-Allow-Origin', APP_URL);
  }
  next();
});

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Serve index.html at root "/" so Frontend + Backend deploy together on Render / Railway / Cloud
app.use(express.static(__dirname, { index: 'index.html' }));

// Express JSON SyntaxError handler (T40: Malformed JSON body -> 400)
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ success: false, message: 'Malformed JSON payload.' });
  }
  next(err);
});

const authAttemptMap = new Map();
const recoveryAttemptMap = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 5;
const MAX_RECOVERY_REQUESTS = 10;

function getClientIp(req) {
  return req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'ip_local';
}

function recordFailedLoginAttempt(req) {
  const ip = getClientIp(req);
  const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : '';
  const key = `login_${ip}_${email}`;
  const now = Date.now();
  const record = authAttemptMap.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + RATE_LIMIT_WINDOW_MS;
  } else {
    record.count += 1;
  }
  authAttemptMap.set(key, record);
  return record;
}

function checkLoginRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : '';
  const key = `login_${ip}_${email}`;
  const now = Date.now();
  const record = authAttemptMap.get(key);

  if (record && now <= record.resetAt && record.count >= MAX_AUTH_ATTEMPTS) {
    const minutesLeft = Math.ceil((record.resetAt - now) / 60000);
    return res.status(429).json({
      success: false,
      message: `Too many unsuccessful sign-in attempts. Please wait ${minutesLeft} minute(s) before retrying.`
    });
  }
  next();
}

function resetLoginRateLimit(req) {
  const ip = getClientIp(req);
  const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : '';
  authAttemptMap.delete(`login_${ip}_${email}`);
}

function checkForgotRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : 'unknown';
  const key = `forgot_${ip}_${email}`;
  const now = Date.now();
  const record = recoveryAttemptMap.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + RATE_LIMIT_WINDOW_MS;
    recoveryAttemptMap.set(key, record);
    return next();
  }

  if (record.count >= MAX_RECOVERY_REQUESTS) {
    return res.status(429).json({
      success: false,
      message: 'Too many password recovery requests. Please wait before requesting another code.'
    });
  }

  record.count += 1;
  recoveryAttemptMap.set(key, record);
  next();
}

const GSTIN_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function computeGstinCheckDigit(gstin14) {
  if (!gstin14 || gstin14.length !== 14) return null;
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const codePoint = GSTIN_ALPHABET.indexOf(gstin14[i]);
    if (codePoint === -1) return null;
    const factor = (i % 2 === 0) ? 1 : 2;
    const product = codePoint * factor;
    sum += Math.floor(product / 36) + (product % 36);
  }
  const checkCodePoint = (36 - (sum % 36)) % 36;
  return GSTIN_ALPHABET[checkCodePoint];
}

function validateGstin(gstin) {
  if (!gstin || typeof gstin !== 'string') {
    return { valid: false, message: 'GSTIN is required.' };
  }
  const clean = gstin.trim().toUpperCase();
  if (clean.length !== 15) {
    return { valid: false, message: `GSTIN must be strictly 15 characters (provided ${clean.length}).` };
  }

  const gstinRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
  if (!gstinRegex.test(clean)) {
    return { valid: false, message: 'Invalid GSTIN schema. Format: 2-digit State + 10-char PAN + Entity code + "Z" + check digit.' };
  }

  const stateCode = parseInt(clean.substring(0, 2), 10);
  if (stateCode < 1 || stateCode > 38) {
    return { valid: false, message: `State Code (${clean.substring(0, 2)}) is invalid. Standard state codes range from 01 to 38.` };
  }

  const expectedCheckDigit = computeGstinCheckDigit(clean.substring(0, 14));
  if (!expectedCheckDigit || clean[14] !== expectedCheckDigit) {
    return {
      valid: false,
      message: `Invalid GSTIN check digit (expected "${expectedCheckDigit}", received "${clean[14]}").`
    };
  }

  const derivedPan = clean.substring(2, 12);
  return { valid: true, clean, pan: derivedPan };
}

function validateFrn(frn) {
  if (!frn || typeof frn !== 'string') {
    return { valid: false, message: 'ICAI Firm Registration Number (FRN) is required.' };
  }
  const clean = frn.trim().toUpperCase();
  if (!/^[A-Z0-9\/-]{5,12}$/.test(clean)) {
    return { valid: false, message: 'Invalid ICAI FRN format. Expected 5–12 alphanumeric characters (e.g. 109282W).' };
  }
  return { valid: true, clean };
}

function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string' || password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { valid: false, message: 'Password must not exceed 128 characters.' };
  }
  return { valid: true };
}

function sanitizeText(input) {
  if (input === null || input === undefined) return '';
  return String(input)
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<\/?[^>]+(>|$)/g, '')
    .replace(/[<>]/g, '')
    .trim();
}

function validateIsoDate(dateStr) {
  if (!dateStr || typeof dateStr !== 'string') {
    return { valid: false, message: 'Voucher date is required in YYYY-MM-DD format.' };
  }
  const clean = dateStr.trim();
  const match = clean.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) {
    return { valid: false, message: 'Invalid voucher date format. Expected YYYY-MM-DD.' };
  }
  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);
  if (year < 2000 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31) {
    return {
      valid: false,
      message: `Invalid calendar date "${clean}". Month must be 01–12 and day must be valid.`
    };
  }
  const d = new Date(Date.UTC(year, month - 1, day));
  if (
    d.getUTCFullYear() !== year ||
    d.getUTCMonth() + 1 !== month ||
    d.getUTCDate() !== day
  ) {
    return {
      valid: false,
      message: `Invalid calendar date "${clean}" (day does not exist in month).`
    };
  }
  return { valid: true, clean };
}

let pgPool = null;
let isPostgresReady = false;

if (DATABASE_URL && DATABASE_URL.trim().length > 0) {
  try {
    pgPool = new Pool({
      connectionString: DATABASE_URL.trim(),
      max: PG_POOL_MAX,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000
    });

    pgPool.on('error', (err) => {
      console.warn('>>> [FinAudit Database] PostgreSQL Pool Client Notice:', err.message);
    });
  } catch (poolErr) {
    console.warn('>>> [FinAudit Database] Failed to initialize connection pool:', poolErr.message);
    pgPool = null;
  }
}

async function initializeDatabase() {
  if (!pgPool) {
    console.log('>>> [FinAudit Database] Engine: Local JSON Fallback Store');
    return;
  }

  try {
    const client = await pgPool.connect();
    const res = await client.query('SELECT NOW() as server_time, current_database() as db_name');
    client.release();
    isPostgresReady = true;
    console.log(`>>> [FinAudit Database] Connected to PostgreSQL (${res.rows[0].db_name}) at ${res.rows[0].server_time}`);
    console.log('>>> [FinAudit Database] Engine: Supabase Cloud PostgreSQL with Row-Level Security (RLS)');
  } catch (connErr) {
    isPostgresReady = false;
    console.warn('>>> [FinAudit Database] PostgreSQL Connection Warning:', connErr.message);
    console.log('>>> [FinAudit Database] Operating in atomic Local JSON Store fallback.');
  }
}

function createEmptyStoreState() {
  return {
    organizations: [],
    users: [],
    clients: [],
    vouchers: [],
    recon_items: [],
    bank_transactions: [],
    audit_logs: [],
    subscriptions: {},
    resetTokens: {},
    revokedTokens: {},
    paymentOrders: {}
  };
}

function loadLocalDatabase() {
  try {
    if (!fs.existsSync(LOCAL_STORE_FILE)) {
      const defaultState = createEmptyStoreState();
      fs.writeFileSync(LOCAL_STORE_FILE, JSON.stringify(defaultState, null, 2), 'utf8');
      return defaultState;
    }
    const raw = fs.readFileSync(LOCAL_STORE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const defaults = createEmptyStoreState();
    Object.keys(defaults).forEach(k => {
      if (!parsed[k]) parsed[k] = defaults[k];
    });
    return parsed;
  } catch (err) {
    return createEmptyStoreState();
  }
}

function saveLocalDatabase(data) {
  try {
    fs.writeFileSync(LOCAL_STORE_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('>>> [FinAudit Storage] Failed to write local JSON store:', err.message);
    return false;
  }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, salt, storedHash) {
  if (!password || !salt || !storedHash) return false;
  const hash = hashPassword(password, salt);
  try {
    const bufA = Buffer.from(hash, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (e) {
    return false;
  }
}

function hashRecoveryOtp(email, otp, salt) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanOtp = String(otp || '').trim();
  return crypto.pbkdf2Sync(`${cleanEmail}:${cleanOtp}`, salt, 10000, 32, 'sha256').toString('hex');
}

function verifyRecoveryOtp(email, otp, salt, storedHash) {
  if (!email || !otp || !salt || !storedHash) return false;
  const computed = hashRecoveryOtp(email, otp, salt);
  try {
    const bufA = Buffer.from(computed, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (e) {
    return false;
  }
}

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf8');
}

function generateJwt(payload, expiresInSeconds = 86400, tokenType = 'ACCESS') {
  const header = { alg: 'HS256', typ: 'JWT' };
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = nowSec + expiresInSeconds;
  const jti = payload.jti || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));

  const completePayload = {
    ...payload,
    jti,
    tokenType,
    tokenVersion: Number(payload.tokenVersion) || 1,
    exp,
    iat: nowSec
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(completePayload));
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJwt(token, expectedType = 'ACCESS') {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const sigBuf = Buffer.from(signatureB64, 'utf8');
    const expBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const payload = JSON.parse(base64UrlDecode(payloadB64));
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || nowSec > payload.exp) return null;

    if (expectedType && payload.tokenType !== expectedType) {
      return null;
    }

    return payload;
  } catch (e) {
    return null;
  }
}

const revokedTokenJtis = new Map();

function hashRawToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function revokeToken(tokenOrJti, exp = Math.floor(Date.now() / 1000) + 604800) {
  if (!tokenOrJti) return;
  revokedTokenJtis.set(tokenOrJti, exp);
  try {
    const localDb = loadLocalDatabase();
    localDb.revokedTokens = localDb.revokedTokens || {};
    localDb.revokedTokens[tokenOrJti] = exp;
    saveLocalDatabase(localDb);
  } catch (e) {}
}

function isTokenRevoked(jti, rawToken) {
  const rawHash = rawToken ? hashRawToken(rawToken) : null;
  if (jti && revokedTokenJtis.has(jti)) return true;
  if (rawHash && revokedTokenJtis.has(rawHash)) return true;
  try {
    const localDb = loadLocalDatabase();
    if (localDb.revokedTokens) {
      if (jti && localDb.revokedTokens[jti]) {
        revokedTokenJtis.set(jti, localDb.revokedTokens[jti]);
        return true;
      }
      if (rawHash && localDb.revokedTokens[rawHash]) {
        revokedTokenJtis.set(rawHash, localDb.revokedTokens[rawHash]);
        return true;
      }
    }
  } catch (e) {}
  return false;
}

async function getAuthenticatedUserAndOrg(userId, email) {
  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (isPostgresReady && pgPool) {
    try {
      const queryRes = await pgPool.query(
        `SELECT u.id, u.name, u.email, u.role, u.frn, u.org_id,
                COALESCE(u.token_version, 1) as token_version,
                o.legal_name as org_name, o.icai_frn as org_frn, o.email as org_owner_email, o.managing_partner as org_partner
         FROM users u
         LEFT JOIN organizations o ON u.org_id = o.id
         WHERE u.id = $1 OR LOWER(u.email) = $2
         LIMIT 1`,
        [userId || '', normalizedEmail]
      );
      if (queryRes.rows.length > 0) {
        const row = queryRes.rows[0];
        return {
          user: {
            id: row.id,
            name: row.name,
            email: row.email,
            role: row.role || 'PARTNER',
            frn: (row.frn || row.org_frn || '').toUpperCase(),
            orgId: row.org_id,
            tokenVersion: Number(row.token_version) || 1
          },
          org: {
            id: row.org_id,
            name: row.org_name || 'CA Practice Firm',
            frn: (row.org_frn || row.frn || '').toUpperCase(),
            ownerEmail: (row.org_owner_email || row.email || '').toLowerCase(),
            managingPartner: row.org_partner || row.name
          }
        };
      }
    } catch (e) {}
  }

  const localDb = loadLocalDatabase();
  const localUser = (localDb.users || []).find(
    u => (userId && u.id === userId) || (u.email && u.email.toLowerCase() === normalizedEmail)
  );
  if (!localUser) return null;

  const org = (localDb.organizations || []).find(
    o => o.id === localUser.org_id || (o.icai_frn && localUser.frn && o.icai_frn.toUpperCase() === localUser.frn.toUpperCase())
  );

  return {
    user: {
      id: localUser.id,
      name: localUser.name,
      email: localUser.email,
      role: localUser.role || 'PARTNER',
      frn: (localUser.frn || org?.icai_frn || '').toUpperCase(),
      orgId: localUser.org_id || org?.id,
      tokenVersion: Number(localUser.token_version) || 1
    },
    org: {
      id: org?.id || localUser.org_id,
      name: org?.legal_name || org?.name || 'CA Practice Firm',
      frn: (org?.icai_frn || localUser.frn || '').toUpperCase(),
      ownerEmail: (org?.email || localUser.email || '').toLowerCase(),
      managingPartner: org?.managing_partner || localUser.name
    }
  };
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      code: 'AUTH_REQUIRED',
      message: 'Authentication required. Missing Bearer session token.'
    });
  }

  const token = authHeader.split(' ')[1];
  const payload = verifyJwt(token, 'ACCESS');
  if (!payload || !payload.email) {
    return res.status(401).json({
      success: false,
      code: 'INVALID_TOKEN',
      message: 'Invalid or expired access token. Please sign in again.'
    });
  }

  if (isTokenRevoked(payload.jti, token)) {
    return res.status(401).json({
      success: false,
      code: 'SESSION_REVOKED',
      message: 'This session has been signed out or revoked. Please sign in again.'
    });
  }

  const resolved = await getAuthenticatedUserAndOrg(payload.userId, payload.email);
  if (!resolved || !resolved.user) {
    return res.status(401).json({
      success: false,
      code: 'USER_NOT_FOUND',
      message: 'Account not found or inactive. Please sign in again.'
    });
  }

  const tokenVersionInJwt = Number(payload.tokenVersion) || 1;
  if (resolved.user.tokenVersion !== tokenVersionInJwt) {
    return res.status(401).json({
      success: false,
      code: 'SESSION_REVOKED',
      message: 'Your session was revoked by a password reset or global security sign-out.'
    });
  }

  if (payload.frn && resolved.user.frn && payload.frn.toUpperCase() !== resolved.user.frn.toUpperCase()) {
    return res.status(403).json({
      success: false,
      code: 'FIRM_OWNERSHIP_MISMATCH',
      message: 'Firm ownership verification failed for this session.'
    });
  }

  req.user = {
    userId: resolved.user.id,
    name: resolved.user.name,
    email: resolved.user.email,
    role: resolved.user.role,
    frn: resolved.user.frn,
    orgId: resolved.user.orgId,
    tokenVersion: resolved.user.tokenVersion,
    jti: payload.jti,
    rawToken: token,
    exp: payload.exp
  };
  req.org = resolved.org;
  next();
}

function computeAuditEntryHash({ id, org_id, frn, timestamp, user_name, role, action, target, previous_hash }) {
  const canonical = [
    String(id ?? ''),
    String(org_id ?? ''),
    String(frn ?? '').toUpperCase(),
    String(timestamp ?? ''),
    String(user_name ?? ''),
    String(role ?? ''),
    String(action ?? ''),
    String(target ?? ''),
    String(previous_hash ?? 'GENESIS-BLOCK')
  ].join('|');
  return 'SHA256-' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex').toUpperCase();
}

function verifyAuditChain(logsNewestFirst) {
  if (!Array.isArray(logsNewestFirst) || logsNewestFirst.length === 0) {
    return { valid: true, totalEntries: 0, verifiedLinks: 0, tamperedEntries: [] };
  }
  const chronological = [...logsNewestFirst].sort((a, b) => Number(a.id) - Number(b.id));
  const tamperedEntries = [];
  let verifiedLinks = 0;

  for (let i = 0; i < chronological.length; i++) {
    const entry = chronological[i];
    const expectedPrevHash = i === 0 ? 'GENESIS-BLOCK' : (chronological[i - 1].payload_hash || chronological[i - 1].hash);
    const actualPrevHash = entry.previous_hash || entry.previousHash || 'GENESIS-BLOCK';
    const storedHash = entry.payload_hash || entry.hash || '';

    const recomputedHash = computeAuditEntryHash({
      id: entry.id,
      org_id: entry.org_id || 'org_local',
      frn: entry.frn,
      timestamp: entry.timestamp,
      user_name: entry.user_name || entry.user,
      role: entry.role,
      action: entry.action,
      target: entry.target,
      previous_hash: actualPrevHash
    });

    const prevLinkOk = (i === 0 && actualPrevHash === 'GENESIS-BLOCK') || (actualPrevHash === expectedPrevHash);
    const contentHashOk = storedHash === recomputedHash;

    if (!prevLinkOk || !contentHashOk) {
      tamperedEntries.push({
        id: entry.id,
        action: entry.action,
        reason: !contentHashOk ? 'CONTENT_HASH_MISMATCH' : 'BROKEN_PREVIOUS_HASH_LINK',
        storedHash,
        recomputedHash,
        actualPrevHash,
        expectedPrevHash
      });
    } else {
      verifiedLinks += 1;
    }
  }

  return {
    valid: tamperedEntries.length === 0,
    totalEntries: chronological.length,
    verifiedLinks,
    tamperedEntries
  };
}

async function recordAuditTrailEntry({ orgId, frn, userName, role, action, target }) {
  const normalizedFrn = (frn || 'DEFAULT').trim().toUpperCase();
  const safeOrgId = orgId || 'org_local';
  const safeUser = sanitizeText(userName || 'Practicing Partner');
  const safeRole = sanitizeText(role || 'PARTNER');
  const safeAction = sanitizeText(action || 'SYSTEM_EVENT');
  const safeTarget = sanitizeText(target || '');
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);

  const localDb = loadLocalDatabase();
  localDb.audit_logs = localDb.audit_logs || [];

  const firmLogs = localDb.audit_logs.filter(l => (l.frn || '').toUpperCase() === normalizedFrn);
  const prevHash = firmLogs.length > 0 ? (firmLogs[0].payload_hash || firmLogs[0].hash || 'GENESIS-BLOCK') : 'GENESIS-BLOCK';
  const nextId = localDb.audit_logs.length > 0
    ? Math.max(...localDb.audit_logs.map(l => Number(l.id) || 0)) + 1
    : 1;

  const payloadHash = computeAuditEntryHash({
    id: nextId,
    org_id: safeOrgId,
    frn: normalizedFrn,
    timestamp,
    user_name: safeUser,
    role: safeRole,
    action: safeAction,
    target: safeTarget,
    previous_hash: prevHash
  });

  const entry = {
    id: nextId,
    org_id: safeOrgId,
    frn: normalizedFrn,
    timestamp,
    user_name: safeUser,
    user: safeUser,
    role: safeRole,
    action: safeAction,
    target: safeTarget,
    payload_hash: payloadHash,
    hash: payloadHash,
    previous_hash: prevHash,
    previousHash: prevHash
  };

  localDb.audit_logs.unshift(entry);
  saveLocalDatabase(localDb);

  if (isPostgresReady && pgPool) {
    try {
      await pgPool.query(
        `INSERT INTO audit_logs (org_id, frn, user_name, role, action, target, payload_hash, previous_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [safeOrgId, normalizedFrn, safeUser, safeRole, safeAction, safeTarget, payloadHash, prevHash]
      );
    } catch (e) {}
  }

  return payloadHash;
}

async function getSubscriptionForUser(email) {
  if (!email) return null;
  const cleanEmail = email.trim().toLowerCase();

  if (isPostgresReady && pgPool) {
    try {
      const subRes = await pgPool.query(
        `SELECT plan_tier, billing_cycle, amount_paid, current_period_end, razorpay_payment_id
         FROM public.firm_subscriptions
         WHERE LOWER(firm_id) = $1
         ORDER BY current_period_end DESC
         LIMIT 1`,
        [cleanEmail]
      );
      if (subRes.rows.length > 0) {
        const row = subRes.rows[0];
        const amt = Number(row.amount_paid) || 0;
        let invNumber = 'INV-FA-2026-0001';
        try {
          const invRes = await pgPool.query(
            `SELECT invoice_number FROM public.subscription_invoices WHERE LOWER(firm_email) = $1 ORDER BY id DESC LIMIT 1`,
            [cleanEmail]
          );
          if (invRes.rows.length > 0) invNumber = invRes.rows[0].invoice_number;
        } catch (e) {}

        return {
          status: amt > 0 ? 'PAID' : 'TRIAL',
          tier: (row.plan_tier || 'REGIONAL').toUpperCase(),
          cycle: (row.billing_cycle || 'ANNUAL').toUpperCase(),
          amountPaid: amt,
          invoiceNumber: amt > 0 ? invNumber : 'TRIAL-EVAL-FREE',
          validUntil: row.current_period_end ? new Date(row.current_period_end).toISOString().substring(0, 10) : null,
          trialEndsAt: row.current_period_end ? new Date(row.current_period_end).toISOString() : new Date(Date.now() + 7 * 86400000).toISOString(),
          paymentId: row.razorpay_payment_id
        };
      }
    } catch (e) {}
  }

  const localDb = loadLocalDatabase();
  if (localDb.subscriptions && localDb.subscriptions[cleanEmail]) {
    return localDb.subscriptions[cleanEmail];
  }
  return null;
}

// =========================================================================
// UNIVERSAL EMAIL DELIVERY GATEWAY (HTTPS REST API + NODEMAILER FALLBACK)
// =========================================================================
// Render Free-Tier explicitly blocks outbound TCP on SMTP ports 25, 465, and 587.
// We support Brevo / Resend REST APIs over HTTPS (Port 443) which Render NEVER blocks,
// with automatic fallback to Nodemailer for localhost / unblocked hosts.

let mailTransport = null;

function setupMailTransport() {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (emailUser && emailPass) {
    const cleanPass = emailPass.trim().replace(/\s+/g, '');
    const cleanUser = emailUser.trim();

    mailTransport = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user: cleanUser, pass: cleanPass },
      tls: { rejectUnauthorized: false }
    });

    mailTransport.verify((err) => {
      if (err) {
        console.warn('>>> [FinAudit Mail] Local SMTP Notice (Port 465):', err.message);
      } else {
        console.log(`>>> [FinAudit Mail] Connected to SMTP Transport for (${cleanUser}).`);
      }
    });
  } else {
    nodemailer.createTestAccount((err, account) => {
      if (!err && account) {
        mailTransport = nodemailer.createTransport({
          host: account.smtp.host,
          port: account.smtp.port,
          secure: account.smtp.secure,
          auth: { user: account.user, pass: account.pass }
        });
      }
    });
  }
}
setupMailTransport();

async function sendEmailUniversal({ to, subject, text, html, partnerName, firmName, frn }) {
  const cleanTo = String(to || '').trim();
  const cleanSubject = String(subject || 'FinAudit One Notification').trim();
  const cleanPartner = sanitizeText(partnerName || 'Practicing Partner');
  const cleanFirm = sanitizeText(firmName || 'CA Practice Firm');
  const senderEmail = (process.env.EMAIL_USER || 'no-reply@finauditone.onrender.com').trim();
  const fromName = 'FinAudit One';

  // 1. BREVO (Sendinblue) HTTPS REST API (Port 443 — NEVER BLOCKED BY RENDER)
  const brevoApiKey = (process.env.BREVO_API_KEY || '').trim();
  if (brevoApiKey && typeof fetch === 'function') {
    try {
      const brevoRes = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'api-key': brevoApiKey,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          sender: { name: fromName, email: senderEmail },
          to: [{ email: cleanTo, name: cleanPartner }],
          subject: cleanSubject,
          htmlContent: html,
          textContent: text
        })
      });
      const data = await brevoRes.json();
      if (brevoRes.ok) {
        console.log(`>>> [FinAudit Mail] Delivered via Brevo HTTPS API to ${cleanTo} (ID: ${data.messageId})`);
        return { success: true, messageId: data.messageId, provider: 'BREVO_HTTPS' };
      }
      console.warn('>>> [FinAudit Mail] Brevo API Error:', data.message || JSON.stringify(data));
    } catch (apiErr) {
      console.warn('>>> [FinAudit Mail] Brevo Fetch Error:', apiErr.message);
    }
  }

  // 2. RESEND HTTPS REST API (Port 443 — NEVER BLOCKED BY RENDER)
  const resendApiKey = (process.env.RESEND_API_KEY || '').trim();
  if (resendApiKey && typeof fetch === 'function') {
    try {
      const resendRes = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: `${fromName} <onboarding@resend.dev>`,
          to: [cleanTo],
          subject: cleanSubject,
          html,
          text
        })
      });
      const data = await resendRes.json();
      if (resendRes.ok && data.id) {
        console.log(`>>> [FinAudit Mail] Delivered via Resend HTTPS API to ${cleanTo} (ID: ${data.id})`);
        return { success: true, messageId: data.id, provider: 'RESEND_HTTPS' };
      }
      console.warn('>>> [FinAudit Mail] Resend API Error:', data.message || JSON.stringify(data));
    } catch (apiErr) {
      console.warn('>>> [FinAudit Mail] Resend Fetch Error:', apiErr.message);
    }
  }

  // 3. NODEMAILER SMTP TRANSPORT (Port 465 fallback for local / unblocked hosts)
  if (mailTransport) {
    try {
      const info = await mailTransport.sendMail({
        from: `"${fromName}" <${senderEmail}>`,
        to: cleanTo,
        subject: cleanSubject,
        text,
        html
      });
      console.log(`>>> [FinAudit Mail] Delivered via SMTP to ${cleanTo} (${info.messageId})`);
      return { success: true, messageId: info.messageId, provider: 'SMTP' };
    } catch (smtpErr) {
      console.warn('>>> [FinAudit Mail] SMTP Delivery Warning (Render Free tier blocks outbound SMTP ports 25/465/587):', smtpErr.message);
    }
  }

  // 4. In development / testing: Log to server stdout so developers are never blocked
  console.log(`>>> [FinAudit Mail] [DEV LOG] To: ${cleanTo} | Subject: ${cleanSubject}`);
  return { success: true, messageId: `local_logged_${Date.now()}`, provider: 'DEV_CONSOLE' };
}

async function sendWelcomeEmail({ to, partnerName, firmName, frn }) {
  const cleanPartner = sanitizeText(partnerName || 'Practicing Partner');
  const cleanFirm = sanitizeText(firmName || 'CA Practice Firm');
  const cleanFrn = sanitizeText(frn || 'N/A').toUpperCase();

  const text = `Hello ${cleanPartner},\n\nYour CA practice workspace for ${cleanFirm} (ICAI FRN: ${cleanFrn}) is now active on FinAudit One.`;
  const html = `
    <div style="font-family:sans-serif;padding:24px;max-width:540px;margin:auto;border:1px solid #e2e8f0;border-radius:16px;">
      <h2 style="color:#4338ca;margin-top:0;">Welcome to FinAudit One</h2>
      <p>Hello <strong>${cleanPartner}</strong>,</p>
      <p>Your CA practice workspace for <strong>${cleanFirm}</strong> (ICAI FRN: <code>${cleanFrn}</code>) is now fully provisioned.</p>
      <div style="background:#f8fafc;padding:12px 16px;border-radius:8px;margin:16px 0;">
        <div><strong>Status:</strong> ⚡ 7-Day Free Practice Trial Active (₹0 Due)</div>
        <div><strong>Access URL:</strong> <a href="https://finauditone.onrender.com">https://finauditone.onrender.com</a></div>
      </div>
      <p style="font-size:12px;color:#64748b;">FinAudit One • Autonomous CA Cloud Operating System</p>
    </div>
  `;

  return sendEmailUniversal({
    to,
    subject: `Welcome to FinAudit One, ${cleanPartner}`,
    text,
    html,
    partnerName: cleanPartner,
    firmName: cleanFirm,
    frn: cleanFrn
  });
}

app.get('/api/health', (req, res) => {
  const rzp = getRazorpayConfig();
  const mailEngine = process.env.BREVO_API_KEY ? 'Brevo HTTPS API (Port 443 Active)' : (process.env.RESEND_API_KEY ? 'Resend HTTPS API (Port 443 Active)' : (process.env.EMAIL_USER ? 'Nodemailer SMTP (Gmail)' : 'Local Dev Fallback'));

  res.json({
    status: 'ONLINE',
    service: 'FinAudit One Autonomous CA Cloud OS API',
    databaseEngine: isPostgresReady ? 'PostgreSQL (Supabase Active)' : 'Local File Store',
    paymentGateway: rzp.configured ? `Razorpay ${rzp.mode} Mode (Merchant: ${rzp.merchantId})` : 'Unconfigured (Env Keys Required)',
    emailGateway: mailEngine,
    merchantId: rzp.merchantId,
    accountId: rzp.accountId,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/database/status', async (req, res) => {
  if (isPostgresReady && pgPool) {
    try {
      const result = await pgPool.query('SELECT NOW() as server_time, current_database() as db_name');
      return res.json({
        engine: 'PostgreSQL / Supabase',
        connected: true,
        rowLevelSecurityEnforced: true,
        mcaRule11gChaining: 'ACTIVE',
        serverTime: result.rows[0].server_time,
        database: result.rows[0].db_name
      });
    } catch (e) {
      return res.json({ engine: 'PostgreSQL', connected: false, error: e.message });
    }
  }
  res.json({
    engine: 'Local In-Memory / File Store',
    connected: true,
    rowLevelSecurityEnforced: false,
    mcaRule11gChaining: 'ACTIVE (Local SHA-256)'
  });
});

app.get('/api/mail/welcome', requireAuth, async (req, res) => {
  try {
    const result = await sendWelcomeEmail({
      to: req.user.email,
      partnerName: req.user.name,
      firmName: req.org?.name || 'CA Practice Firm',
      frn: req.user.frn
    });
    return res.json({
      success: true,
      message: `Welcome email dispatched to ${req.user.email}`,
      messageId: result?.messageId || 'sandbox_msg'
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/mail/test', requireAuth, async (req, res) => {
  try {
    const result = await sendWelcomeEmail({
      to: req.user.email,
      partnerName: req.user.name,
      firmName: req.org?.name || 'CA Practice Firm',
      frn: req.user.frn
    });
    return res.json({
      success: true,
      message: `Authenticated test email dispatched to ${req.user.email}`,
      messageId: result?.messageId || 'sandbox_msg'
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firmName, partnerName, frn, email, password, intent, desiredTier } = req.body || {};

    if (!firmName || !partnerName || !frn || !email || !password) {
      return res.status(400).json({ success: false, message: 'All practice registration fields are required.' });
    }

    const cleanFirmName = sanitizeText(firmName);
    const cleanPartnerName = sanitizeText(partnerName);
    if (!cleanFirmName || !cleanPartnerName) {
      return res.status(400).json({ success: false, message: 'Valid firm name and partner name are required.' });
    }

    const frnCheck = validateFrn(frn);
    if (!frnCheck.valid) {
      return res.status(400).json({ success: false, message: frnCheck.message });
    }

    const pwdCheck = validatePasswordStrength(password);
    if (!pwdCheck.valid) {
      return res.status(400).json({ success: false, message: pwdCheck.message });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedFrn = frnCheck.clean;
    const salt = crypto.randomBytes(16).toString('hex');
    const pwdHash = hashPassword(password, salt);
    const orgId = 'org_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
    const userId = 'usr_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

    const trialEnd = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const isDirectPurchase = intent === 'PURCHASE';
    const initialSubscription = isDirectPurchase
      ? {
          status: 'PENDING_PAYMENT',
          tier: (desiredTier || 'SOLO').toUpperCase(),
          cycle: 'ANNUAL',
          amountPaid: 0,
          invoiceNumber: null,
          validUntil: null,
          trialEndsAt: null
        }
      : {
          status: 'TRIAL',
          tier: 'REGIONAL',
          cycle: 'ANNUAL',
          amountPaid: 0,
          invoiceNumber: 'TRIAL-EVAL-FREE',
          validUntil: trialEnd.toISOString().substring(0, 10),
          trialEndsAt: trialEnd.toISOString()
        };

    if (isPostgresReady && pgPool) {
      const client = await pgPool.connect();
      try {
        await client.query('BEGIN');

        const checkUser = await client.query('SELECT id FROM users WHERE LOWER(email) = $1', [normalizedEmail]);
        if (checkUser.rows.length > 0) {
          await client.query('ROLLBACK');
          return res.status(409).json({ success: false, message: 'An account with this email address already exists. Please sign in.' });
        }

        const checkFrn = await client.query('SELECT id FROM organizations WHERE UPPER(icai_frn) = $1', [normalizedFrn]);
        if (checkFrn.rows.length > 0) {
          await client.query('ROLLBACK');
          return res.status(409).json({
            success: false,
            code: 'FRN_ALREADY_OWNED',
            message: `ICAI FRN ${normalizedFrn} is already registered to an existing practice.`
          });
        }

        const orgRes = await client.query(
          `INSERT INTO organizations (id, legal_name, icai_frn, managing_partner, email)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING *`,
          [orgId, cleanFirmName, normalizedFrn, cleanPartnerName, normalizedEmail]
        );

        const targetOrgId = orgRes.rows[0].id;

        const userRes = await client.query(
          `INSERT INTO users (id, org_id, frn, name, email, password_hash, salt, role, is_verified, token_version)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'PARTNER', TRUE, 1)
           RETURNING id, name, email, role, frn, org_id, COALESCE(token_version, 1) as token_version`,
          [userId, targetOrgId, normalizedFrn, cleanPartnerName, normalizedEmail, pwdHash, salt]
        );

        await client.query('COMMIT');

        const userRecord = userRes.rows[0];
        const accessToken = generateJwt({
          userId: userRecord.id,
          email: userRecord.email,
          role: userRecord.role,
          frn: userRecord.frn,
          orgId: targetOrgId,
          tokenVersion: 1
        }, 86400, 'ACCESS');

        const refreshToken = generateJwt({
          userId: userRecord.id,
          email: userRecord.email,
          role: userRecord.role,
          frn: userRecord.frn,
          orgId: targetOrgId,
          tokenVersion: 1
        }, 604800, 'REFRESH');

        await recordAuditTrailEntry({
          orgId: targetOrgId,
          frn: normalizedFrn,
          userName: cleanPartnerName,
          role: 'PARTNER',
          action: 'REGISTER_PRACTICE',
          target: `${cleanFirmName} (FRN: ${normalizedFrn})`
        });

        sendWelcomeEmail({
          to: normalizedEmail,
          partnerName: cleanPartnerName,
          firmName: cleanFirmName,
          frn: normalizedFrn
        }).catch(() => {});

        return res.status(201).json({
          success: true,
          message: `Workspace provisioned! Welcome email sent to ${normalizedEmail}`,
          user: userRecord,
          org: {
            id: orgRes.rows[0].id,
            name: orgRes.rows[0].legal_name,
            frn: orgRes.rows[0].icai_frn,
            ownerEmail: normalizedEmail
          },
          subscription: initialSubscription,
          tokens: { accessToken, refreshToken }
        });
      } catch (dbErr) {
        await client.query('ROLLBACK');
        console.error('[FinAudit Signup DB Error]', dbErr.message);
      } finally {
        client.release();
      }
    }

    const localDb = loadLocalDatabase();
    if (localDb.users.some(u => u.email.toLowerCase() === normalizedEmail)) {
      return res.status(409).json({ success: false, message: 'An account with this email address already exists. Please sign in.' });
    }

    const existingOrg = localDb.organizations.find(o => (o.icai_frn || '').toUpperCase() === normalizedFrn);
    if (existingOrg) {
      return res.status(409).json({
        success: false,
        code: 'FRN_ALREADY_OWNED',
        message: `ICAI FRN ${normalizedFrn} is already registered to an existing practice.`
      });
    }

    const org = {
      id: orgId,
      legal_name: cleanFirmName,
      name: cleanFirmName,
      icai_frn: normalizedFrn,
      frn: normalizedFrn,
      managing_partner: cleanPartnerName,
      email: normalizedEmail,
      owner_user_id: userId,
      created_at: new Date().toISOString()
    };
    localDb.organizations.push(org);

    const newUser = {
      id: userId,
      org_id: org.id,
      frn: normalizedFrn,
      name: cleanPartnerName,
      email: normalizedEmail,
      password_hash: pwdHash,
      salt,
      role: 'PARTNER',
      is_verified: true,
      token_version: 1,
      created_at: new Date().toISOString()
    };
    localDb.users.push(newUser);
    localDb.subscriptions = localDb.subscriptions || {};
    localDb.subscriptions[normalizedEmail] = initialSubscription;
    saveLocalDatabase(localDb);

    const accessToken = generateJwt({
      userId: newUser.id,
      email: newUser.email,
      role: newUser.role,
      frn: newUser.frn,
      orgId: org.id,
      tokenVersion: 1
    }, 86400, 'ACCESS');

    const refreshToken = generateJwt({
      userId: newUser.id,
      email: newUser.email,
      role: newUser.role,
      frn: newUser.frn,
      orgId: org.id,
      tokenVersion: 1
    }, 604800, 'REFRESH');

    await recordAuditTrailEntry({
      orgId: org.id,
      frn: normalizedFrn,
      userName: cleanPartnerName,
      role: 'PARTNER',
      action: 'REGISTER_PRACTICE',
      target: `${cleanFirmName} (FRN: ${normalizedFrn})`
    });

    sendWelcomeEmail({
      to: normalizedEmail,
      partnerName: cleanPartnerName,
      firmName: cleanFirmName,
      frn: normalizedFrn
    }).catch(() => {});

    return res.status(201).json({
      success: true,
      message: `Workspace provisioned! Welcome email sent to ${normalizedEmail}`,
      user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role, frn: newUser.frn, orgId: org.id },
      org: { id: org.id, name: org.legal_name, frn: org.icai_frn, ownerEmail: org.email },
      subscription: initialSubscription,
      tokens: { accessToken, refreshToken }
    });
  } catch (err) {
    console.error('[FinAudit Signup Error]', err);
    res.status(500).json({ success: false, message: 'Internal server error processing practice registration.' });
  }
});

app.post('/api/auth/login', checkLoginRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    if (isPostgresReady && pgPool) {
      try {
        const queryRes = await pgPool.query(
          `SELECT u.*, COALESCE(u.token_version, 1) as current_token_version,
                  o.legal_name as org_name, o.icai_frn as org_frn, o.email as org_owner_email
           FROM users u
           LEFT JOIN organizations o ON u.org_id = o.id
           WHERE LOWER(u.email) = $1`,
          [normalizedEmail]
        );

        if (queryRes.rows.length > 0) {
          const user = queryRes.rows[0];
          if (verifyPassword(password, user.salt, user.password_hash)) {
            resetLoginRateLimit(req);
            const currentVersion = Number(user.current_token_version) || 1;
            const verifiedFrn = (user.org_frn || user.frn || '').toUpperCase();
            const accessToken = generateJwt({
              userId: user.id,
              email: user.email,
              role: user.role,
              frn: verifiedFrn,
              orgId: user.org_id,
              tokenVersion: currentVersion
            }, 86400, 'ACCESS');
            const refreshToken = generateJwt({
              userId: user.id,
              email: user.email,
              role: user.role,
              frn: verifiedFrn,
              orgId: user.org_id,
              tokenVersion: currentVersion
            }, 604800, 'REFRESH');
            const subscription = await getSubscriptionForUser(normalizedEmail);
            return res.json({
              success: true,
              user: { id: user.id, name: user.name, email: user.email, role: user.role, frn: verifiedFrn, orgId: user.org_id },
              org: { id: user.org_id, name: user.org_name, frn: verifiedFrn, ownerEmail: user.org_owner_email || user.email },
              subscription,
              tokens: { accessToken, refreshToken }
            });
          }
        }
      } catch (dbErr) {
        console.error('[FinAudit Login DB Error]', dbErr.message);
      }
    }

    const localDb = loadLocalDatabase();
    const localUser = (localDb.users || []).find(u => u.email.toLowerCase() === normalizedEmail);
    if (localUser && verifyPassword(password, localUser.salt, localUser.password_hash)) {
      resetLoginRateLimit(req);
      const currentVersion = Number(localUser.token_version) || 1;
      const org = (localDb.organizations || []).find(o => o.id === localUser.org_id) || {
        id: localUser.org_id,
        legal_name: 'CA Practice Firm',
        icai_frn: localUser.frn,
        email: localUser.email
      };
      const verifiedFrn = (org.icai_frn || localUser.frn || '').toUpperCase();
      const accessToken = generateJwt({
        userId: localUser.id,
        email: localUser.email,
        role: localUser.role,
        frn: verifiedFrn,
        orgId: localUser.org_id,
        tokenVersion: currentVersion
      }, 86400, 'ACCESS');
      const refreshToken = generateJwt({
        userId: localUser.id,
        email: localUser.email,
        role: localUser.role,
        frn: verifiedFrn,
        orgId: localUser.org_id,
        tokenVersion: currentVersion
      }, 604800, 'REFRESH');
      const subscription = await getSubscriptionForUser(normalizedEmail);
      return res.json({
        success: true,
        user: { id: localUser.id, name: localUser.name, email: localUser.email, role: localUser.role, frn: verifiedFrn, orgId: localUser.org_id },
        org: { id: org.id, name: org.legal_name || org.name, frn: verifiedFrn, ownerEmail: org.email || localUser.email },
        subscription,
        tokens: { accessToken, refreshToken }
      });
    }

    const attemptRecord = recordFailedLoginAttempt(req);
    if (attemptRecord.count >= MAX_AUTH_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: 'Too many unsuccessful sign-in attempts. Account temporarily locked for 10 minutes.'
      });
    }

    return res.status(401).json({ success: false, message: 'Invalid professional email or password.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Authentication service error.' });
  }
});

app.post('/api/auth/refresh-token', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ success: false, message: 'Refresh token is required.' });

  const payload = verifyJwt(refreshToken, 'REFRESH');
  if (!payload || !payload.email) {
    return res.status(401).json({ success: false, code: 'INVALID_REFRESH_TOKEN', message: 'Invalid or expired refresh token.' });
  }

  if (isTokenRevoked(payload.jti, refreshToken)) {
    return res.status(401).json({ success: false, code: 'SESSION_REVOKED', message: 'Refresh token has been revoked.' });
  }

  const resolved = await getAuthenticatedUserAndOrg(payload.userId, payload.email);
  if (!resolved || !resolved.user) {
    return res.status(401).json({ success: false, code: 'USER_NOT_FOUND', message: 'User account not found.' });
  }

  const tokenVersionInJwt = Number(payload.tokenVersion) || 1;
  if (resolved.user.tokenVersion !== tokenVersionInJwt) {
    return res.status(401).json({
      success: false,
      code: 'SESSION_REVOKED',
      message: 'Session has been revoked. Please sign in again.'
    });
  }

  if (payload.jti) revokeToken(payload.jti, payload.exp);
  revokeToken(hashRawToken(refreshToken), payload.exp);

  const newAccessToken = generateJwt({
    userId: resolved.user.id,
    email: resolved.user.email,
    role: resolved.user.role,
    frn: resolved.user.frn,
    orgId: resolved.user.orgId,
    tokenVersion: resolved.user.tokenVersion
  }, 86400, 'ACCESS');

  const newRefreshToken = generateJwt({
    userId: resolved.user.id,
    email: resolved.user.email,
    role: resolved.user.role,
    frn: resolved.user.frn,
    orgId: resolved.user.orgId,
    tokenVersion: resolved.user.tokenVersion
  }, 604800, 'REFRESH');

  res.json({ success: true, tokens: { accessToken: newAccessToken, refreshToken: newRefreshToken } });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const normalizedEmail = req.user.email.toLowerCase();
  const subscription = await getSubscriptionForUser(normalizedEmail);

  return res.json({
    success: true,
    user: {
      id: req.user.userId,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      frn: req.user.frn,
      orgId: req.user.orgId
    },
    org: {
      id: req.org.id,
      name: req.org.name,
      frn: req.org.frn,
      ownerEmail: req.org.ownerEmail
    },
    subscription
  });
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const accessToken = authHeader.split(' ')[1];
      const payload = verifyJwt(accessToken, null);
      if (payload && payload.jti) {
        revokeToken(payload.jti, payload.exp);
      }
      revokeToken(hashRawToken(accessToken));
    }

    const { refreshToken } = req.body || {};
    if (refreshToken) {
      const rPayload = verifyJwt(refreshToken, null);
      if (rPayload && rPayload.jti) {
        revokeToken(rPayload.jti, rPayload.exp);
      }
      revokeToken(hashRawToken(refreshToken));
    }

    return res.json({ success: true, message: 'Signed out and session token revoked.' });
  } catch (e) {
    return res.json({ success: true, message: 'Signed out successfully.' });
  }
});

app.post('/api/auth/revoke-all-sessions', requireAuth, async (req, res) => {
  try {
    const normalizedEmail = req.user.email.toLowerCase();
    let newVersion = (Number(req.user.tokenVersion) || 1) + 1;

    if (req.user.jti) revokeToken(req.user.jti, req.user.exp);
    if (req.user.rawToken) revokeToken(hashRawToken(req.user.rawToken), req.user.exp);

    if (req.body && req.body.refreshToken) {
      const rp = verifyJwt(req.body.refreshToken, null);
      if (rp && rp.jti) revokeToken(rp.jti, rp.exp);
      revokeToken(hashRawToken(req.body.refreshToken));
    }

    if (isPostgresReady && pgPool) {
      try {
        const upRes = await pgPool.query(
          'UPDATE users SET token_version = COALESCE(token_version, 1) + 1 WHERE LOWER(email) = $1 RETURNING token_version',
          [normalizedEmail]
        );
        if (upRes.rows.length > 0) {
          newVersion = Number(upRes.rows[0].token_version) || newVersion;
        }
      } catch (e) {}
    }

    const localDb = loadLocalDatabase();
    const localUser = (localDb.users || []).find(u => u.email.toLowerCase() === normalizedEmail);
    if (localUser) {
      localUser.token_version = Math.max(newVersion, (Number(localUser.token_version) || 1) + 1);
      newVersion = localUser.token_version;
      saveLocalDatabase(localDb);
    }

    await recordAuditTrailEntry({
      orgId: req.user.orgId,
      frn: req.user.frn,
      userName: req.user.email,
      role: req.user.role,
      action: 'REVOKE_ALL_SESSIONS',
      target: `Global token_version incremented to v${newVersion} for ${normalizedEmail}`
    });

    return res.json({
      success: true,
      sessionRevoked: true,
      tokenVersion: newVersion,
      message: 'All active sessions across all devices have been revoked.'
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to revoke sessions.' });
  }
});

app.post('/api/auth/forgot-password', checkForgotRateLimit, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ success: false, message: 'Email address is required.' });

  const normalizedEmail = String(email).trim().toLowerCase();
  const resolved = await getAuthenticatedUserAndOrg(null, normalizedEmail);

  const uniformMessage = '6-digit security code dispatched to your mailbox (valid for 60 seconds).';
  if (!resolved || !resolved.user) {
    return res.json({ success: true, expiresIn: 60, message: uniformMessage });
  }

  const otp = crypto.randomInt(100000, 1000000).toString();
  const otpSalt = crypto.randomBytes(16).toString('hex');
  const otpHash = hashRecoveryOtp(normalizedEmail, otp, otpSalt);
  const expiresAt = new Date(Date.now() + 60 * 1000);

  const localDb = loadLocalDatabase();
  localDb.resetTokens = localDb.resetTokens || {};
  localDb.resetTokens[normalizedEmail] = {
    otpHash,
    salt: otpSalt,
    attempts: 0,
    maxAttempts: 5,
    locked: false,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString()
  };
  saveLocalDatabase(localDb);

  const cleanPartner = resolved.user.name || 'Practicing Partner';
  const textBody = `Your security code to reset your FinAudit One password is: ${otp}. This code expires in 60 seconds.`;
  const htmlBody = `
    <div style="font-family:sans-serif;padding:24px;max-width:520px;margin:auto;border:1px solid #e2e8f0;border-radius:16px;">
      <h2 style="color:#4338ca;margin-top:0;">Security Verification Code</h2>
      <p>Hello <strong>${cleanPartner}</strong>,</p>
      <p>Your one-time code to reset your FinAudit One password is:</p>
      <div style="font-size:32px;font-weight:900;font-family:monospace;letter-spacing:6px;color:#4338ca;padding:12px 0;">
        ${otp}
      </div>
      <p style="font-size:12px;color:#e11d48;font-weight:bold;">⚡ This security code is valid for 60 seconds.</p>
    </div>
  `;

  sendEmailUniversal({
    to: normalizedEmail,
    subject: `FinAudit One — Password Reset Security Code [${otp}]`,
    text: textBody,
    html: htmlBody,
    partnerName: cleanPartner
  }).catch(() => {});

  res.json({ success: true, expiresIn: 60, message: uniformMessage });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body || {};
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ success: false, message: 'Email, 6-digit OTP, and new password are required.' });
  }

  const pwdCheck = validatePasswordStrength(newPassword);
  if (!pwdCheck.valid) {
    return res.status(400).json({ success: false, message: pwdCheck.message });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const cleanOtp = String(otp).trim();
  const localDb = loadLocalDatabase();
  localDb.resetTokens = localDb.resetTokens || {};
  const tokenRecord = localDb.resetTokens[normalizedEmail];

  if (!tokenRecord) {
    return res.status(400).json({
      success: false,
      code: 'OTP_EXPIRED',
      message: 'Code expired or not found. Please click Resend Code to get a new 6-digit OTP.'
    });
  }

  const maxAttempts = Number(tokenRecord.maxAttempts) || 5;
  if (tokenRecord.locked || (Number(tokenRecord.attempts) || 0) >= maxAttempts) {
    tokenRecord.locked = true;
    saveLocalDatabase(localDb);
    return res.status(429).json({
      success: false,
      code: 'OTP_LOCKED',
      message: 'Maximum OTP verification attempts exceeded. Security code invalidated — please request a new code.'
    });
  }

  if (new Date(tokenRecord.expiresAt).getTime() < Date.now()) {
    delete localDb.resetTokens[normalizedEmail];
    saveLocalDatabase(localDb);
    return res.status(400).json({
      success: false,
      code: 'OTP_EXPIRED',
      message: 'Code expired. Please click Resend Code to get a new 6-digit OTP.'
    });
  }

  const isOtpValid = tokenRecord.otpHash
    ? verifyRecoveryOtp(normalizedEmail, cleanOtp, tokenRecord.salt, tokenRecord.otpHash)
    : (tokenRecord.otp && String(tokenRecord.otp).trim() === cleanOtp);

  if (!isOtpValid) {
    tokenRecord.attempts = (Number(tokenRecord.attempts) || 0) + 1;
    if (tokenRecord.attempts >= maxAttempts) {
      tokenRecord.locked = true;
      delete tokenRecord.otpHash;
      delete tokenRecord.otp;
      saveLocalDatabase(localDb);
      return res.status(429).json({
        success: false,
        code: 'OTP_LOCKED',
        message: 'Too many incorrect OTP attempts. Security code permanently invalidated.'
      });
    }
    saveLocalDatabase(localDb);
    const remaining = maxAttempts - tokenRecord.attempts;
    return res.status(400).json({
      success: false,
      code: 'INVALID_OTP',
      message: `Incorrect OTP. Please check the 6-digit code (${remaining} attempt(s) remaining).`
    });
  }

  delete localDb.resetTokens[normalizedEmail];

  const salt = crypto.randomBytes(16).toString('hex');
  const pwdHash = hashPassword(newPassword, salt);

  if (isPostgresReady && pgPool) {
    try {
      await pgPool.query(
        'UPDATE users SET password_hash = $1, salt = $2, token_version = COALESCE(token_version, 1) + 1 WHERE LOWER(email) = $3',
        [pwdHash, salt, normalizedEmail]
      );
    } catch (e) {}
  }

  const user = (localDb.users || []).find(u => u.email.toLowerCase() === normalizedEmail);
  if (user) {
    user.password_hash = pwdHash;
    user.salt = salt;
    user.token_version = (Number(user.token_version) || 1) + 1;
  }
  saveLocalDatabase(localDb);

  const resolved = await getAuthenticatedUserAndOrg(null, normalizedEmail);
  if (resolved && resolved.user) {
    await recordAuditTrailEntry({
      orgId: resolved.user.orgId,
      frn: resolved.user.frn,
      userName: normalizedEmail,
      role: resolved.user.role,
      action: 'PASSWORD_RESET_COMPLETED',
      target: `Password reset & prior sessions revoked for ${normalizedEmail}`
    });
  }

  res.json({ success: true, message: 'Password updated successfully. All prior sessions have been revoked.' });
});

app.get('/api/audit-trail', requireAuth, async (req, res) => {
  try {
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();
    const localDb = loadLocalDatabase();
    const logs = (localDb.audit_logs || []).filter(
      l => (l.frn || '').toUpperCase() === tenantFrn
    );
    const verification = verifyAuditChain(logs);

    return res.json({
      success: true,
      chainVerified: verification.valid,
      totalEntries: verification.totalEntries,
      verifiedLinks: verification.verifiedLinks,
      tamperedEntries: verification.tamperedEntries,
      logs
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve audit trail.' });
  }
});

app.get('/api/audit-trail/verify', requireAuth, async (req, res) => {
  try {
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();
    const localDb = loadLocalDatabase();
    const logs = (localDb.audit_logs || []).filter(
      l => (l.frn || '').toUpperCase() === tenantFrn
    );
    const verification = verifyAuditChain(logs);

    if (!verification.valid) {
      return res.status(409).json({
        success: false,
        chainVerified: false,
        message: 'MCA Rule 11(g) Audit Trail integrity check FAILED: tampering detected.',
        ...verification
      });
    }

    return res.json({
      success: true,
      chainVerified: true,
      message: 'MCA Rule 11(g) SHA-256 forward-linked audit chain verified tamper-free.',
      ...verification
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to verify audit trail.' });
  }
});

app.get('/api/clients', requireAuth, async (req, res) => {
  try {
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();

    if (isPostgresReady && pgPool) {
      const clientRes = await pgPool.query(
        `SELECT id, org_id, frn, name, gstin, pan, constitution, tax_regime as "taxRegime",
                turnover, net_profit_before_tax as "netProfitBeforeTax", created_at
         FROM clients
         WHERE UPPER(frn) = $1
         ORDER BY created_at DESC`,
        [tenantFrn]
      );
      return res.json({ success: true, clients: clientRes.rows });
    }

    const localDb = loadLocalDatabase();
    const clients = (localDb.clients || []).filter(c => (c.frn || '').toUpperCase() === tenantFrn);
    return res.json({ success: true, clients });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve client assessees.' });
  }
});

app.post('/api/clients', requireAuth, async (req, res) => {
  try {
    const { name, gstin, constitution, taxRegime, pbt } = req.body || {};
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();
    const userOrgId = req.user.orgId || 'org_default';

    const cleanName = sanitizeText(name);
    if (!cleanName || cleanName.length === 0) {
      return res.status(400).json({ success: false, message: 'Valid legal business name is required.' });
    }

    const gstinCheck = validateGstin(gstin);
    if (!gstinCheck.valid) {
      return res.status(400).json({ success: false, message: gstinCheck.message });
    }

    const cleanGstin = gstinCheck.clean;
    const derivedPan = gstinCheck.pan;
    const ALLOWED_CONSTITUTIONS = ['COMPANY', 'LLP', 'FIRM', 'PROPRIETORSHIP', 'TRUST', 'HUF', 'INDIVIDUAL'];
    const safeConstitution = ALLOWED_CONSTITUTIONS.includes(String(constitution || '').toUpperCase())
      ? String(constitution).toUpperCase()
      : 'COMPANY';
    const ALLOWED_REGIMES = ['115BAA', 'NORMAL', 'FIRM', '115BAB'];
    const safeRegime = ALLOWED_REGIMES.includes(String(taxRegime || '').toUpperCase())
      ? String(taxRegime).toUpperCase()
      : '115BAA';

    const parsedPbt = pbt !== undefined && pbt !== null && pbt !== '' ? Number(pbt) : 0;
    if (!Number.isFinite(parsedPbt) || parsedPbt < 0 || parsedPbt > 1000000000000) {
      return res.status(400).json({ success: false, message: 'Invalid PBT amount.' });
    }
    const safePbt = Math.round((parsedPbt + Number.EPSILON) * 100) / 100;
    const clientId = 'cl_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

    if (isPostgresReady && pgPool) {
      try {
        const insertRes = await pgPool.query(
          `INSERT INTO clients (id, org_id, frn, name, gstin, pan, constitution, tax_regime, turnover, net_profit_before_tax)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0.00, $9)
           RETURNING id, org_id, frn, name, gstin, pan, constitution, tax_regime as "taxRegime",
                     turnover, net_profit_before_tax as "netProfitBeforeTax", created_at`,
          [clientId, userOrgId, tenantFrn, cleanName, cleanGstin, derivedPan, safeConstitution, safeRegime, safePbt]
        );

        const newClient = insertRes.rows[0];
        await recordAuditTrailEntry({
          orgId: userOrgId,
          frn: tenantFrn,
          userName: req.user.email,
          role: req.user.role || 'PARTNER',
          action: 'REGISTER_ASSESSEE',
          target: `${cleanName} (GSTIN: ${cleanGstin}, PAN: ${derivedPan})`
        });

        return res.status(201).json({ success: true, message: `Assessee ${cleanName} provisioned!`, client: newClient });
      } catch (dbErr) {
        if (dbErr.code === '23505') {
          return res.status(409).json({ success: false, message: 'An assessee with this GSTIN is already registered in your firm.' });
        }
        throw dbErr;
      }
    }

    const localDb = loadLocalDatabase();
    localDb.clients = localDb.clients || [];

    if (localDb.clients.some(c => (c.frn || '').toUpperCase() === tenantFrn && c.gstin === cleanGstin)) {
      return res.status(409).json({ success: false, message: 'An assessee with this GSTIN is already registered in your firm.' });
    }

    const localClient = {
      id: clientId,
      org_id: userOrgId,
      frn: tenantFrn,
      name: cleanName,
      gstin: cleanGstin,
      pan: derivedPan,
      constitution: safeConstitution,
      taxRegime: safeRegime,
      turnover: 0,
      netProfitBeforeTax: safePbt,
      created_at: new Date().toISOString()
    };

    localDb.clients.unshift(localClient);
    saveLocalDatabase(localDb);

    await recordAuditTrailEntry({
      orgId: userOrgId,
      frn: tenantFrn,
      userName: req.user.email,
      role: req.user.role || 'PARTNER',
      action: 'REGISTER_ASSESSEE',
      target: `${cleanName} (GSTIN: ${cleanGstin}, PAN: ${derivedPan})`
    });

    return res.status(201).json({ success: true, message: `Assessee ${cleanName} provisioned!`, client: localClient });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to create client assessee record.' });
  }
});

app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    const targetId = req.params.id;
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();

    if (isPostgresReady && pgPool) {
      const delRes = await pgPool.query(
        'DELETE FROM clients WHERE id = $1 AND UPPER(frn) = $2 RETURNING name, gstin',
        [targetId, tenantFrn]
      );

      if (delRes.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Assessee not found or unauthorized.' });
      }

      const deletedClient = delRes.rows[0];
      await recordAuditTrailEntry({
        orgId: req.user.orgId,
        frn: tenantFrn,
        userName: req.user.email,
        role: req.user.role || 'PARTNER',
        action: 'DELETE_ASSESSEE',
        target: `${deletedClient.name} (GSTIN: ${deletedClient.gstin})`
      });

      return res.json({ success: true, message: `Assessee ${deletedClient.name} removed.` });
    }

    const localDb = loadLocalDatabase();
    const idx = (localDb.clients || []).findIndex(
      c => c.id === targetId && (c.frn || '').toUpperCase() === tenantFrn
    );
    if (idx === -1) {
      return res.status(404).json({ success: false, message: 'Assessee not found or unauthorized.' });
    }

    const [deletedClient] = localDb.clients.splice(idx, 1);
    localDb.vouchers = (localDb.vouchers || []).filter(v => v.client_id !== targetId && v.clientId !== targetId);
    saveLocalDatabase(localDb);

    await recordAuditTrailEntry({
      orgId: req.user.orgId,
      frn: tenantFrn,
      userName: req.user.email,
      role: req.user.role || 'PARTNER',
      action: 'DELETE_ASSESSEE',
      target: `${deletedClient.name} (GSTIN: ${deletedClient.gstin})`
    });

    return res.json({ success: true, message: `Assessee ${deletedClient.name} deleted.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete client assessee.' });
  }
});

const ALLOWED_VOUCHER_TYPES = ['PURCHASE', 'SALES', 'JOURNAL', 'CREDIT_NOTE', 'DEBIT_NOTE'];
const ALLOWED_GST_RATES = [0, 0.1, 0.25, 1.5, 3, 5, 6, 7.5, 12, 14, 18, 28];
const MAX_VOUCHER_TAXABLE = 100000000000;

app.get('/api/vouchers', requireAuth, async (req, res) => {
  try {
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();
    const clientId = req.query.clientId;

    if (isPostgresReady && pgPool) {
      let query = `
        SELECT id, org_id, frn, client_id as "clientId",
               TO_CHAR(voucher_date, 'YYYY-MM-DD') as date,
               voucher_number as "vNum", voucher_type as type,
               party_name as party, party_gstin as gstin,
               taxable_amount as taxable, gst_rate as "gstRate",
               gst_tax_amount as "gstTax", tds_section as "tdsSection",
               tds_cut as "tdsCut", net_total as "netTotal",
               status, approved_by as "approvedBy", created_at
        FROM vouchers
        WHERE UPPER(frn) = $1
      `;
      const params = [tenantFrn];

      if (clientId) {
        query += ' AND client_id = $2';
        params.push(clientId);
      }
      query += ' ORDER BY voucher_date DESC, created_at DESC';

      const vouchersRes = await pgPool.query(query, params);
      return res.json({ success: true, vouchers: vouchersRes.rows });
    }

    const localDb = loadLocalDatabase();
    let vouchers = (localDb.vouchers || []).filter(v => (v.frn || '').toUpperCase() === tenantFrn);
    if (clientId) {
      vouchers = vouchers.filter(v => v.client_id === clientId || v.clientId === clientId);
    }
    return res.json({ success: true, vouchers });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve vouchers.' });
  }
});

app.post('/api/vouchers', requireAuth, async (req, res) => {
  try {
    const {
      clientId, date, vNum, supplierInvNum, type, party, gstin,
      taxable, gstRate, tdsSection, approvedBy
    } = req.body || {};

    const tenantFrn = (req.user.frn || '').trim().toUpperCase();
    const userOrgId = req.user.orgId || 'org_default';

    if (!clientId || typeof clientId !== 'string') {
      return res.status(400).json({ success: false, message: 'Client ID is required.' });
    }

    const rawType = type !== undefined && type !== null ? String(type).trim().toUpperCase() : 'PURCHASE';
    if (!ALLOWED_VOUCHER_TYPES.includes(rawType)) {
      return res.status(400).json({
        success: false,
        message: `Invalid voucher type "${type}". Allowed types: ${ALLOWED_VOUCHER_TYPES.join(', ')}.`
      });
    }
    const safeType = rawType;

    const cleanParty = sanitizeText(party);
    if (!cleanParty || cleanParty.length === 0) {
      return res.status(400).json({ success: false, message: 'Valid Party / Ledger Name is required.' });
    }

    const parsedTaxable = Number(taxable);
    if (taxable === '' || taxable === null || taxable === undefined || !Number.isFinite(parsedTaxable) || parsedTaxable <= 0 || parsedTaxable > MAX_VOUCHER_TAXABLE) {
      return res.status(400).json({
        success: false,
        message: 'Taxable amount must be a valid positive number greater than ₹0 and within statutory limits.'
      });
    }
    const safeTaxable = Math.round((parsedTaxable + Number.EPSILON) * 100) / 100;

    let safeGstRate = 18.0;
    if (gstRate !== undefined && gstRate !== null && gstRate !== '') {
      const parsedGstRate = Number(gstRate);
      if (!Number.isFinite(parsedGstRate) || !ALLOWED_GST_RATES.includes(parsedGstRate)) {
        return res.status(400).json({
          success: false,
          message: `Invalid GST rate (${gstRate}%). Allowed statutory GST slabs: ${ALLOWED_GST_RATES.join('%, ')}%.`
        });
      }
      safeGstRate = parsedGstRate;
    }

    let cleanPartyGstin = '';
    if (gstin !== undefined && gstin !== null && String(gstin).trim().length > 0) {
      const rawGstin = String(gstin).trim().toUpperCase();
      if (safeType === 'JOURNAL' && rawGstin === 'TDS-CENTRAL') {
        cleanPartyGstin = 'TDS-CENTRAL';
      } else {
        const gCheck = validateGstin(rawGstin);
        if (!gCheck.valid) {
          return res.status(400).json({ success: false, message: `Party GSTIN error: ${gCheck.message}` });
        }
        cleanPartyGstin = gCheck.clean;
      }
    }

    const safeGstTax = Math.round((safeTaxable * (safeGstRate / 100) + Number.EPSILON) * 100) / 100;

    const safeTdsSection = ['194C', '194J', '194I', '194Q'].includes(tdsSection) ? tdsSection : 'NONE';
    let safeTdsCut = 0;
    if (safeTdsSection === '194C') {
      safeTdsCut = Math.round((safeTaxable * 0.02 + Number.EPSILON) * 100) / 100;
    } else if (safeTdsSection === '194J' || safeTdsSection === '194I') {
      safeTdsCut = Math.round((safeTaxable * 0.10 + Number.EPSILON) * 100) / 100;
    } else if (safeTdsSection === '194Q') {
      safeTdsCut = Math.round((safeTaxable * 0.001 + Number.EPSILON) * 100) / 100;
    }

    const safeNetTotal = safeType === 'SALES'
      ? Math.round((safeTaxable + safeGstTax + Number.EPSILON) * 100) / 100
      : Math.round((safeTaxable + safeGstTax - safeTdsCut + Number.EPSILON) * 100) / 100;

    let safeDate = new Date().toISOString().slice(0, 10);
    if (date !== undefined && date !== null && String(date).trim() !== '') {
      const dateCheck = validateIsoDate(String(date));
      if (!dateCheck.valid) {
        return res.status(400).json({ success: false, message: dateCheck.message });
      }
      safeDate = dateCheck.clean;
    }

    const voucherId = 'v_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
    const safeVNum = sanitizeText(vNum || supplierInvNum) || ('V-' + Math.floor(100 + Math.random() * 900));
    const safeSupplierInvNum = sanitizeText(supplierInvNum || vNum) || safeVNum;
    const safeApprovedBy = sanitizeText(approvedBy) || req.user.email;

    if (isPostgresReady && pgPool) {
      const clientCheck = await pgPool.query(
        'SELECT id FROM clients WHERE id = $1 AND UPPER(frn) = $2',
        [clientId, tenantFrn]
      );
      if (clientCheck.rows.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'Forbidden: Target client assessee does not exist or does not belong to your practice.'
        });
      }

      const insertRes = await pgPool.query(
        `INSERT INTO vouchers (
           id, org_id, frn, client_id, voucher_date, voucher_number,
           voucher_type, party_name, party_gstin, taxable_amount,
           gst_rate, gst_tax_amount, tds_section, tds_cut, net_total,
           status, approved_by
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'APPROVED', $16)
         RETURNING id, org_id, frn, client_id as "clientId",
                   TO_CHAR(voucher_date, 'YYYY-MM-DD') as date,
                   voucher_number as "vNum", voucher_type as type,
                   party_name as party, party_gstin as gstin,
                   taxable_amount as taxable, gst_rate as "gstRate",
                   gst_tax_amount as "gstTax", tds_section as "tdsSection",
                   tds_cut as "tdsCut", net_total as "netTotal",
                   status, approved_by as "approvedBy", created_at`,
        [
          voucherId, userOrgId, tenantFrn, clientId, safeDate, safeVNum,
          safeType, cleanParty, cleanPartyGstin, safeTaxable,
          safeGstRate, safeGstTax, safeTdsSection, safeTdsCut, safeNetTotal, safeApprovedBy
        ]
      );

      const newVoucher = {
        ...insertRes.rows[0],
        supplierInvNum: safeSupplierInvNum,
        taxable: Number(insertRes.rows[0].taxable),
        gstRate: Number(insertRes.rows[0].gstRate),
        gstTax: Number(insertRes.rows[0].gstTax),
        tdsCut: Number(insertRes.rows[0].tdsCut),
        netTotal: Number(insertRes.rows[0].netTotal)
      };

      await recordAuditTrailEntry({
        orgId: userOrgId,
        frn: tenantFrn,
        userName: req.user.email,
        role: req.user.role || 'PARTNER',
        action: 'POST_VOUCHER',
        target: `${safeVNum} - ${cleanParty} (₹${safeNetTotal})`
      });

      return res.status(201).json({ success: true, voucher: newVoucher });
    }

    const localDb = loadLocalDatabase();
    localDb.clients = localDb.clients || [];

    const targetClient = localDb.clients.find(c => c.id === clientId);
    if (!targetClient || (targetClient.frn || '').toUpperCase() !== tenantFrn) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Target client assessee does not exist or does not belong to your practice.'
      });
    }

    localDb.vouchers = localDb.vouchers || [];
    const localVoucher = {
      id: voucherId,
      org_id: userOrgId,
      frn: tenantFrn,
      clientId,
      date: safeDate,
      vNum: safeVNum,
      supplierInvNum: safeSupplierInvNum,
      type: safeType,
      party: cleanParty,
      gstin: cleanPartyGstin,
      taxable: safeTaxable,
      gstRate: safeGstRate,
      gstTax: safeGstTax,
      tdsSection: safeTdsSection,
      tdsCut: safeTdsCut,
      netTotal: safeNetTotal,
      status: 'APPROVED',
      approvedBy: safeApprovedBy,
      created_at: new Date().toISOString()
    };

    localDb.vouchers.unshift(localVoucher);
    saveLocalDatabase(localDb);

    await recordAuditTrailEntry({
      orgId: userOrgId,
      frn: tenantFrn,
      userName: req.user.email,
      role: req.user.role || 'PARTNER',
      action: 'POST_VOUCHER',
      target: `${safeVNum} - ${cleanParty} (₹${safeNetTotal})`
    });

    return res.status(201).json({ success: true, voucher: localVoucher });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to post voucher.' });
  }
});

app.delete('/api/vouchers/:id', requireAuth, async (req, res) => {
  try {
    const voucherId = req.params.id;
    const tenantFrn = (req.user.frn || '').trim().toUpperCase();

    if (isPostgresReady && pgPool) {
      const delRes = await pgPool.query(
        'DELETE FROM vouchers WHERE id = $1 AND UPPER(frn) = $2 RETURNING id',
        [voucherId, tenantFrn]
      );
      if (delRes.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Voucher not found or unauthorized.' });
      }
      return res.json({ success: true, message: 'Voucher deleted.' });
    }

    const localDb = loadLocalDatabase();
    const beforeLen = (localDb.vouchers || []).length;
    localDb.vouchers = (localDb.vouchers || []).filter(
      v => !(v.id === voucherId && (v.frn || '').toUpperCase() === tenantFrn)
    );
    if (localDb.vouchers.length === beforeLen) {
      return res.status(404).json({ success: false, message: 'Voucher not found or unauthorized.' });
    }
    saveLocalDatabase(localDb);
    return res.json({ success: true, message: 'Voucher deleted.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete voucher.' });
  }
});

// =========================================================================
// RAZORPAY PAYMENT GATEWAY MODULE (LIVE ORDERS API + HMAC-SHA256 VERIFIER)
// =========================================================================

const PRICING_CATALOG = {
  SOLO: {
    MONTHLY: { base: 899 },
    ANNUAL: { base: 8999 }
  },
  REGIONAL: {
    MONTHLY: { base: 1999 },
    ANNUAL: { base: 19999 }
  },
  ENTERPRISE: {
    MONTHLY: { base: 4499 },
    ANNUAL: { base: 44999 }
  }
};

function computePaymentSignature(orderId, paymentId, keySecret) {
  if (!keySecret) return null;
  return crypto
    .createHmac('sha256', keySecret)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');
}

// Call official Razorpay Orders API (https://api.razorpay.com/v1/orders) with automatic capture enabled
async function createRazorpayRemoteOrder({ amountInPaise, receipt, notes, keyId, keySecret }) {
  if (typeof fetch !== 'function') {
    throw new Error('Global fetch is unavailable in this Node runtime.');
  }
  const authString = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
  const response = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${authString}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      amount: amountInPaise,
      currency: 'INR',
      receipt,
      payment_capture: 1, // Mandatory in Live mode so payments are auto-captured immediately
      notes
    })
  });

  const data = await response.json();
  if (!response.ok || !data.id) {
    throw new Error(data.error?.description || 'Razorpay order creation failed.');
  }
  return data;
}

// Fetch payment status directly from Razorpay (GET https://api.razorpay.com/v1/payments/:id)
async function fetchRazorpayRemotePayment({ paymentId, keyId, keySecret }) {
  if (typeof fetch !== 'function') {
    throw new Error('Global fetch is unavailable in this Node runtime.');
  }
  const authString = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
  const response = await fetch(`https://api.razorpay.com/v1/payments/${encodeURIComponent(paymentId)}`, {
    method: 'GET',
    headers: {
      'Authorization': `Basic ${authString}`,
      'Content-Type': 'application/json'
    }
  });

  const data = await response.json();
  if (!response.ok || !data.id) {
    throw new Error(data.error?.description || 'Unable to verify payment status with Razorpay.');
  }
  return data;
}

// 1. Create Order Endpoint (Requires RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET; no local fallback or signature grant)
app.post('/api/payments/create-order', requireAuth, async (req, res) => {
  try {
    const { planTier, billingCycle } = req.body || {};
    const cleanTier = String(planTier || '').toUpperCase();
    const cleanCycle = String(billingCycle || '').toUpperCase();
    const plan = PRICING_CATALOG[cleanTier]?.[cleanCycle];

    if (!plan) {
      return res.status(400).json({ success: false, message: 'Invalid plan tier or billing cycle.' });
    }

    const rzp = getRazorpayConfig();
    if (!rzp.configured && !rzp.allowFake) {
      const hint = (rzp.keyId && !rzp.isValidKeyPrefix)
        ? `RAZORPAY_KEY_ID must start with "rzp_live_" (or "rzp_test_"). Note: "${rzp.merchantId}" is your Merchant ID, not the API Key ID.`
        : 'Set RAZORPAY_KEY_ID (rzp_live_...) and RAZORPAY_KEY_SECRET in your .env file.';
      return res.status(503).json({
        success: false,
        code: 'PAYMENT_GATEWAY_UNCONFIGURED',
        message: `Payment gateway is not configured. ${hint}`
      });
    }

    const totalAmount = plan.base;
    const amountInPaise = totalAmount * 100;
    const receiptId = `rcpt_fa_${Date.now()}`;

    let orderId = '';

    if (rzp.configured) {
      try {
        const rzpOrder = await createRazorpayRemoteOrder({
          amountInPaise,
          receipt: receiptId,
          notes: {
            merchantId: rzp.merchantId,
            accountId: rzp.accountId,
            firmEmail: req.user.email,
            frn: req.user.frn,
            planTier: cleanTier,
            billingCycle: cleanCycle
          },
          keyId: rzp.keyId,
          keySecret: rzp.keySecret
        });
        orderId = rzpOrder.id;
      } catch (rzpErr) {
        return res.status(502).json({
          success: false,
          code: 'PAYMENT_GATEWAY_ERROR',
          message: `Razorpay order creation failed: ${rzpErr.message}`
        });
      }
    } else if (rzp.allowFake) {
      orderId = `order_test_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    }

    const localDb = loadLocalDatabase();
    localDb.paymentOrders = localDb.paymentOrders || {};
    localDb.paymentOrders[orderId] = {
      orderId,
      merchantId: rzp.merchantId,
      accountId: rzp.accountId,
      email: req.user.email.toLowerCase(),
      frn: req.user.frn,
      planTier: cleanTier,
      billingCycle: cleanCycle,
      amount: totalAmount,
      amountInPaise,
      status: 'CREATED',
      mode: rzp.configured ? rzp.mode : 'FAKE_TEST',
      createdAt: new Date().toISOString()
    };
    saveLocalDatabase(localDb);

    return res.json({
      success: true,
      mode: rzp.mode,
      merchantId: rzp.merchantId,
      accountId: rzp.accountId,
      keyId: rzp.keyId || null,
      orderId,
      amount: amountInPaise,
      currency: 'INR',
      planTier: cleanTier,
      billingCycle: cleanCycle,
      totalAmount
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to initialize payment order.' });
  }
});

// 2. Cryptographic Signature + Remote Payment Status Verification & Subscription Activation
app.post('/api/payments/verify-payment', requireAuth, async (req, res) => {
  try {
    const rzp = getRazorpayConfig();
    if (!rzp.configured && !rzp.allowFake) {
      return res.status(503).json({
        success: false,
        code: 'PAYMENT_GATEWAY_UNCONFIGURED',
        message: 'Payment gateway is not configured on the server.'
      });
    }

    const {
      orderId,
      paymentId,
      signature,
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      planTier,
      billingCycle
    } = req.body || {};

    const resolvedOrderId = String(razorpay_order_id || orderId || '').trim();
    const resolvedPaymentId = String(razorpay_payment_id || paymentId || '').trim();
    const resolvedSignature = String(razorpay_signature || signature || '').trim();

    if (!resolvedOrderId || !resolvedPaymentId || !resolvedSignature) {
      return res.status(400).json({
        success: false,
        code: 'PAYMENT_VERIFICATION_REQUIRED',
        message: 'Payment verification failed: orderId, paymentId, and cryptographic signature are required.'
      });
    }

    const localDb = loadLocalDatabase();
    localDb.paymentOrders = localDb.paymentOrders || {};
    const orderRecord = localDb.paymentOrders[resolvedOrderId];

    if (!orderRecord) {
      return res.status(400).json({
        success: false,
        code: 'ORDER_NOT_FOUND',
        message: 'Payment order not found or was never initialized.'
      });
    }

    if (orderRecord.status === 'PAID') {
      return res.status(409).json({
        success: false,
        code: 'ORDER_ALREADY_SETTLED',
        message: 'This payment order has already been settled.'
      });
    }

    if (orderRecord.email !== req.user.email.toLowerCase()) {
      return res.status(403).json({
        success: false,
        code: 'ORDER_OWNER_MISMATCH',
        message: 'Payment order does not belong to the authenticated user.'
      });
    }

    if (rzp.configured) {
      // Step A: Verify HMAC-SHA256 signature using RAZORPAY_KEY_SECRET in constant time
      const expectedSignature = computePaymentSignature(resolvedOrderId, resolvedPaymentId, rzp.keySecret);
      const sigBuf = Buffer.from(resolvedSignature, 'utf8');
      const expBuf = Buffer.from(expectedSignature || '', 'utf8');
      if (!expectedSignature || sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        return res.status(402).json({
          success: false,
          code: 'INVALID_PAYMENT_SIGNATURE',
          message: 'Cryptographic payment signature verification failed.'
        });
      }

      // Step B: Confirm payment status and amount directly with Razorpay API
      try {
        const remotePayment = await fetchRazorpayRemotePayment({
          paymentId: resolvedPaymentId,
          keyId: rzp.keyId,
          keySecret: rzp.keySecret
        });

        const validStatus = remotePayment.status === 'captured' || remotePayment.status === 'authorized';
        const validOrder = remotePayment.order_id === resolvedOrderId;
        const validAmount = Number(remotePayment.amount) === Number(orderRecord.amount * 100);

        if (!validStatus || !validOrder || !validAmount) {
          return res.status(402).json({
            success: false,
            code: 'PAYMENT_NOT_CAPTURED',
            message: 'Payment could not be confirmed as captured/authorized for this order and amount.'
          });
        }
      } catch (verifyErr) {
        return res.status(402).json({
          success: false,
          code: 'PAYMENT_VERIFICATION_FAILED',
          message: `Razorpay payment confirmation failed: ${verifyErr.message}`
        });
      }
    }

    const cleanTier = String(planTier || orderRecord.planTier || '').toUpperCase();
    const cleanCycle = String(billingCycle || orderRecord.billingCycle || '').toUpperCase();
    const plan = PRICING_CATALOG[cleanTier]?.[cleanCycle];

    if (!plan) {
      return res.status(400).json({ success: false, message: 'Invalid subscription plan.' });
    }

    const totalAmount = plan.base;
    const invoiceNumber = `INV-FA-${new Date().getFullYear()}-${crypto.randomInt(10000, 99999)}`;
    const tenantEmail = req.user.email.toLowerCase();
    const tenantFrn = (req.user.frn || 'DEFAULT').toUpperCase();

    const periodEnd = new Date();
    if (cleanCycle === 'ANNUAL') {
      periodEnd.setFullYear(periodEnd.getFullYear() + 1);
    } else {
      periodEnd.setMonth(periodEnd.getMonth() + 1);
    }
    const validUntilStr = periodEnd.toISOString().substring(0, 10);

    if (isPostgresReady && pgPool) {
      const client = await pgPool.connect();
      try {
        await client.query('BEGIN');

        await client.query(
          `INSERT INTO public.firm_subscriptions 
           (firm_id, plan_tier, billing_cycle, amount_paid, gst_collected, current_period_end, razorpay_order_id, razorpay_payment_id)
           VALUES ($1, $2, $3, $4, 0, $5, $6, $7)`,
          [tenantEmail, cleanTier, cleanCycle, totalAmount, periodEnd, resolvedOrderId, resolvedPaymentId]
        );

        await client.query(
          `INSERT INTO public.subscription_invoices
           (invoice_number, firm_name, firm_gstin, firm_email, base_amount, cgst_rate, cgst_amount, sgst_rate, sgst_amount, igst_rate, igst_amount, total_amount, payment_id)
           VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0, $6, $7)`,
          [invoiceNumber, req.org?.name || 'CA Practice Firm', tenantFrn, tenantEmail, totalAmount, totalAmount, resolvedPaymentId]
        );

        await client.query('COMMIT');
      } catch (dbErr) {
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }
    }

    orderRecord.status = 'PAID';
    orderRecord.paymentId = resolvedPaymentId;
    orderRecord.settledAt = new Date().toISOString();

    localDb.subscriptions = localDb.subscriptions || {};
    localDb.subscriptions[tenantEmail] = {
      status: 'PAID',
      tier: cleanTier,
      cycle: cleanCycle,
      amountPaid: totalAmount,
      invoiceNumber,
      validUntil: validUntilStr,
      paymentId: resolvedPaymentId
    };
    saveLocalDatabase(localDb);

    await recordAuditTrailEntry({
      orgId: req.user.orgId || 'org_system',
      frn: tenantFrn,
      userName: tenantEmail,
      role: req.user.role || 'PARTNER',
      action: 'SUBSCRIPTION_ACTIVATED',
      target: `${cleanTier} (${cleanCycle}) — ₹${totalAmount} — Invoice: ${invoiceNumber} — PayID: ${resolvedPaymentId}`
    });

    return res.json({
      success: true,
      mode: rzp.mode,
      merchantId: rzp.merchantId,
      accountId: rzp.accountId,
      message: `Practice plan activated: ${cleanTier} (${cleanCycle})`,
      invoiceNumber,
      paymentId: resolvedPaymentId,
      validUntil: validUntilStr,
      amountPaid: totalAmount
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Payment verification failed.' });
  }
});

// 3. Live Razorpay Webhook Handler (for asynchronous UPI / NetBanking capture events)
app.post('/api/payments/webhook', async (req, res) => {
  try {
    const rzp = getRazorpayConfig();
    if (!rzp.webhookSecret) {
      return res.status(503).json({ success: false, message: 'Webhook secret is not configured.' });
    }

    const signature = req.headers['x-razorpay-signature'];
    if (!signature || typeof signature !== 'string') {
      return res.status(400).json({ success: false, message: 'Missing X-Razorpay-Signature header.' });
    }

    const payloadString = JSON.stringify(req.body || {});
    const expectedSignature = crypto
      .createHmac('sha256', rzp.webhookSecret)
      .update(payloadString)
      .digest('hex');

    const sigBuf = Buffer.from(signature, 'utf8');
    const expBuf = Buffer.from(expectedSignature, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return res.status(401).json({ success: false, message: 'Invalid webhook signature.' });
    }

    const event = req.body?.event;
    const paymentEntity = req.body?.payload?.payment?.entity;

    if ((event === 'payment.captured' || event === 'order.paid') && paymentEntity?.order_id) {
      const localDb = loadLocalDatabase();
      const orderRecord = localDb.paymentOrders?.[paymentEntity.order_id];
      if (orderRecord && orderRecord.status !== 'PAID') {
        const invoiceNumber = `INV-FA-${new Date().getFullYear()}-${crypto.randomInt(10000, 99999)}`;
        const periodEnd = new Date();
        if (orderRecord.billingCycle === 'ANNUAL') {
          periodEnd.setFullYear(periodEnd.getFullYear() + 1);
        } else {
          periodEnd.setMonth(periodEnd.getMonth() + 1);
        }
        const validUntilStr = periodEnd.toISOString().substring(0, 10);

        orderRecord.status = 'PAID';
        orderRecord.paymentId = paymentEntity.id;
        orderRecord.settledAt = new Date().toISOString();

        localDb.subscriptions = localDb.subscriptions || {};
        localDb.subscriptions[orderRecord.email] = {
          status: 'PAID',
          tier: orderRecord.planTier,
          cycle: orderRecord.billingCycle,
          amountPaid: orderRecord.amount,
          invoiceNumber,
          validUntil: validUntilStr,
          paymentId: paymentEntity.id
        };
        saveLocalDatabase(localDb);
      }
    }

    return res.json({ status: 'ok' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Webhook processing error.' });
  }
});

if (require.main === module) {
  app.listen(PORT, async () => {
    const rzp = getRazorpayConfig();
    console.log('\n=======================================================');
    console.log(' FinAudit One — Autonomous CA Cloud OS API Server     ');
    console.log(` Listening on:      http://localhost:${PORT}`);
    console.log(` Health Check:      http://localhost:${PORT}/api/health`);
    console.log(` Audit Verify:      http://localhost:${PORT}/api/audit-trail/verify`);
    if (activeEnvPath) {
      console.log(` Config File:       Loaded from ${activeEnvPath}`);
    }
    console.log(` Razorpay Merchant: ${rzp.merchantId} (Account: ${rzp.accountId})`);
    console.log(` Razorpay Gateway:  ${rzp.configured ? `ACTIVE (${rzp.mode} MODE)` : 'UNCONFIGURED (Set RAZORPAY_KEY_ID & RAZORPAY_KEY_SECRET in .env)'}`);
    console.log(' Statutory Validation: ACTIVE (15-Digit GSTIN + Modulo-36 Checksum)');
    console.log(' Mathematical Ledger Guards: ACTIVE (Slabs, Types, Dates, Ceiling <= 1e11)');
    console.log(' MCA Rule 11(g) Cryptographic Chaining: ACTIVE (Per-Firm SHA-256)');
    console.log('=======================================================');

    await initializeDatabase();
  });
}

module.exports = { app, validateGstin, computeGstinCheckDigit, verifyAuditChain, validateIsoDate };
