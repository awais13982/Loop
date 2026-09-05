import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import OpenAI from "openai";
import Stripe from "stripe";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// Password policy: 8+ chars, at least one uppercase, one lowercase, one
// number, and one special character. Returns null if valid, or an error
// message string if not — used by both signup and password reset.
function passwordPolicyError(password) {
  if (password.length < 8) return "Password must be at least 8 characters.";
  if (!/[a-z]/.test(password)) return "Password must include at least one lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Password must include at least one uppercase letter.";
  if (!/[0-9]/.test(password)) return "Password must include at least one number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Password must include at least one special character (e.g. !@#$%).";
  return null;
}

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

const STRIPE_PRICE_IDS = {
  pro: process.env.STRIPE_PRICE_PRO || "",
  business: process.env.STRIPE_PRICE_BUSINESS || "",
  team: process.env.STRIPE_PRICE_TEAM || "",
};

const requireVerification = process.env.REQUIRE_EMAIL_VERIFICATION === "true";

// LOOP's own subscription tiers (separate from the Stripe invoicing your
// users send to their own clients — this is what YOU charge for LOOP).
const PLAN_LIMITS = {
  free:     { label: "Free",     analysesPerMonth: 5,    priceCents: 0 },
  pro:      { label: "Pro",      analysesPerMonth: 100,  priceCents: 900 },
  business: { label: "Business", analysesPerMonth: 500,  priceCents: 1900 },
  team:     { label: "Team",     analysesPerMonth: 2000, priceCents: 4900 },
};

const databaseUrl = process.env.DATABASE_URL || process.env.DATABASE_URI;
if (!databaseUrl) {
  console.error("[LOOP] DATABASE_URL (or DATABASE_URI) is not set. Set it to a Postgres connection string.");
  process.exit(1);
}
const pool = new pg.Pool({ connectionString: databaseUrl });

// --- tiny query helpers (Postgres, async) ---
const q = (text, params = []) => pool.query(text, params);
const one = async (text, params = []) => (await q(text, params)).rows[0] || null;
const many = async (text, params = []) => (await q(text, params)).rows;

// --- Stripe webhook: needs the RAW body for signature verification, so it
// must be registered before the general JSON parser / helmet body handling.
app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send("Stripe is not configured on this server.");
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).send(`Webhook signature verification failed: ${e.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;

    // Two totally different kinds of checkout share this event: a client
    // paying an invoice (existing v0.9 flow), and a user subscribing to a
    // LOOP plan (new). Distinguish by which metadata is present.
    const invoiceId = session.metadata?.invoice_id;
    const subPlan = session.metadata?.loop_plan;
    const subUserId = session.metadata?.loop_user_id;

    if (invoiceId) {
      const inv = await one(
        "UPDATE invoices SET status='paid', stripe_payment_intent_id=$1 WHERE id=$2 RETURNING *",
        [session.payment_intent, invoiceId]
      );
      if (inv?.payment_id) await q("UPDATE payments SET status='paid' WHERE id=$1", [inv.payment_id]);
    } else if (subPlan && subUserId && PLAN_LIMITS[subPlan]) {
      await q(
        "UPDATE users SET plan=$1, stripe_customer_id=$2, stripe_subscription_id=$3, plan_renews_at=$4 WHERE id=$5",
        [subPlan, session.customer, session.subscription, null, subUserId]
      );
    }
  }

  if (["customer.subscription.created", "customer.subscription.updated"].includes(event.type)) {
    const sub = event.data.object;
    const plan = sub.metadata?.loop_plan || Object.entries(STRIPE_PRICE_IDS).find(([, priceId]) => priceId && priceId === sub.items?.data?.[0]?.price?.id)?.[0];
    const userId = sub.metadata?.loop_user_id;
    const renewAt = sub.current_period_end ? new Date(Number(sub.current_period_end) * 1000) : null;
    if (plan && PLAN_LIMITS[plan]) {
      const params = [plan, sub.customer, sub.id, renewAt];
      if (userId) {
        await q("UPDATE users SET plan=$1, stripe_customer_id=$2, stripe_subscription_id=$3, plan_renews_at=$4 WHERE id=$5", [...params, userId]);
      } else {
        await q("UPDATE users SET plan=$1, stripe_customer_id=$2, plan_renews_at=$4 WHERE stripe_subscription_id=$3 OR stripe_customer_id=$2", params);
      }
    } else {
      await q("UPDATE users SET plan_renews_at=$1 WHERE stripe_subscription_id=$2", [renewAt, sub.id]);
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object;
    await q("UPDATE users SET plan='free', stripe_subscription_id=NULL, plan_renews_at=NULL WHERE stripe_subscription_id=$1", [sub.id]);
  }

  res.json({ received: true });
});

// WhatsApp/Meta webhook — needs the RAW body to verify Meta's
// X-Hub-Signature-256 header (HMAC-SHA256 over the exact bytes received),
// same reason the Stripe webhook above needs raw body. Registered here,
// before the global JSON parser, for the same reason.
app.post("/api/webhooks/whatsapp", express.raw({ type: "application/json" }), async (req, res) => {
  if (!process.env.META_APP_SECRET) {
    return res.status(503).send("WhatsApp webhook signature verification is not configured (set META_APP_SECRET).");
  }
  const signature = req.headers["x-hub-signature-256"];
  if (!signature || !signature.startsWith("sha256=")) {
    return res.status(403).send("Missing signature.");
  }
  const expected = crypto.createHmac("sha256", process.env.META_APP_SECRET).update(req.body).digest("hex");
  const provided = signature.slice("sha256=".length);
  const expectedBuf = Buffer.from(expected, "hex");
  const providedBuf = Buffer.from(provided, "hex");
  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return res.status(403).send("Invalid signature.");
  }
  let payload;
  try { payload = JSON.parse(req.body.toString("utf8")); } catch { return res.status(400).send("Invalid JSON."); }

  // Signature is verified — now route each message to the LOOP account
  // that owns the receiving phone number, and store it in the shared
  // inbox. Wrapped in try/catch and always acking 200 on the way out
  // (aside from the signature check above): Meta retries aggressively on
  // non-200 responses, and ingestInboxMessage's dedup on
  // external_message_id means a retried delivery is harmless, so failing
  // to ack just causes duplicate work, not duplicate data.
  try {
    for (const entry of payload.entry || []) {
      for (const change of entry.changes || []) {
        const value = change.value || {};
        const phoneNumberId = value.metadata?.phone_number_id;
        if (!phoneNumberId || !Array.isArray(value.messages)) continue;
        const owner = await one(
          "SELECT user_id FROM integration_connections WHERE provider='whatsapp' AND metadata->>'phone_number_id'=$1",
          [phoneNumberId]
        );
        if (!owner) { console.warn(`[LOOP] WhatsApp message for unrecognized phone_number_id ${phoneNumberId} — no LOOP account has linked it.`); continue; }
        const contactsByWaId = Object.fromEntries((value.contacts || []).map(c => [c.wa_id, c.profile?.name || null]));
        for (const msg of value.messages) {
          if (msg.type !== "text" || !msg.text?.body) continue; // MVP: text messages only; media types are skipped, not lost silently — logged below
          await ingestInboxMessage(owner.user_id, "whatsapp", {
            threadKey: msg.from,
            externalMessageId: msg.id,
            contactName: contactsByWaId[msg.from] || null,
            contactIdentifier: msg.from,
            direction: "inbound",
            body: msg.text.body,
            occurredAt: msg.timestamp ? new Date(Number(msg.timestamp) * 1000) : new Date(),
          });
        }
      }
    }
  } catch (e) {
    console.error("[LOOP] WhatsApp webhook ingestion error:", e);
  }
  res.sendStatus(200);
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "250kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting: tighter on auth (brute-force/credential-stuffing surface),
// looser general ceiling on everything else under /api.
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

const secret = process.env.JWT_SECRET || "dev-only-secret-change-me";
if (!process.env.JWT_SECRET) {
  console.warn("[LOOP] WARNING: JWT_SECRET is not set. Using an insecure development default.");
}

if (process.env.NODE_ENV === "production") {
  const required = ["JWT_SECRET", "INTEGRATION_ENCRYPTION_KEY"];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error(`[LOOP] Refusing production start. Missing required secrets: ${missing.join(", ")}`);
    process.exit(1);
  }
  if (requireVerification && !process.env.RESEND_API_KEY) {
    console.error("[LOOP] REQUIRE_EMAIL_VERIFICATION=true requires RESEND_API_KEY in production.");
    process.exit(1);
  }
}

// --- generic email sender: swap this out for your provider of choice.
// Without RESEND_API_KEY set, this logs to the console instead of silently
// doing nothing, so verification/reset flows are still testable in dev.
async function sendEmail(to, subject, text) {
  if (process.env.RESEND_API_KEY && to) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from: process.env.NOTIFY_FROM_EMAIL || "loop@example.com", to, subject, text }),
      });
      return;
    } catch (e) {
      console.error("[LOOP] email delivery failed:", e.message);
    }
  }
  console.log(`[LOOP] (no email provider configured) would send to ${to}: "${subject}" — ${text}`);
}

const integrationKey = crypto.createHash("sha256").update(process.env.INTEGRATION_ENCRYPTION_KEY || secret).digest();
if (!process.env.INTEGRATION_ENCRYPTION_KEY) {
  console.warn("[LOOP] WARNING: INTEGRATION_ENCRYPTION_KEY is not set. Falling back to deriving the " +
    "OAuth token encryption key from JWT_SECRET — this means a leaked JWT_SECRET also exposes every " +
    "connected Gmail/WhatsApp token. Set INTEGRATION_ENCRYPTION_KEY to a separate long random value before storing real credentials.");
}
function encryptSecret(value) {
  if (!value) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", integrationKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}
function decryptSecret(value) {
  if (!value) return null;
  try {
    const [ivB64, tagB64, dataB64] = String(value).split(".");
    const decipher = crypto.createDecipheriv("aes-256-gcm", integrationKey, Buffer.from(ivB64, "base64url"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(dataB64, "base64url")), decipher.final()]).toString("utf8");
  } catch { return null; }
}
function appUrl() { return process.env.APP_URL || "http://localhost:3000"; }
function integrationRedirect(provider) { return `${appUrl()}/api/integrations/${provider}/callback`; }
function integrationConfigured(provider) {
  if (provider === "gmail") return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
  if (provider === "whatsapp") return Boolean(process.env.META_APP_ID && process.env.META_APP_SECRET);
  if (provider === "slack") return Boolean(process.env.SLACK_CLIENT_ID && process.env.SLACK_CLIENT_SECRET);
  return false;
}
function oauthState(userId, provider) {
  return jwt.sign({ uid: userId, provider, nonce: crypto.randomBytes(16).toString("hex") }, secret, { expiresIn: "10m" });
}
function readOAuthState(value, provider) {
  const data = jwt.verify(String(value || ""), secret);
  if (data.provider !== provider) throw new Error("Invalid OAuth state.");
  return data;
}
async function saveIntegration(userId, provider, data) {
  await q(`INSERT INTO integration_connections(user_id,provider,account_email,access_token_enc,refresh_token_enc,expires_at,metadata,connected_at)
    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,now())
    ON CONFLICT(user_id,provider) DO UPDATE SET account_email=EXCLUDED.account_email,access_token_enc=EXCLUDED.access_token_enc,
      refresh_token_enc=COALESCE(EXCLUDED.refresh_token_enc,integration_connections.refresh_token_enc),expires_at=EXCLUDED.expires_at,
      metadata=EXCLUDED.metadata,connected_at=now()`,
    [userId, provider, data.account_email || null, encryptSecret(data.access_token), encryptSecret(data.refresh_token), data.expires_at || null, JSON.stringify(data.metadata || {})]);
}
async function getIntegration(userId, provider) { return one("SELECT * FROM integration_connections WHERE user_id=$1 AND provider=$2", [userId, provider]); }
async function deleteIntegration(userId, provider) { await q("DELETE FROM integration_connections WHERE user_id=$1 AND provider=$2", [userId, provider]); }
async function googleAccessToken(row) {
  const access = decryptSecret(row?.access_token_enc), refresh = decryptSecret(row?.refresh_token_enc);
  if (access && row.expires_at && new Date(row.expires_at).getTime() > Date.now()+60000) return access;
  if (!refresh || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return access;
  const body = new URLSearchParams({client_id:process.env.GOOGLE_CLIENT_ID,client_secret:process.env.GOOGLE_CLIENT_SECRET,refresh_token:refresh,grant_type:"refresh_token"});
  const r = await fetch("https://oauth2.googleapis.com/token", {method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body});
  const d = await r.json();
  if (!r.ok || !d.access_token) throw new Error(d.error_description || "Gmail token refresh failed.");
  await q("UPDATE integration_connections SET access_token_enc=$1,expires_at=$2 WHERE id=$3", [encryptSecret(d.access_token), new Date(Date.now()+Number(d.expires_in||3600)*1000), row.id]);
  return d.access_token;
}

// --- Unified inbox: every connected platform (WhatsApp, Gmail, Slack)
// lands messages here in one shape, so the rest of the app (listing,
// assigning to a client, running analysis) only has to deal with one
// table instead of three different platform-specific ones.
// external_message_id is how we dedupe re-delivered webhook events /
// re-synced messages — NULL values never collide (Postgres treats each
// NULL as distinct), so it's safe to omit for sources that don't have a
// stable per-message id, at the cost of not deduping those specific rows.
async function ingestInboxMessage(userId, provider, m) {
  await q(
    `INSERT INTO inbox_messages(user_id,provider,thread_key,external_message_id,contact_name,contact_identifier,direction,body,occurred_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT(user_id,provider,external_message_id) DO NOTHING`,
    [userId, provider, m.threadKey, m.externalMessageId || null, m.contactName || null, m.contactIdentifier || null,
     m.direction || "inbound", m.body, m.occurredAt || new Date()]
  );
}


async function initSchema() {
  await q(`
CREATE TABLE IF NOT EXISTS users(
 id SERIAL PRIMARY KEY,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 email_verified BOOLEAN DEFAULT false,
 email_verify_token TEXT,
 email_verify_expires TIMESTAMPTZ,
 password_reset_token TEXT,
 password_reset_expires TIMESTAMPTZ,
 plan TEXT DEFAULT 'free',
 stripe_customer_id TEXT,
 stripe_subscription_id TEXT,
 plan_renews_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clients(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 notes TEXT DEFAULT '',
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS people(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 name TEXT NOT NULL,
 email TEXT,
 role TEXT,
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS projects(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 name TEXT NOT NULL,
 status TEXT DEFAULT 'active',
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS conversations(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
 content TEXT NOT NULL,
 summary TEXT,
 primary_bottleneck TEXT,
 overall_priority INTEGER,
 follow_up_message TEXT,
 follow_up_status TEXT DEFAULT 'draft',
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS loops(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
 conversation_id INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
 person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
 title TEXT NOT NULL,
 type TEXT,
 status TEXT DEFAULT 'open',
 priority INTEGER DEFAULT 50,
 dependency TEXT,
 deadline TEXT,
 payment_amount TEXT,
 next_action TEXT,
 is_bottleneck BOOLEAN DEFAULT false,
 is_micro_promise BOOLEAN DEFAULT false,
 commitment_phrase TEXT,
 draft_reply TEXT,
 draft_reply_updated_at TIMESTAMPTZ,
 last_status_change TIMESTAMPTZ DEFAULT now(),
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payments(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
 amount DOUBLE PRECISION NOT NULL,
 currency TEXT DEFAULT 'USD',
 status TEXT DEFAULT 'pending',
 due_date TEXT,
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reminders(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 loop_id INTEGER REFERENCES loops(id) ON DELETE SET NULL,
 payment_id INTEGER REFERENCES payments(id) ON DELETE SET NULL,
 message TEXT NOT NULL,
 channel TEXT DEFAULT 'in_app',
 remind_at TIMESTAMPTZ NOT NULL,
 status TEXT DEFAULT 'pending',
 source TEXT DEFAULT 'manual',
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notifications(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 reminder_id INTEGER REFERENCES reminders(id) ON DELETE SET NULL,
 message TEXT NOT NULL,
 read BOOLEAN DEFAULT false,
 created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS integration_connections(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 account_email TEXT,
 access_token_enc TEXT,
 refresh_token_enc TEXT,
 expires_at TIMESTAMPTZ,
 metadata JSONB DEFAULT '{}'::jsonb,
 connected_at TIMESTAMPTZ DEFAULT now(),
 UNIQUE(user_id, provider)
);
CREATE TABLE IF NOT EXISTS inbox_messages(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 thread_key TEXT NOT NULL,
 external_message_id TEXT,
 contact_name TEXT,
 contact_identifier TEXT,
 direction TEXT DEFAULT 'inbound',
 body TEXT NOT NULL,
 occurred_at TIMESTAMPTZ DEFAULT now(),
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 analyzed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ DEFAULT now(),
 UNIQUE(user_id, provider, external_message_id)
);
CREATE TABLE IF NOT EXISTS usage_events(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 event_type TEXT NOT NULL,
 reference_id INTEGER,
 source TEXT DEFAULT 'manual',
 created_at TIMESTAMPTZ DEFAULT now(),
 UNIQUE(user_id, event_type, reference_id)
);
-- Safe migrations for databases created by earlier LOOP versions.
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_renews_at TIMESTAMPTZ;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS person_id INTEGER REFERENCES people(id) ON DELETE SET NULL;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS dependency TEXT;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS is_bottleneck BOOLEAN DEFAULT false;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS is_micro_promise BOOLEAN DEFAULT false;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS commitment_phrase TEXT;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS draft_reply TEXT;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS draft_reply_updated_at TIMESTAMPTZ;
ALTER TABLE loops ADD COLUMN IF NOT EXISTS last_status_change TIMESTAMPTZ DEFAULT now();
ALTER TABLE loops ADD COLUMN IF NOT EXISTS follow_up_stage INTEGER DEFAULT 0;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS primary_bottleneck TEXT;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS overall_priority INTEGER;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS follow_up_message TEXT;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS follow_up_status TEXT DEFAULT 'draft';

CREATE TABLE IF NOT EXISTS invoices(
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
 project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
 payment_id INTEGER REFERENCES payments(id) ON DELETE SET NULL,
 amount DOUBLE PRECISION NOT NULL,
 currency TEXT DEFAULT 'USD',
 status TEXT DEFAULT 'draft',
 due_date TEXT,
 stripe_checkout_session_id TEXT,
 stripe_payment_intent_id TEXT,
 created_at TIMESTAMPTZ DEFAULT now()
);
`);
}

// --- Auth middleware ---
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch {
    res.status(401).json({ error: "Authentication required." });
  }
}

async function ownedOrNull(table, id, userId) {
  if (!id) return null;
  const row = await one(`SELECT id FROM ${table} WHERE id=$1 AND user_id=$2`, [id, userId]);
  return row ? id : undefined; // undefined signals "was provided but not owned"
}

// --- Auth routes ---
app.post("/api/auth/signup", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email || !password) {
    return res.status(400).json({ error: "Use a valid email and password." });
  }
  const pwErr = passwordPolicyError(password);
  if (pwErr) return res.status(400).json({ error: pwErr });
  try {
    const hash = await bcrypt.hash(password, 12);
    const verifyToken = crypto.randomBytes(32).toString("hex");
    const verifyExpires = new Date(Date.now() + 24 * 3600 * 1000);
    const user = await one(
      "INSERT INTO users(email,password_hash,email_verify_token,email_verify_expires) VALUES($1,$2,$3,$4) RETURNING id,email",
      [email, hash, verifyToken, verifyExpires]
    );
    await sendEmail(email, "Verify your LOOP account", `Verify here: ${process.env.APP_URL || "http://localhost:3000"}/api/auth/verify-email?token=${verifyToken}`);
    const token = jwt.sign({ id: user.id, email }, secret, { expiresIn: "7d" });
    res.json({ token, user, email_verification_required: requireVerification });
  } catch {
    res.status(409).json({ error: "An account with that email already exists." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const u = await one("SELECT * FROM users WHERE email=$1", [email]);
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  if (requireVerification && !u.email_verified) {
    return res.status(403).json({ error: "Please verify your email before logging in." });
  }
  res.json({ token: jwt.sign({ id: u.id, email: u.email }, secret, { expiresIn: "7d" }), user: { id: u.id, email: u.email } });
});

app.get("/api/auth/verify-email", async (req, res) => {
  const token = String(req.query?.token || "");
  const u = await one(
    "SELECT * FROM users WHERE email_verify_token=$1 AND email_verify_expires>now()",
    [token]
  );
  if (!u) return res.status(400).json({ error: "This verification link is invalid or has expired." });
  await q("UPDATE users SET email_verified=true, email_verify_token=NULL, email_verify_expires=NULL WHERE id=$1", [u.id]);
  res.json({ ok: true, message: "Email verified. You can now log in." });
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const u = await one("SELECT * FROM users WHERE email=$1", [email]);
  // Always respond the same way whether or not the account exists, so this
  // endpoint can't be used to find out which emails have accounts.
  if (u) {
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 3600 * 1000);
    await q("UPDATE users SET password_reset_token=$1, password_reset_expires=$2 WHERE id=$3", [token, expires, u.id]);
    await sendEmail(email, "Reset your LOOP password", `Reset here: ${process.env.APP_URL || "http://localhost:3000"}/reset-password?token=${token}`);
  }
  res.json({ ok: true, message: "If that email has an account, a reset link has been sent." });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const token = String(req.body?.token || "");
  const password = String(req.body?.password || "");
  { const pwErr = passwordPolicyError(password); if (pwErr) return res.status(400).json({ error: pwErr }); }
  const u = await one("SELECT * FROM users WHERE password_reset_token=$1 AND password_reset_expires>now()", [token]);
  if (!u) return res.status(400).json({ error: "This reset link is invalid or has expired." });
  const hash = await bcrypt.hash(password, 12);
  await q("UPDATE users SET password_hash=$1, password_reset_token=NULL, password_reset_expires=NULL WHERE id=$2", [hash, u.id]);
  res.json({ ok: true, message: "Password updated. You can now log in." });
});

app.get("/api/me", auth, async (req, res) => res.json({ user: req.user }));

// --- Clients ---
app.get("/api/clients", auth, async (req, res) =>
  res.json(await many("SELECT * FROM clients WHERE user_id=$1 ORDER BY id DESC", [req.user.id]))
);
app.post("/api/clients", auth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "Client name required." });
  const row = await one(
    "INSERT INTO clients(user_id,name,notes) VALUES($1,$2,$3) RETURNING *",
    [req.user.id, name, String(req.body?.notes || "")]
  );
  res.json(row);
});

// --- Projects ---
app.get("/api/projects", auth, async (req, res) =>
  res.json(await many("SELECT * FROM projects WHERE user_id=$1 ORDER BY id DESC", [req.user.id]))
);
app.post("/api/projects", auth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  if (!name) return res.status(400).json({ error: "Project name required." });
  if (clientId === undefined) return res.status(403).json({ error: "Invalid client." });
  const row = await one(
    "INSERT INTO projects(user_id,client_id,name) VALUES($1,$2,$3) RETURNING *",
    [req.user.id, clientId, name]
  );
  res.json(row);
});

// --- Payments ---
app.get("/api/payments", auth, async (req, res) =>
  res.json(await many("SELECT * FROM payments WHERE user_id=$1 ORDER BY id DESC", [req.user.id]))
);
app.post("/api/payments", auth, async (req, res) => {
  const amount = Number(req.body?.amount);
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  const projectId = await ownedOrNull("projects", req.body?.project_id, req.user.id);
  if (!(amount > 0)) return res.status(400).json({ error: "Payment amount must be greater than zero." });
  if (clientId === undefined || projectId === undefined) return res.status(403).json({ error: "Invalid client or project." });
  const row = await one(
    "INSERT INTO payments(user_id,client_id,project_id,amount,currency,status,due_date) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",
    [req.user.id, clientId, projectId, amount, String(req.body?.currency || "USD"), String(req.body?.status || "pending"), req.body?.due_date || null]
  );
  res.json(row);
});
app.patch("/api/payments/:id", auth, async (req, res) => {
  const status = String(req.body?.status || "");
  if (!["pending", "paid", "overdue"].includes(status)) return res.status(400).json({ error: "Invalid status." });
  const row = await one("UPDATE payments SET status=$1, updated_at=now() WHERE id=$2 AND user_id=$3 RETURNING *", [status, req.params.id, req.user.id]);
  if (!row) return res.status(404).json({ error: "Payment not found." });
  res.json(row);
});

// --- Loops ---
// --- LOOP Calendar ---
// Lays open loops out by deadline day instead of a flat list — the roadmap's
// "put it into their day" view. Built from the same deadline field the
// loop-card date picker writes to, so no separate scheduling system to keep
// in sync.
// --- Weekly Work Health report ---
// A once-a-week rollup rather than a live dashboard number — the point is
// to surface a trend (response time, biggest bottleneck) that a snapshot
// view can't show, using data that's already tracked elsewhere.
app.get("/api/weekly-report", auth, async (req, res) => {
  const uid = req.user.id;
  const [analyses, created, closed, waitingLoops, overdue, recovered, bottleneck] = await Promise.all([
    one("SELECT count(*)::int AS n FROM usage_events WHERE user_id=$1 AND event_type='analysis' AND created_at >= now() - interval '7 days'", [uid]),
    one("SELECT count(*)::int AS n FROM loops WHERE user_id=$1 AND created_at >= now() - interval '7 days'", [uid]),
    one("SELECT count(*)::int AS n FROM loops WHERE user_id=$1 AND status='resolved' AND last_status_change >= now() - interval '7 days'", [uid]),
    many("SELECT last_status_change FROM loops WHERE user_id=$1 AND status='waiting'", [uid]),
    one("SELECT count(*)::int AS n FROM loops WHERE user_id=$1 AND status!='resolved' AND deadline IS NOT NULL AND deadline::date < CURRENT_DATE", [uid]),
    one("SELECT COALESCE(sum(amount),0)::float AS n FROM payments WHERE user_id=$1 AND status='paid' AND updated_at >= now() - interval '7 days'", [uid]),
    one(`SELECT c.name, count(*)::int AS n FROM loops l JOIN clients c ON c.id=l.client_id
         WHERE l.user_id=$1 AND l.status!='resolved' GROUP BY c.name ORDER BY n DESC LIMIT 1`, [uid]),
  ]);

  const avgWaitDays = waitingLoops.length
    ? waitingLoops.reduce((s, l) => s + (Date.now() - new Date(l.last_status_change).getTime()) / 86400000, 0) / waitingLoops.length
    : 0;

  let recommendation = "Nothing urgent stands out this week — keep the pace.";
  if (bottleneck && bottleneck.n >= 3) recommendation = `${bottleneck.name} has the most open loops right now — worth a check-in.`;
  else if (avgWaitDays > 3) recommendation = `Clients are taking ${avgWaitDays.toFixed(1)} days to respond on average — consider a 48-hour follow-up rule.`;
  else if (overdue.n > 0) recommendation = `${overdue.n} loop${overdue.n === 1 ? " is" : "s are"} past its deadline — worth clearing those first.`;

  res.json({
    analyses_this_week: analyses.n,
    loops_created: created.n,
    loops_closed: closed.n,
    still_waiting: waitingLoops.length,
    overdue: overdue.n,
    payments_recovered: recovered.n,
    avg_wait_days: Math.round(avgWaitDays * 10) / 10,
    biggest_bottleneck: bottleneck ? bottleneck.name : null,
    recommendation,
  });
});

app.get("/api/calendar", auth, async (req, res) => {
  const loops = await many(
    `SELECT l.*, c.name AS client_name FROM loops l LEFT JOIN clients c ON c.id=l.client_id
     WHERE l.user_id=$1 AND l.status!='resolved' AND l.deadline IS NOT NULL
     ORDER BY l.deadline ASC`, [req.user.id]);

  const today = new Date(); today.setHours(0, 0, 0, 0);
  const overdue = [], days = {};
  for (const l of loops) {
    const d = new Date(l.deadline); d.setHours(0, 0, 0, 0);
    const item = { id: l.id, title: l.title, client_name: l.client_name, next_action: l.next_action, deadline: l.deadline };
    if (d < today) overdue.push(item);
    else {
      const key = d.toISOString().slice(0, 10);
      (days[key] ||= []).push(item);
    }
  }
  res.json({ overdue, days: Object.entries(days).map(([date, items]) => ({ date, items })) });
});

app.get("/api/loops", auth, async (req, res) =>
  res.json((await many(
    `SELECT l.*, p.name AS person_name FROM loops l LEFT JOIN people p ON p.id=l.person_id
     WHERE l.user_id=$1 ORDER BY l.priority DESC,l.id DESC`, [req.user.id]))
    .map(l => {
      const stuckDays = (Date.now() - new Date(l.last_status_change).getTime()) / 86400000;
      return l.status === "resolved"
        ? { ...l, score: null, health: "resolved", reasons: [] }
        : { ...l, score: scoreLoop(l), health: healthBucket(l), reasons: riskReasons(l, stuckDays) };
    }))
);
app.patch("/api/loops/:id", auth, async (req, res) => {
  const sets = [];
  const params = [];
  let i = 1;

  if (req.body?.status !== undefined) {
    const status = String(req.body.status || "");
    if (!["open", "in_progress", "waiting", "resolved"].includes(status)) return res.status(400).json({ error: "Invalid status." });
    sets.push(`status=$${i++}`, `last_status_change=now()`, `follow_up_stage=0`);
    params.push(status);
  }
  // deadline/payment_amount/dependency are optional manual overrides for
  // loops that weren't extracted from a pasted conversation (or need a
  // correction). deadline accepts "" to clear it.
  if (req.body?.deadline !== undefined) {
    sets.push(`deadline=$${i++}`);
    params.push(req.body.deadline || null);
  }
  if (req.body?.payment_amount !== undefined) {
    sets.push(`payment_amount=$${i++}`);
    params.push(req.body.payment_amount || null);
  }
  if (req.body?.dependency !== undefined) {
    sets.push(`dependency=$${i++}`);
    params.push(req.body.dependency || null);
  }
  if (!sets.length) return res.status(400).json({ error: "Nothing to update." });

  params.push(req.params.id, req.user.id);
  const row = await one(
    `UPDATE loops SET ${sets.join(", ")} WHERE id=$${i++} AND user_id=$${i++} RETURNING *`,
    params
  );
  if (!row) return res.status(404).json({ error: "Loop not found." });
  res.json(row);
});

// One-tap reply drafts: generates a short, channel-neutral draft the user
// reviews and pastes themselves into Gmail/Slack/WhatsApp — deliberately
// NOT auto-sent. This is a suggestion, not an action taken on the user's
// behalf; a false positive here should cost a copy-paste, not an
// embarrassing message that went out on its own.
async function draftReplyForLoop(loop) {
  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, baseURL: process.env.OPENAI_BASE_URL || undefined });
  const system = `You draft short, professional follow-up messages for a freelancer to send to a client, based on one specific stuck item. Write ONLY the message body — no subject line, no "Hi [name]," placeholder brackets (use "Hi there," if no name is given), no explanation, no markdown, no quotes around it. Keep it under 80 words, friendly but direct, and specific to the details given rather than generic. Do not invent facts not present in the details.`;
  const details = [
    `Item: ${loop.title}`,
    loop.type ? `Type: ${loop.type}` : null,
    loop.person_name ? `Person: ${loop.person_name}` : null,
    loop.dependency ? `Currently blocked on: ${loop.dependency}` : null,
    loop.deadline ? `Deadline: ${loop.deadline}` : null,
    loop.next_action ? `What needs to happen next: ${loop.next_action}` : null,
    loop.payment_amount ? `Related amount: ${loop.payment_amount}` : null,
  ].filter(Boolean).join("\n");
  const response = await client.chat.completions.create({
    model: process.env.OPENAI_MODEL || "llama-3.3-70b-versatile",
    messages: [{ role: "system", content: system }, { role: "user", content: details }],
  });
  return response.choices[0].message.content.trim();
}

app.post("/api/loops/:id/draft", auth, async (req, res) => {
  const loop = await one(
    `SELECT l.*, p.name AS person_name FROM loops l LEFT JOIN people p ON p.id=l.person_id
     WHERE l.id=$1 AND l.user_id=$2`, [req.params.id, req.user.id]
  );
  if (!loop) return res.status(404).json({ error: "Loop not found." });
  if (!process.env.OPENAI_API_KEY) return res.status(500).json({ error: "AI is not configured on this server yet." });
  let draft;
  try {
    draft = await draftReplyForLoop(loop);
  } catch (e) {
    console.error("[LOOP] draft-reply failed:", e.message);
    return res.status(502).json({ error: "Could not generate a draft right now. Try again in a moment." });
  }
  const row = await one(
    "UPDATE loops SET draft_reply=$1, draft_reply_updated_at=now() WHERE id=$2 AND user_id=$3 RETURNING *",
    [draft, req.params.id, req.user.id]
  );
  res.json(row);
});

// Urgency score (used for ranking) and health bucket (used for the
// Blocked/At Risk/Waiting/Moving dashboard) are deliberately separate:
// score answers "what should I do first", health answers "why is this
// stuck". A loop can be high-priority and still just "moving" if nothing's
// actually blocking it yet.
function scoreLoop(l) {
  let score = l.priority || 0;
  if (l.deadline) {
    const days = (new Date(l.deadline) - new Date()) / 86400000;
    if (days <= 0) score += 30;
    else if (days <= 2) score += 20;
    else if (days <= 7) score += 8;
  }
  if (l.payment_amount) score += 15;
  const stuckDays = (Date.now() - new Date(l.last_status_change).getTime()) / 86400000;
  score += Math.min(stuckDays * 2, 20);
  if (l.status === "waiting" && stuckDays > 5) score += 10; // genuinely stalled, not just recently asked
  return Math.round(score);
}

// payment_amount is free text written by the AI from conversation
// language ("$4,500", "2000 USD", "around 1.2k") — this pulls the first
// plausible number out of it for aggregation. Deliberately conservative:
// if nothing number-like is found, returns 0 rather than guessing, so
// Value at Risk never silently inflates itself off a bad parse.
function parsePaymentAmount(text) {
  if (!text) return 0;
  const s = String(text).replace(/,/g, "");
  const kMatch = s.match(/(\d+(?:\.\d+)?)\s*k\b/i);
  if (kMatch) return Math.round(parseFloat(kMatch[1]) * 1000);
  const match = s.match(/(\d+(?:\.\d+)?)/);
  return match ? Math.round(parseFloat(match[1])) : 0;
}

function healthBucket(l) {
  if (l.status === "resolved") return "resolved";
  const stuckDays = (Date.now() - new Date(l.last_status_change).getTime()) / 86400000;
  const deadlineDays = l.deadline ? (new Date(l.deadline) - new Date()) / 86400000 : null;
  if (l.status === "waiting" && stuckDays > 5) return "blocked";
  if (deadlineDays !== null && deadlineDays <= 2) return "at_risk";
  if (l.status === "waiting" && stuckDays > 2) return "at_risk";
  if (l.status === "waiting") return "waiting";
  return "moving"; // open or in_progress, nothing overdue or stalled
}

// Plain-language breakdown of why a loop scored the way it did — same
// inputs as scoreLoop(), just surfaced as sentences instead of collapsed
// into a number, so the Command Center can say *why* something is urgent
// instead of just asserting that it is.
function riskReasons(l, stuckDays) {
  const reasons = [];
  if (l.deadline) {
    const days = Math.ceil((new Date(l.deadline) - new Date()) / 86400000);
    if (days < 0) reasons.push(`Deadline passed ${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago`);
    else if (days === 0) reasons.push("Due today");
    else if (days <= 2) reasons.push(`Due in ${days} day${days === 1 ? "" : "s"}`);
    else if (days <= 7) reasons.push(`Due in ${days} days`);
  }
  if (l.status === "waiting" && stuckDays > 1) {
    reasons.push(`Waiting ${Math.floor(stuckDays)} day${Math.floor(stuckDays) === 1 ? "" : "s"} for a reply`);
  } else if (stuckDays > 3) {
    reasons.push(`No movement in ${Math.floor(stuckDays)} days`);
  }
  if (l.payment_amount) reasons.push(`Payment tied to this: ${l.payment_amount}`);
  if (l.dependency) reasons.push(`Blocked on: ${l.dependency}`);
  return reasons;
}

// Rule-based (no extra AI call — keeps this endpoint fast and free-tier
// friendly) recommended next step, one tier more specific than "do
// something about this loop".
function recommendedAction(l) {
  if (l.next_action) return l.next_action;
  if (l.status === "waiting" && l.dependency) return `Follow up on: ${l.dependency}`;
  if (l.payment_amount) return "Send a payment reminder";
  return "Send a status check-in";
}

// --- Command Center: "What should I do now?" ---
// Wraps the same scoring/health logic as /api/dashboard and /api/next-actions
// into a short ranked worklist with a plain-language reason and a
// recommended (rule-based, not AI-generated) next step per item — the
// "Fix My Day" screen the roadmap calls the AI Command Center.
app.get("/api/command-center", auth, async (req, res) => {
  const loops = await many(
    `SELECT l.*, p.name AS person_name, c.name AS client_name FROM loops l
     LEFT JOIN people p ON p.id=l.person_id LEFT JOIN clients c ON c.id=l.client_id
     WHERE l.user_id=$1 AND l.status!='resolved'`, [req.user.id]);

  const enriched = loops.map(l => {
    const stuckDays = (Date.now() - new Date(l.last_status_change).getTime()) / 86400000;
    return {
      id: l.id,
      title: l.title,
      client_name: l.client_name,
      person_name: l.person_name,
      dependency: l.dependency,
      deadline: l.deadline,
      payment_amount: l.payment_amount,
      draft_reply: l.draft_reply,
      score: scoreLoop(l),
      health: healthBucket(l),
      reasons: riskReasons(l, stuckDays),
      recommended_action: recommendedAction(l),
    };
  }).sort((a, b) => b.score - a.score);

  const needsAttention = enriched.filter(l => l.health === "blocked" || l.health === "at_risk");
  const valueAtRisk = needsAttention.reduce((s, l) => s + parsePaymentAmount(l.payment_amount), 0);

  res.json({
    open_loops: enriched.length,
    needs_attention_count: needsAttention.length,
    message: enriched.length === 0
      ? "No open loops right now."
      : needsAttention.length === 0
        ? `You have ${enriched.length} open loop${enriched.length === 1 ? "" : "s"}, nothing urgent today.`
        : `You have ${enriched.length} open loop${enriched.length === 1 ? "" : "s"}. ${needsAttention.length} need${needsAttention.length === 1 ? "s" : ""} attention today.`,
    value_at_risk: valueAtRisk,
    items: needsAttention.slice(0, 5),
  });
});

app.get("/api/next-actions", auth, async (req, res) => {
  const loops = await many(
    `SELECT l.*, p.name AS person_name FROM loops l LEFT JOIN people p ON p.id=l.person_id
     WHERE l.user_id=$1 AND l.status!='resolved'`, [req.user.id]);
  const clients = await many("SELECT id,name FROM clients WHERE user_id=$1", [req.user.id]);
  const clientName = Object.fromEntries(clients.map(c => [c.id, c.name]));

  const scored = loops.map(l => ({ ...l, score: scoreLoop(l), health: healthBucket(l), client_name: clientName[l.client_id] || null }));
  scored.sort((a, b) => b.score - a.score);

  const perClient = new Map();
  for (const l of scored) {
    const key = l.client_id ?? "unassigned";
    if (!perClient.has(key)) perClient.set(key, l);
  }
  res.json({ top_overall: scored[0] || null, by_client: [...perClient.values()], all_ranked: scored });
});

// --- Dashboard: Blocked / At Risk / Waiting / Moving ---
app.get("/api/dashboard", auth, async (req, res) => {
  const loops = await many(
    `SELECT l.*, p.name AS person_name, c.name AS client_name FROM loops l
     LEFT JOIN people p ON p.id=l.person_id LEFT JOIN clients c ON c.id=l.client_id
     WHERE l.user_id=$1 AND l.status!='resolved'`, [req.user.id]);
  const enriched = loops.map(l => ({ ...l, score: scoreLoop(l), health: healthBucket(l), value: parsePaymentAmount(l.payment_amount) }));
  const bucket = (name) => enriched.filter(l => l.health === name).sort((a, b) => b.score - a.score);
  const buckets = { blocked: bucket("blocked"), at_risk: bucket("at_risk"), waiting: bucket("waiting"), moving: bucket("moving") };

  // Value at risk: dollar exposure sitting in loops that are stalled or
  // close to slipping (blocked + at_risk only — "waiting" on its own isn't
  // yet a problem, that's normal workflow). Only counts loops with a
  // parsed, nonzero amount so the total is never inflated by guesswork.
  const riskLoops = [...buckets.blocked, ...buckets.at_risk].filter(l => l.value > 0);
  const valueAtRisk = {
    total: riskLoops.reduce((s, l) => s + l.value, 0),
    count: riskLoops.length,
    currency: "USD",
    by_bucket: {
      blocked: buckets.blocked.filter(l => l.value > 0).reduce((s, l) => s + l.value, 0),
      at_risk: buckets.at_risk.filter(l => l.value > 0).reduce((s, l) => s + l.value, 0),
    },
    loops: riskLoops.map(l => ({ id: l.id, title: l.title, client_name: l.client_name, value: l.value, health: l.health })),
  };

  const pendingPayments = await many(
    "SELECT amount FROM payments WHERE user_id=$1 AND status!='paid'", [req.user.id]
  );

  res.json({
    buckets,
    counts: { blocked: buckets.blocked.length, at_risk: buckets.at_risk.length, waiting: buckets.waiting.length, moving: buckets.moving.length },
    top_action: enriched.sort((a, b) => b.score - a.score)[0] || null,
    value_at_risk: valueAtRisk,
    stats: {
      critical: buckets.blocked.length,
      waiting: buckets.waiting.length + buckets.at_risk.length,
      on_track: buckets.moving.length,
      pending_amount: pendingPayments.reduce((s, p) => s + Number(p.amount || 0), 0),
      pending_count: pendingPayments.length,
    },
  });
});

app.get("/api/notifications", auth, async (req, res) => {
  const rows = await many(
    "SELECT * FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]
  );
  const unread = rows.filter(n => !n.read).length;
  res.json({ unread, notifications: rows });
});
app.post("/api/notifications/:id/read", auth, async (req, res) => {
  const row = await one(
    "UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2 RETURNING *", [req.params.id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: "Notification not found." });
  res.json(row);
});

// --- Micro-promises: soft/passive commitments the analyzer caught in
// conversation language ("I'll send it by EOD") rather than explicit
// tasks. Surfaced separately so the UI can call out "things you promised
// without quite meaning to promise them" as its own list. ---
app.get("/api/micro-promises", auth, async (req, res) => {
  const loops = await many(
    `SELECT l.*, p.name AS person_name, c.name AS client_name FROM loops l
     LEFT JOIN people p ON p.id=l.person_id LEFT JOIN clients c ON c.id=l.client_id
     WHERE l.user_id=$1 AND l.is_micro_promise=true AND l.status!='resolved'`, [req.user.id]);
  const enriched = loops
    .map(l => ({ ...l, score: scoreLoop(l), health: healthBucket(l), value: parsePaymentAmount(l.payment_amount) }))
    .sort((a, b) => b.score - a.score);
  res.json({ count: enriched.length, micro_promises: enriched });
});

// --- People ---
app.get("/api/people", auth, async (req, res) => {
  const clientId = req.query.client_id;
  const rows = clientId
    ? await many("SELECT * FROM people WHERE user_id=$1 AND client_id=$2 ORDER BY id DESC", [req.user.id, clientId])
    : await many("SELECT * FROM people WHERE user_id=$1 ORDER BY id DESC", [req.user.id]);
  res.json(rows);
});
app.post("/api/people", auth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "Name required." });
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  if (clientId === undefined) return res.status(403).json({ error: "Invalid client." });
  const row = await one(
    "INSERT INTO people(user_id,client_id,name,email,role) VALUES($1,$2,$3,$4,$5) RETURNING *",
    [req.user.id, clientId, name, req.body?.email || null, req.body?.role || null]
  );
  res.json(row);
});

// Finds an existing person by name for this client (case-insensitive) or
// creates one. Keeps "who made this commitment" structured instead of a
// free-text string, without asking the user to manage a contacts list.
async function findOrCreatePerson(userId, clientId, name) {
  if (!name || !String(name).trim()) return null;
  const trimmed = String(name).trim();
  const existing = await one(
    "SELECT id FROM people WHERE user_id=$1 AND client_id IS NOT DISTINCT FROM $2 AND lower(name)=lower($3)",
    [userId, clientId, trimmed]
  );
  if (existing) return existing.id;
  const created = await one(
    "INSERT INTO people(user_id,client_id,name) VALUES($1,$2,$3) RETURNING id",
    [userId, clientId, trimmed]
  );
  return created.id;
}

// --- Conversations & Follow-ups ---
app.get("/api/conversations", auth, async (req, res) =>
  res.json(await many(
    `SELECT id,client_id,project_id,summary,primary_bottleneck,overall_priority,follow_up_status,created_at
     FROM conversations WHERE user_id=$1 ORDER BY id DESC`, [req.user.id]))
);
app.get("/api/conversations/:id/followup", auth, async (req, res) => {
  const row = await one("SELECT * FROM conversations WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!row) return res.status(404).json({ error: "Conversation not found." });
  res.json(row);
});
app.patch("/api/conversations/:id/followup", auth, async (req, res) => {
  const message = req.body?.follow_up_message;
  const status = req.body?.follow_up_status;
  if (status && !["draft", "sent"].includes(status)) return res.status(400).json({ error: "Invalid follow-up status." });
  const row = await one(
    `UPDATE conversations SET
       follow_up_message = COALESCE($1, follow_up_message),
       follow_up_status = COALESCE($2, follow_up_status)
     WHERE id=$3 AND user_id=$4 RETURNING *`,
    [message ?? null, status ?? null, req.params.id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: "Conversation not found." });
  res.json(row);
});

// --- Action Center ---
app.get("/api/action-center/:clientId", auth, async (req, res) => {
  const clientId = Number(req.params.clientId);
  const client = await one("SELECT * FROM clients WHERE id=$1 AND user_id=$2", [clientId, req.user.id]);
  if (!client) return res.status(404).json({ error: "Client not found." });

  const loops = await many(
    `SELECT l.*, p.name AS person_name FROM loops l LEFT JOIN people p ON p.id=l.person_id
     WHERE l.user_id=$1 AND l.client_id=$2 ORDER BY l.id DESC`, [req.user.id, clientId]);
  const openLoops = loops.filter(l => l.status !== "resolved").map(l => ({ ...l, score: scoreLoop(l), health: healthBucket(l) })).sort((a, b) => b.score - a.score);
  const resolvedLoops = loops.filter(l => l.status === "resolved").slice(0, 10);

  const payments = await many("SELECT * FROM payments WHERE user_id=$1 AND client_id=$2 ORDER BY id DESC", [req.user.id, clientId]);
  const projects = await many("SELECT * FROM projects WHERE user_id=$1 AND client_id=$2", [req.user.id, clientId]);

  res.json({
    client, projects,
    next_action: openLoops[0] || null,
    open_loops: openLoops,
    resolved_loops: resolvedLoops,
    payments_pending: payments.filter(p => p.status !== "paid"),
    payments_paid: payments.filter(p => p.status === "paid"),
    totals: {
      open_loops: openLoops.length,
      amount_pending: payments.filter(p => p.status !== "paid").reduce((s, p) => s + p.amount, 0),
    },
  });
});

// --- Reminders & notifications ---
async function deliverReminder(reminder) {
  await q("INSERT INTO notifications(user_id,reminder_id,message) VALUES($1,$2,$3)", [reminder.user_id, reminder.id, reminder.message]);
  if (process.env.RESEND_API_KEY && process.env.NOTIFY_EMAIL) {
    await sendEmail(process.env.NOTIFY_EMAIL, "LOOP reminder", reminder.message);
  }
}
async function runReminderSweep() {
  const due = await many("SELECT * FROM reminders WHERE status='pending' AND remind_at<=now()");
  for (const r of due) {
    await deliverReminder(r);
    await q("UPDATE reminders SET status='sent' WHERE id=$1", [r.id]);
  }
  return due.length;
}
const SWEEP_INTERVAL_MS = 60_000;
setInterval(() => { runReminderSweep().catch(e => console.error("[LOOP] reminder sweep failed:", e)); }, SWEEP_INTERVAL_MS);

// --- Automatic Follow-Up Engine ---
// Watches loops sitting in "waiting" status (nobody has replied) and nudges
// the user at two thresholds, without them having to set a manual reminder:
//   day 3+  -> stage 1: "hasn't responded, want to follow up?" + an
//              auto-generated draft reply so acting on it is one tap
//   day 7+  -> stage 2: "still no response" escalation notification
// follow_up_stage is reset to 0 whenever a loop's status changes (see PATCH
// /api/loops/:id), so re-opening or resolving a loop clears it and a loop
// that goes back to "waiting" later starts the clock over.
const FOLLOW_UP_STAGES = [
  { stage: 1, days: 3, label: (t) => `No response yet on "${t}" — it's been 3+ days. Want to follow up?` },
  { stage: 2, days: 7, label: (t) => `Still no response on "${t}" after 7+ days — this one may need escalating.` },
];

async function runAutoFollowUpSweep() {
  const stuck = await many(
    `SELECT * FROM loops WHERE status='waiting' AND follow_up_stage < 2
     AND last_status_change <= now() - interval '3 days'`
  );
  let notified = 0;
  for (const loop of stuck) {
    const days = (Date.now() - new Date(loop.last_status_change).getTime()) / 86400000;
    // Walk stages in order so a loop that's been silent 8 days but was
    // never checked in on lands on stage 1 first, not straight to stage 2.
    const next = FOLLOW_UP_STAGES.find(s => s.stage > (loop.follow_up_stage || 0) && days >= s.days);
    if (!next) continue;

    const message = next.label(loop.title);
    await q("INSERT INTO notifications(user_id,message) VALUES($1,$2)", [loop.user_id, message]);
    await q("UPDATE loops SET follow_up_stage=$1 WHERE id=$2", [next.stage, loop.id]);

    // First-stage nudges also get a ready-to-send draft, if AI is
    // configured and the loop doesn't already have one — the point is to
    // make "follow up" a one-tap action, not just another notification.
    if (next.stage === 1 && !loop.draft_reply && process.env.OPENAI_API_KEY) {
      try {
        const person = loop.person_id ? await one("SELECT name FROM people WHERE id=$1", [loop.person_id]) : null;
        const draft = await draftReplyForLoop({ ...loop, person_name: person?.name });
        await q("UPDATE loops SET draft_reply=$1, draft_reply_updated_at=now() WHERE id=$2", [draft, loop.id]);
      } catch (e) {
        console.error("[LOOP] auto-follow-up draft failed:", e.message);
      }
    }
    notified++;
  }
  return notified;
}
setInterval(() => { runAutoFollowUpSweep().catch(e => console.error("[LOOP] auto-follow-up sweep failed:", e)); }, SWEEP_INTERVAL_MS);

async function autoScheduleReminder(userId, clientId, loopId, loop) {
  let remindAt = null, message = null;
  if (loop.deadline) {
    const d = new Date(loop.deadline);
    d.setDate(d.getDate() - 1);
    if (d > new Date()) { remindAt = d.toISOString(); message = `Due soon: "${loop.title}"`; }
  } else if (loop.type === "payment") {
    const d = new Date(); d.setDate(d.getDate() + 3);
    remindAt = d.toISOString(); message = `Follow up on unpaid: "${loop.title}"`;
  }
  if (remindAt) {
    await q(
      "INSERT INTO reminders(user_id,client_id,loop_id,message,remind_at,channel,source) VALUES($1,$2,$3,$4,$5,$6,$7)",
      [userId, clientId, loopId, message, remindAt, "in_app", "auto"]
    );
  }
}

app.get("/api/reminders", auth, async (req, res) =>
  res.json(await many("SELECT * FROM reminders WHERE user_id=$1 ORDER BY remind_at ASC", [req.user.id]))
);
app.post("/api/reminders", auth, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  const remindAt = req.body?.remind_at;
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  if (!message || !remindAt || isNaN(new Date(remindAt).getTime())) {
    return res.status(400).json({ error: "A message and a valid remind_at date are required." });
  }
  if (clientId === undefined) return res.status(403).json({ error: "Invalid client." });
  const row = await one(
    "INSERT INTO reminders(user_id,client_id,message,remind_at,channel,source) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
    [req.user.id, clientId, message, new Date(remindAt).toISOString(), "in_app", "manual"]
  );
  res.json(row);
});
app.patch("/api/reminders/:id", auth, async (req, res) => {
  const row = await one(
    "UPDATE reminders SET status='cancelled' WHERE id=$1 AND user_id=$2 AND status='pending' RETURNING *",
    [req.params.id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: "Reminder not found or already sent." });
  res.json({ ok: true });
});
app.get("/api/notifications", auth, async (req, res) =>
  res.json(await many("SELECT * FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT 50", [req.user.id]))
);
app.patch("/api/notifications/:id/read", auth, async (req, res) => {
  await q("UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  res.json({ ok: true });
});
app.post("/api/reminders/run-now", auth, async (req, res) => res.json({ sent: await runReminderSweep() }));
app.post("/api/follow-ups/run-now", auth, async (req, res) => res.json({ notified: await runAutoFollowUpSweep() }));

// --- Invoices ---
app.get("/api/invoices", auth, async (req, res) =>
  res.json(await many("SELECT * FROM invoices WHERE user_id=$1 ORDER BY id DESC", [req.user.id]))
);
app.post("/api/invoices", auth, async (req, res) => {
  const amount = Number(req.body?.amount);
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  const projectId = await ownedOrNull("projects", req.body?.project_id, req.user.id);
  if (!(amount > 0)) return res.status(400).json({ error: "Invoice amount must be greater than zero." });
  if (clientId === undefined || projectId === undefined) return res.status(403).json({ error: "Invalid client or project." });
  const currency = String(req.body?.currency || "USD");
  const dueDate = req.body?.due_date || null;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const pay = await client.query(
      "INSERT INTO payments(user_id,client_id,project_id,amount,currency,status,due_date) VALUES($1,$2,$3,$4,$5,'pending',$6) RETURNING id",
      [req.user.id, clientId, projectId, amount, currency, dueDate]
    );
    const inv = await client.query(
      "INSERT INTO invoices(user_id,client_id,project_id,payment_id,amount,currency,status,due_date) VALUES($1,$2,$3,$4,$5,$6,'draft',$7) RETURNING *",
      [req.user.id, clientId, projectId, pay.rows[0].id, amount, currency, dueDate]
    );
    await client.query("COMMIT");
    res.json(inv.rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "Could not create invoice." });
  } finally {
    client.release();
  }
});
app.post("/api/invoices/:id/checkout", auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Stripe is not configured on this server. Set STRIPE_SECRET_KEY in .env." });
  const inv = await one("SELECT * FROM invoices WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!inv) return res.status(404).json({ error: "Invoice not found." });
  if (inv.status === "paid") return res.status(400).json({ error: "This invoice is already paid." });
  try {
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [{
        price_data: { currency: inv.currency.toLowerCase(), product_data: { name: `Invoice #${inv.id}` }, unit_amount: Math.round(inv.amount * 100) },
        quantity: 1,
      }],
      success_url: `${appUrl}/?invoice=${inv.id}&paid=1`,
      cancel_url: `${appUrl}/?invoice=${inv.id}&cancelled=1`,
      metadata: { invoice_id: String(inv.id), user_id: String(req.user.id) },
    });
    await q("UPDATE invoices SET stripe_checkout_session_id=$1, status='sent' WHERE id=$2", [session.id, inv.id]);
    res.json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not create a Stripe checkout session." });
  }
});

// --- LOOP's own billing (subscribing to LOOP itself, not your users' invoices) ---
async function analysesThisMonth(userId) {
  const row = await one(
    "SELECT count(*)::int AS n FROM usage_events WHERE user_id=$1 AND event_type='analysis' AND created_at >= date_trunc('month', now())",
    [userId]
  );
  return row?.n || 0;
}

async function recordAnalysisUsage(userId, conversationId, source = "manual") {
  await q(
    "INSERT INTO usage_events(user_id,event_type,reference_id,source) VALUES($1,'analysis',$2,$3) ON CONFLICT(user_id,event_type,reference_id) DO NOTHING",
    [userId, conversationId, source]
  );
}

app.get("/api/billing/status", auth, async (req, res) => {
  const u = await one("SELECT plan, plan_renews_at FROM users WHERE id=$1", [req.user.id]);
  const plan = u?.plan || "free";
  const used = await analysesThisMonth(req.user.id);
  res.json({
    plan, plan_renews_at: u?.plan_renews_at || null,
    analyses_used_this_month: used,
    analyses_limit: PLAN_LIMITS[plan]?.analysesPerMonth ?? PLAN_LIMITS.free.analysesPerMonth,
    plans: PLAN_LIMITS,
  });
});

app.post("/api/billing/checkout", auth, async (req, res) => {
  const plan = String(req.body?.plan || "");
  if (!["pro", "business", "team"].includes(plan)) return res.status(400).json({ error: "Invalid plan." });
  if (!stripe) return res.status(503).json({ error: "Stripe is not configured on this server. Set STRIPE_SECRET_KEY in .env." });
  if (!STRIPE_PRICE_IDS[plan]) return res.status(503).json({ error: `Stripe price for ${plan} is not configured. Set STRIPE_PRICE_${plan.toUpperCase()} in .env.` });
  try {
    const user = await one("SELECT id,email,plan,stripe_customer_id,stripe_subscription_id FROM users WHERE id=$1", [req.user.id]);
    const appUrl = process.env.APP_URL || "http://localhost:3000";

    // Existing subscriber: change the existing subscription instead of creating
    // a second subscription. This makes upgrades/downgrades idempotent.
    if (user?.stripe_subscription_id) {
      const sub = await stripe.subscriptions.retrieve(user.stripe_subscription_id);
      if (!["active", "trialing", "past_due"].includes(sub.status)) {
        await q("UPDATE users SET stripe_subscription_id=NULL WHERE id=$1", [req.user.id]);
      } else {
        const item = sub.items.data[0];
        if (!item) throw new Error("Stripe subscription has no billable item.");
        const updated = await stripe.subscriptions.update(sub.id, {
          items: [{ id: item.id, price: STRIPE_PRICE_IDS[plan] }],
          metadata: { loop_plan: plan, loop_user_id: String(req.user.id) },
          cancel_at_period_end: false,
          proration_behavior: "create_prorations",
        });
        const renewAt = updated.current_period_end ? new Date(Number(updated.current_period_end) * 1000) : null;
        await q("UPDATE users SET plan=$1, plan_renews_at=$2 WHERE id=$3", [plan, renewAt, req.user.id]);
        return res.json({ ok: true, upgraded: true, plan, subscription_id: updated.id });
      }
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: user?.stripe_customer_id || undefined,
      customer_email: user?.stripe_customer_id ? undefined : user?.email,
      line_items: [{ price: STRIPE_PRICE_IDS[plan], quantity: 1 }],
      success_url: `${appUrl}/?billing=success`,
      cancel_url: `${appUrl}/?billing=cancelled`,
      metadata: { loop_plan: plan, loop_user_id: String(req.user.id) },
      subscription_data: { metadata: { loop_plan: plan, loop_user_id: String(req.user.id) } },
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error("[LOOP] Stripe checkout/update failed:", e);
    res.status(500).json({ error: "Could not start the Stripe subscription." });
  }
});

app.post("/api/billing/cancel", auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Stripe is not configured on this server." });
  const u = await one("SELECT stripe_subscription_id FROM users WHERE id=$1", [req.user.id]);
  if (!u?.stripe_subscription_id) return res.status(400).json({ error: "No active subscription to cancel." });
  try {
    const sub = await stripe.subscriptions.update(u.stripe_subscription_id, { cancel_at_period_end: true });
    const renewAt = sub.current_period_end ? new Date(Number(sub.current_period_end) * 1000) : null;
    await q("UPDATE users SET plan_renews_at=$1 WHERE id=$2", [renewAt, req.user.id]);
    res.json({ ok: true, cancel_at_period_end: true, plan_renews_at: renewAt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not cancel the subscription." });
  }
});

// --- AI Analyzer ---
// Shared core used by both the paste-a-conversation flow (/api/analyze)
// and the connected-inbox flow (/api/inbox/analyze) — extracted so both
// entry points run through identical, already-tested logic rather than
// two copies that could quietly drift apart.
async function runLoopAnalysis(userId, clientId, projectId, conversationText) {
  // baseURL is configurable so this can point at any OpenAI-compatible
  // provider (Groq, OpenRouter, etc.) instead of OpenAI itself — several
  // of those have genuine no-card free tiers. Uses the standard Chat
  // Completions endpoint rather than OpenAI's newer Responses API:
  // Completions is the format virtually every compatible provider
  // actually implements (Groq specifically does not support Responses),
  // so this works against real OpenAI too, just via the more
  // universally-supported path.
  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, baseURL: process.env.OPENAI_BASE_URL || undefined });
  const system = `You are LOOP. Analyze a client conversation and find what's stuck, not just what's due. Return ONLY JSON:
{"summary":"...","primary_bottleneck":"...","overall_priority":0,"follow_up_message":"...",
"loops":[{"title":"...","person":"the specific person who made or owns this commitment, or null if unclear","type":"task|waiting|approval|follow_up|payment|deadline|decision","status":"open|in_progress|waiting|resolved","dependency":"what specifically is blocking this, or null","deadline":"... or null","payment_amount":"... or null","priority":0,"next_action":"...","is_micro_promise":false,"commitment_phrase":"... or null"}]}.
"status" reflects workflow stage only (open=not started, in_progress=actively being worked, waiting=blocked on someone/something else, resolved=done) — do not use it to express urgency, that's what "priority" is for.

In addition to explicit tasks and deadlines, also catch soft/passive commitments — casual language that implies a promise without stating it as a task, e.g. "I'll send the asset by EOD", "let me check with the team", "I'll get back to you on that", "should be ready by Friday". For any loop created from language like this, set "is_micro_promise":true and put the exact phrase (verbatim, from the conversation) that triggered the detection into "commitment_phrase". For loops derived from an explicit, already-tracked task rather than passive language, set "is_micro_promise":false and "commitment_phrase":null.
Do not invent names, amounts or dates. Do not mark something a micro-promise unless the conversation actually contains language resembling a soft commitment — when unsure, set is_micro_promise:false rather than guessing.`;
  const response = await client.chat.completions.create({
    model: process.env.OPENAI_MODEL || "llama-3.3-70b-versatile",
    messages: [{ role: "system", content: system }, { role: "user", content: conversationText }],
    response_format: { type: "json_object" },
  });
  const data = JSON.parse(response.choices[0].message.content);
  const loopsIn = data.loops || [];
  const bottleneckIdx = loopsIn.length
    ? loopsIn.reduce((best, l, i) => (l.priority || 0) > (loopsIn[best].priority || 0) ? i : best, 0)
    : -1;

  const dbClient = await pool.connect();
  let conversationId;
  try {
    await dbClient.query("BEGIN");
    const c = await dbClient.query(
      `INSERT INTO conversations(user_id,client_id,project_id,content,summary,primary_bottleneck,overall_priority,follow_up_message)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [userId, clientId, projectId, conversationText, data.summary || null, data.primary_bottleneck || null, data.overall_priority || null, data.follow_up_message || null]
    );
    conversationId = c.rows[0].id;
    for (let i = 0; i < loopsIn.length; i++) {
      const l = loopsIn[i];
      const personId = await findOrCreatePerson(userId, clientId, l.person);
      const loopRow = await dbClient.query(
        `INSERT INTO loops(user_id,client_id,project_id,conversation_id,person_id,title,type,status,priority,dependency,deadline,payment_amount,next_action,is_bottleneck,is_micro_promise,commitment_phrase)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
        [userId, clientId, projectId, conversationId, personId, l.title, l.type,
         ["open", "in_progress", "waiting", "resolved"].includes(l.status) ? l.status : "open",
         l.priority || 50, l.dependency || null, l.deadline || null, l.payment_amount || null, l.next_action || null,
         i === bottleneckIdx, Boolean(l.is_micro_promise), l.commitment_phrase || null]
      );
      await autoScheduleReminder(userId, clientId, loopRow.rows[0].id, loopRow.rows[0]);
    }
    await dbClient.query("COMMIT");
  } catch (e) {
    await dbClient.query("ROLLBACK");
    throw e;
  } finally {
    dbClient.release();
  }

  return { ...data, conversation_id: conversationId };
}

app.post("/api/analyze", auth, async (req, res) => {
  const conversation = String(req.body?.conversation || "").trim();
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  const projectId = await ownedOrNull("projects", req.body?.project_id, req.user.id);
  if (!conversation) return res.status(400).json({ error: "Conversation is required." });
  if (clientId === undefined || projectId === undefined) return res.status(403).json({ error: "Invalid client or project." });
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: "AI is not configured on this server." });

  const userRow = await one("SELECT plan FROM users WHERE id=$1", [req.user.id]);
  const plan = userRow?.plan || "free";
  const limit = PLAN_LIMITS[plan]?.analysesPerMonth ?? PLAN_LIMITS.free.analysesPerMonth;
  const used = await analysesThisMonth(req.user.id);
  if (used >= limit) {
    return res.status(402).json({
      error: `You've used all ${limit} analyses included in your ${PLAN_LIMITS[plan].label} plan this month. Upgrade to keep going.`,
      upgrade_required: true, plan, used, limit,
    });
  }

  try {
    const result = await runLoopAnalysis(req.user.id, clientId, projectId, conversation);
    await recordAnalysisUsage(req.user.id, result.conversation_id, "manual");
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "AI analysis failed." });
  }
});

// --- Gmail + WhatsApp integrations ---
app.get("/api/integrations", auth, async (req,res) => {
  const rows = await many("SELECT provider,account_email,expires_at,metadata,connected_at FROM integration_connections WHERE user_id=$1", [req.user.id]);
  const by = Object.fromEntries(rows.map(r=>[r.provider,r]));
  res.json({
    gmail: { configured: integrationConfigured("gmail"), connected: Boolean(by.gmail), account_email: by.gmail?.account_email || null, connected_at: by.gmail?.connected_at || null },
    whatsapp: { configured: integrationConfigured("whatsapp"), connected: Boolean(by.whatsapp), account_email: by.whatsapp?.account_email || null, connected_at: by.whatsapp?.connected_at || null, metadata: by.whatsapp?.metadata || {} },
    slack: { configured: integrationConfigured("slack"), connected: Boolean(by.slack), account_email: by.slack?.account_email || null, connected_at: by.slack?.connected_at || null, metadata: by.slack?.metadata || {} }
  });
});

app.get("/api/integrations/gmail/connect", auth, (req,res) => {
  if (!integrationConfigured("gmail")) return res.status(503).json({error:"Gmail integration is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."});
  const scopes = ["https://www.googleapis.com/auth/gmail.readonly"];
  const params = new URLSearchParams({client_id:process.env.GOOGLE_CLIENT_ID,redirect_uri:integrationRedirect("gmail"),response_type:"code",access_type:"offline",prompt:"consent",include_granted_scopes:"true",scope:scopes.join(" "),state:oauthState(req.user.id,"gmail")});
  res.json({url:`https://accounts.google.com/o/oauth2/v2/auth?${params}`});
});
app.get("/api/integrations/gmail/callback", async (req,res) => {
  try {
    const st=readOAuthState(req.query.state,"gmail"); if(req.query.error) throw new Error(String(req.query.error));
    const body=new URLSearchParams({code:String(req.query.code||""),client_id:process.env.GOOGLE_CLIENT_ID,client_secret:process.env.GOOGLE_CLIENT_SECRET,redirect_uri:integrationRedirect("gmail"),grant_type:"authorization_code"});
    const tr=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body}); const tok=await tr.json();
    if(!tr.ok||!tok.access_token) throw new Error(tok.error_description||"Google authorization failed.");
    const pr=await fetch("https://gmail.googleapis.com/gmail/v1/users/me/profile",{headers:{Authorization:`Bearer ${tok.access_token}`}}); const prof=await pr.json();
    if(!pr.ok) throw new Error("Could not read the connected Gmail account.");
    await saveIntegration(st.uid,"gmail",{account_email:prof.emailAddress,access_token:tok.access_token,refresh_token:tok.refresh_token,expires_at:new Date(Date.now()+Number(tok.expires_in||3600)*1000),metadata:{historyId:prof.historyId||null}});
    res.redirect(`${appUrl()}/?integration=gmail&status=connected`);
  } catch(e) { res.redirect(`${appUrl()}/?integration=gmail&status=error&message=${encodeURIComponent(e.message)}`); }
});
app.post("/api/integrations/gmail/disconnect", auth, async(req,res)=>{await deleteIntegration(req.user.id,"gmail");res.json({ok:true});});
app.get("/api/integrations/gmail/threads", auth, async(req,res)=>{
  const row=await getIntegration(req.user.id,"gmail"); if(!row) return res.status(400).json({error:"Connect Gmail first."});
  const access=await googleAccessToken(row); const params=new URLSearchParams({maxResults:String(Math.min(Number(req.query.limit||10),50)),q:String(req.query.q||"in:anywhere newer_than:30d")});
  const lr=await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads?${params}`,{headers:{Authorization:`Bearer ${access}`}}); const list=await lr.json(); if(!lr.ok) return res.status(lr.status).json({error:list.error?.message||"Gmail request failed."});
  const threads=[];
  for(const t of (list.threads||[]).slice(0,50)){const r=await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Date`,{headers:{Authorization:`Bearer ${access}`}}); if(r.ok){const d=await r.json();threads.push({id:d.id,snippet:d.snippet,messages:(d.messages||[]).map(m=>({id:m.id,headers:m.payload?.headers||[],labelIds:m.labelIds||[]}))});}}
  res.json({threads});
});

app.get("/api/integrations/gmail/thread/:id", auth, async(req,res)=>{
  const row=await getIntegration(req.user.id,"gmail");
  if(!row) return res.status(400).json({error:"Connect Gmail first."});
  try{
    const access=await googleAccessToken(row);
    const r=await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${encodeURIComponent(req.params.id)}?format=full`,{headers:{Authorization:`Bearer ${access}`}});
    const d=await r.json();
    if(!r.ok) return res.status(r.status).json({error:d.error?.message||"Gmail thread request failed."});
    const decode=(s)=>{try{return Buffer.from(String(s||"").replace(/-/g,"+").replace(/_/g,"/"),"base64").toString("utf8")}catch{return ""}};
    const walk=(part)=>{if(!part)return ""; if(part.mimeType==='text/plain'&&part.body?.data)return decode(part.body.data); return (part.parts||[]).map(walk).filter(Boolean).join("\n")};
    const messages=(d.messages||[]).map(m=>({id:m.id,headers:m.payload?.headers||[],text:walk(m.payload)||m.snippet||""}));
    res.json({id:d.id,snippet:d.snippet,messages});
  }catch(e){res.status(500).json({error:e.message||"Could not read Gmail thread."});}
});

// Pulls recent Gmail threads into the shared inbox — one inbox_messages
// row per thread (not per individual email), since a Gmail thread is
// already a ready-made "conversation" the way WhatsApp/Slack messages
// aren't. Re-syncing is safe: external_message_id = the Gmail thread id,
// so a thread that hasn't changed just gets skipped by the ON CONFLICT.
app.post("/api/integrations/gmail/sync", auth, async (req, res) => {
  const row = await getIntegration(req.user.id, "gmail");
  if (!row) return res.status(400).json({ error: "Connect Gmail first." });
  const decode = (s) => { try { return Buffer.from(String(s||"").replace(/-/g,"+").replace(/_/g,"/"),"base64").toString("utf8") } catch { return "" } };
  const walk = (part) => { if(!part) return ""; if(part.mimeType==='text/plain'&&part.body?.data) return decode(part.body.data); return (part.parts||[]).map(walk).filter(Boolean).join("\n") };
  const headerVal = (headers, name) => (headers||[]).find(h => h.name?.toLowerCase()===name.toLowerCase())?.value || null;
  try {
    const access = await googleAccessToken(row);
    const limit = Math.min(Number(req.body?.limit || 10), 25);
    const params = new URLSearchParams({ maxResults: String(limit), q: String(req.body?.q || "in:anywhere newer_than:30d") });
    const lr = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads?${params}`, { headers: { Authorization: `Bearer ${access}` } });
    const list = await lr.json();
    if (!lr.ok) return res.status(lr.status).json({ error: list.error?.message || "Gmail request failed." });

    let synced = 0;
    for (const t of (list.threads || [])) {
      const r = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?format=full`, { headers: { Authorization: `Bearer ${access}` } });
      if (!r.ok) continue;
      const d = await r.json();
      const msgs = d.messages || [];
      if (!msgs.length) continue;
      const first = msgs[0], last = msgs[msgs.length-1];
      const fromHeader = headerVal(first.payload?.headers, "From") || "";
      const nameMatch = fromHeader.match(/^"?([^"<]*)"?\s*<?/);
      const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/([\w.+-]+@[\w.-]+)/);
      const threadText = msgs.map(m => {
        const from = headerVal(m.payload?.headers, "From") || "unknown";
        const text = walk(m.payload) || m.snippet || "";
        return `[${from}]: ${text}`;
      }).join("\n\n");
      await ingestInboxMessage(req.user.id, "gmail", {
        threadKey: d.id,
        externalMessageId: d.id,
        contactName: (nameMatch?.[1] || "").trim() || null,
        contactIdentifier: emailMatch?.[1] || null,
        direction: "inbound",
        body: threadText.slice(0, 20000), // guard against pathological threads blowing past reasonable storage/prompt size
        occurredAt: last.internalDate ? new Date(Number(last.internalDate)) : new Date(),
      });
      synced++;
    }
    res.json({ synced });
  } catch (e) {
    res.status(500).json({ error: e.message || "Gmail sync failed." });
  }
});

app.get("/api/integrations/whatsapp/connect", auth, (req,res)=>{
  if(!integrationConfigured("whatsapp")) return res.status(503).json({error:"WhatsApp integration is not configured. Add META_APP_ID and META_APP_SECRET."});
  const params=new URLSearchParams({client_id:process.env.META_APP_ID,redirect_uri:integrationRedirect("whatsapp"),response_type:"code",state:oauthState(req.user.id,"whatsapp"),scope:"business_management,whatsapp_business_management,whatsapp_business_messaging"});
  res.json({url:`https://www.facebook.com/v23.0/dialog/oauth?${params}`});
});
app.get("/api/integrations/whatsapp/callback", async(req,res)=>{
  try {
    const st=readOAuthState(req.query.state,"whatsapp"); if(req.query.error) throw new Error(String(req.query.error));
    const tokenUrl=new URL("https://graph.facebook.com/v23.0/oauth/access_token"); tokenUrl.search=new URLSearchParams({client_id:process.env.META_APP_ID,client_secret:process.env.META_APP_SECRET,redirect_uri:integrationRedirect("whatsapp"),code:String(req.query.code||"")});
    const tr=await fetch(tokenUrl); const tok=await tr.json(); if(!tr.ok||!tok.access_token) throw new Error(tok.error?.message||"Meta authorization failed.");
    const meR=await fetch(`https://graph.facebook.com/v23.0/me?fields=id,name&access_token=${encodeURIComponent(tok.access_token)}`); const me=await meR.json();
    await saveIntegration(st.uid,"whatsapp",{account_email:me.name||null,access_token:tok.access_token,metadata:{meta_user_id:me.id||null,permissions_note:"Configure WhatsApp Business assets/webhooks in Meta before messaging."}});
    res.redirect(`${appUrl()}/?integration=whatsapp&status=connected`);
  } catch(e) { res.redirect(`${appUrl()}/?integration=whatsapp&status=error&message=${encodeURIComponent(e.message)}`); }
});
app.post("/api/integrations/whatsapp/disconnect", auth, async(req,res)=>{await deleteIntegration(req.user.id,"whatsapp");res.json({ok:true});});
app.post("/api/integrations/whatsapp/phone-number", auth, async (req, res) => {
  // Meta's OAuth for WhatsApp Business doesn't hand back a single "this is
  // your number" answer — the user configures phone numbers in Meta's own
  // dashboard and pastes the Phone Number ID here so incoming webhook
  // events (which are keyed by that ID, not by the OAuth user) can be
  // routed to the right LOOP account.
  const phoneNumberId = String(req.body?.phone_number_id || "").trim();
  if (!phoneNumberId) return res.status(400).json({ error: "phone_number_id is required." });
  const row = await getIntegration(req.user.id, "whatsapp");
  if (!row) return res.status(400).json({ error: "Connect WhatsApp first." });
  const metadata = { ...(row.metadata || {}), phone_number_id: phoneNumberId };
  await q("UPDATE integration_connections SET metadata=$1::jsonb WHERE id=$2", [JSON.stringify(metadata), row.id]);
  res.json({ ok: true, phone_number_id: phoneNumberId });
});
app.get("/api/webhooks/whatsapp", (req,res)=>{const mode=req.query["hub.mode"],token=req.query["hub.verify_token"],challenge=req.query["hub.challenge"];if(mode==="subscribe"&&token&&token===process.env.WHATSAPP_VERIFY_TOKEN)return res.status(200).send(challenge);res.sendStatus(403);});

// --- Slack ---
// Slack bot tokens (xoxb-...) don't expire the way Google's do, so there's
// no refresh-token dance here — connect once, sync on demand.
app.get("/api/integrations/slack/connect", auth, (req, res) => {
  if (!integrationConfigured("slack")) return res.status(503).json({ error: "Slack integration is not configured. Add SLACK_CLIENT_ID and SLACK_CLIENT_SECRET." });
  const params = new URLSearchParams({
    client_id: process.env.SLACK_CLIENT_ID,
    scope: "channels:history,channels:read,groups:history,groups:read,users:read",
    redirect_uri: integrationRedirect("slack"),
    state: oauthState(req.user.id, "slack"),
  });
  res.json({ url: `https://slack.com/oauth/v2/authorize?${params}` });
});
app.get("/api/integrations/slack/callback", async (req, res) => {
  try {
    const st = readOAuthState(req.query.state, "slack");
    if (req.query.error) throw new Error(String(req.query.error));
    const body = new URLSearchParams({
      client_id: process.env.SLACK_CLIENT_ID, client_secret: process.env.SLACK_CLIENT_SECRET,
      code: String(req.query.code || ""), redirect_uri: integrationRedirect("slack"),
    });
    const tr = await fetch("https://slack.com/api/oauth.v2.access", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    const tok = await tr.json();
    if (!tok.ok) throw new Error(tok.error || "Slack authorization failed.");
    await saveIntegration(st.uid, "slack", {
      account_email: tok.team?.name || null,
      access_token: tok.access_token, // bot token — no refresh_token in this flow
      metadata: { team_id: tok.team?.id || null, team_name: tok.team?.name || null },
    });
    res.redirect(`${appUrl()}/?integration=slack&status=connected`);
  } catch (e) { res.redirect(`${appUrl()}/?integration=slack&status=error&message=${encodeURIComponent(e.message)}`); }
});
app.post("/api/integrations/slack/disconnect", auth, async (req, res) => { await deleteIntegration(req.user.id, "slack"); res.json({ ok: true }); });

// Pulls recent messages from channels the bot has been added to into the
// shared inbox. Polling via conversations.history rather than the Events
// API webhook — no public URL / separate signature scheme to stand up for
// a first cut, and it matches the same "sync on demand" pattern as Gmail.
app.post("/api/integrations/slack/sync", auth, async (req, res) => {
  const row = await getIntegration(req.user.id, "slack");
  if (!row) return res.status(400).json({ error: "Connect Slack first." });
  const token = decryptSecret(row.access_token_enc);
  const slackApi = async (method, params) => {
    const r = await fetch(`https://slack.com/api/${method}?${new URLSearchParams(params)}`, { headers: { Authorization: `Bearer ${token}` } });
    return r.json();
  };
  try {
    const channels = await slackApi("conversations.list", { types: "public_channel,private_channel", limit: "50" });
    if (!channels.ok) return res.status(400).json({ error: channels.error || "Could not list Slack channels." });

    const userNameCache = {};
    const resolveUser = async (uid) => {
      if (!uid) return null;
      if (userNameCache[uid]) return userNameCache[uid];
      const u = await slackApi("users.info", { user: uid });
      const name = u.ok ? (u.user?.real_name || u.user?.name || uid) : uid;
      userNameCache[uid] = name;
      return name;
    };

    let synced = 0;
    for (const ch of (channels.channels || []).filter(c => c.is_member)) {
      const hist = await slackApi("conversations.history", { channel: ch.id, limit: "20" });
      if (!hist.ok) continue;
      for (const msg of (hist.messages || [])) {
        if (!msg.text || msg.subtype) continue; // skip join/leave/edit system messages, MVP: text only
        const senderName = await resolveUser(msg.user);
        await ingestInboxMessage(req.user.id, "slack", {
          threadKey: ch.id,
          externalMessageId: msg.ts, // Slack's per-channel message timestamp is a stable unique id
          contactName: senderName,
          contactIdentifier: msg.user || null,
          direction: "inbound",
          body: msg.text,
          occurredAt: new Date(Number(msg.ts.split(".")[0]) * 1000),
        });
        synced++;
      }
    }
    res.json({ synced, channels_scanned: (channels.channels || []).filter(c => c.is_member).length });
  } catch (e) {
    res.status(500).json({ error: e.message || "Slack sync failed." });
  }
});

// --- Unified Inbox: every synced/ingested message from Gmail, WhatsApp,
// and Slack lives in one place, grouped into threads, ready to assign to
// a client and analyze — same downstream pipeline as pasting a
// conversation in by hand.
app.get("/api/inbox", auth, async (req, res) => {
  const rows = await many(
    `SELECT DISTINCT ON (provider, thread_key)
       provider, thread_key, contact_name, contact_identifier, body, occurred_at, client_id, analyzed_at, direction
     FROM inbox_messages WHERE user_id=$1 ORDER BY provider, thread_key, occurred_at DESC`,
    [req.user.id]
  );
  const counts = await many(
    `SELECT provider, thread_key, count(*)::int AS n FROM inbox_messages WHERE user_id=$1 GROUP BY provider, thread_key`,
    [req.user.id]
  );
  const countMap = Object.fromEntries(counts.map(c => [`${c.provider}:${c.thread_key}`, c.n]));
  // A thread is "unanswered" when the most recent message is inbound (from
  // the customer) — meaning nobody on our side has replied yet. We surface
  // how long it's been waiting so the busiest/oldest ones stand out.
  const now = Date.now();
  const threads = rows.map(r => {
    const waitingMs = now - new Date(r.occurred_at).getTime();
    return {
      ...r,
      message_count: countMap[`${r.provider}:${r.thread_key}`] || 1,
      unanswered: r.direction === "inbound",
      waiting_hours: r.direction === "inbound" ? Math.round(waitingMs / 3600000 * 10) / 10 : null,
    };
  }).sort((a, b) => {
    // Unanswered threads first (oldest wait first within that group), then
    // everything else by most recent activity.
    if (a.unanswered !== b.unanswered) return a.unanswered ? -1 : 1;
    if (a.unanswered) return b.waiting_hours - a.waiting_hours;
    return new Date(b.occurred_at) - new Date(a.occurred_at);
  });
  const unansweredCount = threads.filter(t => t.unanswered).length;
  res.json({ threads, unanswered_count: unansweredCount });
});

app.patch("/api/inbox/thread", auth, async (req, res) => {
  const { provider, thread_key } = req.body || {};
  if (!provider || !thread_key) return res.status(400).json({ error: "provider and thread_key are required." });
  const clientId = await ownedOrNull("clients", req.body?.client_id, req.user.id);
  if (clientId === undefined) return res.status(403).json({ error: "Invalid client." });
  await q("UPDATE inbox_messages SET client_id=$1 WHERE user_id=$2 AND provider=$3 AND thread_key=$4", [clientId, req.user.id, provider, thread_key]);
  res.json({ ok: true });
});

app.post("/api/inbox/analyze", auth, async (req, res) => {
  const { provider, thread_key } = req.body || {};
  if (!provider || !thread_key) return res.status(400).json({ error: "provider and thread_key are required." });
  const messages = await many(
    "SELECT * FROM inbox_messages WHERE user_id=$1 AND provider=$2 AND thread_key=$3 ORDER BY occurred_at ASC",
    [req.user.id, provider, thread_key]
  );
  if (!messages.length) return res.status(404).json({ error: "No messages found for this thread." });
  const clientId = await ownedOrNull("clients", req.body?.client_id ?? messages[messages.length-1].client_id, req.user.id);
  const projectId = await ownedOrNull("projects", req.body?.project_id, req.user.id);
  if (clientId === undefined || projectId === undefined) return res.status(403).json({ error: "Invalid client or project." });
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: "AI is not configured on this server." });

  const userRow = await one("SELECT plan FROM users WHERE id=$1", [req.user.id]);
  const plan = userRow?.plan || "free";
  const limit = PLAN_LIMITS[plan]?.analysesPerMonth ?? PLAN_LIMITS.free.analysesPerMonth;
  const used = await analysesThisMonth(req.user.id);
  if (used >= limit) {
    return res.status(402).json({
      error: `You've used all ${limit} analyses included in your ${PLAN_LIMITS[plan].label} plan this month. Upgrade to keep going.`,
      upgrade_required: true, plan, used, limit,
    });
  }

  // Gmail threads already arrive as one full-thread row; WhatsApp/Slack
  // arrive as individual messages that need assembling into one block —
  // this formatting is what the AI actually reads, so getting the sender
  // labels right here matters as much as the extraction prompt itself.
  const conversationText = provider === "gmail"
    ? messages[messages.length-1].body
    : messages.map(m => `[${m.contact_name || m.contact_identifier || "unknown"}]: ${m.body}`).join("\n");

  try {
    const result = await runLoopAnalysis(req.user.id, clientId, projectId, conversationText);
    await recordAnalysisUsage(req.user.id, result.conversation_id, "inbox");
    await q(
      "UPDATE inbox_messages SET analyzed_at=now(), client_id=COALESCE(client_id,$1) WHERE user_id=$2 AND provider=$3 AND thread_key=$4",
      [clientId, req.user.id, provider, thread_key]
    );
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "AI analysis failed." });
  }
});


app.get("/api/plans", (req, res) => res.json({ plans: [
  { id: "free", name: "Free", price: 0, interval: "month", analyses: 5, loops: 50 },
  { id: "pro", name: "Pro", price: 9, interval: "month", analyses: 100, loops: 1000 },
  { id: "business", name: "Business", price: 19, interval: "month", analyses: 500, loops: 10000 },
  { id: "team", name: "Team", price: 49, interval: "month", analyses: 2000, loops: 50000 }
]}));

app.get("/api/health", (req, res) => res.json({ ok: true, aiConfigured: Boolean(process.env.OPENAI_API_KEY), stripeConfigured: Boolean(stripe), stripePricesConfigured: Object.values(STRIPE_PRICE_IDS).filter(Boolean).length === 3, integrations: { gmail: integrationConfigured("gmail"), whatsapp: integrationConfigured("whatsapp"), slack: integrationConfigured("slack") } }));
app.get("/{*splat}", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

initSchema()
  .then(() => app.listen(process.env.PORT || 3000, () => console.log("LOOP server running")))
  .catch(e => { console.error("[LOOP] failed to initialize database schema:", e); process.exit(1); });
