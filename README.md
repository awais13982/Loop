# LOOP v1.6 — Production-ready foundation

## Patch note (applied after review)
This copy adds one fix: the AI call was reverted to OpenAI's Responses
API in this version, which dropped Groq/free-tier compatibility (Groq
and most free OpenAI-compatible providers only implement the older Chat
Completions format). Switched back to `chat.completions.create` with
`response_format: json_object`, and re-added `OPENAI_BASE_URL` support
in `.env.example`. Verified: the AI call pipeline executes correctly
through the new format (confirmed via a fake key failing at the actual
API call rather than earlier validation), and the full endpoint
regression suite still passes.

LOOP is an AI-powered work assistant that finds unfinished work hidden inside conversations, identifies what is stuck, and tells users what to do next.

## What's new in v1.6

### Billing hardening
- Stripe now uses Dashboard-created recurring Price IDs (`STRIPE_PRICE_PRO`, `STRIPE_PRICE_BUSINESS`, `STRIPE_PRICE_TEAM`) instead of creating ad-hoc prices during checkout.
- Existing active subscriptions are upgraded/downgraded in place rather than creating a second subscription.
- Stripe subscription metadata carries the LOOP user and plan so webhook events can keep the database synchronized.
- Cancellation is scheduled at period end, so customers retain their paid plan until the current billing period finishes.
- Subscription webhook handling supports `created`, `updated`, and `deleted` lifecycle events.

### Usage tracking
- AI analyses are recorded in a dedicated `usage_events` table.
- Usage counts are monthly and source-aware (`manual` or `inbox`).
- A unique `(user_id,event_type,reference_id)` constraint prevents duplicate usage charges for the same analysis.

### Integrations
- `/api/integrations` now reports Gmail, WhatsApp, and Slack consistently.
- Slack remains sync-on-demand in v1.6; real-time Events API ingestion is a future hardening step.
- Gmail token refresh remains supported.
- WhatsApp webhook signature verification and message deduplication remain enabled.

### Production security
- Production startup refuses to run without `JWT_SECRET` and `INTEGRATION_ENCRYPTION_KEY`.
- Production deployments using required email verification must also configure `RESEND_API_KEY`.
- Development can still run with the documented local defaults.

## Included
- Authentication, email verification and password reset
- PostgreSQL persistence and automatic startup migrations
- AI conversation analyzer using OpenAI
- Open-loop detection, dependencies, bottleneck and priority
- Next-best-action dashboard
- Follow-up drafting and lifecycle tracking
- Clients and projects
- Payments and invoices
- Stripe subscription billing
- Gmail OAuth and inbox sync
- WhatsApp Business OAuth foundation + verified webhook ingestion
- Slack OAuth + inbox sync
- Unified Inbox
- Monthly analysis usage tracking
- Responsive browser UI

## Production environment
Copy `.env.example` to `.env` and configure real values on the server. Never put provider secrets in a browser bundle or APK.

Minimum: `DATABASE_URL`, `JWT_SECRET`, `OPENAI_API_KEY`, `INTEGRATION_ENCRYPTION_KEY`.

Billing: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_BUSINESS`, `STRIPE_PRICE_TEAM`.

Gmail: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`.

WhatsApp Business: `META_APP_ID`, `META_APP_SECRET`, `WHATSAPP_VERIFY_TOKEN`, plus the Meta Business/phone configuration required for your account.

Slack: `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`.

Email: `RESEND_API_KEY`, `NOTIFY_FROM_EMAIL` if verification/reset email delivery is required.

## Stripe setup
1. Create three recurring monthly Stripe Prices in the Stripe Dashboard.
2. Put their IDs in `STRIPE_PRICE_PRO`, `STRIPE_PRICE_BUSINESS`, and `STRIPE_PRICE_TEAM`.
3. Add a Stripe webhook endpoint at `APP_URL/api/webhooks/stripe`.
4. Subscribe the endpoint to at least:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
5. Put the signing secret in `STRIPE_WEBHOOK_SECRET`.
6. Test checkout, upgrade, downgrade, cancellation, renewal, failed payment and webhook retries in Stripe test mode before accepting real payments.

## Run
1. Install Node.js 20+ and PostgreSQL.
2. Run `npm install`.
3. Create `.env` from `.env.example`.
4. Run `npm start`.
5. Open `APP_URL`.

The database schema is created/migrated automatically on startup.

## Core flow
Conversation → AI Analysis → Open Loops → Bottleneck → Priority → Do This Next → Follow-up → Resolution
