# recenzePro tracker

Tiny redirect + logging service for NFC/QR review cards, with per-client
logins, website uptime/SSL monitoring, and AI-drafted review replies.

Each card points to `https://<your-service>/r/<code>`. That route logs the
scan (timestamp, device, referrer) to Postgres and then 302-redirects the
visitor on to the client's real Google review link.

- `/admin` — your login. Manage clients, cards, monitored websites.
- `/client` — each client's own login. Scan stats, uptime status for their
  site, and an AI review-reply drafting tool.
- `check-sites.js` — run on a schedule (Render Cron Job) to check every
  monitored site's uptime and SSL expiry, and email an alert if configured.

## Local test (optional)

```
cp .env.example .env      # fill in a local/dev Postgres URL
npm install
npm start
```

## Deploy on Render

1. Push this folder to a GitHub repo.
2. Render dashboard → New → PostgreSQL → copy the Internal Database URL.
3. Render dashboard → New → Web Service → connect the repo.
   - Build command: `npm install`
   - Start command: `npm start`
   - Env vars: `DATABASE_URL`, `SESSION_SECRET`, `ADMIN_PASSWORD`
4. Open `/admin`, log in, create clients and cards.
5. Point each physical NFC/QR card at `https://<service>/r/<code>`.

### Optional: uptime/SSL monitoring

1. Render dashboard → New → Cron Job → connect the same repo.
   - Build command: `npm install`
   - Command: `node check-sites.js`
   - Schedule: e.g. `*/15 * * * *` (every 15 minutes)
   - Env vars: same `DATABASE_URL` as the web service, plus optionally
     `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`,
     `ALERT_EMAIL_TO` for down/expiry email alerts.
2. In `/admin`, open a client and add their website URL under "Stav webu".

### Optional: AI review-reply drafting

1. Get an API key from console.anthropic.com (separate from a claude.ai login).
2. Add `ANTHROPIC_API_KEY` to the web service's environment variables.
3. The "Návrh odpovědi na recenzi" tool appears automatically on both the
   admin client-detail page and each client's own dashboard.
