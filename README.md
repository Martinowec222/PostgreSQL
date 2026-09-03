# recenzePro tracker

Tiny redirect + logging service for NFC/QR review cards, with per-client
logins, website uptime/SSL monitoring, and AI-drafted review replies.

Each card points to `https://<your-service>/r/<code>`. That route logs the
scan (timestamp, device, referrer) to Postgres and then 302-redirects the
visitor on to the client's real Google review link.

- `/admin` — your login. Manage clients, cards, monitored websites.
- `/client` — each client's own login. Scan stats, uptime status for their
  site, and an AI review-reply drafting tool.

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

### Uptime/SSL monitoring

No extra Render resource needed. A site is checked automatically the moment
someone opens the admin or client dashboard, as long as its last check is
older than `SITE_CHECK_INTERVAL_MINUTES` (default 10). Repeat page visits
within that window skip the network check and load instantly.

1. In `/admin`, open a client and add their website URL under "Stav webu".
2. Optionally set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`,
   `SMTP_FROM`, `ALERT_EMAIL_TO` to get an email when a site goes down or
   its SSL certificate is close to expiring. Since checks only run on page
   visits, an alert fires on the next visit after the problem occurred, not
   necessarily the instant it happens.

`check-sites.js` is still included as an optional alternative — deploy it
as a separate Render Cron Job if you ever want checks to run even when
nobody opens the dashboard (e.g. catching an outage overnight).

### AI review-reply drafting

1. Get an API key from console.anthropic.com (separate from a claude.ai login).
2. Add `ANTHROPIC_API_KEY` to the web service's environment variables.
3. The "Návrh odpovědi na recenzi" tool appears automatically on both the
   admin client-detail page and each client's own dashboard.
