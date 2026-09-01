# recenzePro tracker

Tiny redirect + logging service for NFC/QR review cards.

Each card points to `https://<your-service>/r/<code>`. That route logs the
scan (timestamp, device, referrer) to Postgres and then 302-redirects the
visitor on to the client's real Google review link. `/admin` shows scan
counts and a 30-day chart per client.

## Local test (optional)

```
cp .env.example .env      # fill in a local/dev Postgres URL
npm install
npm start
```

## Deploy on Render — see the chat message for full steps

1. Push this folder to a GitHub repo.
2. Render dashboard → New → PostgreSQL → copy the Internal Database URL.
3. Render dashboard → New → Web Service → connect the repo.
   - Build command: `npm install`
   - Start command: `npm start`
   - Env vars: `DATABASE_URL`, `SESSION_SECRET`, `ADMIN_PASSWORD`
4. Open `/admin`, log in, click "Přidat kartičku" for each client.
5. Point each physical NFC/QR card at `https://<service>/r/<code>`.
