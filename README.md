# NovOS Proxy Server

A lightweight proxy server for the NovOS browser app. Strips `X-Frame-Options` and `Content-Security-Policy` headers so pages can load inside NovOS iframes.

## Setup

```bash
npm install
npm start
```

## Deploy to Render.com

1. Push this folder to a GitHub repo
2. Go to render.com → New → Web Service
3. Connect your GitHub repo
4. Set:
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
   - **Instance type:** Free
5. Deploy — your URL will be `https://your-app-name.onrender.com`

## Endpoints

| Route | Description |
|-------|-------------|
| `GET /proxy?url=https://...` | Proxy a URL through the server |
| `GET /health` | Health check — returns "OK" |
| `GET /ping` | Keep-alive ping — returns JSON with timestamp |

## Usage in NovOS

```js
const PROXY = 'https://your-app.onrender.com/proxy?url=';
iframe.src = PROXY + encodeURIComponent('https://example.com');
```

## Keep-Alive (Free Tier)

Free Render instances sleep after 15 minutes of inactivity. To prevent cold starts, ping `/ping` every 10 minutes from NovOS:

```js
setInterval(() => fetch('https://your-app.onrender.com/ping'), 10 * 60 * 1000);
```
