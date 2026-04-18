import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(cors());

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('No URL provided');

  try {
    const response = await fetch(target, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });

    const contentType = response.headers.get('content-type') || 'text/html';

    res.set('Content-Type', contentType);
    res.set('Access-Control-Allow-Origin', '*');
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');

    if (contentType.includes('text/html')) {
      let body = await response.text();
      const origin = new URL(target).origin;

      // Rewrite relative URLs to route through proxy
      body = body.replace(
        /(href|src|action)="\/(?!\/)/g,
        `$1="/proxy?url=${origin}/`
      );
      body = body.replace(
        /(href|src|action)="(?!http|\/\/|#|mailto|javascript)([^"]+)"/g,
        (match, attr, path) => {
          const base = target.replace(/\/[^\/]*$/, '/');
          return `${attr}="/proxy?url=${base}${path}"`;
        }
      );

      res.send(body);
    } else {
      // Stream binary content (images, fonts, etc.) directly
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send(`
      <html><body style="font-family:sans-serif;padding:2rem;background:#0d0d1a;color:#e8e8f0;">
        <h2>NovOS Proxy Error</h2>
        <p style="color:#ff6b6b;">${err.message}</p>
        <p style="color:#9090b0;">The page could not be loaded. It may be blocking proxy access.</p>
      </body></html>
    `);
  }
});

// Health check endpoint — ping this to keep the server awake
app.get('/health', (_, res) => res.send('OK'));

// Keep-alive ping route (call from NovOS every 10 mins)
app.get('/ping', (_, res) => res.json({ status: 'alive', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NovOS proxy running on port ${PORT}`));
