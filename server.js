import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { JSDOM } from 'jsdom';

const app = express();
app.use(cors());

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const BLOCKED_SCRIPTS = [
  'securly', 'goguardian', 'lightspeed', 'relay.school',
  'blocksi', 'linewize', 'contentkeeper', 'smoothwall',
  'iboss', 'bark', 'gaggle', 'hapara', 'dyknow',
  'lanschool', 'impero', 'senso.cloud', 'securus',
  'netsweeper', 'webpurify', 'cyberhound'
];

function shouldBlock(url) {
  if (!url) return false;
  const lower = url.toLowerCase();
  return BLOCKED_SCRIPTS.some(s => lower.includes(s));
}

function resolveUrl(base, relative) {
  try {
    return new URL(relative, base).href;
  } catch {
    return relative;
  }
}

async function fetchResource(url, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(url, {
      headers: {
        'User-Agent': UA,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': new URL(url).origin,
      },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);
    return resp;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

async function toDataUri(url) {
  try {
    const resp = await fetchResource(url, 6000);
    if (!resp.ok) return null;
    const buf = await resp.buffer();
    const ct = resp.headers.get('content-type') || 'application/octet-stream';
    return `data:${ct.split(';')[0]};base64,${buf.toString('base64')}`;
  } catch {
    return null;
  }
}

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('No URL provided');

  try {
    const response = await fetchResource(target);
    const contentType = response.headers.get('content-type') || 'text/html';

    if (!contentType.includes('text/html')) {
      res.set('Content-Type', contentType);
      res.set('Access-Control-Allow-Origin', '*');
      response.body.pipe(res);
      return;
    }

    let body = await response.text();
    const baseUrl = response.url || target;
    const origin = new URL(baseUrl).origin;
    const proxyBase = `${req.protocol}://${req.get('host')}/proxy?url=`;

    const dom = new JSDOM(body, { url: baseUrl });
    const doc = dom.window.document;

    doc.querySelectorAll('meta[http-equiv]').forEach(m => {
      const equiv = (m.getAttribute('http-equiv') || '').toLowerCase();
      if (['content-security-policy', 'x-frame-options'].includes(equiv)) m.remove();
    });

    doc.querySelectorAll('script').forEach(s => {
      const src = s.getAttribute('src') || '';
      const text = s.textContent || '';
      if (shouldBlock(src) || shouldBlock(text)) {
        s.remove();
        return;
      }
      if (src) {
        const abs = resolveUrl(baseUrl, src);
        s.setAttribute('src', proxyBase + encodeURIComponent(abs));
      }
    });

    doc.querySelectorAll('link[rel="stylesheet"], link[rel="preload"][as="style"]').forEach(l => {
      const href = l.getAttribute('href');
      if (!href) return;
      if (shouldBlock(href)) { l.remove(); return; }
      const abs = resolveUrl(baseUrl, href);
      l.setAttribute('href', proxyBase + encodeURIComponent(abs));
    });

    doc.querySelectorAll('img, video source, audio source').forEach(el => {
      const src = el.getAttribute('src');
      if (src && !src.startsWith('data:') && !src.startsWith('blob:')) {
        const abs = resolveUrl(baseUrl, src);
        el.setAttribute('src', proxyBase + encodeURIComponent(abs));
      }
      const srcset = el.getAttribute('srcset');
      if (srcset) {
        el.setAttribute('srcset', srcset.replace(/(https?:\/\/[^\s,]+)/g, (u) => proxyBase + encodeURIComponent(u)));
      }
    });

    doc.querySelectorAll('a').forEach(a => {
      const href = a.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('javascript:') || href.startsWith('data:')) return;
      const abs = resolveUrl(baseUrl, href);
      a.setAttribute('href', proxyBase + encodeURIComponent(abs));
      a.setAttribute('target', '_self');
    });

    doc.querySelectorAll('form').forEach(f => {
      const action = f.getAttribute('action');
      if (action) {
        const abs = resolveUrl(baseUrl, action);
        f.setAttribute('action', proxyBase + encodeURIComponent(abs));
      }
      f.removeAttribute('target');
    });

    doc.querySelectorAll('iframe').forEach(f => {
      const src = f.getAttribute('src');
      if (src && !src.startsWith('data:') && !src.startsWith('blob:') && !src.startsWith('about:')) {
        const abs = resolveUrl(baseUrl, src);
        f.setAttribute('src', proxyBase + encodeURIComponent(abs));
      }
    });

    doc.querySelectorAll('[style]').forEach(el => {
      let style = el.getAttribute('style');
      if (style && style.includes('url(')) {
        style = style.replace(/url\((['"]?)((?!data:|blob:)[^)'"]+)\1\)/g, (match, q, u) => {
          const abs = resolveUrl(baseUrl, u);
          return `url(${q}${proxyBase}${encodeURIComponent(abs)}${q})`;
        });
        el.setAttribute('style', style);
      }
    });

    doc.querySelectorAll('style').forEach(st => {
      let text = st.textContent;
      if (text && text.includes('url(')) {
        text = text.replace(/url\((['"]?)((?!data:|blob:)[^)'"]+)\1\)/g, (match, q, u) => {
          const abs = resolveUrl(baseUrl, u);
          return `url(${q}${proxyBase}${encodeURIComponent(abs)}${q})`;
        });
        st.textContent = text;
      }
    });

    const interceptScript = doc.createElement('script');
    interceptScript.textContent = `
      (function(){
        const _P = ${JSON.stringify(proxyBase)};
        const _B = ${JSON.stringify(baseUrl)};
        function _abs(u) { try { return new URL(u, _B).href; } catch(e) { return u; } }
        function _px(u) {
          if (!u || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
          const a = _abs(u);
          if (a.startsWith(_P)) return a;
          return _P + encodeURIComponent(a);
        }

        const origFetch = window.fetch;
        window.fetch = function(input, init) {
          if (typeof input === 'string') input = _px(input);
          else if (input && input.url) input = new Request(_px(input.url), input);
          return origFetch.call(this, input, init);
        };

        const XHR = XMLHttpRequest.prototype;
        const origOpen = XHR.open;
        XHR.open = function(method, url) {
          arguments[1] = _px(url);
          return origOpen.apply(this, arguments);
        };

        const origPushState = history.pushState;
        const origReplaceState = history.replaceState;
        history.pushState = function() { return origPushState.apply(this, arguments); };
        history.replaceState = function() { return origReplaceState.apply(this, arguments); };

        document.addEventListener('click', function(e) {
          const a = e.target.closest('a');
          if (a && a.href && !a.href.startsWith('#') && !a.href.startsWith('javascript:')) {
            const h = a.getAttribute('href');
            if (h && !h.startsWith(_P) && !h.startsWith('#') && !h.startsWith('javascript:') && !h.startsWith('mailto:')) {
              e.preventDefault();
              window.location.href = _px(h);
            }
          }
        }, true);

        const origCreateElement = document.createElement.bind(document);
        document.createElement = function(tag) {
          const el = origCreateElement(tag);
          if (tag.toLowerCase() === 'script') {
            const origSetAttr = el.setAttribute.bind(el);
            el.setAttribute = function(name, value) {
              if (name === 'src') value = _px(value);
              return origSetAttr(name, value);
            };
          }
          return el;
        };

        if (window.parent && window.parent !== window) {
          try {
            window.parent.postMessage({ type: 'novproxy-url', url: ${JSON.stringify(target)} }, '*');
          } catch(e) {}
        }
      })();
    `;
    const head = doc.querySelector('head');
    if (head && head.firstChild) head.insertBefore(interceptScript, head.firstChild);
    else if (head) head.appendChild(interceptScript);
    else doc.documentElement.insertBefore(interceptScript, doc.documentElement.firstChild);

    const html = dom.serialize();

    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Access-Control-Allow-Origin', '*');
    res.set('X-Frame-Options', 'ALLOWALL');
    res.removeHeader('Content-Security-Policy');
    res.send(html);

  } catch (err) {
    res.status(500).send(`
      <html><body style="font-family:sans-serif;padding:2rem;background:#0d0d1a;color:#e8e8f0;">
        <h2>NovOS Proxy Error</h2>
        <p style="color:#ff6b6b;">${err.message}</p>
        <p style="color:#9090b0;">The page could not be loaded.</p>
      </body></html>
    `);
  }
});

app.get('/raw', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('No URL');
  try {
    const resp = await fetchResource(target);
    const ct = resp.headers.get('content-type') || 'application/octet-stream';
    res.set('Content-Type', ct);
    res.set('Access-Control-Allow-Origin', '*');
    resp.body.pipe(res);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.get('/health', (_, res) => res.send('OK'));
app.get('/ping', (_, res) => res.json({ status: 'alive', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NovOS proxy running on port ${PORT}`));
