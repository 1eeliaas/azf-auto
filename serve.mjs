import http   from 'http';
import fs     from 'fs';
import path   from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname   = path.dirname(fileURLToPath(import.meta.url));
const PORT        = process.env.PORT || 3000;
const ROOT        = __dirname;
const CARS_FILE   = path.join(ROOT, 'data', 'cars.json');
const USERS_FILE  = path.join(ROOT, 'data', 'users.json');

const MIME = {
  '.html':  'text/html; charset=utf-8',
  '.css':   'text/css',
  '.js':    'text/javascript',
  '.mjs':   'text/javascript',
  '.json':  'application/json',
  '.png':   'image/png',
  '.jpg':   'image/jpeg',
  '.jpeg':  'image/jpeg',
  '.svg':   'image/svg+xml',
  '.ico':   'image/x-icon',
  '.webp':  'image/webp',
  '.woff2': 'font/woff2',
  '.woff':  'font/woff',
};

/* ── Sessions (in-memory) ── */
// token -> { userId, role, expiresAt }
const sessions = new Map();

/* ── Helpers: Cars ── */
function readCars()       { return JSON.parse(fs.readFileSync(CARS_FILE,  'utf-8')); }
function writeCars(data)  { fs.writeFileSync(CARS_FILE,  JSON.stringify(data, null, 2), 'utf-8'); }

/* ── Helpers: Users ── */
function readUsers()      { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8')); }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf-8'); }

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getSession(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) { sessions.delete(token); return null; }
  return { token, ...session };
}

function safeUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt, favorites: u.favorites, history: u.history };
}

/* ── Helpers: Misc ── */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(data));
}

function slugify(str) {
  return str.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
}

/* ════════════════════════════════════════════
   HTTP SERVER
════════════════════════════════════════════ */
http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];

  /* ── CORS preflight ── */
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    res.end();
    return;
  }

  /* ════════ AUTH ROUTES ════════ */

  /* POST /api/auth/register */
  if (urlPath === '/api/auth/register' && req.method === 'POST') {
    try {
      const { name, email, password } = await parseBody(req);
      if (!name || !email || !password) { json(res, 400, { error: 'Champs manquants.' }); return; }
      if (password.length < 6) { json(res, 400, { error: 'Mot de passe trop court (6 caractères min).' }); return; }
      const data = readUsers();
      if (data.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        json(res, 409, { error: 'Cet email est déjà utilisé.' }); return;
      }
      const user = {
        id: 'user-' + crypto.randomBytes(6).toString('hex'),
        email: email.toLowerCase().trim(),
        passwordHash: hashPassword(password),
        name: name.trim(),
        role: 'user',
        createdAt: new Date().toISOString(),
        favorites: [],
        history: [],
      };
      data.users.push(user);
      writeUsers(data);
      const token = generateToken();
      sessions.set(token, { userId: user.id, role: user.role, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 });
      json(res, 201, { token, user: safeUser(user) });
    } catch (e) {
      json(res, 400, { error: 'Requête invalide.' });
    }
    return;
  }

  /* POST /api/auth/login */
  if (urlPath === '/api/auth/login' && req.method === 'POST') {
    try {
      const { email, password } = await parseBody(req);
      if (!email || !password) { json(res, 400, { error: 'Champs manquants.' }); return; }
      const data = readUsers();
      const user = data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (!user || user.passwordHash !== hashPassword(password)) {
        json(res, 401, { error: 'Email ou mot de passe incorrect.' }); return;
      }
      const token = generateToken();
      sessions.set(token, { userId: user.id, role: user.role, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 });
      json(res, 200, { token, user: safeUser(user) });
    } catch (e) {
      json(res, 400, { error: 'Requête invalide.' });
    }
    return;
  }

  /* POST /api/auth/logout */
  if (urlPath === '/api/auth/logout' && req.method === 'POST') {
    const session = getSession(req);
    if (session) sessions.delete(session.token);
    json(res, 200, { ok: true });
    return;
  }

  /* GET /api/auth/me */
  if (urlPath === '/api/auth/me' && req.method === 'GET') {
    const session = getSession(req);
    if (!session) { json(res, 401, { error: 'Non authentifié.' }); return; }
    const data = readUsers();
    const user = data.users.find(u => u.id === session.userId);
    if (!user) { sessions.delete(session.token); json(res, 401, { error: 'Utilisateur introuvable.' }); return; }
    json(res, 200, { user: safeUser(user) });
    return;
  }

  /* ════════ USER ROUTES ════════ */

  /* GET /api/users/favorites */
  if (urlPath === '/api/users/favorites' && req.method === 'GET') {
    const session = getSession(req);
    if (!session) { json(res, 401, { error: 'Non authentifié.' }); return; }
    const usersData = readUsers();
    const user = usersData.users.find(u => u.id === session.userId);
    if (!user) { json(res, 404, { error: 'Utilisateur introuvable.' }); return; }
    const carsData = readCars();
    const favCars = user.favorites.map(id => carsData.cars.find(c => c.id === id)).filter(Boolean);
    json(res, 200, favCars);
    return;
  }

  /* POST /api/users/favorites  { carId } */
  if (urlPath === '/api/users/favorites' && req.method === 'POST') {
    const session = getSession(req);
    if (!session) { json(res, 401, { error: 'Non authentifié.' }); return; }
    try {
      const { carId } = await parseBody(req);
      if (!carId) { json(res, 400, { error: 'carId manquant.' }); return; }
      const data = readUsers();
      const idx  = data.users.findIndex(u => u.id === session.userId);
      if (idx === -1) { json(res, 404, { error: 'Utilisateur introuvable.' }); return; }
      const favs = data.users[idx].favorites;
      const pos  = favs.indexOf(carId);
      let added;
      if (pos === -1) { favs.push(carId); added = true; }
      else            { favs.splice(pos, 1); added = false; }
      writeUsers(data);
      json(res, 200, { added, favorites: favs });
    } catch (e) {
      json(res, 400, { error: 'Requête invalide.' });
    }
    return;
  }

  /* GET /api/users/history */
  if (urlPath === '/api/users/history' && req.method === 'GET') {
    const session = getSession(req);
    if (!session) { json(res, 401, { error: 'Non authentifié.' }); return; }
    const usersData = readUsers();
    const user = usersData.users.find(u => u.id === session.userId);
    if (!user) { json(res, 404, { error: 'Utilisateur introuvable.' }); return; }
    const carsData = readCars();
    const histCars = user.history.map(id => carsData.cars.find(c => c.id === id)).filter(Boolean);
    json(res, 200, histCars);
    return;
  }

  /* POST /api/users/history  { carId } */
  if (urlPath === '/api/users/history' && req.method === 'POST') {
    const session = getSession(req);
    if (!session) { json(res, 401, { error: 'Non authentifié.' }); return; }
    try {
      const { carId } = await parseBody(req);
      if (!carId) { json(res, 400, { error: 'carId manquant.' }); return; }
      const data = readUsers();
      const idx  = data.users.findIndex(u => u.id === session.userId);
      if (idx === -1) { json(res, 404, { error: 'Utilisateur introuvable.' }); return; }
      let hist = data.users[idx].history;
      hist = hist.filter(id => id !== carId); // déduplique
      hist.unshift(carId);
      if (hist.length > 20) hist = hist.slice(0, 20);
      data.users[idx].history = hist;
      writeUsers(data);
      json(res, 200, { ok: true });
    } catch (e) {
      json(res, 400, { error: 'Requête invalide.' });
    }
    return;
  }

  /* ════════ CARS ROUTES ════════ */

  /* GET /api/cars */
  if (urlPath === '/api/cars' && req.method === 'GET') {
    const data = readCars();
    json(res, 200, data.cars);
    return;
  }

  /* POST /api/cars — admin only */
  if (urlPath === '/api/cars' && req.method === 'POST') {
    const session = getSession(req);
    if (!session || session.role !== 'admin') { json(res, 403, { error: 'Accès refusé.' }); return; }
    try {
      const body = await parseBody(req);
      const data = readCars();
      if (!body.id) {
        body.id = slugify((body.marque || 'car') + '-' + (body.modele || '') + '-' + Date.now());
      }
      data.cars.push(body);
      writeCars(data);
      json(res, 201, body);
    } catch (e) {
      json(res, 400, { error: 'Invalid body' });
    }
    return;
  }

  /* PUT /api/cars/:id — admin only */
  const putMatch = urlPath.match(/^\/api\/cars\/(.+)$/);
  if (putMatch && req.method === 'PUT') {
    const session = getSession(req);
    if (!session || session.role !== 'admin') { json(res, 403, { error: 'Accès refusé.' }); return; }
    try {
      const id   = putMatch[1];
      const body = await parseBody(req);
      const data = readCars();
      const idx  = data.cars.findIndex(c => c.id === id);
      if (idx === -1) { json(res, 404, { error: 'Not found' }); return; }
      data.cars[idx] = { ...data.cars[idx], ...body, id };
      writeCars(data);
      json(res, 200, data.cars[idx]);
    } catch (e) {
      json(res, 400, { error: 'Invalid body' });
    }
    return;
  }

  /* DELETE /api/cars/:id — admin only */
  const delMatch = urlPath.match(/^\/api\/cars\/(.+)$/);
  if (delMatch && req.method === 'DELETE') {
    const session = getSession(req);
    if (!session || session.role !== 'admin') { json(res, 403, { error: 'Accès refusé.' }); return; }
    const id   = delMatch[1];
    const data = readCars();
    const idx  = data.cars.findIndex(c => c.id === id);
    if (idx === -1) { json(res, 404, { error: 'Not found' }); return; }
    data.cars.splice(idx, 1);
    writeCars(data);
    json(res, 200, { ok: true });
    return;
  }

  /* ── Static files ── */
  let filePath = urlPath;
  if (filePath === '/') filePath = '/index.html';
  const fullPath    = path.join(ROOT, filePath);
  const ext         = path.extname(fullPath);
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });

}).listen(PORT, () => {
  console.log(`AZF AUTO dev server → http://localhost:${PORT}`);
  console.log(`API cars            → http://localhost:${PORT}/api/cars`);
  console.log(`API auth            → http://localhost:${PORT}/api/auth/`);
  console.log(`Admin panel         → http://localhost:${PORT}/admin.html`);
});
