const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = __dirname;
const DATA_DIR = path.resolve(process.env.AUTH_DATA_DIR || path.join(__dirname, 'data'));
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;
// 게시 권한 계정은 서버에서만 설정합니다. 비밀번호는 단방향 해시만 저장합니다.
const CREATOR_ACCOUNT = 'everymonkey18';
const CREATOR_PASSWORD_SALT = '7fad3d6f2da083a2d62386d47b19e75c';
const CREATOR_PASSWORD_HASH = 'cc21db1e73f2955f0f8f4d7cd3a255ab5f64da7a983afc607ab5c3d4df88148aae5878b8f25e7129b966c0141ead18c23f953b38dfd1d622c39fe871d13e513a';

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'users.db'));
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) STRICT;
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) STRICT;
`);

function findUser(email) {
    return db.prepare('SELECT id, email, password_hash, password_salt FROM users WHERE email = ?').get(email);
}

function createUser(email, passwordHash, passwordSalt) {
    return db.prepare('INSERT INTO users (email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)')
        .run(email, passwordHash, passwordSalt, new Date().toISOString());
}

function createSession(id, userId, expiresAt) {
    db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(id, userId, expiresAt);
}

function findSession(id) {
    return db.prepare(`
        SELECT users.id AS user_id, users.email
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ? AND sessions.expires_at > ?
    `).get(id, new Date().toISOString());
}

function removeSession(id) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

function removeExpiredSessions() {
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
}

function createPost(userId, title, content) {
    return db.prepare('INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)')
        .run(userId, title, content, new Date().toISOString());
}

function listPosts() {
    return db.prepare(`
        SELECT posts.id, posts.title, posts.content, posts.created_at, users.email AS author
        FROM posts JOIN users ON users.id = posts.user_id
        ORDER BY posts.id DESC
    `).all();
}

function sendJson(response, statusCode, body) {
    response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify(body));
}

function parseCookies(request) {
    return Object.fromEntries((request.headers.cookie || '').split(';').flatMap((part) => {
        const index = part.indexOf('=');
        if (index < 0) return [];
        return [[part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())]];
    }));
}

function getSession(request) {
    const sessionId = parseCookies(request).sessionId;
    if (!sessionId || !/^[a-f0-9]{64}$/.test(sessionId)) return null;
    return findSession(sessionId) || null;
}

function setSession(response, userId) {
    const id = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_SECONDS * 1000).toISOString();
    createSession(id, userId, expiresAt);
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    response.setHeader('Set-Cookie', `sessionId=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}${secure}`);
}

function clearSession(response) {
    response.setHeader('Set-Cookie', 'sessionId=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let data = '';
        request.on('data', (chunk) => {
            data += chunk;
            if (data.length > 10_000) {
                reject(new Error('요청 내용이 너무 큽니다.'));
                request.destroy();
            }
        });
        request.on('end', () => {
            try {
                resolve(JSON.parse(data || '{}'));
            } catch {
                reject(new Error('잘못된 요청 형식입니다.'));
            }
        });
        request.on('error', reject);
    });
}

function validCredentials(email, password) {
    const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail);
    const validAccountId = /^[\p{L}\p{N}_.-]{2,30}$/u.test(normalizedEmail);
    if (!validEmail && !validAccountId) {
        return { error: '아이디는 한글·영문·숫자·._-만 사용해 2~30자로 입력해 주세요.' };
    }
    if (typeof password !== 'string' || password.length < 8) {
        return { error: '비밀번호는 8자 이상이어야 합니다.' };
    }
    if (password.length > 200) return { error: '비밀번호가 너무 깁니다.' };
    return { email: normalizedEmail, password };
}

function validPost(title, content) {
    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    const cleanContent = typeof content === 'string' ? content.trim() : '';
    if (!cleanTitle || !cleanContent) return { error: '제목과 내용을 모두 입력해 주세요.' };
    if (cleanTitle.length > 100) return { error: '제목은 100자 이하로 입력해 주세요.' };
    if (cleanContent.length > 2_000) return { error: '내용은 2,000자 이하로 입력해 주세요.' };
    return { title: cleanTitle, content: cleanContent };
}

function canCreatePosts(accountId) {
    return accountId === CREATOR_ACCOUNT;
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function ensureCreatorAccount() {
    if (!findUser(CREATOR_ACCOUNT)) {
        createUser(CREATOR_ACCOUNT, CREATOR_PASSWORD_HASH, CREATOR_PASSWORD_SALT);
    }
}

ensureCreatorAccount();

function serveStatic(response, pathname) {
    const requested = pathname === '/' ? '/index.html' : pathname;
    const filePath = path.resolve(PUBLIC_DIR, `.${requested}`);
    const relativePath = path.relative(PUBLIC_DIR, filePath);
    const firstPart = relativePath.split(path.sep)[0];
    const isPrivateFile = relativePath === 'server.js' || relativePath === 'package.json' || firstPart === 'data';

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath) || isPrivateFile || !fs.statSync(filePath, { throwIfNoEntry: false })?.isFile()) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('페이지를 찾을 수 없습니다.');
        return;
    }

    const extension = path.extname(filePath).toLowerCase();
    const contentType = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.webp': 'image/webp'
    }[extension] || 'application/octet-stream';
    response.writeHead(200, { 'Content-Type': contentType, 'X-Content-Type-Options': 'nosniff' });
    fs.createReadStream(filePath).pipe(response);
}

const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    const pathname = decodeURIComponent(url.pathname);

    try {
        removeExpiredSessions();
        if (request.method === 'POST' && (pathname === '/api/signup' || pathname === '/api/login')) {
            const body = await readJson(request);
            const { email, password, error } = validCredentials(body.email, body.password);
            if (error) return sendJson(response, 400, { message: error });

            const user = findUser(email);
            if (pathname === '/api/signup') {
                if (user) return sendJson(response, 409, { message: '이미 가입된 계정입니다.' });
                const salt = crypto.randomBytes(16).toString('hex');
                const result = createUser(email, hashPassword(password, salt), salt);
                setSession(response, Number(result.lastInsertRowid));
                return sendJson(response, 201, { email });
            }

            if (!user) return sendJson(response, 401, { message: '아이디(이메일) 또는 비밀번호가 올바르지 않습니다.' });
            const savedHash = Buffer.from(user.password_hash, 'hex');
            const passwordHash = Buffer.from(hashPassword(password, user.password_salt), 'hex');
            if (savedHash.length !== passwordHash.length || !crypto.timingSafeEqual(savedHash, passwordHash)) {
                return sendJson(response, 401, { message: '아이디(이메일) 또는 비밀번호가 올바르지 않습니다.' });
            }
            setSession(response, user.id);
            return sendJson(response, 200, { email: user.email });
        }

        if (request.method === 'GET' && pathname === '/api/me') {
            const session = getSession(request);
            if (!session) return sendJson(response, 401, { message: '로그인이 필요합니다.' });
            return sendJson(response, 200, { email: session.email, canPost: canCreatePosts(session.email) });
        }

        if (request.method === 'GET' && pathname === '/api/posts') {
            if (!getSession(request)) return sendJson(response, 401, { message: '로그인이 필요합니다.' });
            return sendJson(response, 200, { posts: listPosts() });
        }

        if (request.method === 'POST' && pathname === '/api/posts') {
            const session = getSession(request);
            if (!session) return sendJson(response, 401, { message: '로그인이 필요합니다.' });
            if (!canCreatePosts(session.email)) {
                return sendJson(response, 403, { message: '게시 권한이 있는 계정만 게시물을 올릴 수 있습니다.' });
            }

            const body = await readJson(request);
            const { title, content, error } = validPost(body.title, body.content);
            if (error) return sendJson(response, 400, { message: error });
            const result = createPost(session.user_id, title, content);
            return sendJson(response, 201, { id: Number(result.lastInsertRowid), title, content, author: session.email });
        }

        if (request.method === 'POST' && pathname === '/api/logout') {
            const sessionId = parseCookies(request).sessionId;
            if (sessionId) removeSession(sessionId);
            clearSession(response);
            return sendJson(response, 200, { message: '로그아웃했습니다.' });
        }

        if (request.method === 'GET' && pathname === '/welcome.html' && !getSession(request)) {
            response.writeHead(302, { Location: '/login.html' });
            response.end();
            return;
        }

        if (request.method === 'GET') return serveStatic(response, pathname);
        sendJson(response, 405, { message: '허용되지 않은 요청입니다.' });
    } catch (error) {
        console.error(error);
        sendJson(response, 500, { message: '서버 오류가 발생했습니다.' });
    }
});

server.listen(PORT, () => {
    console.log(`서버 실행 중: http://localhost:${PORT}`);
});
