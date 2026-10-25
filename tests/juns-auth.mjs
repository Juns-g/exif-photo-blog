// Run after pnpm build: node tests/juns-auth.mjs
// Uses only loopback and synthetic credentials.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { decode } from 'next-auth/jwt';

const secret = randomBytes(32).toString('base64url');
const authSecret = randomBytes(32).toString('base64url');
const email = 'synthetic-owner@example.invalid';
const password = randomBytes(32).toString('base64url');
const random = () => randomBytes(32).toString('base64url');
const sha = value => createHash('sha256').update(value).digest('hex');
const flows = new Map();
let origin, deadline, tokenCalls = 0, child;

const listen = server => new Promise(resolve => {
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});
const tokenServer = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://synthetic.invalid');
  if (url.pathname === '/start') {
    const state = random(), code = random();
    flows.set(state, {
      code, binding: url.searchParams.get('binding'),
      path: url.searchParams.get('path'), expires: deadline,
    });
    res.writeHead(303, { Location: origin + '/api/juns-auth/callback?' +
      new URLSearchParams({ state, code }) });
    return res.end();
  }
  assert.equal(url.pathname, '/token');
  assert.equal(req.method, 'POST');
  assert.equal(req.headers.authorization, 'Bearer ' + secret);
  tokenCalls++;
  let text = '';
  for await (const chunk of req) text += chunk;
  const b = JSON.parse(text), flow = flows.get(b.state);
  res.setHeader('Content-Type', 'application/json');
  if (b.client !== 'photos' || !flow || flow.code !== b.code ||
    flow.binding !== sha(b.binding) || flow.expires <= Date.now()) {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: 'synthetic denial' }));
  }
  flows.delete(b.state);
  res.end(JSON.stringify({ ok: true, path: flow.path, expires: flow.expires }));
});
const tokenOrigin = 'http://127.0.0.1:' + await listen(tokenServer);

class Jar extends Map {
  header() { return [...this].map(([k, v]) => `${k}=${v}`).join('; '); }
  read(response) {
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0], i = pair.indexOf('=');
      if (/max-age=0/i.test(cookie)) this.delete(pair.slice(0, i));
      else this.set(pair.slice(0, i), pair.slice(i + 1));
    }
  }
}
async function request(path, jar = new Jar(), options = {}) {
  const response = await fetch(new URL(path, origin), {
    ...options, redirect: 'manual',
    headers: { Cookie: jar.header(), ...options.headers },
    signal: AbortSignal.timeout(30_000),
  });
  jar.read(response);
  return response;
}
async function stop() {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.kill('SIGTERM');
  await exited;
}
async function start(enabled) {
  const probe = createServer(), port = await listen(probe);
  await new Promise(resolve => probe.close(resolve));
  // Next normalizes loopback request URLs to localhost.
  origin = 'http://localhost:' + port;
  child = spawn(process.execPath, ['node_modules/next/dist/bin/next',
    'start', '--hostname', '127.0.0.1',
    '--port', String(port)], {
    stdio: ['ignore', 'inherit', 'inherit'],
    env: {
      ...process.env, ADMIN_EMAIL: email, ADMIN_PASSWORD: password,
      AUTH_SECRET: authSecret, AUTH_TRUST_HOST: 'true', AUTH_URL: origin,
      JUNS_AUTH_ORIGIN: tokenOrigin,
      JUNS_AUTH_CLIENT_SECRET: enabled ? secret : '',
      NEXT_TELEMETRY_DISABLED: '1',
      POSTGRES_URL: 'postgres://synthetic:synthetic@127.0.0.1:1/synthetic',
      DISABLE_POSTGRES_SSL: '1',
      // Prevent implicit external proxy use for this loopback-only fixture.
      NO_PROXY: '127.0.0.1,localhost',
    },
  });
  for (let i = 0; i < 90; i++) {
    if (child.exitCode !== null) throw new Error('Next server exited');
    try {
      if ((await request('/api/auth/session')).status === 200) return;
    } catch { /* Wait for the actual listener. */ }
    await delay(1000);
  }
  throw new Error('Next server readiness timeout');
}
async function ticket(jar, callbackUrl = '/admin/photos') {
  const response = await request('/api/juns-auth/start?' +
    new URLSearchParams({ callbackUrl }), jar);
  assert.equal(response.status, 303);
  const cookie = response.headers.getSetCookie().find(c =>
    c.startsWith('__Host-juns-auth-binding='));
  for (const flag of ['HttpOnly', 'Secure', 'SameSite=lax',
    'Max-Age=300', 'Path=/']) assert(cookie.toLowerCase().includes(
    flag.toLowerCase()), flag);
  assert(!cookie.toLowerCase().includes('domain='));
  const url = new URL(response.headers.get('Location'));
  assert.equal(url.origin, tokenOrigin);
  assert.equal(url.pathname, '/start');
  assert.equal(url.searchParams.get('client'), 'photos');
  assert.equal(url.searchParams.get('binding'),
    sha(jar.get('__Host-juns-auth-binding')));
  const r = await fetch(url, { redirect: 'manual' });
  return r.headers.get('Location');
}
async function session(jar) {
  return (await (await request('/api/auth/session', jar)).json()) || {};
}
async function passwordLogin() {
  const jar = new Jar();
  const { csrfToken } = await (await request('/api/auth/csrf', jar)).json();
  await request('/api/auth/callback/credentials', jar, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ csrfToken, email, password,
      callbackUrl: origin + '/admin/photos' }),
  });
  assert.equal((await session(jar)).user.email, email);
  return jar;
}
try {
  await start(false);
  assert(!(await (await request('/sign-in')).text()).includes('Passkey 登录'));
  assert.equal((await request('/api/juns-auth/start')).status, 503);
  await passwordLogin();
  console.log('PASS no secret: button hidden, start closed, ' +
    'password login works');
  await stop();

  await start(true);
  const signInPage = await request('/sign-in?callbackUrl=/admin/photos');
  assert((await signInPage.text()).includes('Passkey 登录'));
  assert.equal((await request('/admin/photos')).status, 307);
  deadline = Date.now() + 12 * 60 * 60 * 1000;
  for (const input of ['https://evil.invalid/admin', '/admin/../outside',
    '//evil.invalid/admin', '/admin/%5cevil', '/admin/%252e%252e/outside']) {
    const location = await ticket(new Jar(), input);
    const state = new URL(location).searchParams.get('state');
    assert.equal(flows.get(state).path, '/admin/photos');
  }
  const good = new Jar();
  const callback = await ticket(good, origin + '/admin/photos?sort=oldest');
  const result = await request(callback, good);
  assert.equal(result.status, 303);
  assert.equal(result.headers.get('Location'),
    origin + '/admin/photos?sort=oldest');
  assert(!good.has('__Host-juns-auth-binding'));
  const s = await session(good);
  assert.equal(s.user.email, email);
  assert.equal(Date.parse(s.expires), deadline);
  const jwt = await decode({ token: good.get('authjs.session-token'),
    secret: authSecret, salt: 'authjs.session-token' });
  assert(jwt.exp * 1000 <= deadline);
  const admin = await request('/admin/photos', good);
  assert(!admin.headers.get('Location')?.includes('/sign-in'));
  assert.equal((await request(callback, new Jar())).status, 400);
  console.log('PASS start cookie/hash/redirect/path normalization; ' +
    'bounded admin session passes admin protection; replay denied');

  const wrong = new Jar(), wrongCallback = await ticket(wrong);
  const savedBinding = wrong.get('__Host-juns-auth-binding');
  wrong.set('__Host-juns-auth-binding', random());
  assert.equal((await request(wrongCallback, wrong)).status, 400);
  assert(!(await session(wrong)).user);
  const failed = new Jar(), failedCallback = new URL(await ticket(failed));
  failedCallback.searchParams.set('code', random());
  assert.equal((await request(failedCallback, failed)).status, 400);
  assert(!(await session(failed)).user);
  const direct = new Jar();
  direct.set('__Host-juns-auth-binding', savedBinding);
  const { csrfToken } = await (await request('/api/auth/csrf', direct)).json();
  const callsBefore = tokenCalls;
  await request('/api/auth/callback/juns-passkey', direct, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ csrfToken, email, junsAuthExpires:
      String(deadline), ...Object.fromEntries(new URL(wrongCallback)
      .searchParams) }),
  });
  assert.equal(tokenCalls, callsBefore);
  assert(!(await session(direct)).user);
  console.log('PASS wrong binding/failed exchange never creates session; ' +
    'direct POST with valid ticket cannot invoke private provider');

  deadline = Date.now() + 6000;
  const short = new Jar();
  assert.equal((await request(await ticket(short), short)).status, 303);
  assert.equal((await session(short)).user.email, email);
  // Repeated reads must not slide the upstream deadline.
  assert.equal(Date.parse((await session(short)).expires), deadline);
  await delay(Math.max(0, deadline - Date.now() + 100));
  assert(!(await session(short)).user);
  assert.equal((await request('/admin/photos', short)).status, 307);
  const backup = await passwordLogin();
  assert(Date.parse((await session(backup)).expires) >
    Date.now() + 20 * 24 * 60 * 60 * 1000);
  console.log('PASS SSO expires at upstream deadline despite refresh; ' +
    'password session keeps original lifetime');
} finally {
  await stop();
  await new Promise(resolve => tokenServer.close(resolve));
}
