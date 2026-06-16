// ============================================================
// Testes HTTP das rotas de autenticação (supertest).
// Usa um Pool PostgreSQL FALSO (em memória) para ser
// determinístico — testa o caminho de produção (SQL) sem DB
// real nem tocar no .db/users.json.
// ============================================================
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import bcrypt from 'bcrypt';

process.env.LOCAL_DEV = 'true';   // ignora os rate limiters nos testes

import { createAuthRouter } from './auth';

// ── Pool falso: dispatch por SQL ──────────────────────────────
let users: any[] = [];
const fakePool: any = {
    query: async (sql: string, params: any[]) => {
        if (sql.includes('INSERT INTO Users')) {
            const [name, email, password_hash, role] = params;
            const u = { id: users.length + 1, name, email, password_hash, role };
            users.push(u);
            return { rows: [{ id: u.id, name: u.name, email: u.email, role: u.role }] };
        }
        if (sql.includes('password_hash')) {                 // login
            const u = users.find(x => x.email === params[0]);
            return { rows: u ? [u] : [] };
        }
        if (sql.includes('SELECT id FROM Users')) {          // existe?
            const u = users.find(x => x.email === params[0]);
            return { rows: u ? [{ id: u.id }] : [] };
        }
        return { rows: [] };
    },
};

function makeApp() {
    const app = express();
    app.use(express.json());
    app.use('/api/v1/auth', createAuthRouter(fakePool));
    return app;
}

const app = makeApp();
const PWD = 'senha_super_segura';

before(async () => {
    users = [{
        id: 1, name: 'Investigador Silva', email: 'silva@policia.pt',
        password_hash: await bcrypt.hash(PWD, 10), role: 'Investigador',
    }];
});

// ── Login ─────────────────────────────────────────────────────
test('login válido devolve 200 + token', async () => {
    const res = await request(app).post('/api/v1/auth/login')
        .send({ email: 'silva@policia.pt', password: PWD });
    assert.equal(res.status, 200);
    assert.ok(res.body.token, 'devia devolver um token');
    assert.equal(res.body.user.role, 'Investigador');
});

test('login com password errada devolve 401', async () => {
    const res = await request(app).post('/api/v1/auth/login')
        .send({ email: 'silva@policia.pt', password: 'errada' });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'InvalidCredentials');
});

test('login sem campos devolve 400', async () => {
    const res = await request(app).post('/api/v1/auth/login').send({ email: 'x@y.pt' });
    assert.equal(res.status, 400);
});

test('login de email inexistente devolve 401 (não revela qual falhou)', async () => {
    const res = await request(app).post('/api/v1/auth/login')
        .send({ email: 'naoexiste@x.pt', password: PWD });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'InvalidCredentials');
});

// ── Registo ───────────────────────────────────────────────────
test('registo válido devolve 201 + token', async () => {
    const res = await request(app).post('/api/v1/auth/register')
        .send({ name: 'Perito Costa', email: 'costa@policia.pt', password: 'password123', role: 'Perito' });
    assert.equal(res.status, 201);
    assert.ok(res.body.token);
    assert.equal(res.body.user.email, 'costa@policia.pt');
});

test('registo com password fraca (<8) devolve 400', async () => {
    const res = await request(app).post('/api/v1/auth/register')
        .send({ name: 'X', email: 'fraca@x.pt', password: 'curta' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'WeakPassword');
});

test('registo com email inválido devolve 400', async () => {
    const res = await request(app).post('/api/v1/auth/register')
        .send({ name: 'X', email: 'nao-email', password: 'password123' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'InvalidEmail');
});

test('registo com role inválido devolve 400', async () => {
    const res = await request(app).post('/api/v1/auth/register')
        .send({ name: 'X', email: 'role@x.pt', password: 'password123', role: 'Hacker' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'InvalidRole');
});

test('registo de email já existente devolve 409', async () => {
    const res = await request(app).post('/api/v1/auth/register')
        .send({ name: 'Dup', email: 'silva@policia.pt', password: 'password123', role: 'Perito' });
    assert.equal(res.status, 409);
    assert.equal(res.body.error, 'EmailAlreadyExists');
});
