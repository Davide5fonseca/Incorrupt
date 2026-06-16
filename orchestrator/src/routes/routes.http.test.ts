// ============================================================
// Testes HTTP das camadas transversais: middleware JWT
// (authenticateToken/requireRole) e validação zod (validateBody).
//
// Ambas correm ANTES de qualquer acesso ao consenso, por isso
// testam-se sem arrancar os nós de auditoria. Só se exercitam os
// caminhos de REJEIÇÃO (401/403/400), que nunca tocam o Mongo.
// ============================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';

process.env.LOCAL_DEV = 'true';

import { createChainRouter } from './chain';
import { createEvidenceRouter } from './evidence';

const SECRET = 'dems_local_dev_secret';          // default usado pelo middleware
const token = jwt.sign({ id: 1, email: 't@t.pt', role: 'Investigador', name: 'T' }, SECRET);
const auth  = `Bearer ${token}`;
const hex64 = 'a'.repeat(64);

function makeApp() {
    const app = express();
    app.use(express.json());
    app.use('/api/v1/chain', createChainRouter());
    app.use('/api/v1/evidence', createEvidenceRouter());
    return app;
}
const app = makeApp();

// ── Middleware JWT ────────────────────────────────────────────
test('rota protegida sem token devolve 401', async () => {
    const res = await request(app).get('/api/v1/chain/blocks');
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'Unauthorized');
});

test('token inválido devolve 403', async () => {
    const res = await request(app).get('/api/v1/chain/blocks')
        .set('Authorization', 'Bearer lixo.invalido.aqui');
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'Forbidden');
});

test('audit-log sem token devolve 401 (antes de qualquer consenso)', async () => {
    const res = await request(app).post('/api/v1/chain/audit-log')
        .send({ fileHash: hex64, fileName: 'a.pdf' });
    assert.equal(res.status, 401);
});

// ── Validação zod ─────────────────────────────────────────────
test('audit-log com body vazio devolve 400 ValidationError', async () => {
    const res = await request(app).post('/api/v1/chain/audit-log')
        .set('Authorization', auth).send({});
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'ValidationError');
});

test('audit-log com fileHash inválido devolve 400 (path fileHash)', async () => {
    const res = await request(app).post('/api/v1/chain/audit-log')
        .set('Authorization', auth).send({ fileHash: 'curto', fileName: 'a.pdf' });
    assert.equal(res.status, 400);
    assert.ok(res.body.issues.some((i: any) => i.path === 'fileHash'));
});

test('audit-log sem fileName devolve 400 (path fileName)', async () => {
    const res = await request(app).post('/api/v1/chain/audit-log')
        .set('Authorization', auth).send({ fileHash: hex64 });
    assert.equal(res.status, 400);
    assert.ok(res.body.issues.some((i: any) => i.path === 'fileName'));
});

test('transfer com toEmail inválido devolve 400', async () => {
    const res = await request(app).post('/api/v1/evidence/transfer')
        .set('Authorization', auth).send({ fileHash: hex64, toEmail: 'nao-email' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'ValidationError');
    assert.ok(res.body.issues.some((i: any) => i.path === 'toEmail'));
});
