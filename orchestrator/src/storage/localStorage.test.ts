// Testes do armazenamento local cifrado.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { LocalStorageProvider } from './LocalStorageProvider';

process.env.ENCRYPTION_KEY = 'a'.repeat(64); // chave hex válida para o teste

function tmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'dems-store-'));
}
function hashOf(b: Buffer) {
    return crypto.createHash('sha256').update(b).digest('hex');
}

test('guardar e recuperar devolve os bytes originais', async () => {
    const store = new LocalStorageProvider(tmpDir());
    const data = Buffer.from('prova forense confidencial');
    const h = hashOf(data);
    await store.put(h, data);
    const got = await store.get(h);
    assert.deepEqual(got, data);
});

test('o ficheiro é guardado CIFRADO (não em claro)', async () => {
    const dir = tmpDir();
    const store = new LocalStorageProvider(dir);
    const data = Buffer.from('texto secreto em claro');
    const h = hashOf(data);
    await store.put(h, data);
    const onDisk = fs.readFileSync(path.join(dir, `${h}.enc`));
    assert.ok(!onDisk.includes('texto secreto'), 'o conteúdo em disco não devia estar em claro');
});

test('put rejeita se o hash não corresponder aos bytes', async () => {
    const store = new LocalStorageProvider(tmpDir());
    await assert.rejects(() => store.put('b'.repeat(64), Buffer.from('xyz')));
});

test('has reflete a presença do ficheiro', async () => {
    const store = new LocalStorageProvider(tmpDir());
    const data = Buffer.from('abc');
    const h = hashOf(data);
    assert.equal(await store.has(h), false);
    await store.put(h, data);
    assert.equal(await store.has(h), true);
});

test('get deteta corrupção do ficheiro em disco', async () => {
    const dir = tmpDir();
    const store = new LocalStorageProvider(dir);
    const data = Buffer.from('conteudo integro');
    const h = hashOf(data);
    await store.put(h, data);
    // Corrompe o ficheiro cifrado.
    fs.writeFileSync(path.join(dir, `${h}.enc`), Buffer.concat([Buffer.alloc(16), Buffer.from('lixo')]));
    await assert.rejects(() => store.get(h));
});
