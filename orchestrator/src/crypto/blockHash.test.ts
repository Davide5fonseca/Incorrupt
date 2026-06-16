// Testes das fórmulas de hash (puros, sem BD).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeHashV4, expectedHashFor } from './blockHash';

const TS = new Date('2024-01-01T00:00:00.000Z');
const GENESIS = '0'.repeat(64);

function v4(prev: string, idx: number, over: Partial<any> = {}): string {
    const b = {
        action: 'EVIDENCE_UPLOAD', actorID: 1, fileHash: 'abc', fileName: 'f.pdf',
        signature: 'NONE', publicKey: 'NONE', timeSource: 'LOCAL', metadata: 'NONE', ...over,
    };
    return computeHashV4(prev, idx, TS, b.action, b.actorID, b.fileHash, b.fileName,
        b.signature, b.publicKey, b.timeSource, b.metadata);
}

test('hash é determinístico (mesma entrada → mesmo hash)', () => {
    assert.equal(v4(GENESIS, 0), v4(GENESIS, 0));
});

test('SHA-256 tem 64 chars hex', () => {
    assert.match(v4(GENESIS, 0), /^[0-9a-f]{64}$/);
});

test('mudar QUALQUER campo muda o hash', () => {
    const base = v4(GENESIS, 0);
    assert.notEqual(base, v4(GENESIS, 1));                          // blockIndex
    assert.notEqual(base, v4('1'.repeat(64), 0));                  // previousHash
    assert.notEqual(base, v4(GENESIS, 0, { action: 'TRANSFER' })); // action
    assert.notEqual(base, v4(GENESIS, 0, { fileHash: 'xyz' }));    // fileHash
    assert.notEqual(base, v4(GENESIS, 0, { metadata: '{"a":1}' }));// metadata (protegido em v4!)
});

test('expectedHashFor reproduz o hash de um bloco v4 íntegro', () => {
    const currentHash = v4(GENESIS, 0);
    const block = {
        schemaVersion: 4, blockIndex: 0, timestamp: TS, action: 'EVIDENCE_UPLOAD',
        actorID: 1, fileHash: 'abc', fileName: 'f.pdf', signature: 'NONE',
        publicKey: 'NONE', timeSource: 'LOCAL', metadata: 'NONE', currentHash,
    };
    assert.equal(expectedHashFor(GENESIS, block), currentHash);
});

test('expectedHashFor deteta adulteração de conteúdo', () => {
    const block = {
        schemaVersion: 4, blockIndex: 0, timestamp: TS, action: 'EVIDENCE_UPLOAD',
        actorID: 1, fileHash: 'abc', fileName: 'f.pdf', signature: 'NONE',
        publicKey: 'NONE', timeSource: 'LOCAL', metadata: 'NONE',
        currentHash: v4(GENESIS, 0),
    };
    block.fileHash = 'HACKED';  // alguém mexeu no registo
    assert.notEqual(expectedHashFor(GENESIS, block), block.currentHash);
});
