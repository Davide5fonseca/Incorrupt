// ============================================================
// Teste de integração do núcleo BFT — arranca os 4 nós a sério
// (mongodb-memory-server). Mais lento: na 1.ª vez descarrega o
// binário do Mongo. Corre com:  npm run test:integration
//
// NOTA: os testes partilham um único ConsensusManager e correm
// por ordem. Os que adulteram dados ficam para o FIM, porque
// deixam a cadeia propositadamente inconsistente.
// ============================================================
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

process.env.LOCAL_DEV = 'true';

import { consensusManager, ConsensusError } from './consensusManager';
import { countValidSignatures } from '../crypto/nodeIdentity';

const mgr = consensusManager as any;

function entry(name: string, hash: string) {
    return {
        action: 'EVIDENCE_UPLOAD', actorID: 1, actorEmail: 't@t.pt', actorRole: 'Investigador',
        fileCID: 'CID', fileName: name, driveFileId: 'OFFLINE', fileHash: hash, fileSize: 10,
    };
}

before(async () => { await consensusManager.initialise(); });
after(async () => { await consensusManager.shutdown(); });

test('commit gera bloco com quorum certificate válido (>=3 nós)', async () => {
    const r = await consensusManager.broadcastAndCommit(entry('a.pdf', 'hash_a'));
    assert.equal(r.success, true);
    assert.ok(r.consensusCount >= 3, `esperava >=3 assinaturas, obteve ${r.consensusCount}`);
    // As assinaturas certificam mesmo o hash do bloco:
    const trusted = new Set<string>(mgr.identities.map((i: any) => i.publicKeyPem as string));
    assert.ok(countValidSignatures(r.currentHash, r.nodeSignatures, trusted) >= 3);
});

test('a cadeia encadeia e mantém-se íntegra', async () => {
    await consensusManager.broadcastAndCommit(entry('b.pdf', 'hash_b'));
    const integrity = await consensusManager.verifyChainIntegrity(0);
    assert.equal(integrity.valid, true);
    assert.ok(integrity.certifiedBlocks >= 2);
});

test('commits concorrentes não colidem no mesmo blockIndex (mutex)', async () => {
    // Dispara 5 uploads ao mesmo tempo — o mutex serializa-os.
    await Promise.all([0, 1, 2, 3, 4].map(i =>
        consensusManager.broadcastAndCommit(entry(`p${i}.pdf`, `hash_p${i}`)),
    ));
    const blocks = await consensusManager.getBlocks(0, 100);
    const indices = blocks.map(b => b.blockIndex).sort((a, b) => a - b);
    // Índices únicos e sem buracos (0..N).
    assert.equal(new Set(indices).size, indices.length, 'há blockIndex duplicado');
    assert.equal(indices[indices.length - 1], indices.length - 1, 'há buracos na sequência');
    const integrity = await consensusManager.verifyChainIntegrity(0);
    assert.equal(integrity.valid, true);
});

test('os 4 nós estão consistentes entre si', async () => {
    const report = await consensusManager.verifyAcrossNodes();
    assert.equal(report.consistent, true);
    assert.equal(report.divergentNodes.length, 0);
});

test('um nó offline durante commits ressincroniza-se ao voltar (anti-entropy)', async () => {
    // Abate o nó 2 (índice 1). Sobram 3 nós saudáveis = quórum exacto.
    await consensusManager.killNode(1);

    // Commits enquanto o nó 2 está offline → fica atrasado em 2 blocos.
    await consensusManager.broadcastAndCommit(entry('r1.pdf', 'hash_r1'));
    await consensusManager.broadcastAndCommit(entry('r2.pdf', 'hash_r2'));

    // Revive → o catch-up automático copia os blocos em falta.
    await consensusManager.reviveNode(1);

    // O nó voltou alinhado com a cadeia canónica.
    const report = await consensusManager.verifyAcrossNodes();
    assert.equal(report.consistent, true, 'o nó revivido devia estar consistente com a maioria');

    const integTarget = await consensusManager.verifyChainIntegrity(1);
    const integRef    = await consensusManager.verifyChainIntegrity(0);
    assert.equal(integTarget.valid, true);
    assert.equal(integTarget.totalBlocks, integRef.totalBlocks, 'o nó revivido devia ter todos os blocos');
});

// ── A partir daqui adultera-se a cadeia de propósito ──────────

test('verifyAcrossNodes deteta o nó cujo hash diverge da maioria', async () => {
    // Nó malicioso reescreve o hash do seu bloco de topo. Os outros 3 discordam.
    const tip = await mgr.models[0].findOne().sort({ blockIndex: -1 }).exec();
    await mgr.models[0].updateOne({ _id: tip._id }, { $set: { currentHash: 'f'.repeat(64) } });

    const report = await consensusManager.verifyAcrossNodes();
    assert.equal(report.consistent, false);
    assert.deepEqual(report.divergentNodes, ['audit_node_1']);
});

test('integridade local apanha conteúdo↔hash inconsistente', async () => {
    // O bloco de topo do nó 0 já tem o hash adulterado pelo teste anterior:
    // o hash recalculado a partir do conteúdo não bate certo.
    const local = await consensusManager.verifyChainIntegrity(0);
    assert.equal(local.valid, false);
    assert.equal(local.reason, 'HASH_MISMATCH');
});

test('sem quórum o commit falha e nada é confirmado', async () => {
    // Abate 2 nós → só 2 saudáveis < quórum 3.
    await consensusManager.killNode(2);
    await consensusManager.killNode(3);
    await assert.rejects(
        () => consensusManager.broadcastAndCommit(entry('c.pdf', 'hash_c')),
        (e: any) => e instanceof ConsensusError,
    );
    await consensusManager.reviveNode(2);
    await consensusManager.reviveNode(3);
});
