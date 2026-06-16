// Testes da identidade dos nós e do quorum certificate (puros, sem BD).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NodeIdentity, countValidSignatures } from './nodeIdentity';

const HASH = 'a'.repeat(64);

test('assinar e verificar (roundtrip)', () => {
    const n = NodeIdentity.ephemeral('audit_node_1');
    const sig = n.sign(HASH);
    assert.equal(NodeIdentity.verify(HASH, sig), true);
});

test('assinatura falha se o hash for adulterado', () => {
    const n = NodeIdentity.ephemeral('audit_node_1');
    const sig = n.sign(HASH);
    assert.equal(NodeIdentity.verify('b'.repeat(64), sig), false);
});

test('assinatura de um nó não vale com a chave de outro', () => {
    const a = NodeIdentity.ephemeral('audit_node_1');
    const b = NodeIdentity.ephemeral('audit_node_2');
    const sig = a.sign(HASH);
    const forged = { ...sig, publicKey: b.publicKeyPem };  // troca a chave pública
    assert.equal(NodeIdentity.verify(HASH, forged), false);
});

test('countValidSignatures: quórum atingido com 3 nós distintos', () => {
    const nodes = [1, 2, 3, 4].map(i => NodeIdentity.ephemeral(`audit_node_${i}`));
    const trusted = new Set(nodes.map(n => n.publicKeyPem));
    const sigs = nodes.slice(0, 3).map(n => n.sign(HASH));
    assert.equal(countValidSignatures(HASH, sigs, trusted), 3);
});

test('countValidSignatures: o mesmo nó não conta duas vezes', () => {
    const n = NodeIdentity.ephemeral('audit_node_1');
    const trusted = new Set([n.publicKeyPem]);
    const sigs = [n.sign(HASH), n.sign(HASH)];  // duplicado
    assert.equal(countValidSignatures(HASH, sigs, trusted), 1);
});

test('countValidSignatures: chave não confiável é ignorada', () => {
    const trustedNode = NodeIdentity.ephemeral('audit_node_1');
    const rogue       = NodeIdentity.ephemeral('rogue');  // não está no conjunto confiável
    const trusted = new Set([trustedNode.publicKeyPem]);
    const sigs = [trustedNode.sign(HASH), rogue.sign(HASH)];
    assert.equal(countValidSignatures(HASH, sigs, trusted), 1);
});
