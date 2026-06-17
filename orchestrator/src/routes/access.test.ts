// Testes do controlo de acesso à cadeia (visibilidade de blocos).
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.LOCAL_DEV = 'true';

import { visibleBlocksFor } from './chain';

const u = (email: string, role: string) => ({ id: 1, email, role, name: email });

// Blocos de exemplo:
//  #0 upload de h1 por silva
//  #1 upload de h2 por costa
//  #2 transferência de h2: costa → silva
//  #3 upload de h3 por ferreira (não relacionado com silva/costa)
const blocks = [
  { blockIndex: 0, action: 'EVIDENCE_UPLOAD',  actorEmail: 'silva@p.pt',    fileHash: 'h1', metadata: 'NONE' },
  { blockIndex: 1, action: 'EVIDENCE_UPLOAD',  actorEmail: 'costa@p.pt',    fileHash: 'h2', metadata: 'NONE' },
  { blockIndex: 2, action: 'CUSTODY_TRANSFER', actorEmail: 'costa@p.pt',    fileHash: 'h2', metadata: JSON.stringify({ from: 'costa@p.pt', to: 'silva@p.pt' }) },
  { blockIndex: 3, action: 'EVIDENCE_UPLOAD',  actorEmail: 'ferreira@t.pt', fileHash: 'h3', metadata: 'NONE' },
] as any[];

const idx = (bs: any[]) => bs.map(b => b.blockIndex).sort((a, b) => a - b);

test('Juiz (supervisão) vê todos os blocos', () => {
  assert.deepEqual(idx(visibleBlocksFor(blocks, u('juiz@t.pt', 'Juiz'))), [0, 1, 2, 3]);
});

test('Admin vê todos os blocos', () => {
  assert.deepEqual(idx(visibleBlocksFor(blocks, u('admin@p.pt', 'Admin'))), [0, 1, 2, 3]);
});

test('Investigador vê os seus + os do ficheiro em que está envolvido (não os alheios)', () => {
  // silva: autor de h1 (#0); destinatário da transferência de h2 (#1, #2). NÃO vê h3 (#3).
  assert.deepEqual(idx(visibleBlocksFor(blocks, u('silva@p.pt', 'Investigador'))), [0, 1, 2]);
});

test('Outro investigador só vê o ficheiro que tocou', () => {
  // costa: autor de h2 e remetente da transferência → vê #1, #2. Não vê h1 (#0) nem h3 (#3).
  assert.deepEqual(idx(visibleBlocksFor(blocks, u('costa@p.pt', 'Investigador'))), [1, 2]);
});

test('Utilizador sem relação não vê nada', () => {
  assert.deepEqual(idx(visibleBlocksFor(blocks, u('estranho@x.pt', 'Utilizador'))), []);
});
