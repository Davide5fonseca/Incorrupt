// ============================================================
// DEMS – Evidence Upload Route
// REQ-02: BFT Consensus fan-out
// REQ-03: Hash chain entry creation
// REQ-05: IPFS/Pinata upload
// REQ-06: AES-256 + Google Drive backup (IV preserved)
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import axios from 'axios';
import FormData from 'form-data';
import crypto from 'crypto';
import stream from 'stream';
import { google } from 'googleapis';
import fs from 'fs';
import path from 'path';
import exifr from 'exifr';
import { z } from 'zod';
import { authenticateToken } from '../middleware/auth';
import { validateBody, sha256Hex } from '../middleware/validate';
import { consensusManager } from '../services/consensusManager';
import { demsEvents } from '../server';
import { localStorage } from '../storage/LocalStorageProvider';
import { encryptBuffer } from '../crypto/fileCipher';

const transferSchema = z.object({
    fileHash:  sha256Hex,
    toEmail:   z.email('email de destino inválido'),
    publicKey: z.string().optional(),
    signature: z.string().optional(),
});

// ── Google Drive setup (optional — fail gracefully) ───────────
let drive: ReturnType<typeof google.drive> | null = null;
const KEY_FILE = path.resolve('./google-key.json');
if (fs.existsSync(KEY_FILE)) {
    try {
        const auth = new google.auth.GoogleAuth({
            keyFile: KEY_FILE,
            scopes: ['https://www.googleapis.com/auth/drive'],
        });
        drive = google.drive({ version: 'v3', auth });
        console.log('[OK] [Drive] Google Drive integration active.');
    } catch (e) {
        console.warn('[AVISO] [Drive] Failed to initialise Google Drive. Backup will be skipped.');
    }
} else {
    console.warn('[AVISO] [Drive] google-key.json not found. Drive backup disabled.');
}

// ── Multer (in-memory storage) ────────────────────────────────
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB (alinhado com /analyse)
});

export function createEvidenceRouter(): Router {
    const router = Router();

    // ── POST /api/v1/evidence/upload ─────────────────────────
    // Auth required: qualquer utilizador autenticado (sem restrição de role)
    router.post(
        '/upload',
        authenticateToken,
        upload.single('evidence_file'),
        async (req: Request, res: Response) => {
            if (!req.file) {
                return res.status(400).json({ error: 'MissingFile', message: 'evidence_file field is required.' });
            }

            const fileBuffer   = req.file.buffer;
            const originalName = req.file.originalname;

            // authenticateToken garante que req.user existe sempre aqui.
            const actor = req.user!;

            const trackingId   = `trk_${Date.now()}_${actor.id}`;

            // ── SHA-256 do ficheiro (prova de conteúdo, vai para o bloco) ──
            const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            const fileSize = fileBuffer.length;

            // ── Armazenamento OBRIGATÓRIO (1.ª classe) ────────────
            // Guarda a prova cifrada ANTES de confirmar. Se isto falha,
            // o upload falha — não adianta registar na cadeia uma prova
            // que depois não se consegue recuperar.
            try {
                await localStorage.put(fileHash, fileBuffer);
            } catch (storeErr: any) {
                console.error(`[ERRO] [Storage] Falha ao guardar ${fileHash}: ${storeErr.message}`);
                return res.status(500).json({
                    error:   'StorageFailed',
                    message: 'Não foi possível guardar a prova. O registo foi abortado.',
                });
            }

            // Prova guardada → responde com o recibo. O commit na cadeia
            // segue em background (notificado via SSE).
            res.status(202).json({
                status:      'PROCESSING',
                message:     'Prova guardada e validada (SHA-256). A registar na cadeia...',
                tracking_id: trackingId,
                fileHash,
                fileSize,
                storageRef:  `local:${fileHash}`,
                actor: { id: actor.id, email: actor.email, role: actor.role },
            });

            // ── Background processing ─────────────────────────
            setImmediate(async () => {
                try {
                    console.log(`[DEMS] Processing: ${originalName} — Actor: ${actor.email}`);

                    demsEvents.emit('event', 'upload_started', {
                        fileName:  originalName,
                        fileSize,
                        actor:     actor.email,
                        trackingId,
                        ts:        new Date().toISOString(),
                    });

                    // ── Extração de EXIF ──────────────────────────────
                    let metadataStr = 'NONE';
                    try {
                        const parsedExif = await exifr.parse(fileBuffer);
                        if (parsedExif) {
                            const relevantData = {
                                Make: parsedExif.Make,
                                Model: parsedExif.Model,
                                DateTimeOriginal: parsedExif.DateTimeOriginal,
                                latitude: parsedExif.latitude,
                                longitude: parsedExif.longitude
                            };
                            // Filtra valores nulos/indefinidos
                            const cleanData = Object.fromEntries(
                                Object.entries(relevantData).filter(([_, v]) => v != null)
                            );
                            if (Object.keys(cleanData).length > 0) {
                                metadataStr = JSON.stringify(cleanData);
                            }
                        }
                    } catch (exifErr) {
                        console.warn('[EXIF] Não foi possível extrair metadados EXIF deste ficheiro.');
                    }

                    // ── 1. BFT Consensus Commit (BLOCKCHAIN FIRST) ─────
                    // O commit na blockchain acontece SEMPRE, independentemente
                    // do IPFS ou Drive. O fileHash é a prova de imutabilidade.
                    const result = await consensusManager.broadcastAndCommit({
                        action:     'EVIDENCE_UPLOAD',
                        actorID:    actor.id,
                        actorEmail: actor.email,
                        actorRole:  actor.role,
                        fileCID:    'CID_PENDING',   // actualizado depois do IPFS
                        fileName:   originalName,
                        driveFileId: 'OFFLINE',
                        fileHash,   // SHA-256 do ficheiro — garante imutabilidade
                        fileSize,
                        publicKey:  req.body.publicKey || 'NONE',
                        signature:  req.body.signature || 'NONE',
                        metadata:   metadataStr
                    });

                    console.log(
                        `[BLOCKCHAIN] Block #${result.blockIndex} committed` +
                        ` | hash: ${result.currentHash.substring(0, 16)}...` +
                        ` | consensus: ${result.consensusCount}/3`
                    );

                    demsEvents.emit('event', 'block_added', {
                        blockIndex:    result.blockIndex,
                        fileName:      originalName,
                        fileHash:      fileHash.substring(0, 16) + '...',
                        blockHash:     result.currentHash.substring(0, 16) + '...',
                        actor:         actor.email,
                        consensusCount: result.consensusCount,
                        ts:            new Date().toISOString(),
                    });

                    // ── 2. IPFS (Pinata) — opcional, não bloqueia a chain ──
                    let fileCID = 'CID_OFFLINE';
                    try {
                        const pinataToken = (process.env.IPFS_PINATA_KEY || '').replace(/\s+/g, '').trim();
                        const formData    = new FormData();
                        formData.append('file', fileBuffer, originalName);
                        formData.append('pinataMetadata', JSON.stringify({
                            name:     originalName,
                            keyvalues: { actorID: String(actor.id), actorEmail: actor.email, trackingId },
                        }));
                        const pinataRes = await axios.post(
                            'https://api.pinata.cloud/pinning/pinFileToIPFS',
                            formData,
                            { headers: { ...formData.getHeaders(), Authorization: `Bearer ${pinataToken}` } }
                        );
                        fileCID = pinataRes.data.IpfsHash;
                        console.log(`[OK] [IPFS] CID: ${fileCID}`);
                    } catch (ipfsErr: any) {
                        console.warn(`[AVISO] [IPFS] Upload falhou (não fatal): ${ipfsErr.message}`);
                    }

                    // ── 3. AES-256 + Google Drive — backup opcional ───────
                    try {
                        const encryptedBuffer = encryptBuffer(fileBuffer);
                        console.log(`[AES-256] Encrypted (${encryptedBuffer.length} bytes).`);

                        if (drive) {
                            const bodyStream = new stream.PassThrough();
                            bodyStream.end(encryptedBuffer);
                            const driveRes = await drive.files.create({
                                requestBody: {
                                    name:    `${originalName}.enc`,
                                    parents: [process.env.GOOGLE_DRIVER_FOLDER_ID || ''],
                                    description: `DEMS | Actor: ${actor.email} | CID: ${fileCID}`,
                                },
                                media: { mimeType: 'application/octet-stream', body: bodyStream },
                            } as any);
                            console.log(`[OK] [Drive] Backup ID: ${driveRes.data.id}`);
                        }
                    } catch (encErr: any) {
                        console.warn(`[AVISO] [AES/Drive] Falhou (não fatal): ${encErr.message}`);
                    }

                } catch (err: any) {
                    console.error(`[ERRO DEMS] Processing failed for ${trackingId}:`);
                    if (err.response) {
                        console.error(`  HTTP ${err.response.status}:`, JSON.stringify(err.response.data));
                    } else {
                        console.error(' ', err.message);
                    }
                }
            });
        }
    );

    // ── GET /api/v1/evidence/chain ────────────────────────────
    // Returns the last N entries in the audit chain
    router.get(
        '/chain',
        authenticateToken,
        async (req: Request, res: Response) => {
            try {
                const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
                // Read chain from Node 1 (primary read source)
                const nodeHealth = consensusManager.getNodeHealth();
                const healthyIdx = nodeHealth.findIndex(n => n.healthy);

                if (healthyIdx === -1) {
                    return res.status(503).json({ error: 'NoHealthyNode', message: 'All audit nodes unreachable.' });
                }

                // We verify integrity on every chain read
                const integrity = await consensusManager.verifyChainIntegrity(healthyIdx);

                return res.status(200).json({
                    status: 'OK',
                    integrity,
                    readFrom: nodeHealth[healthyIdx].name,
                    message: 'Use GET /api/v1/health for live node status.',
                });
            } catch (err: any) {
                return res.status(500).json({ error: 'InternalServerError', message: err.message });
            }
        }
    );

    // ── POST /api/v1/evidence/transfer ────────────────────────
    // Allows transferring custody of an evidence file
    router.post(
        '/transfer',
        authenticateToken,
        validateBody(transferSchema),
        async (req: Request, res: Response) => {
            try {
                const { fileHash, toEmail } = req.body;

                const actor = req.user;
                if (!actor) {
                    return res.status(401).json({ error: 'Unauthorized', message: 'Missing user context' });
                }

                // Procura o bloco de upload original por fileHash (query
                // indexada por fileHash — não varre a cadeia inteira).
                const matches = await consensusManager.findAllBlocksByFileHash(fileHash);
                const originalBlock = matches.find(b => b.action === 'EVIDENCE_UPLOAD');

                if (!originalBlock) {
                    return res.status(404).json({ error: 'NotFound', message: 'Original evidence not found in blockchain' });
                }

                const metadataStr = JSON.stringify({ from: actor.email, to: toEmail });

                const result = await consensusManager.broadcastAndCommit({
                    action:     'CUSTODY_TRANSFER',
                    actorID:    actor.id,
                    actorEmail: actor.email,
                    actorRole:  actor.role,
                    fileCID:    originalBlock.fileCID,
                    fileName:   originalBlock.fileName,
                    driveFileId: 'OFFLINE',
                    fileHash:   fileHash,
                    fileSize:   originalBlock.fileSize,
                    publicKey:  req.body.publicKey || 'NONE',
                    signature:  req.body.signature || 'NONE',
                    metadata:   metadataStr
                });

                demsEvents.emit('event', 'block_added', {
                    blockIndex:    result.blockIndex,
                    fileName:      originalBlock.fileName,
                    fileHash:      fileHash.substring(0, 16) + '...',
                    blockHash:     result.currentHash.substring(0, 16) + '...',
                    actor:         actor.email,
                    consensusCount: result.consensusCount,
                    ts:            new Date().toISOString(),
                    action:        'CUSTODY_TRANSFER'
                });

                return res.status(200).json({
                    status: 'OK',
                    message: `Custody transferred to ${toEmail}`,
                    block: result
                });
            } catch (err: any) {
                return res.status(500).json({ error: 'InternalServerError', message: err.message });
            }
        }
    );

    // ── GET /api/v1/evidence/:fileHash/download ───────────────
    // Recupera a prova original a partir do armazenamento. Só
    // devolve se o fileHash existir mesmo na cadeia (evita servir
    // ficheiros que não foram registados). Requer autenticação.
    router.get(
        '/:fileHash/download',
        authenticateToken,
        async (req: Request, res: Response) => {
            try {
                const fileHash = req.params.fileHash;

                const block = await consensusManager.findBlockByFileHash(fileHash);
                if (!block) {
                    return res.status(404).json({ error: 'NotInChain', message: 'fileHash não consta da cadeia.' });
                }
                if (!(await localStorage.has(fileHash))) {
                    return res.status(404).json({ error: 'NotStored', message: 'Prova registada mas não disponível no armazenamento.' });
                }

                const data = await localStorage.get(fileHash);   // valida o hash ao ler
                res.setHeader('Content-Type', 'application/octet-stream');
                res.setHeader('Content-Disposition', `attachment; filename="${block.fileName}"`);
                res.setHeader('X-File-Hash', fileHash);
                return res.status(200).send(data);
            } catch (err: any) {
                return res.status(500).json({ error: 'InternalServerError', message: err.message });
            }
        }
    );

    return router;
}
