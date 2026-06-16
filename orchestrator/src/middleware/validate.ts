// ============================================================
// Incorrupt / DEMS — Validação de bodies com zod
//
// Middleware que valida (e normaliza) req.body contra um schema
// zod. Centraliza a validação que antes estava espalhada em
// checks manuais por cada rota. Em caso de erro devolve 400 com
// a lista de problemas; em caso de sucesso substitui req.body
// pelos dados já validados/coagidos.
// ============================================================

import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

export function validateBody(schema: z.ZodType) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const result = schema.safeParse(req.body ?? {});
        if (!result.success) {
            res.status(400).json({
                error:   'ValidationError',
                message: 'Dados inválidos.',
                issues:  result.error.issues.map(i => ({ path: i.path.join('.'), message: i.message })),
            });
            return;
        }
        req.body = result.data;
        next();
    };
}

// ── Schemas reutilizáveis ─────────────────────────────────────
export const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/i, 'esperado SHA-256 (64 hex)');
