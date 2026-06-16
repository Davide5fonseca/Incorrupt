// ============================================================
// Incorrupt / DEMS — Abstração de armazenamento de prova
//
// A cadeia guarda o HASH do ficheiro (prova de integridade), mas
// o ficheiro em si tem de ser guardado em ALGUM lado fiável — caso
// contrário consegue-se verificar uma prova que já se tem, mas não
// recuperá-la. Esta interface torna o armazenamento de 1.ª classe:
//
//   • LocalStorageProvider — OBRIGATÓRIO. Guarda o ficheiro cifrado
//     (AES-256) em disco, indexado pelo fileHash. Se falhar, o
//     upload falha (ao contrário do IPFS/Drive, que são extra).
//
// Como o caminho deriva do fileHash — que já está no bloco — a
// cadeia referencia implicitamente o ficheiro: dado um bloco,
// sabe-se sempre onde está a prova.
// ============================================================

export interface StorageProvider {
    readonly name: string;
    /** Guarda os bytes do ficheiro indexados pelo fileHash. Devolve a referência. */
    put(fileHash: string, data: Buffer): Promise<string>;
    /** Recupera os bytes originais (decifrados) a partir do fileHash. */
    get(fileHash: string): Promise<Buffer>;
    /** Indica se um ficheiro com este hash já está guardado. */
    has(fileHash: string): Promise<boolean>;
}
