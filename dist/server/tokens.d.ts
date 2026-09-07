export declare function issueToken(secret: string, payload: Record<string, unknown>, ttlMs: number): string;
export declare function readToken<T extends Record<string, unknown>>(secret: string, token: unknown): T | null;
/** A secret that is missing or short is the same as no signature. */
export declare function assertSecret(secret: unknown): asserts secret is string;
