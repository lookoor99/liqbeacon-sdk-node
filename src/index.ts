import crypto from "crypto";

/**
 * Liqbeacon SDK.
 *
 * The whole job of this package is to make verification hard to get wrong. Two
 * mistakes account for almost every broken integration:
 *
 *   1. Verifying against a re-serialized body. The signature covers the exact
 *      bytes that were sent, so `JSON.stringify(req.body)` will not match --
 *      key order and spacing differ. Every helper here takes raw bytes.
 *   2. Comparing digests with `===`, which leaks timing. `timingSafeEqual` is
 *      used throughout.
 */

export const SIGNATURE_HEADER = "x-cardano-signature";
export const EVENT_ID_HEADER = "x-cardano-event-id";
export const EVENT_SEQ_HEADER = "x-cardano-event-seq";
export const SUBSCRIPTION_HEADER = "x-cardano-subscription";

export type EventType = "utxo.produced" | "utxo.spent" | "rollback" | "test";

export type Value = {
    lovelace: string;
    /** policyId -> assetNameHex -> quantity, both as decimal strings. */
    assets: Record<string, Record<string, string>>;
};

export type Utxo = {
    tx_id: string;
    index: number;
    address: string;
    value: Value;
    datum_hash: string | null;
    datum: unknown | null;
    script_hash: string | null;
};

/** One output from the snapshot endpoint. Datums are not included there. */
export type SnapshotUtxo = {
    tx_id: string;
    index: number;
    address: string;
    value: Value;
    datum_hash: string | null;
    script_hash: string | null;
    created_slot: number;
};

export type ProducedData = { utxo: Utxo };
export type SpentData = { utxo: Utxo; spent_by_tx_id: string };
export type RollbackData = {
    reverted_event_id: string;
    reverted_seq: number;
    reverted_type: EventType;
    reverted_block_height: number;
    reverted_block_hash: string;
};

export type CardanoEvent = {
    id: string;
    /** Gap-free per subscription. A jump means an event was missed. */
    seq: number | null;
    type: EventType;
    subscription_id: string;
    created_at: string;
    block: { height: number; slot: number; hash: string } | null;
    tx_id: string | null;
    /** Depth of the block at delivery time. */
    confirmations: number | null;
    /** True when the chain abandoned this block; a rollback event follows. */
    rolled_back: boolean;
    data: ProducedData | SpentData | RollbackData | Record<string, unknown>;
};

export class SignatureError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SignatureError";
    }
}

function timingSafeEqual(a: string, b: string): boolean {
    const left = Buffer.from(a, "utf8");
    const right = Buffer.from(b, "utf8");
    if (left.length !== right.length) return false;
    return crypto.timingSafeEqual(left, right);
}

export function parseSignatureHeader(header: string): {
    timestamp: number;
    signatures: string[];
} {
    let timestamp = 0;
    const signatures: string[] = [];

    for (const part of header.split(",")) {
        const index = part.indexOf("=");
        if (index < 0) continue;
        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();
        // Digits only: the same header must parse the same way in every SDK.
        if (key === "t") timestamp = /^\d+$/.test(value) ? Number(value) : 0;
        else if (key === "v1" && value) signatures.push(value);
    }

    return { timestamp, signatures };
}

export type VerifyOptions = {
    /** Raw request body. A string or Buffer, never a parsed object. */
    payload: string | Buffer | Uint8Array;
    /** Value of the X-Cardano-Signature header. */
    header: string;
    /**
     * The subscription's signing secret (whsec_...). Pass both the new and the
     * old secret while deploying a rotation; any one of them may match.
     */
    secret: string | string[];
    /** Replay tolerance in seconds. Default 300. */
    toleranceSeconds?: number;
};

/**
 * Verifies a webhook and returns the parsed event.
 *
 * Throws rather than returning false: a handler that forgets to check a boolean
 * still fails closed.
 */
export function verifyEvent(options: VerifyOptions): CardanoEvent {
    const raw = rawBytes(options.payload);
    const secrets = normalizeSecrets(options.secret);
    const tolerance = options.toleranceSeconds ?? 300;
    // NaN compares false against everything, so `age > NaN` would silently
    // switch replay protection off (e.g. `Number(process.env.UNSET)`).
    if (typeof tolerance !== "number" || Number.isNaN(tolerance) || tolerance < 0) {
        throw new TypeError(`verifyEvent: toleranceSeconds must be a non-negative number, got ${String(tolerance)}`);
    }

    if (!options.header) throw new SignatureError("missing X-Cardano-Signature header");

    const { timestamp, signatures } = parseSignatureHeader(options.header);
    if (!timestamp || signatures.length === 0) {
        throw new SignatureError("malformed X-Cardano-Signature header");
    }

    const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
    if (age > tolerance) {
        throw new SignatureError(`timestamp is ${age}s old, outside the ${tolerance}s window`);
    }

    // Over the bytes as received: decoding first would rewrite any invalid
    // UTF-8 sequence and the digest would no longer match.
    const expected = secrets.map((secret) =>
        crypto.createHmac("sha256", secret).update(`${timestamp}.`, "utf8").update(raw).digest("hex")
    );

    const matches = signatures.some((candidate) =>
        expected.some((digest) => timingSafeEqual(candidate, digest))
    );
    if (!matches) {
        throw new SignatureError("signature mismatch");
    }

    return JSON.parse(raw.toString("utf8")) as CardanoEvent;
}

function normalizeSecrets(secret: string | string[]): string[] {
    const secrets = (Array.isArray(secret) ? secret : [secret]).filter(
        (value) => typeof value === "string" && value.length > 0
    );
    // A TypeError, not a SignatureError: this is a configuration bug on the
    // receiving side, and should surface as one rather than as a forged request.
    if (secrets.length === 0) {
        throw new TypeError("verifyEvent: no webhook secret configured (is WEBHOOK_SECRET set?)");
    }
    return secrets;
}

function rawBytes(payload: unknown): Buffer {
    if (typeof payload === "string") return Buffer.from(payload, "utf8");
    if (Buffer.isBuffer(payload)) return payload;
    if (payload instanceof Uint8Array) return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
    // Almost always express.json() (or another body parser) running before
    // this: the raw bytes are gone and no signature can ever match.
    throw new TypeError(
        "verifyEvent: payload must be the raw request body (string or Buffer), not a parsed object. " +
            'In Express, use express.raw({ type: "application/json" }) on this route instead of express.json().'
    );
}

/** Narrowing helpers, so a handler can switch on type without casting. */
export function isProduced(event: CardanoEvent): event is CardanoEvent & { data: ProducedData } {
    return event.type === "utxo.produced";
}

export function isSpent(event: CardanoEvent): event is CardanoEvent & { data: SpentData } {
    return event.type === "utxo.spent";
}

export function isRollback(event: CardanoEvent): event is CardanoEvent & { data: RollbackData } {
    return event.type === "rollback";
}

/**
 * Tracks sequence numbers to detect loss and redelivery.
 *
 * Use it in two steps around your handler:
 *
 *   const { duplicate, missing } = tracker.check(event);
 *   if (duplicate) return ok();          // already processed
 *   if (missing.length) requestReplay(missing[0]);
 *   await handle(event);                 // may throw: nothing is recorded
 *   tracker.commit(event);               // only after it really succeeded
 *
 * Committing only after success is what makes a retry of a failed event a
 * retry, not a "duplicate". And because committed numbers above a gap are
 * remembered individually, events replayed to fill a gap are recognised as new.
 *
 * Seed it from a snapshot with `next_seq - 1`: the tracker stores the last
 * sequence number processed, not the next one expected.
 */
export class SequenceTracker {
    /** Highest seq such that it and everything below it are committed. */
    private contiguous = new Map<string, number>();
    /** Committed seqs above the contiguous mark, i.e. on the far side of a gap. */
    private above = new Map<string, Set<number>>();

    constructor(initial?: Record<string, number>) {
        for (const [subscription, seq] of Object.entries(initial ?? {})) {
            this.contiguous.set(subscription, seq);
        }
    }

    /**
     * Classifies an event without recording it. `missing` lists the sequence
     * numbers before this one that have not been committed.
     */
    check(event: CardanoEvent): { duplicate: boolean; missing: number[] } {
        if (event.seq == null) return { duplicate: false, missing: [] };

        const mark = this.contiguous.get(event.subscription_id);
        // Nothing known yet: this event sets the baseline.
        if (mark === undefined) return { duplicate: false, missing: [] };

        const above = this.above.get(event.subscription_id);
        if (event.seq <= mark || above?.has(event.seq)) return { duplicate: true, missing: [] };

        const missing: number[] = [];
        for (let seq = mark + 1; seq < event.seq; seq++) {
            if (!above?.has(seq)) missing.push(seq);
        }
        return { duplicate: false, missing };
    }

    /** Records an event as processed. Call only once your handler succeeded. */
    commit(event: CardanoEvent): void {
        if (event.seq == null) return;
        const id = event.subscription_id;

        const mark = this.contiguous.get(id);
        if (mark === undefined) {
            this.contiguous.set(id, event.seq);
            return;
        }
        if (event.seq <= mark) return;

        let above = this.above.get(id);
        if (!above) {
            above = new Set();
            this.above.set(id, above);
        }
        above.add(event.seq);

        let next = mark;
        while (above.has(next + 1)) {
            next++;
            above.delete(next);
        }
        this.contiguous.set(id, next);
        if (above.size === 0) this.above.delete(id);
    }

    /**
     * `check` and `commit` in one call. Only safe when handling cannot fail
     * after this point; otherwise use the two-step form.
     */
    track(event: CardanoEvent): { duplicate: boolean; missing: number[] } {
        const result = this.check(event);
        if (!result.duplicate) this.commit(event);
        return result;
    }

    /** Last sequence number up to which everything has been processed. */
    cursor(subscriptionId: string): number | null {
        return this.contiguous.get(subscriptionId) ?? null;
    }

    /**
     * Persist this alongside your own data so the cursor survives a restart.
     * Only the contiguous mark is kept; anything committed beyond a gap is
     * redelivered by the replay that fills it, and deduplicated on event.id.
     */
    snapshot(): Record<string, number> {
        return Object.fromEntries(this.contiguous);
    }
}

/**
 * Express middleware.
 *
 * Mount with `express.raw({ type: "application/json" })` so the raw bytes
 * survive; `express.json()` discards them and verification cannot work.
 */
export function expressWebhook(
    secret: string | string[],
    handler: (event: CardanoEvent) => void | Promise<void>
) {
    // Fail at startup, not on every delivery: a missing secret would otherwise
    // answer 500 to everything and leave the sender retrying for hours.
    const secrets = normalizeSecrets(secret);

    return async function middleware(
        req: { body: unknown; headers: Record<string, unknown> },
        res: { status: (code: number) => { send: (body?: string) => void }; },
        next?: (error?: unknown) => void
    ): Promise<void> {
        let event: CardanoEvent;
        try {
            event = verifyEvent({
                // Passed through as is: a parsed object raises a TypeError
                // naming the misconfiguration, instead of a misleading 400.
                payload: req.body as string | Buffer,
                header: String(req.headers[SIGNATURE_HEADER] ?? ""),
                secret: secrets,
            });
        } catch (error) {
            if (error instanceof SignatureError) {
                // The reason stays server-side: it would tell a forger how
                // close they got (for example, the clock skew).
                res.status(400).send("invalid signature");
                return;
            }
            if (next) next(error);
            else res.status(500).send();
            return;
        }

        // Separate from verification, so a SignatureError thrown by the handler
        // itself is a handler failure (retried), not a forged request.
        try {
            await handler(event);
            // Acknowledge fast. Anything slow belongs on a queue, because a
            // timeout here counts as a failure and triggers a retry.
            res.status(200).send();
        } catch (error) {
            // A non-2xx tells the sender to retry, which is what should happen
            // when a handler fails.
            if (next) next(error);
            else res.status(500).send();
        }
    };
}

export type ClientOptions = {
    baseUrl: string;
    /** An API key (sk_live_...), sent as X-Api-Key. */
    apiKey: string;
    /** Per-request timeout in milliseconds. Default 30000. */
    timeoutMs?: number;
};

/**
 * Raised when the API answers with a non-2xx status, or cannot be reached.
 *
 * `status` is the HTTP status code (0 when the request never got an answer),
 * and `body` the raw response text, which usually carries the API's
 * `{"error": ..., "message": ...}`. Mirrors `ApiError` in the Python SDK.
 */
export class ApiError extends Error {
    constructor(
        readonly status: number,
        readonly reason: string,
        readonly body: string
    ) {
        super(`${status} ${reason}: ${body}`);
        this.name = "ApiError";
    }
}

function networkError(error: unknown): ApiError {
    const reason = error instanceof Error && error.name === "TimeoutError" ? "timeout" : "request failed";
    let message = error instanceof Error ? error.message : String(error);
    // Node's fetch reports every failure as "fetch failed"; the cause has the
    // useful part (ECONNREFUSED, ENOTFOUND, ...).
    const cause = error instanceof Error ? (error as { cause?: unknown }).cause : undefined;
    if (cause instanceof Error && cause.message) message += `: ${cause.message}`;
    return new ApiError(0, reason, message);
}

/** Thin client for the endpoints a consumer needs at runtime. */
export class LiqbeaconClient {
    private readonly baseUrl: string;
    private readonly timeoutMs: number;

    constructor(private readonly options: ClientOptions) {
        if (!options?.baseUrl) throw new TypeError("LiqbeaconClient: baseUrl is required");
        if (!options.apiKey) throw new TypeError("LiqbeaconClient: apiKey is required");
        const timeoutMs = options.timeoutMs ?? 30_000;
        // AbortSignal.timeout would otherwise throw on every request, and that
        // would be reported as a network failure.
        if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
            throw new TypeError(`LiqbeaconClient: timeoutMs must be a positive integer, got ${String(timeoutMs)}`);
        }
        let end = options.baseUrl.length;
        while (end > 0 && options.baseUrl[end - 1] === "/") end--;
        this.baseUrl = options.baseUrl.slice(0, end);
        this.timeoutMs = timeoutMs;
    }

    private async request<T>(path: string, init?: RequestInit): Promise<T> {
        let response: Response;
        // Covers reading the body too, not just waiting for the headers.
        const signal = AbortSignal.timeout(this.timeoutMs);
        try {
            response = await fetch(`${this.baseUrl}${path}`, {
                ...init,
                signal,
                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json",
                    "X-Api-Key": this.options.apiKey,
                    ...(init?.headers ?? {}),
                },
            });
        } catch (error) {
            // DNS failure, refused connection, timeout: one error type for the
            // caller to handle, as in the Python client.
            throw networkError(error);
        }

        let text: string;
        try {
            text = await response.text();
        } catch (error) {
            // The connection dropped or timed out mid-body.
            throw networkError(error);
        }
        if (!response.ok) {
            throw new ApiError(response.status, response.statusText, text);
        }
        try {
            return JSON.parse(text) as T;
        } catch {
            // A proxy's HTML error page with a 200, for instance.
            throw new ApiError(response.status, "invalid JSON response", text);
        }
    }

    /**
     * One page of the watched UTxO set. It reflects exactly the events that
     * already have a sequence number: apply events from `next_seq` onward.
     * When paging, keep the first page's `next_seq` and apply events
     * idempotently by (tx_id, index).
     */
    async snapshot(
        subscriptionId: string,
        options: { cursor?: string; limit?: number } = {}
    ): Promise<{ utxos: SnapshotUtxo[]; next_cursor: string | null; next_seq: number }> {
        const params = new URLSearchParams();
        if (options.cursor) params.set("after", options.cursor);
        if (options.limit) params.set("limit", String(options.limit));
        const query = params.toString() ? `?${params}` : "";
        return this.request(`/v1/subscriptions/${encodeURIComponent(subscriptionId)}/utxos${query}`);
    }

    /**
     * Every watched output, following the cursor. `nextSeq` is the first
     * page's value, which is the one to resume events from.
     */
    async loadSnapshot(subscriptionId: string): Promise<{ utxos: SnapshotUtxo[]; nextSeq: number }> {
        const utxos: SnapshotUtxo[] = [];
        let cursor: string | undefined;
        let nextSeq: number | undefined;
        do {
            const page = await this.snapshot(subscriptionId, { cursor, limit: 1000 });
            nextSeq ??= page.next_seq;
            utxos.push(...page.utxos);
            cursor = page.next_cursor ?? undefined;
        } while (cursor);
        return { utxos, nextSeq: nextSeq ?? 1 };
    }

    /** Pages through every watched output, following the cursor. */
    async *allUtxos(subscriptionId: string): AsyncGenerator<SnapshotUtxo> {
        let cursor: string | undefined;
        do {
            const page = await this.snapshot(subscriptionId, { cursor });
            for (const utxo of page.utxos) yield utxo;
            cursor = page.next_cursor ?? undefined;
        } while (cursor);
    }

    /**
     * Re-sends events from `fromSeq`, with their original ids and sequence
     * numbers. The recovery step when `SequenceTracker.check` reports a gap.
     */
    async replay(
        subscriptionId: string,
        fromSeq: number,
        limit?: number
    ): Promise<{ requeued: number; from_seq: number; message: string }> {
        return this.request(`/v1/subscriptions/${encodeURIComponent(subscriptionId)}/replay`, {
            method: "POST",
            body: JSON.stringify({ from_seq: fromSeq, ...(limit ? { limit } : {}) }),
        });
    }

    /** Sequence range currently retained, for reconciling after an outage. */
    async cursor(subscriptionId: string): Promise<{
        oldest_retained_seq: number | null;
        latest_seq: number | null;
        latest_delivered_seq: number | null;
        next_seq: number;
        replay_window_days: number;
    }> {
        return this.request(`/v1/subscriptions/${encodeURIComponent(subscriptionId)}/events/cursor`);
    }
}
