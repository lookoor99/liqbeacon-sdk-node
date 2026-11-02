# @liqbeacon/sdk

Verify Liqbeacon webhooks, and notice when you have missed one.

```bash
npm install @liqbeacon/sdk
```

Node 18 or newer. No runtime dependencies.

### Offline install

When the registry is unreachable, download `liqbeacon-sdk-<version>.tgz` from the
console's Quickstart page, copy it into your project and install the file:

```bash
npm install ./liqbeacon-sdk-1.0.0.tgz
```

npm records it as `"@liqbeacon/sdk": "file:liqbeacon-sdk-1.0.0.tgz"`; commit the
tarball so CI can install it too. To build one yourself: `npm run pack:offline`.

## Verify a webhook

```ts
import express from "express";
import { verifyEvent, SignatureError } from "@liqbeacon/sdk";

const app = express();

// express.raw, not express.json: the signature covers the exact bytes we sent,
// and a re-serialized body will not match.
app.post("/webhooks/cardano", express.raw({ type: "application/json" }), (req, res) => {
  let event;
  try {
    event = verifyEvent({
      payload: req.body,
      header: req.header("X-Cardano-Signature") ?? "",
      secret: process.env.WEBHOOK_SECRET!,
    });
  } catch (error) {
    // A SignatureError: reject it, so it is never processed.
    if (error instanceof SignatureError) return res.sendStatus(400);
    // Anything else (a TypeError) is a misconfiguration on this side.
    throw error;
  }

  console.log(event.type, event.data);
  res.sendStatus(200);
});
```

`verifyEvent` throws `SignatureError` on a bad signature or a stale timestamp, so
a handler that forgets to check a return value still fails closed.

While deploying a rotated secret, pass both: `secret: [newSecret, oldSecret]`.

Shorter, with the middleware:

```ts
import { expressWebhook } from "@liqbeacon/sdk";

app.post(
  "/webhooks/cardano",
  express.raw({ type: "application/json" }),
  expressWebhook(process.env.WEBHOOK_SECRET!, async (event) => {
    await recordEvent(event);
  })
);
```

## Handle the three event types

```ts
import { isProduced, isSpent, isRollback } from "@liqbeacon/sdk";

if (isProduced(event)) {
  // An output was created at an address you watch.
  await credit(event.data.utxo);
} else if (isSpent(event)) {
  // An output you were watching was consumed. The full contents of the spent
  // output are included, so there is nothing to look up.
  await debit(event.data.utxo, event.data.spent_by_tx_id);
} else if (isRollback(event)) {
  // The chain abandoned a block. Undo the event named here; you have already
  // seen it, and its id is the one you stored.
  await revert(event.data.reverted_event_id);
}
```

An event rolled back while it was still waiting for `min_confirmations` is
dropped silently: it never took a sequence number, so there is no gap. Once an
event has a sequence number it is always delivered — even if the chain has
abandoned its block by then, in which case it arrives with `rolled_back: true`
and a `rollback` event naming it follows. Make the revert idempotent: it may
name an event you chose to skip because it was already flagged. With
`min_confirmations: 3` or more you will most likely never see one.

## Detect a missed event

`seq` is gap-free per subscription. A jump means an outage lasted long enough to
exhaust retries.

```ts
import { LiqbeaconClient, SequenceTracker } from "@liqbeacon/sdk";

const client = new LiqbeaconClient({
  baseUrl: "https://liqbeacon.com",
  apiKey: process.env.LIQBEACON_API_KEY!,
});
const tracker = new SequenceTracker(await loadCursors());

const { duplicate, missing } = tracker.check(event);

if (duplicate) return res.sendStatus(200); // at-least-once; already handled
if (missing.length > 0) {
  console.warn("missed", missing);
  await client.replay(event.subscription_id, missing[0]);
}

await handle(event);   // if this throws, nothing is recorded and the retry is handled normally
tracker.commit(event); // only after the handler succeeded
```

`check` never records anything; `commit` does, and only once you call it. That
is what keeps a retried event from being mistaken for a duplicate, and lets
replayed events fill a gap instead of being dropped.

Persist `tracker.snapshot()` alongside your own data so the cursor survives a
restart.

## Load the starting state

Streaming only tells you what changed. To know where you are starting from:

```ts
import { LiqbeaconClient } from "@liqbeacon/sdk";

const client = new LiqbeaconClient({
  baseUrl: "https://liqbeacon.com",
  apiKey: process.env.LIQBEACON_API_KEY!,
});

const { utxos, nextSeq } = await client.loadSnapshot("sub_abc123");

// The snapshot reflects exactly the events that already have a sequence
// number. Apply events from nextSeq onward; the tracker stores the last
// processed number, so seed it with nextSeq - 1.
const tracker = new SequenceTracker({ sub_abc123: nextSeq - 1 });
```

Apply events idempotently by `(tx_id, index)`: an output sequenced while the
snapshot was being paged may be both in the snapshot and in an event.

## The API client

`new LiqbeaconClient({ baseUrl, apiKey, timeoutMs = 30000 })` authenticates with
an API key (`sk_live_...`) and uses the built-in `fetch`.

| Method | Endpoint | Returns |
| --- | --- | --- |
| `snapshot(sub, { cursor, limit })` | `GET /v1/subscriptions/{id}/utxos` | One page: `utxos`, `next_cursor`, `next_seq` |
| `loadSnapshot(sub)` | the same, every page | `{ utxos, nextSeq }`, with the first page's `next_seq` |
| `allUtxos(sub)` | the same, every page | An async iterator over the outputs |
| `replay(sub, fromSeq, limit?)` | `POST /v1/subscriptions/{id}/replay` | `requeued`, `from_seq`, `message` |
| `cursor(sub)` | `GET /v1/subscriptions/{id}/events/cursor` | The retained sequence range and `next_seq` |

A non-2xx answer, a network failure, a timeout or a response that is not JSON throws `ApiError`, with
`status` (0 when the API could not be reached) and the raw response `body`.

## Errors

| Error | When | What to do |
| --- | --- | --- |
| `SignatureError` | Bad or missing signature, stale timestamp | Answer 400. Never process the event. |
| `TypeError` | `payload` is a parsed object, no secret was given, or `toleranceSeconds` is not a non-negative number | Fix the route: `express.raw`, and set `WEBHOOK_SECRET`. `expressWebhook` throws this when mounted, so a missing secret stops the app at startup. |
| `ApiError` | The API client got a non-2xx, or no answer | Retry later; `status` and `body` say why. |

## Delivery contract

| Property | Behaviour |
| --- | --- |
| Ordering | Strictly by `seq` within a subscription. A failure blocks that queue rather than letting a later event overtake. |
| Duplicates | Possible. Deduplicate on `event.id`, also sent as `Idempotency-Key`. |
| Loss | Retries run for hours. After they are exhausted the subscription pauses and events keep queueing; nothing is discarded. |
| Retries | Exponential with jitter, up to 12 attempts. A non-2xx or a timeout counts as a failure. `410 Gone` stops delivery immediately. |
| Replay | `POST /v1/subscriptions/{id}/replay` re-sends from a sequence number, with the original ids. |
| Rollbacks | Reported explicitly, as a `rollback` event, for anything that already had a sequence number. |
| Secret rotation | For 24 hours after a rotation every delivery carries a `v1` signature from both secrets. Pass both to verify while you deploy. |

Return 2xx quickly. Your response time is inside the delivery timeout, so slow
work belongs on a queue.
