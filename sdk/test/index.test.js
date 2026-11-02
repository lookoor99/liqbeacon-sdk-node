// Runs against the build output, so it checks what is actually published.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyEvent, SignatureError, SequenceTracker, expressWebhook, parseSignatureHeader } = require("../dist");

const SECRET = "whsec_test";
const body = JSON.stringify({ id: "evt_1", seq: 1, type: "test", subscription_id: "sub_1", data: {} });

function sign(payload, secret = SECRET, t = Math.floor(Date.now() / 1000)) {
    const digest = crypto.createHmac("sha256", secret).update(`${t}.`).update(payload).digest("hex");
    return `t=${t},v1=${digest}`;
}

test("verifies a string and a Buffer body", () => {
    assert.equal(verifyEvent({ payload: body, header: sign(body), secret: SECRET }).id, "evt_1");
    assert.equal(verifyEvent({ payload: Buffer.from(body), header: sign(body), secret: SECRET }).id, "evt_1");
});

test("accepts any of several secrets during a rotation", () => {
    const header = sign(body, "whsec_old");
    assert.equal(verifyEvent({ payload: body, header, secret: ["whsec_new", "whsec_old"] }).id, "evt_1");
});

test("rejects a tampered body, a stale timestamp and a malformed header", () => {
    assert.throws(() => verifyEvent({ payload: body + " ", header: sign(body), secret: SECRET }), SignatureError);
    const old = Math.floor(Date.now() / 1000) - 3600;
    assert.throws(() => verifyEvent({ payload: body, header: sign(body, SECRET, old), secret: SECRET }), SignatureError);
    assert.throws(() => verifyEvent({ payload: body, header: "garbage", secret: SECRET }), SignatureError);
    assert.throws(() => verifyEvent({ payload: body, header: "", secret: SECRET }), SignatureError);
});

test("signs the exact bytes, even when they are not valid UTF-8", () => {
    const bytes = Buffer.concat([Buffer.from('{"id":"evt_1","type":"test","subscription_id":"s","data":{},"x":"'), Buffer.from([0xff]), Buffer.from('"}')]);
    assert.equal(verifyEvent({ payload: bytes, header: sign(bytes), secret: SECRET }).id, "evt_1");
});

test("a parsed body or a missing secret is a TypeError, not a SignatureError", () => {
    assert.throws(() => verifyEvent({ payload: JSON.parse(body), header: sign(body), secret: SECRET }), TypeError);
    assert.throws(() => verifyEvent({ payload: body, header: sign(body), secret: undefined }), TypeError);
    assert.throws(() => verifyEvent({ payload: body, header: sign(body), secret: "" }), TypeError);
});

test("parses the header the same way as the other SDKs", () => {
    assert.deepEqual(parseSignatureHeader("t=17,v1=a, v1=b"), { timestamp: 17, signatures: ["a", "b"] });
    assert.equal(parseSignatureHeader("t=+17,v1=a").timestamp, 0);
});

test("SequenceTracker detects gaps, duplicates and fills a gap from a replay", () => {
    const tracker = new SequenceTracker({ sub: 1 });
    const ev = (seq) => ({ subscription_id: "sub", seq });

    assert.deepEqual(tracker.check(ev(4)), { duplicate: false, missing: [2, 3] });
    tracker.commit(ev(4));
    assert.equal(tracker.cursor("sub"), 1);

    assert.deepEqual(tracker.check(ev(2)), { duplicate: false, missing: [] });
    tracker.commit(ev(2));
    tracker.commit(ev(3));
    assert.equal(tracker.cursor("sub"), 4);
    assert.deepEqual(tracker.check(ev(4)), { duplicate: true, missing: [] });
    assert.deepEqual(tracker.snapshot(), { sub: 4 });
});

test("expressWebhook answers 200, 400 and passes handler errors on", async () => {
    const res = () => {
        const r = { code: 0 };
        r.status = (code) => ((r.code = code), { send: () => {} });
        return r;
    };
    const headers = { "x-cardano-signature": sign(body) };

    const ok = res();
    await expressWebhook(SECRET, () => {})({ body: Buffer.from(body), headers }, ok);
    assert.equal(ok.code, 200);

    const bad = res();
    await expressWebhook("whsec_other", () => {})({ body: Buffer.from(body), headers }, bad);
    assert.equal(bad.code, 400);

    let passed;
    await expressWebhook(SECRET, () => {
        throw new Error("boom");
    })({ body: Buffer.from(body), headers }, res(), (error) => (passed = error));
    assert.equal(passed.message, "boom");

    // express.json() mounted by mistake: surfaced as an error, not a 400.
    let misconfigured;
    await expressWebhook(SECRET, () => {})({ body: JSON.parse(body), headers }, res(), (e) => (misconfigured = e));
    assert.ok(misconfigured instanceof TypeError);
});
