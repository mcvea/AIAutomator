// wb_helper.js - WorkBuddy 5.6.2+ encrypted-credential transient decryptor
//
// Usage (spawned by platforms/workbuddy.py):
//   env ELECTRON_RUN_AS_NODE=1
//   <WorkBuddy.exe> wb_helper.js <auth-file-path> [field-path]
//
// Output:
//   success -> stdout: plaintext token only (nothing else), exit 0
//   failure -> stderr: "WB_HELPER_ERROR: <reason>", exit 1
//
// Security (zero-leak, same doctrine as FlapPearLabs/workbuddy-toolkit):
//   - the at-rest key never leaves this process, never printed, never stored
//   - plaintext goes to stdout pipe only (consumed in-memory by parent)
//   - buffers best-effort zeroized after use
//
// Crypto (reverse-engineered from client packages/at-rest-crypto):
//   key    = SHA256(atRestSecretKey utf8)              (32 bytes, AES-256)
//   keyId  = SHA256(key).hex[:16]                      (must equal envelope.keyId)
//   cipher = AES-256-GCM, nonce 12B, authTag 16B
//   AAD    = "WB-AAD\0" | 0x01 | lp("WBEV1") | lp("sym-v1")
//            | uint32be(suite) | lp(keyId) | 0x02 | 0x00 | 0x00
//            (lp = uint32be length + utf8 bytes; framing=field)

"use strict";
const fs = require("fs");
const crypto = require("crypto");

function fail(msg) {
    try { process.stderr.write("WB_HELPER_ERROR: " + msg + "\n"); } catch (e) {}
    process.exit(1);
}

function encodeUint32(v) {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32BE(v >>> 0);
    return b;
}
function encodeLenPrefixed(s) {
    const b = Buffer.from(s, "utf8");
    return Buffer.concat([encodeUint32(b.length), b]);
}
function buildFieldAad(keyId, suite) {
    return Buffer.concat([
        Buffer.from("WB-AAD\0", "ascii"),
        Buffer.from([1]),
        encodeLenPrefixed("WBEV1"),
        encodeLenPrefixed("sym-v1"),
        encodeUint32(suite),
        encodeLenPrefixed(keyId),
        Buffer.from([2]),
        Buffer.from([0]),
        Buffer.from([0]),
    ]);
}

function main() {
    const authPath = process.argv[2];
    const fieldPath = process.argv[3] || "auth.accessToken";
    if (!authPath) fail("missing auth file path argument");

    // 1) load credential file, locate field
    let doc;
    try {
        doc = JSON.parse(fs.readFileSync(authPath, "utf8"));
    } catch (e) {
        fail("cannot read auth file: " + e.message);
    }
    let node = doc;
    for (const seg of String(fieldPath).split(".")) {
        if (node === null || typeof node !== "object") fail("field not found: " + fieldPath);
        node = node[seg];
    }

    // plaintext passthrough (pre-5.6.2 compatibility)
    if (typeof node === "string" && node) {
        process.stdout.write(node);
        process.exit(0);
    }
    if (!node || typeof node !== "object" || node.$wbEncrypted !== 1 || typeof node.envelope !== "string") {
        fail("field is not a $wbEncrypted envelope");
    }

    // 2) obtain at-rest key via client's linked native binding
    let payload;
    try {
        if (typeof process._linkedBinding !== "function") {
            fail("process._linkedBinding unavailable (must run under WorkBuddy.exe with ELECTRON_RUN_AS_NODE=1)");
        }
        const binding = process._linkedBinding("electron_browser_workbuddy_storage");
        payload = JSON.parse(binding.loggerGet());
    } catch (e) {
        fail("native key binding: " + e.message);
    }
    const secret = payload && payload.atRestSecretKey;
    if (typeof secret !== "string" || secret.length !== 44) fail("atRestSecretKey missing or malformed");

    // 3) derive key + keyId
    const key = crypto.createHash("sha256").update(secret, "utf8").digest();
    const keyId = crypto.createHash("sha256").update(key).digest("hex").slice(0, 16);

    // 4) parse envelope (base64 -> JSON)
    let env;
    try {
        env = JSON.parse(Buffer.from(node.envelope, "base64").toString("utf8"));
    } catch (e) {
        fail("envelope parse: " + e.message);
    }
    if (!env || env.suite !== 1) fail("unsupported envelope suite");
    if (env.keyId !== keyId) fail("keyId mismatch (envelope=" + env.keyId + ", derived=" + keyId + ")");

    // 5) AES-256-GCM decrypt with authenticated context AAD
    let plain;
    try {
        const decipher = crypto.createDecipheriv(
            "aes-256-gcm", key, Buffer.from(env.nonce, "base64"), { authTagLength: 16 }
        );
        decipher.setAAD(buildFieldAad(env.keyId, env.suite));
        decipher.setAuthTag(Buffer.from(env.authTag, "base64"));
        plain = Buffer.concat([
            decipher.update(Buffer.from(env.ciphertext, "base64")),
            decipher.final(),
        ]);
    } catch (e) {
        key.fill(0);
        fail("decrypt/auth failed: " + e.message);
    }

    // 6) emit plaintext token only; best-effort zeroization
    key.fill(0);
    const out = plain.toString("utf8");
    plain.fill(0);
    process.stdout.write(out);
    process.exit(0);
}

main();
