// Atlas eufy bridge — the one process that talks to eufy for Atlas (replaces bropat/eufy-security-ws + the
// Home Assistant eufy_security integration, 2026-11-09).
//
// What it does:
//   1. EVENTS: logs in, keeps the SDK's push + P2P realtime up, and turns each camera event into the SAME
//      Home Assistant–shaped state change Atlas has always ingested (POST {ATLAS_EVENTS_URL}, i.e.
//      /api/ha-events): binary_sensor.{camera}_motion_detected / _person_detected / doorbell _ringing go
//      "on", then "off" EVENT_RESET_SECONDS after the last push (HA's eufy integration did exactly this).
//      Attributes carry what HA never had: the camera's own clip path for the event (file_path), the
//      push thumbnail, and an image_url on this bridge.
//   2. IMAGES: GET /images/{id}.jpg — the event's push thumbnail, decoded (waits up to 10 s for it).
//      POST /images/exists {station, files[]} — which on-camera image paths exist (P2P CMD_DATABASE_IMAGE).
//   3. CLIPS: GET /clip?station=&path=[&channel=] — the camera's own recording over P2P (CMD_DOWNLOAD_VIDEO),
//      keyframes decrypted, returned as the plain elementary video stream (H.265 garage / H.264 doorbell).
//      404 = the camera has no such file, 409 = busy, 502 = failed (body says why).
//   4. GET /latest?station=&device= — the station's latest-event row (database 10013).
//   5. GET /health.
//
// Clip decryption (measured on our devices 2026-10-28 / 2026-11-09, see Atlas docs): a video frame whose
// message is signed (signCode > 0) has bytes 22..150 AES-128-ECB encrypted with
// getImageKey(stationSn, p2pDid, code).slice(0,16), code = the ASCII result of CMD_DOWNLOAD_VIDEO. A
// HomeBase-type station (the doorbell chime) splits frames over 64000 bytes into several messages and every
// continuation is encrypted the same way — keyframe OR NOT (Atlas's old container patch missed the non-key
// ones, leaving 128 bytes of ciphertext in each large P-frame). Frames carry 1-3 padding bytes past the
// length in their 22-byte header (u32 LE @0), trimmed here.
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { EufyMega, FileSessionStore, LoginStatus } from "../dist/index.js";

const env = (k, d) => process.env[k] ?? d;
const PORT = Number(env("PORT", "3100"));
const ATLAS_EVENTS_URL = env("ATLAS_EVENTS_URL", "http://nova-api:8080/api/ha-events");
const PUBLIC_URL = env("BRIDGE_PUBLIC_URL", `http://eufy-bridge:${PORT}`);
const RESET_MS = Number(env("EVENT_RESET_SECONDS", "10")) * 1000;
// serial=name pairs: the name becomes the HA-style entity prefix (binary_sensor.{name}_motion_detected).
const CAMERAS = Object.fromEntries(
  env("CAMERAS", "").split(",").map((p) => p.trim().split("=")).filter((p) => p.length === 2 && p[0] && p[1]),
);
// Stations that negotiate a cipher they hold no key for (garage T8423: cipher 1): send database/image reads in
// the clear, as upstream #502 does for cipher-0 sessions — without it they time out.
const CLEAR_READS = new Set(env("CLEAR_READS_STATIONS", "").split(",").map((s) => s.trim()).filter(Boolean));

const log = (...a) => console.log(new Date().toISOString(), ...a);
const quiet = () => {};

// ── eufy client ──────────────────────────────────────────────────────────────────────────────────────────
const eufy = new EufyMega({
  email: env("EUFY_EMAIL"),
  password: env("EUFY_PASSWORD"),
  countryCode: env("EUFY_COUNTRY", "US"),
  store: new FileSessionStore(env("SESSION_FILE", "/data/session.json")),
  logger: { debug: quiet, info: quiet, warn: (m) => log("[sdk warn]", m), error: (m) => log("[sdk error]", m) },
});

const state = { loggedIn: false, push: false, events: 0, lastEvent: null, posted: 0, postFailures: 0, downloads: 0 };
let devices = [];

async function login() {
  const r = await eufy.login();
  if (r.status !== LoginStatus.Ok) {
    // Captcha / 2FA cannot be answered by a headless service: say so loudly and stay up (health shows it).
    throw new Error(`eufy login needs interaction (${r.status}); run the SDK's examples/01-login-list-devices.ts once against this SESSION_FILE`);
  }
  devices = await eufy.getDevices();
  state.loggedIn = true;
  log(`logged in; ${devices.length} devices:`, devices.map((d) => `${d.sn}${CAMERAS[d.sn] ? `=${CAMERAS[d.sn]}` : ""}`).join(" "));
}

const deviceBySn = (sn) => devices.find((d) => d.sn === sn);
const p2pDidOf = (stationSn) => deviceBySn(stationSn)?.p2pDid;
const accountIdOf = (stationSn) => deviceBySn(stationSn)?.raw?.member?.admin_user_id ?? "";

// ── events → Atlas ───────────────────────────────────────────────────────────────────────────────────────
const SENSORS = {
  motion: ["motion_detected"],
  personDetected: ["person_detected", "motion_detected"],
  strangerDetected: ["person_detected", "motion_detected"],
  doorbellPress: ["ringing"],
};
const onTimers = new Map(); // entity_id -> timeout handle while "on"

async function postState(entityId, oldState, newState, attributes) {
  const body = JSON.stringify({
    entity_id: entityId, domain: "binary_sensor", old_state: oldState, new_state: newState,
    changed_at: new Date().toISOString(), attributes,
  });
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(ATLAS_EVENTS_URL, {
        method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(10_000),
      });
      if (res.ok) { state.posted++; return; }
      log(`[event] POST ${entityId} ${newState} -> HTTP ${res.status}`);
    } catch (e) {
      log(`[event] POST ${entityId} ${newState} failed (attempt ${attempt}): ${e.message}`);
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
  state.postFailures++;
}

// Push thumbnails: id -> Promise<Buffer|undefined>, newest 200 kept.
const images = new Map();
function rememberImage(id, promise) {
  images.set(id, promise);
  while (images.size > 200) images.delete(images.keys().next().value);
}

/** The push thumbnail. The first attempt, ~0.4 s after the push, failed with an HTTP status on the first live event
 *  (2026-11-09): the picture is likely not uploaded yet. Retries over ~15 s. */
async function fetchThumbnail(id, url, did) {
  const delays = [0, 2000, 4000, 8000];
  for (let i = 0; i < delays.length; i++) {
    if (delays[i]) await new Promise((r) => setTimeout(r, delays[i]));
    try {
      const buf = await eufy.mega.downloadImage(url, did);
      if (i > 0) log(`[image] ${id} fetched on attempt ${i + 1}`);
      return buf;
    } catch (e) {
      log(`[image] ${id} attempt ${i + 1} failed: ${e.message}${e.mediaFailure ? ` (${e.mediaFailure}${e.status ? ` ${e.status}` : ""})` : ""}`);
    }
  }
  return undefined;
}

function onEvent(ev) {
  const name = ev?.eventName;
  const sensors = SENSORS[name];
  const camera = CAMERAS[ev?.deviceSn];
  state.events++;
  state.lastEvent = { at: new Date().toISOString(), name, deviceSn: ev?.deviceSn, file_path: ev?.file_path };
  log(`[event] ${name} ${ev?.deviceSn}${camera ? ` (${camera})` : ""} file=${ev?.file_path ?? "-"}`);
  if (!sensors || !camera) return;

  const id = crypto.randomUUID();
  const picUrl = ev.pic_url || ev.thumbnailUrl;
  if (picUrl) {
    rememberImage(id, fetchThumbnail(id, picUrl, p2pDidOf(ev.stationSn || ev.deviceSn)));
  }
  const attributes = {
    source: "eufy-bridge", event: name, event_type: ev.event_type ?? ev.eventType, device_sn: ev.deviceSn,
    station_sn: ev.stationSn, channel: ev.channel, file_path: ev.file_path ?? null,
    trigger_time: ev.trigger_time ? new Date(Number(ev.trigger_time)).toISOString() : null,
    image_url: picUrl ? `${PUBLIC_URL}/images/${id}.jpg` : null, image_id: picUrl ? id : null,
  };
  for (const suffix of sensors) {
    const entityId = `binary_sensor.${camera}_${suffix}`;
    const wasOn = onTimers.has(entityId);
    if (wasOn) clearTimeout(onTimers.get(entityId));
    onTimers.set(entityId, setTimeout(() => {
      onTimers.delete(entityId);
      void postState(entityId, "on", "off", { source: "eufy-bridge" });
    }, RESET_MS));
    // Already on: HA's integration extended the state without a new state change; so do we.
    if (!wasOn) void postState(entityId, "off", "on", attributes);
  }
}

// ── P2P helpers ──────────────────────────────────────────────────────────────────────────────────────────
const stationLocks = new Map();
/** One P2P job per station at a time. A job that fails for any reason but "no such file" drops the station's
 *  session and runs once more on a fresh one: after the garage camera rebooted (2026-11-09) its old session kept
 *  "working" and every read came back empty until the session was replaced. */
async function withStation(stationSn, fn) {
  const prev = stationLocks.get(stationSn) ?? Promise.resolve();
  let release;
  const mine = new Promise((r) => (release = r));
  stationLocks.set(stationSn, prev.then(() => mine));
  await prev;
  try {
    try { return await fn(); } catch (e) {
      if ((e instanceof ClipError && e.status === 404) || !deviceBySn(stationSn)) throw e;
      log(`[p2p] ${stationSn}: ${e.message} — reconnecting and retrying once`);
      await resetStation(stationSn);
      return await fn();
    }
  } finally { release(); }
}

// Closing the session makes the SDK's session manager drop it (its `close` handler), so the next connectStation()
// opens a fresh one. (The manager itself is private to the SDK's command router.)
async function resetStation(stationSn) {
  const s = eufy.getP2pSessions().get(stationSn);
  if (!s) return;
  try { await s.close(); } catch (e) { log(`[p2p] ${stationSn}: close failed: ${e.message}`); }
}

/** `reads`: database / image reads, which a CLEAR_READS station only answers in the clear. Everything else
 *  (the clip download) keeps the SDK's own choice — forced clear, the garage refuses a download (-111). */
async function session(stationSn, { reads = false } = {}) {
  await eufy.connectStation(stationSn);
  let s = eufy.getP2pSessions().get(stationSn);
  if (s && (!s.isConnected || !s.pathAnswering)) {
    log(`[p2p] ${stationSn}: session ${s.isConnected ? "silent" : "closed"} — reconnecting`);
    await resetStation(stationSn);
    await eufy.connectStation(stationSn);
    s = eufy.getP2pSessions().get(stationSn);
  }
  if (!s) throw new Error(`no P2P session for ${stationSn}`);
  // Let the level-2 negotiation settle (or give up) before sending: the chime negotiates cipher 62.
  try { await s.awaitLevel2Key(9000, "session"); } catch { /* no key is a normal answer */ }
  if (reads && CLEAR_READS.has(stationSn)) s.sendsInTheClear = () => true;
  else delete s.sendsInTheClear; // back to the prototype's
  return s;
}

// getImageKey from eufy-security-client (http/utils.js), unchanged in behaviour.
function idSuffix(did) {
  const m = /^[A-Z]+-(\d+)-[A-Z]+$/.exec(did ?? "");
  if (!m) return 0;
  const [n1, n2, n3, n4] = [m[1][0], m[1][1], m[1][3], m[1][5]].map(Number);
  let r = n1 + n2 + n3;
  if (n3 < 5) r += n3;
  return r + n4;
}
function imageKey(sn, did, code) {
  const nr = (Number.parseInt(sn[sn.length - 1], 16) + 10) % 10;
  const baseCode = `${sn.substring(nr)}${idSuffix(did)}`;
  const seed = crypto.createHash("md5").update(`${1000 - idSuffix(did)}${Number.parseInt(code.substring(2))}`).digest("hex").toUpperCase();
  const h = [...crypto.createHash("sha256").update(`01${baseCode}${seed}`).digest()];
  const start = h[10];
  for (let i = 0; i < 32; i++) {
    const b = h[i];
    const fixed = i < 31 ? h[i + 1] : start;
    if (i === 31 || (i & 1) !== 0) {
      h[10] = fixed;
      if (126 < b || 126 < h[10]) h[i] = b < h[10] || b - h[10] === 0 ? h[10] - b : b - h[10];
    } else if (b < 125 || fixed < 125) {
      h[i] = fixed + b;
    }
  }
  return Buffer.from(h.slice(16)).toString("hex").toUpperCase();
}

// Clip key codes seen per station, newest first, persisted beside the session (see downloadClip). Seeded from
// CLIP_CODES="station:code,station:code" for codes learnt before the bridge existed.
const CODES_FILE = `${env("SESSION_FILE", "/data/session.json").replace(/[^/]*$/, "")}clip-codes.json`;
let codes = {};
try { codes = JSON.parse(fs.readFileSync(CODES_FILE, "utf8")); } catch { /* first run */ }
for (const pair of env("CLIP_CODES", "").split(",").map((s) => s.trim()).filter(Boolean)) {
  const [st, c] = pair.split(":");
  if (st && c && !(codes[st] ?? []).includes(c)) (codes[st] ??= []).push(c);
}
const knownCodes = (st) => codes[st] ?? [];
function rememberCode(st, c) {
  const list = [c, ...knownCodes(st).filter((x) => x !== c)].slice(0, 100);
  if (list.join() === knownCodes(st).join()) return;
  codes[st] = list;
  try { fs.writeFileSync(CODES_FILE, JSON.stringify(codes)); } catch (e) { log(`[clip] cannot save ${CODES_FILE}: ${e.message}`); }
}

const isStart = (b, o) => b.length >= o + 4 && (b.readUInt32BE(o) === 1 || b.readUIntBE(o, 3) === 1);

class ClipError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function downloadClip(stationSn, path, channel) {
  return withStation(stationSn, async () => {
    const s = await session(stationSn);
    const did = p2pDidOf(stationSn);
    const t0 = Date.now();
    // Frames are kept raw and decrypted once the download ends: the key code's reply can arrive after the first
    // video frames (seen 2026-11-09: a whole clip came back with its first keyframe still encrypted).
    const raws = [];
    let code, frames = 0, decrypted = 0, undecryptable = 0, last = Date.now(), finished = false, refused;
    const onData = (f) => {
      const cmd = f.commandId;
      if (cmd === 1024) {
        // CMD_DOWNLOAD_VIDEO reply: int32 result, then the ASCII clip key code (NUL padded).
        const d = f.data;
        const rc = d.length >= 4 ? d.readInt32LE(0) : -1;
        if (rc !== 0) { refused = rc; return; }
        code = d.subarray(4).toString("latin1").split("\0")[0];
        log(`[clip] ${stationSn} key reply len=${d.length} after ${frames} frames, code ${code.length} chars, head ${d.subarray(0, 20).toString("hex")}`);
        return;
      }
      if (cmd === 1304) { finished = true; return; }
      if (cmd !== 1300) return;
      last = Date.now();
      const raw = Buffer.from(f.raw);
      if (raw.length < 22) return;
      frames++;
      raws.push({ raw, signed: f.signCode > 0 });
    };
    const onResult = (r) => { if (r?.code !== undefined && r.code !== 0 && !code) refused = r.code; };
    s.on("data", onData);
    s.on("commandResult", onResult);
    try {
      s.sendStringPairCommand(1024, path, accountIdOf(stationSn), channel);
      while (!finished) {
        await new Promise((r) => setTimeout(r, 200));
        if (refused !== undefined) throw new ClipError(404, `camera refused ${path}: result ${refused}`);
        if (!frames && Date.now() - t0 > 12_000) throw new ClipError(502, `no data within 12s (code ${code ? "received" : "missing"})`);
        if (frames && Date.now() - last > 15_000) throw new ClipError(502, `stalled after ${frames} frames`);
        if (Date.now() - t0 > 180_000) throw new ClipError(502, `still running after 180s (${frames} frames)`);
      }
    } finally {
      s.off("data", onData);
      s.off("commandResult", onResult);
    }
    if (!code) throw new ClipError(502, `download finished but no key code arrived (${frames} frames)`);
    if (process.env.DUMP_DIR) {
      // Debug: the raw transfer in the probe's length-prefixed format (u32 cmd, u32 len, raw).
      const parts = raws.flatMap(({ raw }) => { const h = Buffer.alloc(8); h.writeUInt32LE(1300, 0); h.writeUInt32LE(raw.length, 4); return [h, Buffer.from(raw)]; });
      fs.writeFileSync(`${process.env.DUMP_DIR}/dump-${stationSn}-${code}.bin`, Buffer.concat(parts));
    }
    // The reply carries the station's CURRENT key code; a clip recorded before the code changed needs the code
    // that was current then (2026-11-09: last night's clip refused today's code and opened with yesterday's).
    // So every code seen is remembered, and the first encrypted frame picks the one that opens it.
    const encrypted = (r) => (r.signed || !isStart(r.raw, 22)) && r.raw.length >= 150;
    const probe = raws.find(encrypted);
    const keyFor = (c) => Buffer.from(imageKey(stationSn, did, c).slice(0, 16), "utf8");
    const opens = (c) => {
      const dc = crypto.createDecipheriv("aes-128-ecb", keyFor(c), null);
      dc.setAutoPadding(false);
      return isStart(Buffer.concat([dc.update(probe.raw.subarray(22, 150)), dc.final()]), 0);
    };
    rememberCode(stationSn, code);
    const usedCode = !probe ? code : [code, ...knownCodes(stationSn).filter((c) => c !== code)].find(opens);
    if (!usedCode) {
      throw new ClipError(502, `no known key code opens ${path} (${knownCodes(stationSn).length} tried; current ${code}) frames=${frames}`);
    }
    if (usedCode !== code) log(`[clip] ${stationSn} ${path}: opened with an earlier key code (current one did not)`);
    const key = keyFor(usedCode);
    const out = [];
    for (const r of raws) {
      const { raw } = r;
      if (encrypted(r)) {
        const dc = crypto.createDecipheriv("aes-128-ecb", key, null);
        dc.setAutoPadding(false);
        Buffer.concat([dc.update(raw.subarray(22, 150)), dc.final()]).copy(raw, 22);
        decrypted++;
      } else if (r.signed) {
        undecryptable++;
      }
      const declared = raw.readUInt32LE(0);
      out.push(raw.subarray(22, declared > 0 && 22 + declared <= raw.length ? 22 + declared : raw.length));
    }
    const body = Buffer.concat(out);
    if (!isStart(body, 0)) {
      throw new ClipError(502, `stream does not start with a NAL start code frames=${frames} decrypted=${decrypted} head=${raws[0]?.raw.subarray(0, 30).toString("hex")}`);
    }
    state.downloads++;
    log(`[clip] ${stationSn} ${path}: ${frames} frames, ${decrypted} decrypted, ${(body.length / 1048576).toFixed(1)} MB in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    return { body, frames, decrypted, undecryptable, seconds: (Date.now() - t0) / 1000 };
  });
}

// "eufysecurity"-wrapped P2P images (SDK requestImage returns them still wrapped).
function unwrapImage(did, data) {
  if (data.length < 41 || data.subarray(0, 12).toString() !== "eufysecurity") return data;
  const sn = data.subarray(13, 29).toString();
  const code = data.subarray(30, 40).toString();
  const rest = Buffer.from(data.subarray(41));
  const dc = crypto.createDecipheriv("aes-128-ecb", Buffer.from(imageKey(sn, did, code), "utf8").subarray(0, 16), null);
  dc.setAutoPadding(false);
  Buffer.concat([dc.update(rest.subarray(0, 256)), dc.final()]).copy(rest);
  return rest;
}

async function imagesExist(stationSn, files, settleMs) {
  return withStation(stationSn, async () => {
    const s = await session(stationSn, { reads: true });
    const want = new Set(files);
    const hits = new Set();
    const onImage = (f) => { if (want.has(f.file)) hits.add(f.file); };
    s.on("image", onImage);
    try {
      for (const f of files) s.requestImage(f, { accountId: accountIdOf(stationSn), channel: 0 });
      // No ack per request here (the SDK does not surface one): wait for replies to stop arriving.
      const t0 = Date.now();
      let seen = 0, quietSince = Date.now();
      while (Date.now() - t0 < 20_000) {
        await new Promise((r) => setTimeout(r, 200));
        if (hits.size !== seen) { seen = hits.size; quietSince = Date.now(); }
        if (hits.size === want.size || Date.now() - quietSince > settleMs) break;
      }
    } finally {
      s.off("image", onImage);
    }
    return [...hits];
  });
}

async function fetchImage(stationSn, file) {
  return withStation(stationSn, async () => {
    const s = await session(stationSn, { reads: true });
    const got = await new Promise((resolve) => {
      const on = (f) => { if (f.file === file || !f.file) { s.off("image", on); resolve(f.data); } };
      s.on("image", on);
      setTimeout(() => { s.off("image", on); resolve(undefined); }, 15_000);
      s.requestImage(file, { accountId: accountIdOf(stationSn), channel: 0 });
    });
    return got ? unwrapImage(p2pDidOf(stationSn), got) : undefined;
  });
}

async function latestInfo(stationSn) {
  return withStation(stationSn, async () => {
    const s = await session(stationSn, { reads: true });
    let text = "";
    const on = (c) => { text += typeof c === "string" ? c : (c?.text ?? ""); };
    s.on("dbChunk", on);
    try {
      s.queryDatabase("history_record_info", { accountId: accountIdOf(stationSn), channel: 0, innerCmd: 10013 });
      const t0 = Date.now();
      while (Date.now() - t0 < 10_000 && !/"cmd":10013/.test(text)) await new Promise((r) => setTimeout(r, 200));
    } finally {
      s.off("dbChunk", on);
    }
    if (!text.includes("{")) throw new Error("no latest-info reply from the station");
    const json = text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
    const parsed = JSON.parse(json);
    const data = typeof parsed.data === "string" ? JSON.parse(parsed.data) : parsed.data;
    return Array.isArray(data) ? data : [];
  });
}


// The station's recording history (database 10017, table history_record_info): every recording with its start,
// end, frame count and on-card path. Answers in the clear on a CLEAR_READS station.
async function history(stationSn, days) {
  return withStation(stationSn, async () => {
    const s = await session(stationSn, { reads: true });
    const ymd = (d) => d.toISOString().slice(0, 10).replaceAll("-", "");
    const now = Date.now();
    let text = "";
    const on = (c) => { text += typeof c === "string" ? c : (c?.text ?? ""); };
    s.on("dbChunk", on);
    try {
      s.queryDatabase("history_record_info", {
        accountId: accountIdOf(stationSn), channel: 0, innerCmd: 10017,
        query: { count: 50, start_date: ymd(new Date(now - days * 86400_000)), end_date: ymd(new Date(now + 86400_000)),
          start_time: "0", event_type: 0, ai_type: 0, storage_cloud: -1, trigger_type: 0, detection_type: 0, flag: 0 },
      });
      const t0 = Date.now();
      let len = -1, quietSince = Date.now();
      while (Date.now() - t0 < 20_000) {
        await new Promise((r) => setTimeout(r, 250));
        if (text.length !== len) { len = text.length; quietSince = Date.now(); }
        if (len > 0 && Date.now() - quietSince > 2000) break;
      }
    } finally {
      s.off("dbChunk", on);
    }
    if (!text) throw new Error("no history reply from the station");
    const rows = [];
    for (const m of text.matchAll(/{"record_id":[^{}]*}/g)) { try { rows.push(JSON.parse(m[0])); } catch { /* split row */ } }
    return rows.map((r) => ({ start: r.start_time, end: r.end_time, frames: r.frame_num, path: r.storage_path,
      thumb: r.thumb_path, device_sn: r.device_sn, trigger_type: r.trigger_type, cipher_id: r.cipher_id }));
  });
}

// ── HTTP ─────────────────────────────────────────────────────────────────────────────────────────────────
function send(res, status, body, type = "application/json") {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  res.writeHead(status, { "content-type": type, "content-length": buf.length });
  res.end(buf);
}
const readJson = (req) => new Promise((resolve, reject) => {
  let s = "";
  req.on("data", (c) => (s += c));
  req.on("end", () => { try { resolve(JSON.parse(s || "{}")); } catch (e) { reject(e); } });
});

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (url.pathname === "/health") {
      return send(res, state.loggedIn ? 200 : 503, { ...state, devices: devices.map((d) => d.sn), cameras: CAMERAS });
    }
    const img = /^\/images\/([0-9a-f-]+)\.jpg$/.exec(url.pathname);
    if (img && req.method === "GET") {
      const p = images.get(img[1]);
      if (!p) return send(res, 404, { error: "unknown image" });
      const buf = await Promise.race([p, new Promise((r) => setTimeout(() => r(undefined), 20_000))]);
      return buf ? send(res, 200, buf, "image/jpeg") : send(res, 504, { error: "image not available" });
    }
    if (url.pathname === "/clip" && req.method === "GET") {
      const station = url.searchParams.get("station"), path = url.searchParams.get("path");
      if (!station || !path) return send(res, 400, { error: "station and path are required" });
      const channel = Number(url.searchParams.get("channel") ?? "0");
      // -111 also came back once for a clip that exists, straight after another download: one retry 4 s later.
      let r;
      try { r = await downloadClip(station, path, channel); } catch (e) {
        if (!(e instanceof ClipError) || e.status !== 404) throw e;
        await new Promise((ok) => setTimeout(ok, 4000));
        r = await downloadClip(station, path, channel);
      }
      res.writeHead(200, {
        "content-type": "application/octet-stream", "content-length": r.body.length,
        "x-frames": r.frames, "x-decrypted": r.decrypted, "x-undecryptable": r.undecryptable, "x-seconds": r.seconds.toFixed(1),
      });
      return res.end(r.body);
    }
    if (url.pathname === "/image" && req.method === "GET") {
      const station = url.searchParams.get("station"), file = url.searchParams.get("file");
      if (!station || !file) return send(res, 400, { error: "station and file are required" });
      const buf = await fetchImage(station, file);
      return buf ? send(res, 200, buf, "image/jpeg") : send(res, 404, { error: "no such image" });
    }
    if (url.pathname === "/images/exists" && req.method === "POST") {
      const b = await readJson(req);
      if (!b.station || !Array.isArray(b.files)) return send(res, 400, { error: "station and files[] are required" });
      return send(res, 200, { hits: await imagesExist(b.station, b.files, Number(b.settleMs ?? 2500)) });
    }
    if (url.pathname === "/history" && req.method === "GET") {
      const station = url.searchParams.get("station");
      if (!station) return send(res, 400, { error: "station is required" });
      return send(res, 200, { rows: await history(station, Number(url.searchParams.get("days") ?? "2")) });
    }
    if (url.pathname === "/latest" && req.method === "GET") {
      const station = url.searchParams.get("station");
      if (!station) return send(res, 400, { error: "station is required" });
      return send(res, 200, { rows: await latestInfo(station) });
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    const status = e instanceof ClipError ? e.status : 500;
    log(`[http] ${req.method} ${url.pathname}${url.search} -> ${status}: ${e.message}`);
    if (!res.headersSent) send(res, status, { error: e.message });
  }
}).listen(PORT, () => log(`listening on :${PORT}; events -> ${ATLAS_EVENTS_URL}; cameras ${JSON.stringify(CAMERAS)}`));

eufy.on("event", onEvent);
eufy.on("pushConnect", () => { state.push = true; log("[push] connected"); });
eufy.on("pushDisconnect", () => { state.push = false; log("[push] disconnected"); });
eufy.on("error", (e) => log("[client error]", e?.message ?? e));

for (let attempt = 1; ; attempt++) {
  try { await login(); break; } catch (e) {
    log(`login failed (attempt ${attempt}): ${e.message}`);
    await new Promise((r) => setTimeout(r, Math.min(300_000, 15_000 * attempt)));
  }
}
