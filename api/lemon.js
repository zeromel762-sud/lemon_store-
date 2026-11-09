const crypto = require("crypto");

function findEnv(suffix) {
  const direct = process.env["UPSTASH_REDIS_REST_" + suffix] || process.env["KV_REST_API_" + suffix];
  if (direct) return direct;
  const k = Object.keys(process.env).find(
    (n) => (n.endsWith("REST_API_" + suffix) || n.endsWith("REDIS_REST_" + suffix)) && process.env[n]
  );
  return k ? process.env[k] : undefined;
}
const URL_ = findEnv("URL");
const TOKEN = findEnv("TOKEN");
const SECRET = process.env.AUTH_SECRET || TOKEN || "change-me";
const APPS = "lemon:apps";
const CFG = "lemon:cfg";

async function redis(cmd) {
  const r = await fetch(URL_, {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const sign = (p) => {
  const d = Buffer.from(JSON.stringify(p)).toString("base64url");
  return d + "." + crypto.createHmac("sha256", SECRET).update(d).digest("base64url");
};
function verify(t) {
  if (!t) return false;
  const [d, m] = t.split(".");
  if (!d || !m) return false;
  const e = crypto.createHmac("sha256", SECRET).update(d).digest("base64url");
  const a = Buffer.from(m), b = Buffer.from(e);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(d, "base64url").toString()).exp > Date.now(); } catch { return false; }
}
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
function same(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
async function passwordOk(pw) {
  const raw = await redis(["GET", CFG]);
  if (!raw) return same(pw, "123");
  const cfg = JSON.parse(raw);
  return same(hashPw(pw, cfg.salt), cfg.hash);
}
async function list() {
  const v = (await redis(["HVALS", APPS])) || [];
  return v.map((x) => { try { return JSON.parse(x); } catch { return null; } }).filter(Boolean);
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    if (!URL_ || !TOKEN)
      return res.status(500).json({ error: "Storage is not connected. Add Upstash Redis in the Vercel Storage tab, then redeploy." });

    if (req.method === "GET") return res.status(200).json({ apps: await list() });
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed." });

    const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};

    if (b.action === "login") {
      const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
      const key = "lemon:fail:" + ip;
      if (Number(await redis(["GET", key])) >= 8)
        return res.status(429).json({ error: "Too many tries. Wait 10 minutes and try again." });
      const ok = String(b.username || "").trim().toLowerCase() === "admin" && (await passwordOk(String(b.password || "")));
      if (!ok) {
        await redis(["INCR", key]);
        await redis(["EXPIRE", key, 600]);
        return res.status(401).json({ error: "Wrong username or password." });
      }
      await redis(["DEL", key]);
      return res.status(200).json({ token: sign({ exp: Date.now() + 12 * 3600 * 1000 }) });
    }

    const auth = String(req.headers.authorization || "").replace(/^Bearer /, "");
    if (!verify(auth)) return res.status(401).json({ error: "Please log in again." });

    if (b.action === "add") {
      const name = String(b.name || "").trim();
      let link;
      try { link = new URL(String(b.link || "")); } catch { link = null; }
      const icon = String(b.icon || "");
      if (!name || name.length > 60) return res.status(400).json({ error: "Enter a name up to 60 characters." });
      if (!link || !/^https?:$/.test(link.protocol)) return res.status(400).json({ error: "Enter a valid http or https link." });
      if (!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(icon) || icon.length > 250000)
        return res.status(400).json({ error: "Icon is invalid or too large." });
      const id = Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
      await redis(["HSET", APPS, id, JSON.stringify({ id, name, link: link.href, icon, createdAt: Date.now() })]);
      return res.status(200).json({ apps: await list() });
    }
    if (b.action === "delete") {
      await redis(["HDEL", APPS, String(b.id || "")]);
      return res.status(200).json({ apps: await list() });
    }
    if (b.action === "password") {
      const pw = String(b.newPassword || "");
      if (pw.length < 3 || pw.length > 100) return res.status(400).json({ error: "Use 3 to 100 characters." });
      const salt = crypto.randomBytes(16).toString("hex");
      await redis(["SET", CFG, JSON.stringify({ salt, hash: hashPw(pw, salt) })]);
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "Unknown action." });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error." });
  }
};
