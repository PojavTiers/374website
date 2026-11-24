// InstaName Finder API backend
// Keeps your Apify API token on the server. Never put it in public/index.html.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

// Railway injects Variables directly into process.env. This optional .env
// loader is only a convenience for local development; Railway does not need it.
function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^["']|["']$/g, "");
  }
}
loadEnv();

const PORT = Number(process.env.PORT || 3000);
const APIFY_TOKEN = process.env.APIFY_TOKEN;
const ACTOR_ENDPOINT =
  "https://api.apify.com/v2/acts/instagram-data-api~instagram-username-checker/run-sync-get-dataset-items";

function send(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "same-origin"
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(body || "{}")); }
      catch { reject(new Error("Invalid JSON body")); }
    });
    req.on("error", reject);
  });
}

function normalizeRow(row) {
  const username = String(row.username || row.userName || "").replace(/^@/, "").toLowerCase();
  let status = String(row.status || "").toLowerCase();
  if (status !== "available" && status !== "taken") {
    if (row.exists === true || row.taken === true) status = "taken";
    else if (row.exists === false || row.taken === false) status = "available";
    else status = "unknown";
  }
  return {
    username,
    status,
    exists: typeof row.exists === "boolean" ? row.exists : (status === "taken" ? true : status === "available" ? false : null),
    fullName: row.fullName || row.full_name || null,
    followers: Number.isFinite(row.followers) ? row.followers : null,
    message: row.message || row.error || null
  };
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
    return res.end();
  }

  if (req.method === "POST" && req.url === "/api/check") {
    if (!APIFY_TOKEN) return send(res, 500, { error: "Missing APIFY_TOKEN. Add it to the .env file on the server." });

    try {
      const body = await readBody(req);
      const input = Array.isArray(body.usernames) ? body.usernames : [];
      const usernames = [...new Set(input.map(value =>
        String(value).trim().replace(/^@/, "").toLowerCase()
      ).filter(value => /^[a-z0-9._]{1,30}$/.test(value)))];

      if (!usernames.length) return send(res, 400, { error: "Add at least one valid username." });
      if (usernames.length > 500) return send(res, 400, { error: "Maximum 500 usernames per check. Split larger lists into batches." });

      const response = await fetch(`${ACTOR_ENDPOINT}?token=${encodeURIComponent(APIFY_TOKEN)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usernames }),
        signal: AbortSignal.timeout(120_000)
      });

      const raw = await response.text();
      if (!response.ok) {
        return send(res, response.status, {
          error: `Apify returned HTTP ${response.status}. Check your API token, Actor access and usage balance.`,
          details: raw.slice(0, 500)
        });
      }

      let rows;
      try { rows = JSON.parse(raw); }
      catch { return send(res, 502, { error: "Apify returned an unexpected response.", details: raw.slice(0, 500) }); }

      if (!Array.isArray(rows)) {
        return send(res, 502, { error: "Unexpected API response: expected a list of result rows.", details: JSON.stringify(rows).slice(0, 500) });
      }

      const results = rows.map(normalizeRow).filter(row => row.username);
      return send(res, 200, {
        results,
        checked: usernames.length,
        returned: results.length,
        note: "Availability is a point-in-time estimate. Instagram may reserve or block some names even when no public account uses them."
      });
    } catch (error) {
      const timeout = error.name === "TimeoutError" || error.name === "AbortError";
      return send(res, timeout ? 504 : 500, {
        error: timeout ? "The availability check timed out. Try a smaller batch." : error.message
      });
    }
  }

  if (req.method === "GET" && (req.url === "/" || req.url.startsWith("/?"))) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return fs.createReadStream(path.join(__dirname, "public", "index.html")).pipe(res);
  }

  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true });
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`InstaName Finder running at http://localhost:${PORT}`));
