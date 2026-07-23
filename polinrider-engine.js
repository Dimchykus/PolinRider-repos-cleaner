/* ════════════════════════════════════════════════════════════════════
 *  PolinRider detection & recovery engine  (shared by all pages)
 *
 *  This is the SINGLE SOURCE OF TRUTH for PolinRider indicators of
 *  compromise and for the scan / restore logic. Both the single-repo tool
 *  (github-recovery-tool.html) and the fleet scanner (fleet-scan.html)
 *  import it via  window.PolinRider  so detection can never drift between
 *  pages.
 *
 *  Every network request goes ONLY to https://api.github.com using the
 *  token the user supplies. Nothing is sent anywhere else. Detection reads
 *  file *contents* over the REST API and matches known IOCs — it never runs
 *  any script supplied by the malware or its repository.
 * ════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  const API = "https://api.github.com";

  // ── PolinRider IOC SIGNATURES (high-signal, low false-positive) ──
  const SIGNATURES = [
    { label: "PolinRider marker (v1 mar-2026)", str: "rmcej%otb%" },
    { label: "PolinRider marker (v2 apr-2026)", str: "Cot%3t=shtP" },
    { label: "XOR payload key", str: "2[gWfGj;<:-93Z^C" },
    { label: "obfuscated decoder _$_hex", re: /_\$_[0-9a-fA-F]{2,8}\s*=\s*\(function/ },
    { label: "global['!'] injection", re: /global\s*\[\s*'!'\s*\]\s*=/ },
    { label: "global['_V'] version tag", re: /global\s*\[\s*'_V'\s*\]\s*=\s*['"]8-/ },
    { label: "atob(process.env) C2 loader", re: /atob\s*\(\s*process\.env/ },
    { label: "eval(await …) stage-2 exec", re: /eval\s*\(\s*await\b/ },
    { label: "node-fetch C2 fetch", re: /require\s*\(\s*['"]node-fetch['"]\s*\)/ },
    { label: "Vercel C2 endpoint", re: /[a-z0-9.-]+\.vercel\.app\/(settings|api)\b/i },
    { label: "TRON dead-drop address", re: /T(?:MfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|XfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG)/ },
    { label: "TRON RPC (trongrid)", re: /api\.trongrid\.io\/v1\/accounts/ },
    { label: "Aptos RPC dead-drop", re: /fullnode\.mainnet\.aptoslabs\.com\/v1\/accounts/ },
    { label: ".vscode auto-run task", re: /task\.allowAutomaticTasks|["']runOn["']\s*:\s*["']folderOpen["']/ },
    { label: "runs fake-font as node script", re: /node\s+\.?\/?[^"'\s]*fonts\/[^"'\s]*\.woff2?/ },
    { label: ".gitignore concealment of engine", re: /(temp_auto_push|temp_interactive_push|config)\.bat|branch_structure\.json/ },
  ];

  // Malicious npm packages seen dropping the loader (checked in package.json / lockfiles).
  const BAD_PACKAGES = [
    "tailwindcss-style-animate", "tailwind-mainanimation", "tailwind-autoanimation",
    "tailwind-animationbased", "tailwindcss-typography-style", "tailwindcss-style-modify",
    "tailwindcss-animate-style",
  ];

  // ── Which files are worth reading for each branch ──
  const CONFIG_RE   = /(^|\/)(postcss|tailwind|eslint|next|vite|webpack|rollup|svelte|gridsome|vue|astro|babel|drizzle|truffle)\.config\.(js|cjs|mjs|ts)$/i;
  const ENTRY_RE    = /(^|\/)(App|index)\.(js|jsx|ts|tsx)$/; // low-confidence: only flags if a SIGNATURE also matches
  const VSCODE_RE   = /(^|\/)\.vscode\/(tasks|settings)\.json$/;
  const GITIGNORE_RE = /(^|\/)\.gitignore$/;
  const FONT_RE     = /(^|\/)(public|static|assets)\/.*\.(woff2?|ttf|otf)$/i;
  const PKG_RE      = /(^|\/)(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/;
  // Presence alone = high-confidence compromise (the re-infection engine committed into the repo).
  const ARTIFACT_RE = /(^|\/)(temp_auto_push\.bat|temp_interactive_push\.bat|config\.bat|branch_structure\.json)$/i;

  const MAX_FILES_PER_BRANCH = 80; // cap blob fetches per branch to stay under rate limits
  const MAX_ACTIVITY_PAGES = 3;    // 300 activity entries back per repo

  // ── pure helpers ──
  function escHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function shortSha(sha) { return sha ? sha.substring(0, 12) : "—"; }
  function allZero(sha) { return !sha || /^0+$/.test(sha); }

  function decodeBlob(b64) {
    const clean = (b64 || "").replace(/\s/g, "");
    let raw = "";
    try { raw = atob(clean); } catch (e) { return { raw: "", text: "" }; }
    let text = raw;
    try { text = decodeURIComponent(escape(raw)); } catch (e) { /* keep raw */ }
    return { raw, text };
  }
  function hasFontMagic(raw) {
    const m4 = raw.slice(0, 4);
    return m4 === "wOF2" || m4 === "wOFF" || m4 === "OTTO" || m4 === "true" ||
           m4 === "ttcf" || m4 === "\x00\x01\x00\x00";
  }

  // Given a file path + decoded content, return the list of IOC labels that fire.
  function matchFile(path, raw, text) {
    const hits = [];
    for (const sig of SIGNATURES) {
      const found = sig.str ? text.indexOf(sig.str) !== -1 : sig.re.test(text);
      if (found) hits.push(sig.label);
    }
    if (FONT_RE.test(path) && raw && !hasFontMagic(raw)) {
      hits.push("fake font — JS payload in a .woff2/.ttf/.otf, not a real font");
    }
    if (PKG_RE.test(path)) {
      for (const p of BAD_PACKAGES) {
        if (text.indexOf('"' + p + '"') !== -1 || text.indexOf(p + "@") !== -1) {
          hits.push("malicious npm dependency: " + p);
        }
      }
    }
    return hits;
  }

  function isCandidate(path) {
    return CONFIG_RE.test(path) || ENTRY_RE.test(path) || VSCODE_RE.test(path) ||
           GITIGNORE_RE.test(path) || FONT_RE.test(path) || PKG_RE.test(path);
  }

  // ════════════════════════════════════════════════════════════════════
  //  Client — everything that needs the token. One per session.
  // ════════════════════════════════════════════════════════════════════
  function createClient(token) {
    const fileHitCache = new Map(); // key: `${owner}/${repo}:${ref}:${path}` -> hits[]

    function headers() {
      return {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      };
    }

    async function api(path, opts = {}) {
      const r = await fetch(API + path, {
        ...opts,
        headers: { ...headers(), ...(opts.headers || {}) },
      });
      if (r.status === 404) return { notFound: true };
      if (r.status === 403 && r.headers.get("x-ratelimit-remaining") === "0") {
        const reset = r.headers.get("x-ratelimit-reset");
        throw new Error(
          "GitHub rate limit hit. Resets ~" +
            (reset ? new Date(reset * 1000).toLocaleTimeString() : "soon") + ".",
        );
      }
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.message || `HTTP ${r.status} on ${path}`);
      }
      if (r.status === 204) return null;
      return r.json();
    }

    // ── Discover every repo the token can reach ──
    async function listRepos() {
      const repos = [];
      for (let page = 1; page <= 50; page++) {
        const list = await api(
          `/user/repos?per_page=100&page=${page}&sort=pushed&affiliation=owner,collaborator,organization_member`,
        );
        if (!list || list.notFound || !list.length) break;
        for (const r of list) {
          repos.push({
            fullName: r.full_name,
            owner: r.owner.login,
            name: r.name,
            private: r.private,
            fork: r.fork,
            archived: r.archived,
            defaultBranch: r.default_branch,
            pushedAt: r.pushed_at,
            canPush: !!(r.permissions && r.permissions.push),
          });
        }
        if (list.length < 100) break;
      }
      return repos;
    }

    async function listBranches(owner, repo) {
      const branches = [];
      for (let page = 1; page <= 20; page++) {
        const list = await api(`/repos/${owner}/${repo}/branches?per_page=100&page=${page}`);
        if (!list || list.notFound || !list.length) break;
        branches.push(...list);
        if (list.length < 100) break;
      }
      return branches;
    }

    async function fileHitsAtRef(owner, repo, path, ref) {
      const key = `${owner}/${repo}:${ref}:${path}`;
      if (fileHitCache.has(key)) return fileHitCache.get(key);
      let hits = [];
      try {
        const encPath = path.split("/").map(encodeURIComponent).join("/");
        const res = await api(`/repos/${owner}/${repo}/contents/${encPath}?ref=${ref}`);
        if (res && !res.notFound && res.content) {
          const { raw, text } = decodeBlob(res.content);
          hits = matchFile(path, raw, text);
        }
      } catch (e) { /* unreadable -> treat as no-hit; boundary logic stays conservative */ }
      fileHitCache.set(key, hits);
      return hits;
    }

    async function isInfectedAt(owner, repo, sha, paths) {
      if (allZero(sha)) return false;
      for (const p of paths) {
        const hits = await fileHitsAtRef(owner, repo, p, sha);
        if (hits.length) return true;
      }
      return false;
    }

    // ── Scan one branch's HEAD tree ──
    async function scanBranch(owner, repo, headSha) {
      const commit = await api(`/repos/${owner}/${repo}/git/commits/${headSha}`);
      if (!commit || commit.notFound) return { files: [], artifacts: [], truncated: false };
      const tree = await api(`/repos/${owner}/${repo}/git/trees/${commit.tree.sha}?recursive=1`);
      if (!tree || tree.notFound) return { files: [], artifacts: [], truncated: false };

      const artifacts = [];
      const candidates = [];
      for (const node of tree.tree || []) {
        if (node.type !== "blob") continue;
        if (ARTIFACT_RE.test(node.path)) { artifacts.push(node.path); continue; }
        if (isCandidate(node.path)) candidates.push(node);
      }

      const files = [];
      let scanned = 0;
      for (const node of candidates) {
        if (scanned >= MAX_FILES_PER_BRANCH) break;
        scanned++;
        try {
          const blob = await api(`/repos/${owner}/${repo}/git/blobs/${node.sha}`);
          if (!blob || blob.notFound) continue;
          const { raw, text } = decodeBlob(blob.content);
          const hits = matchFile(node.path, raw, text);
          if (hits.length) {
            files.push({ path: node.path, iocs: hits });
            fileHitCache.set(`${owner}/${repo}:${headSha}:${node.path}`, hits);
          }
        } catch (e) { /* skip unreadable blob */ }
      }
      return {
        files,
        artifacts,
        truncated: !!tree.truncated || candidates.length > MAX_FILES_PER_BRANCH,
      };
    }

    // ── Server-side Activity log for a branch (timestamps NOT spoofable) ──
    async function branchActivity(owner, repo, branchName) {
      const ref = "refs/heads/" + branchName;
      const wanted = new Set(["push", "force_push", "branch_creation", "pr_merge", "merge_queue_merge"]);
      const out = [];
      for (let page = 1; page <= MAX_ACTIVITY_PAGES; page++) {
        let list;
        try {
          list = await api(`/repos/${owner}/${repo}/activity?per_page=100&page=${page}`);
        } catch (e) { break; }
        if (!list || list.notFound || !list.length) break;
        for (const a of list) if (a.ref === ref && wanted.has(a.activity_type)) out.push(a);
        if (list.length < 100) break;
      }
      out.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)); // ascending by trustworthy server time
      return out;
    }

    // ── Find the correct pre-infection commit for an infected branch ──
    async function findCleanTarget(owner, repo, branchName, headSha, infectedPaths) {
      const acts = await branchActivity(owner, repo, branchName);
      if (!acts.length) {
        return { sha: null, verified: false, reason: "no push activity available (token lacks access, or activity older than the retention window)" };
      }
      for (const ev of acts) {
        const afterInfected = await isInfectedAt(owner, repo, ev.after, infectedPaths);
        if (!afterInfected) continue; // still clean at this point
        if (allZero(ev.before)) {
          return { sha: null, verified: false, reason: "branch was created already infected (no clean predecessor exists on this branch)", via: ev };
        }
        const beforeInfected = await isInfectedAt(owner, repo, ev.before, infectedPaths);
        if (beforeInfected) {
          return { sha: null, verified: false, reason: "infection predates the visible activity window — earliest known predecessor is also infected", via: ev };
        }
        return { sha: ev.before, verified: true, via: ev };
      }
      const lastClean = [...acts].reverse().find((ev) => ev.after && !allZero(ev.after));
      return {
        sha: lastClean ? lastClean.after : null,
        verified: false,
        reason: "HEAD is infected but no clean→infected transition was found in the activity window; the suggested SHA is the newest recorded tip and must be verified manually",
      };
    }

    // ── Scan an entire repo. onProgress(index, total, branchName) is optional. ──
    async function scanRepo(owner, repo, onProgress) {
      const branches = await listBranches(owner, repo);
      const findings = [];
      for (let i = 0; i < branches.length; i++) {
        const b = branches[i];
        if (onProgress) onProgress(i, branches.length, b.name);
        try {
          const head = b.commit.sha;
          const { files, artifacts, truncated } = await scanBranch(owner, repo, head);
          if (!files.length && !artifacts.length) continue;
          const infectedPaths = files.map((f) => f.path);
          const target = infectedPaths.length
            ? await findCleanTarget(owner, repo, b.name, head, infectedPaths)
            : { sha: null, verified: false, reason: "only repo artifacts found (no infected tracked file to bound); restore target must be chosen manually" };
          findings.push({ owner, repo, branch: b.name, head, files, artifacts, target, truncated });
        } catch (e) {
          findings.push({ owner, repo, branch: b.name, head: b.commit ? b.commit.sha : null, files: [], artifacts: [], scanError: e.message, target: { sha: null, verified: false, reason: "scan error: " + e.message } });
        }
      }
      return { branchCount: branches.length, findings };
    }

    // ── Restore ONE branch to a clean SHA. Never throws. { ok, msg, tipInfected } ──
    async function restore(owner, repo, branch, sha, infectedPaths) {
      const paths = infectedPaths || [];
      try {
        if (paths.length) {
          const stillInfected = await isInfectedAt(owner, repo, sha, paths);
          if (stillInfected) return { ok: false, msg: "target SHA re-checked as INFECTED — refused" };
        }
        const r = await fetch(
          `${API}/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`,
          { method: "PATCH", headers: { ...headers(), "Content-Type": "application/json" }, body: JSON.stringify({ sha, force: true }) },
        );
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          return { ok: false, msg: err.message || `HTTP ${r.status}` };
        }
        let tipInfected = false;
        if (paths.length) {
          for (const [k] of fileHitCache) if (k.startsWith(`${owner}/${repo}:${sha}:`)) fileHitCache.delete(k);
          tipInfected = await isInfectedAt(owner, repo, sha, paths);
        }
        return { ok: true, tipInfected, msg: `restored to ${shortSha(sha)}${paths.length ? (tipInfected ? " (⚠ tip still flags IOCs — investigate!)" : " (tip verified clean)") : ""}` };
      } catch (err) {
        return { ok: false, msg: err.message };
      }
    }

    return {
      api, listRepos, listBranches, scanBranch, branchActivity,
      findCleanTarget, isInfectedAt, scanRepo, restore,
    };
  }

  window.PolinRider = {
    SIGNATURES, BAD_PACKAGES, createClient,
    escHtml, shortSha, allZero, matchFile, decodeBlob, isCandidate,
  };
})();
