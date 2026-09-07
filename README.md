# Reflix

**Smart parameter injection & reflection fuzzing tool**

Reflix takes a list of target URLs and answers one question at scale: *"where does user-controlled input come back unescaped?"* It discovers hidden parameters, injects a unique canary value into query strings, URL paths, and request headers, then checks the raw HTTP response for that canary — flagging reflections, and optionally following up with a lightweight XSS probe.

No browser, no Playwright, no rendering — everything runs over plain HTTP requests, which makes it fast, lightweight, and easy to run at scale (CI, VPS, bug bounty recon boxes, whatever).

```
[REFLIX-GET] [http] [medium] [HTML] https://target.com/search?q=%27nexovir
```

---

## Table of Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Scan stages, in order](#scan-stages-in-order)
- [Static asset filtering](#static-asset-filtering)
- [Full flag reference](#full-flag-reference)
- [Output formats](#output-formats)
- [DOM source/sink scanning](#dom-sourcesink-scanning)
- [Recipes](#recipes)
- [Notes & caveats](#notes--caveats)
- [Legal / ethical use](#legal--ethical-use)

---

## How it works

1. **Discover** — [`fallparams`](https://github.com/ImAyrix/fallparams) crawls each target and extracts every parameter name it can find (query strings, forms, inline JS, etc.).
2. **Inject** — Reflix builds candidate URLs with a canary value (default: `nexovir`) dropped into those parameters, plus URL paths and common request headers if you ask it to.
3. **Verify** — Each candidate is sent through [`nuclei`](https://github.com/projectdiscovery/nuclei) (for query-string reflections) or a plain `requests` call (for path/header reflections), and the response body/headers are checked for the canary.
4. **Escalate** — On a confirmed reflection, `-xt` swaps the canary for `'`, `"`, and `>` and checks whether any of them survive unescaped — a strong signal of exploitable XSS, not just "your input showed up somewhere."
5. **Report** — Every hit is printed live, and can optionally be written to a findings file and/or a clean JSON array.

---

## Installation

```bash
pip install pyfiglet colorama pyyaml requests --break-system-packages
```

You also need these two on your `PATH`:

| Tool | Purpose | Install |
|---|---|---|
| [`fallparams`](https://github.com/ImAyrix/fallparams) | Parameter discovery | `go install github.com/ImAyrix/fallparams@latest` |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | Templated reflection scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> Reflix does **not** need Playwright or a headless browser — all reflection checks run over plain HTTP.

---

## Quick start

```bash
python3 reflix.py -l urls.txt
```

That's it — this runs parameter discovery + query-string reflection fuzzing on every URL in `urls.txt`, printing findings live to the console.

A more complete run:

```bash
python3 reflix.py -l urls.txt \
  -w params.txt \
  -pi -hi -xt -sd \
  -t 20 \
  -jo findings.json
```

This discovers + fuzzes params, also tries path injection (`-pi`), header injection (`-hi`), follows every hit with an XSS probe (`-xt`), scans page source for DOM XSS sinks (`-sd`), runs 20 tasks concurrently, and dumps everything to a clean `findings.json` at the end.

---

## Scan stages, in order

| Stage | Runs by default? | Flag | What it does |
|---|---|---|---|
| **Static Reflix** | ✅ always | — | Builds candidate URLs (existing query params + your wordlist) and reflection-tests them via `nuclei`. |
| **Light Reflix** | ✅ always | — | Per URL: runs `fallparams` to discover parameters, then fuzzes *that URL's own* discovered params. Also runs `-sd` DOM scan here if enabled. |
| **Path Injection** | ❌ opt-in | `-pi` | Appends the canary to the URL path (`/search` → `/searchnexovir`) and checks body + response headers for reflection. |
| **Header Injection** | ❌ opt-in | `-hi` | Sends the canary in a batch of commonly-trusted headers (`X-Forwarded-For`, `X-Original-URL`, `Referer`, ...) in one request and checks for reflection. |
| **Heavy Reflix** | ❌ opt-in | `-hv` | Takes *every unique parameter discovered anywhere in the whole run* and re-tests it against *every* fuzzable URL — not just the URL it came from. Much more expensive; see below. |

### What "Heavy" actually buys you

Say `fallparams` found `token` on URL A and `search` on URL B. Without `-hv`, A only ever gets tested with `token`, and B only with `search`. With `-hv`, after everything else finishes, Reflix pools `{token, search}` and fires *both* at A, B, and every other fuzzable URL — catching cases where a parameter only shows up in one place (e.g. buried in a `.js` file) but is actually honored everywhere. The cost is roughly:

```
requests ≈ (fuzzable URLs) × (unique params ÷ chunk size)
```

so it's off by default — turn it on when you want thoroughness over speed.

---

## Static asset filtering

Reflix automatically classifies every URL before doing anything expensive with it:

| Category | Examples | Discovery (`fallparams`) | DOM scan (`-sd`) | Fuzzing / injection |
|---|---|:---:|:---:|:---:|
| **Binary assets** | `.png` `.jpg` `.woff2` `.mp4` `.zip` `.pdf` `.docx` ... | ❌ | ❌ | ❌ |
| **Static text assets** | `.js` `.mjs` `.css` `.map` | ✅ | ✅ | ❌ |
| **Everything else** | `.php` `.html` `.aspx`, extensionless API paths, etc. | ✅ | ✅ | ✅ |

Reasoning: a server ignores query strings on a static `.js`/`.css` file, so fuzzing it just burns requests for nothing — but the *file itself* is exactly where `fallparams` finds real API parameter names, and exactly where the DOM sink scanner finds real `eval()`/`innerHTML` usage. Binary files (images, fonts, archives, office docs) get skipped entirely since there's no text to parse.

On startup you'll see a summary like:

```
[*] 340 URLs loaded — 58 binary asset(s) skipped entirely, 71 static JS/CSS/map file(s) kept for parameter discovery only (no fuzzing).
```

---

## Full flag reference

### Input
| Flag | Description |
|---|---|
| `-l, --urls-path` **(required)** | File with one target URL per line |
| `-p, --parameter` | Canary value used to detect reflection (default: `nexovir`) |
| `-w, --wordlist` | File of extra parameter names to fuzz |

### Request configuration
| Flag | Description |
|---|---|
| `-X, --methods` | Comma-separated HTTP methods (default: `GET,POST`) |
| `-H, --headers` | Custom header `"Name: value"` — repeatable, e.g. `-H "User-Agent: mac" -H "Accept: html"` |
| `-x, --proxy` | HTTP/SOCKS proxy, e.g. `http://127.0.0.1:8080` (great for routing through Burp) |
| `-c, --chunk` | Parameters per batched request (default: `25`) |
| `-vm, --value-mode` | `append` or `replace` an existing query value (default: `append`) |
| `-gm, --generate-mode` | `root` / `ignore` / `combine` / `all` — how candidate URLs are built in Static Reflix (default: `all`) |
| `-to, --timeout` | Per-request timeout in seconds (default: `15`) |

### Scan modules
| Flag | Description |
|---|---|
| `-sd, --dom-scan` | Keyword-scan the raw response body for known DOM source/sink APIs, with line numbers |
| `-xt, --xss-test` | On every confirmed reflection, also probe with `'`, `"`, `>` payloads |
| `-pi, --path-injection` | Test reflection via URL path injection |
| `-hi, --header-injection` | Test reflection via common request headers |
| `-hw, --header-wordlist` | File of extra header names to add to the header-injection test set |
| `-hv, --heavy` | Re-fuzz every URL with every parameter discovered anywhere in the run |

### Rate limiting
| Flag | Description |
|---|---|
| `-t, --threads` | Max concurrent tasks (default: `1`) |
| `-rd, --delay` | Seconds to wait after each task completes (default: `0`) |

### Notification & logging
| Flag | Description |
|---|---|
| `-n, --notify` | Send errors/summary to Telegram — needs `BOT_TOKEN` and `BOT_CHAT_ID` env vars (no defaults are hardcoded) |
| `-lf, --log-file` | Optional log file path — **off by default** |
| `-s, --silent` | Suppress the banner and informational console output |
| `-v, --verbose` | Print INFO/DEBUG status messages to the console (findings are *always* printed regardless of this flag) |

### Outputs
| Flag | Description |
|---|---|
| `-o, --output` | Optional file to also write confirmed findings to — off by default |
| `-po, --params-output` | Optional file to also write discovered parameters to — off by default; `--heavy` works from in-memory state either way |
| `-jo, --json-output` | Export every finding as one clean JSON array |

---

## Output formats

**Console (always on):**
```
[GET] [http] [medium] [HTML] https://target.com/?q=%27nexovir
[GET] [http] [info] [Common-Sources: document.cookie@L10 location.hash@L9] https://target.com/app.js
```

**JSON (`-jo findings.json`)** — clean, structured, no ANSI color codes:
```json
[
  {
    "method": "GET",
    "severity": "medium",
    "place": "HTML",
    "url": "https://target.com/?q=%27nexovir"
  },
  {
    "method": "GET",
    "severity": "info",
    "place": "Common-Sources",
    "url": "https://target.com/app.js",
    "sinks": [
      { "keyword": "document.cookie", "lines": [10] },
      { "keyword": "location.hash", "lines": [9] }
    ]
  }
]
```

**End-of-run summary** (always shown unless `-s`):
```
[+] Done. 47 finding(s), 812 parameter(s) discovered.
[+] Findings also written to findings.output
```

By default, running Reflix writes **nothing to disk** except what you explicitly ask for with `-o`, `-po`, `-jo`, or `-lf` — clean for CI pipelines and quick one-off scans alike.

---

## DOM source/sink scanning

`-sd` fetches each page's raw HTML (no rendering) and keyword-scans it against a reference list of DOM XSS sources and sinks compiled from PortSwigger's DOM-XSS cheat sheet, the `domxsswiki` project, and common framework taint sinks (jQuery, Angular, Vue, React). Categories include:

- `Common-Sources` — `location`, `document.cookie`, `window.name`, `localStorage`, ...
- `Message-Event-Sources` — `postMessage`, `onmessage`, `BroadcastChannel`
- `DOM-XSS-Sinks` — `innerHTML`, `document.write`, `insertAdjacentHTML`, ...
- `Open-Redirection-Sinks` — `location.href`, `window.open`, ...
- `Client-Side-Template-Injection-Sinks` — `dangerouslySetInnerHTML`, `v-html`, `ng-bind-html`, `$sce.trustAsHtml`, ...
- `jQuery-Sinks` — `.html()`, `.append()`, `.before()`, ...
- ...and several more (see `DOM_SOURCES_AND_SINKS` in the source).

Every hit reports the **exact line number(s)** it was found on, so you can jump straight to it instead of grepping the page yourself.

> This is a keyword scan over static HTML/JS, not real taint analysis — it tells you where to *look*, not that a vulnerability definitely exists. Treat hits as leads for manual review.

---

## Recipes

**Fast, quiet triage of a huge URL list:**
```bash
python3 reflix.py -l urls.txt -t 30 -s -jo results.json
```

**Full audit of a single app, through Burp:**
```bash
python3 reflix.py -l urls.txt -x http://127.0.0.1:8080 -pi -hi -xt -sd -v
```

**Custom headers + extended header-injection wordlist:**
```bash
python3 reflix.py -l urls.txt -H "User-Agent: mac" -H "Accept: html" \
  -hi -hw extra_headers.txt
```

**Thorough pass, willing to pay in requests:**
```bash
python3 reflix.py -l urls.txt -w big_wordlist.txt -pi -hi -hv -xt -sd -t 10
```

---

## Notes & caveats

- No headless browser is used anywhere — reflection checks read the raw HTTP response, not a rendered DOM. This is faster and dependency-light, but it won't catch reflections that only appear after client-side JavaScript execution.
- `-o`/`-po`/`-lf` are all opt-in; nothing is written to disk unless you ask.
- `-n/--notify` will **not** silently phone home — it only fires if you've explicitly set `BOT_TOKEN` and `BOT_CHAT_ID`.
- `verify=False` is used for HTTPS requests (labs and internal targets are frequently self-signed); the resulting `InsecureRequestWarning` spam is suppressed.

---

## Legal / ethical use

Reflix sends real HTTP traffic — including injected payloads — to whatever URLs you point it at. Only run it against systems you own or are explicitly authorized to test (e.g. your own infrastructure, a sanctioned bug bounty scope, or a lab environment like PortSwigger's Web Security Academy). Scanning systems without authorization may be illegal in your jurisdiction.
