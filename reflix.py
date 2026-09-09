#!/usr/bin/env python3
"""
Reflix - Smart parameter injection and reflection fuzzing tool

Requires external tools on PATH: fallparams, nuclei
(URL-injection generation is built in - no external `injector` tool needed)
Requires: pyfiglet, colorama, pyyaml, requests
    pip install pyfiglet colorama pyyaml requests --break-system-packages

Pipeline (in order):
  1. Parameter Discovery - fallparams runs on every non-binary URL (incl.
     .js/.css) to find real parameter names actually used by that page/script.
  2. DOM Scan (optional, -sd) - keyword scan for known DOM XSS source/sink
     API names in the raw response body.
  3. Reflection Fuzz - every fuzzable URL is tested with the parameters
     discovered ON THAT URL in phase 1, merged with the optional -w/--wordlist
     seed list. If neither produced anything for a given URL, root/ignore
     injection is skipped for it entirely (no meaningless canary-as-param
     noise) - only 'combine' mode (mutating a param the URL's query string
     already has) still runs, since that never needed a wordlist to begin
     with.
  4. Path Injection (optional, -pi) / Header Injection (optional, -hi).
  5. Heavy Reflix (optional, -hv) - cross-pollination pass: every fuzzable
     URL is re-tested against the UNION of every parameter discovered across
     ALL urls this run (+ the -w seed), not just its own. Most expensive
     stage by design, hence opt-in.

All reflection checks (body, path, header, DOM source/sink keyword scan) are
done with plain HTTP requests against the raw response body/headers - no
headless browser needed.

--- Per-parameter canary numbering ---
When multiple wordlist parameters get batched into the same chunked
root/ignore request, each parameter is given its OWN numbered canary value
(param1=nexovir1&param2=nexovir2&...) instead of an identical canary for
every parameter. This costs zero extra requests - it's just what value gets
written into the URL that was going to be built anyway. Because every
numbered canary still contains the base canary string as a substring (e.g.
"nexovir7" contains "nexovir"), nuclei's existing word-matcher keeps working
unchanged. Only when nuclei reports a match on a request does the tool look
at the raw response body it already captured (no extra fetch) and figure out
exactly which parameter's numbered value actually appears in it, so the
finding line can say precisely which parameter(s) reflected instead of "some
parameter in this chunk reflected, go find out which one yourself".
"""

import colorama
import time
import subprocess
import requests
import argparse
import os
import random
import pyfiglet
import yaml
import tempfile
import asyncio
import json
import itertools
import urllib3
from colorama import Fore, Style
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

colorama.init()

# We intentionally set verify=False (targets are often self-signed / lab
# environments like PortSwigger Web Security Academy). Silence the resulting
# per-request InsecureRequestWarning spam instead of showing it on every hit.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

green = '\033[92m'
blue = '\033[94m'
cyan = '\033[34m'
yellow = '\033[33m'
red = '\033[91m'
magenta = '\033[95m'
bold = '\033[1m'
dim = '\033[2m'
reset = '\033[0m'

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Expanded DOM XSS source/sink reference list.
# Compiled from the commonly cited public references: PortSwigger's DOM-XSS
# cheat sheet, the wisec/domxsswiki project, HackTricks' DOM XSS page, and
# framework-specific taint sinks (jQuery/Angular/Vue/React). This is used for
# a simple keyword scan over the raw response body - it is not a substitute
# for real taint analysis, but flags pages worth a closer manual look.
DOM_SOURCES_AND_SINKS = {
    'Common-Sources': [
        'document.url', 'document.documenturi', 'document.urlunencoded',
        'document.baseuri', 'document.cookie', 'document.referrer',
        'window.name', 'history.pushstate', 'history.replacestate',
        'history.state', 'localstorage', 'sessionstorage', 'indexeddb',
        'database', 'location', 'location.hash', 'location.search',
        'location.href', 'urlsearchparams', 'window.location',
    ],
    'Message-Event-Sources': [
        'addeventlistener(\'message', 'addeventlistener("message',
        'onmessage', 'postmessage', 'window.onmessage',
        'broadcastchannel', 'sharedworker',
    ],
    'DOM-XSS-Sinks': [
        'document.write', 'document.writeln', 'document.domain',
        '.innerhtml', '.outerhtml', '.insertadjacenthtml', '.onevent',
        'document.body.innerhtml', 'document.body.outerhtml',
        'insertadjacentelement', 'createcontextualfragment',
        'domparser', 'parsefromstring', 'document.implementation',
    ],
    'Open-Redirection-Sinks': [
        'location', 'location.host', 'location.hostname', 'location.href',
        'location.pathname', 'location.search', 'location.protocol',
        'location.assign', 'location.replace', 'open(', 'element.srcdoc',
        'xmlhttprequest.open', 'xmlhttprequest.send', 'jquery.ajax', '$.ajax',
        'window.open', 'top.location', 'self.location', 'parent.location',
    ],
    'Cookie-Manipulation-Sink': ['document.cookie'],
    'JavaScript-Injection-Sinks': [
        'eval(', 'function(', 'settimeout', 'setinterval', 'setimmediate',
        'execcommand', 'execscript', 'mssetimmediate', 'new function',
        'range.createcontextualfragment', 'crypto.generatecrmfrequest',
        'importscripts', 'worker(', 'sharedworker(',
    ],
    'WebSocket-URL-Poisoning-Sink': ['websocket', 'new websocket'],
    'Link-Manipulation-Sinks': [
        'element.href', 'element.src', 'element.action', 'a.href',
        'iframe.src', 'form.action', 'base.href', 'embed.src', 'object.data',
    ],
    'Ajax-Request-Header-Manipulation-Sinks': [
        'xmlhttprequest.setrequestheader', 'xmlhttprequest.open',
        'xmlhttprequest.send', 'jquery.globaleval', '$.globaleval',
        'fetch(', 'navigator.sendbeacon',
    ],
    'Local-File-Path-Manipulation-Sinks': [
        'filereader.readasarraybuffer', 'filereader.readasbinarystring',
        'filereader.readasdataurl', 'filereader.readastext',
        'filereader.readasfile', 'filereader.root.getfile',
    ],
    'Client-Side-SQL-Injection-Sink': ['executesql', 'indexeddb.open'],
    'HTML5-Storage-Manipulation-Sinks': [
        'sessionstorage.setitem', 'localstorage.setitem',
        'sessionstorage.getitem', 'localstorage.getitem',
    ],
    'XPath-Injection-Sinks': ['document.evaluate', 'element.evaluate'],
    'Client-Side-JSON-Injection-Sinks': [
        'json.parse', 'jquery.parsejson', '$.parsejson', 'json.stringify',
    ],
    'Client-Side-Template-Injection-Sinks': [
        'dangerouslysetinnerhtml', 'v-html', 'ng-bind-html', '$sce.trustashtml',
        '$sce.trustasresourceurl', 'sce.trustasjs', 'ng-include',
        'templateurl', '{{constructor', '[[constructor',
    ],
    'jQuery-Sinks': [
        '.html(', '.append(', '.prepend(', '.before(', '.after(',
        '.wrap(', '.replacewith(', '.attr(', '.parsehtml',
    ],
    'DOM-Data-Manipulation-Sinks': [
        'script.src', 'script.text', 'script.textcontent', 'script.innertext',
        'element.setattribute', 'element.search', 'element.text',
        'element.textcontent', 'element.innertext', 'element.outertext',
        'element.value', 'element.name', 'element.target', 'element.method',
        'element.type', 'element.backgroundimage', 'element.csstext',
        'element.codebase', 'document.title', 'style.csstext',
        'document.implementation.createhtmldocument',
        'history.pushstate', 'history.replacestate',
    ],
    'Denial-Of-Service-Sinks': ['requestfilesystem', 'regexp'],
}

# Common headers worth testing for reflected-header injection.
# Can be extended at runtime with -hw/--header-wordlist.
HEADER_TEST_KEYS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Forwarded-Scheme", "X-Forwarded-Port", "X-Forwarded-Server",
    "X-Original-URL", "X-Rewrite-URL", "X-Host", "Referer",
    "X-Client-IP", "X-Real-IP", "X-Remote-IP", "X-Remote-Addr",
    "Origin", "True-Client-IP", "CF-Connecting-IP", "Forwarded",
]

# Pure binary assets: fetching/parsing these as text is meaningless, so they
# are dropped from the whole pipeline (discovery, DOM scan, and fuzzing).
BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.avif',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.wav', '.avi', '.mov', '.webm', '.ogg', '.flac',
    '.pdf', '.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.exe', '.dmg',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
}

# Static-but-textual assets (JS/CSS/sourcemaps): the server ignores query
# params on these, so injecting/fuzzing them wastes requests and never
# reflects anything. They ARE still worth crawling for parameter DISCOVERY
# though - fallparams pulls real API/param names straight out of JS source.
STATIC_TEXT_EXTENSIONS = {'.js', '.mjs', '.cjs', '.css', '.map'}

NON_FUZZABLE_EXTENSIONS = BINARY_EXTENSIONS | STATIC_TEXT_EXTENSIONS

# unique per-parameter canary counter for chunked root/ignore injection, so
# every parameter batched into the same request gets its own distinguishable
# value (param1=nexovir1&param2=nexovir2...) instead of an identical canary -
# this costs zero extra requests, it only changes what value is written into
# the URL that was going to be built anyway, and lets a hit be traced back to
# the exact parameter(s) that reflected once nuclei reports a match.
param_canary_counter = itertools.count(1)

# generated_url -> {param_name: canary_value}, populated by
# generate_injected_urls' append_wordlist_params(), consumed by
# run_nuclei_scan() ONLY on confirmed matches to identify which parameter(s)
# reflected - never touched on non-matching requests, so it adds no
# per-request overhead.
url_param_canaries = {}


def is_json_output_path(path):
    """True if the given -o/--output path should get a clean JSON array
    instead of the default plain-text line-per-finding log (i.e. it ends
    with .json). Lets '-o output.json' produce a full structured JSON
    export without needing the separate -jo flag."""
    return bool(path) and path.lower().endswith('.json')


def url_ext(url):
    return os.path.splitext(urlparse(url).path.lower())[1]


def is_binary_asset(url):
    """True for assets we should never fetch as text at all (images, fonts,
    media, archives, office docs, ...)."""
    return url_ext(url) in BINARY_EXTENSIONS


def is_fuzzable(url):
    """False for anything (binary assets or static JS/CSS/map files) that
    shouldn't go through parameter injection / reflection fuzzing."""
    return url_ext(url) not in NON_FUZZABLE_EXTENSIONS


def extract_meta(body_text, resp_headers):
    """Extract Content-Type and page size (bytes) from a response, used to
    enrich every finding with [content_type] [size_page] info."""
    content_type = ""
    for k, v in (resp_headers or {}).items():
        if k.lower() == "content-type":
            content_type = v.split(";")[0].strip()
            break
    size_page = len(body_text.encode('utf-8', errors='ignore')) if body_text is not None else 0
    return content_type, size_page


def parse_raw_http_response(raw_response):
    """Extract Content-Type and body size (bytes) straight out of nuclei's
    own captured raw response text (headers+body), so run_nuclei_scan never
    needs to fire a second HTTP request just to get this metadata - zero
    extra requests, faster, and no additional load on the target."""
    if not raw_response:
        return "", 0
    # headers/body are separated by the first blank line (CRLF or LF style)
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_response:
            head, _, body = raw_response.partition(sep)
            break
    else:
        head, body = raw_response, ""

    content_type = ""
    for line in head.splitlines():
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].split(";")[0].strip()
            break

    size_page = len(body.encode('utf-8', errors='ignore'))
    return content_type, size_page


def extract_raw_body(raw_response):
    """Same split logic as parse_raw_http_response, but returns just the
    body text. Used ONLY after nuclei already reported a match, to figure
    out which numbered per-parameter canary actually appears in the body
    that was already captured - no extra HTTP request involved."""
    if not raw_response:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_response:
            _, _, body = raw_response.partition(sep)
            return body
    return raw_response


def show_banner():
    banner = pyfiglet.figlet_format("Reflix")
    twitter = Style.BRIGHT + Fore.CYAN + "X.com: @nexovir" + Style.RESET_ALL
    version = Fore.LIGHTBLACK_EX + f"v{VERSION}" + Style.RESET_ALL
    total_width = 20
    twitter_centered = twitter.center(total_width)
    version_right = version.rjust(total_width)
    print(banner + twitter_centered + version_right + "\n")


def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: str = None,
                silent: bool = False):
    color = getattr(colorama.Fore, colour, colorama.Fore.YELLOW)
    if not silent and debug:
        print(color + message + colorama.Style.RESET_ALL)

    time_string = time.strftime("%d/%m/%Y, %H:%M:%S", time.localtime())
    if logger:
        try:
            log_dir = os.path.dirname(logger)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            with open(logger, 'a') as file:
                file.write(message + ' -> ' + time_string + '\n')
        except Exception:
            pass

    if telegram:
        bot_token = os.environ.get('BOT_TOKEN', '')
        chat_id = os.environ.get('BOT_CHAT_ID', '')
        # NOTE: no hardcoded default chat id here on purpose - sending your
        # scan results/errors to a third party by default would be a silent
        # data-exfiltration bug. Both must be explicitly configured by the user.
        if not bot_token or not chat_id:
            if not silent and debug:
                print(Fore.YELLOW + "[WARN] BOT_TOKEN/BOT_CHAT_ID not set, skipping Telegram notification" + Style.RESET_ALL)
            return
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': message}
        try:
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            try:
                with open(logger, 'a') as file:
                    file.write(f"[ERROR] Telegram message failed: {e}\n")
            except Exception:
                pass


VERSION = "1.4.0"

parser = argparse.ArgumentParser(description='Reflix - Smart parameter injection and reflection fuzzing tool')
parser.add_argument('--version', action='version', version=f'Reflix v{VERSION}')

# --- Input ---
input_group = parser.add_argument_group('Input')
input_group.add_argument('-l', '--urls-path', dest='urlspath', required=True,
                          help='Path to file containing the list of target URLs')
input_group.add_argument('-p', '--parameter', default='nexovir', required=False,
                          help='Canary value used to detect reflection (default: "nexovir")')
input_group.add_argument('-w', '--wordlist', required=False,
                          help='Optional. Extra parameter names to seed the fuzzer with, merged per-URL '
                               'with whatever fallparams auto-discovers on that URL. If omitted, the '
                               'tool relies entirely on auto-discovery instead of guessing - this is the '
                               'recommended default and avoids sending meaningless canary-as-param noise.')

# --- Request Configuration ---
config_group = parser.add_argument_group('Request Configuration')
config_group.add_argument('-X', '--methods', type=str, default='GET,POST', required=False,
                           help='Comma-separated HTTP methods to test (default: "GET,POST")')
config_group.add_argument('-H', '--headers', action='append', default=[], required=False,
                           help='Custom header "Name: value", repeatable (add as many -H as you need)')
config_group.add_argument('-x', '--proxy', type=str, default='', required=False,
                           help='HTTP/SOCKS proxy URL, e.g. http://127.0.0.1:8080')
config_group.add_argument('-c', '--chunk', type=str, default='25', required=False,
                           help='Number of parameters fuzzed per batched request (default: 25)')
config_group.add_argument('-vm', '--value-mode', dest='valuemode', choices=['append', 'replace'],
                           default='append', required=False,
                           help='How to mutate an existing query value: append or replace (default: append)')
config_group.add_argument('-gm', '--generate-mode', dest='generatemode',
                           choices=['root', 'ignore', 'combine', 'all'], default='all', required=False,
                           help='How candidate URLs are generated in the static stage (default: all)')
config_group.add_argument('-to', '--timeout', dest='timeout', type=int, default=15, required=False,
                           help='Per-request timeout in seconds (default: 15)')
config_group.add_argument('-rl', '--rate-limit', dest='ratelimit', type=float, default=70, required=False,
                           help='Global cap on requests sent per second, across all threads (default: 70). '
                                'Set to 0 to disable rate limiting entirely (unlimited).')

# --- Scan Modules ---
modules_group = parser.add_argument_group('Scan Modules')
modules_group.add_argument('-sd', '--dom-scan', dest='dom', action='store_true', default=False,
                            help='Scan the raw response body for known DOM source/sink keywords')
modules_group.add_argument('-xt', '--xss-test', dest='xss', action='store_true', default=False,
                            help="On every reflection hit, also probe with ' \" > payloads")
modules_group.add_argument('-pi', '--path-injection', dest='pathinjection', action='store_true', default=False,
                            help='Test reflection by injecting the parameter into the URL path')
modules_group.add_argument('-hi', '--header-injection', dest='headerinjection', action='store_true', default=False,
                            help='Test reflection by injecting the parameter into common request headers')
modules_group.add_argument('-hw', '--header-wordlist', dest='headerwordlist', default=None, required=False,
                            help='Path to a file with extra header names (one per line) to add to the '
                                 'header-injection test set, on top of the built-in list')
modules_group.add_argument('-hv', '--heavy', action='store_true', default=False,
                            help='After the normal pass, re-fuzz every URL with every parameter discovered so far')

# --- Rate Limiting ---
ratelimit_group = parser.add_argument_group('Rate Limiting')
ratelimit_group.add_argument('-t', '--threads', dest='thread', type=int, default=1, required=False,
                              help='Maximum number of concurrent tasks (default: 1)')
ratelimit_group.add_argument('-rd', '--delay', dest='delay', type=str, default='0', required=False,
                              help='Seconds to wait after each task completes. Accepts a single value '
                                   '(e.g. "1.5") or a random range "min-max" (e.g. "0.1-2.0"), in which '
                                   'case a random delay is drawn uniformly from that range after every '
                                   'task (default: 0)')

# --- Notification & Logging ---
notif_group = parser.add_argument_group('Notification & Logging')
notif_group.add_argument('-n', '--notify', action='store_true', default=False, required=False,
                          help='Send errors/summary to Telegram (needs BOT_TOKEN and BOT_CHAT_ID env vars)')
notif_group.add_argument('-lf', '--log-file', dest='logger', type=str, default=None, required=False,
                          help='Optional log file path (off by default). Console output is controlled '
                               'by -v/--verbose, not by this flag.')
notif_group.add_argument('-s', '--silent', action='store_true', default=False, required=False,
                          help='Suppress the banner, status summary, live progress line, and informational '
                               'console output')
notif_group.add_argument('-q', '--quiet-findings', dest='quiet', action='store_true', default=False,
                          required=False,
                          help='Keep the banner, status summary, and live progress counter on screen, but '
                               'do not print vulnerability/finding lines to the console. Findings are '
                               'still recorded and still written to -o/-jo/-lf if those are set. Ignored '
                               'if -s/--silent is also set (silent already suppresses everything).')
notif_group.add_argument('-v', '--verbose', dest='debug', action='store_true', default=False, required=False,
                          help='Print INFO/DEBUG level status messages to the console (findings are always printed)')

# --- Outputs ---
output_group = parser.add_argument_group('Outputs')
output_group.add_argument('-o', '--output', type=str, default=None, required=False,
                           help='Optional file to also write confirmed findings to (off by default; '
                                'findings are always printed to the console). If the path ends in '
                                '.json (e.g. "-o output.json"), each finding is streamed to it live, '
                                'one JSON object per line (JSON Lines format), as soon as it is found - '
                                'so nothing is lost if the run is interrupted. Any other extension gets '
                                'the plain-text line log instead.')
output_group.add_argument('-po', '--params-output', dest='paramsoutput', default=None, required=False,
                           help='Optional file to also write every parameter discovered by fallparams to '
                                '(off by default; discovered parameters are kept in memory either way, '
                                'so --heavy works without this flag)')
output_group.add_argument('-jo', '--json-output', dest='jsonoutput', type=str, required=False,
                           help='Export every finding as a single clean JSON array to this file')

args = parser.parse_args()

urls_path = args.urlspath
parameter = args.parameter
wordlist_parameters = args.wordlist
methods = args.methods.split(',')
headers = {}
for header in args.headers:
    if ':' in header:
        key, value = header.split(':', 1)
        headers[key.strip()] = value.strip()

proxy = args.proxy
chunk = args.chunk
heavy = args.heavy
dom = args.dom
xss = args.xss
thread = max(1, args.thread)
value_mode = args.valuemode
generate_mode = args.generatemode
pathinjection = args.pathinjection
headerinjection = args.headerinjection
header_wordlist_path = args.headerwordlist
notification = args.notify
logger = args.logger
silent = args.silent
quiet = args.quiet
debug = args.debug
output = args.output
params_output = args.paramsoutput
json_output = args.jsonoutput
timeout = args.timeout
rate_limit = max(0.0, args.ratelimit)


def parse_delay(delay_str: str):
    """
    Parse the -rd/--delay value into a (low, high) float tuple.

    Accepts:
      - a single number, e.g. "1.5"      -> (1.5, 1.5)  (fixed delay)
      - a range "min-max", e.g. "0.1-2.0" -> (0.1, 2.0)  (random delay per task)

    Falls back to (0.0, 0.0) - i.e. no delay - on any parse error, with a
    warning so a typo doesn't silently blow past rate limits.
    """
    delay_str = (delay_str or '0').strip()
    if '-' in delay_str:
        parts = delay_str.split('-', 1)
        try:
            lo, hi = float(parts[0]), float(parts[1])
            if lo < 0 or hi < 0:
                raise ValueError("negative delay")
            return (lo, hi) if lo <= hi else (hi, lo)
        except ValueError:
            print(f"{yellow}[WARN] Invalid --delay range '{delay_str}', ignoring (no delay applied){reset}")
            return (0.0, 0.0)
    try:
        v = float(delay_str)
        if v < 0:
            raise ValueError("negative delay")
        return (v, v)
    except ValueError:
        print(f"{yellow}[WARN] Invalid --delay value '{delay_str}', ignoring (no delay applied){reset}")
        return (0.0, 0.0)


# (low, high) seconds - low == high means a fixed delay, low < high means a
# random delay drawn uniformly from that range is applied after every task.
delay_range = parse_delay(args.delay)


class RateLimiter:
    """Global asyncio token-bucket rate limiter.

    Caps the total number of requests/tasks *started* per second across the
    whole run, regardless of how many --threads are running concurrently.
    This is independent from --delay (which just pauses a single task after
    it finishes) - the rate limiter is what actually guarantees "~N req/s"
    as an overall ceiling, like ffuf's -rate flag.

    rate <= 0 means unlimited (no gating at all).
    """

    def __init__(self, rate_per_sec: float):
        self.rate = max(0.0, float(rate_per_sec))
        self._lock = asyncio.Lock()
        # Start with a single token's worth of headroom (not a full bucket)
        # so the tool doesn't fire an initial burst of `rate` requests all
        # at once before settling into the steady ~rate req/s - it ramps up
        # smoothly from the very first request instead.
        self._tokens = 1.0 if self.rate > 0 else 0.0
        self._last = time.monotonic()

    async def acquire(self):
        if self.rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait_for = (1 - self._tokens) / self.rate
            await asyncio.sleep(wait_for)


# Shared across every request the tool sends (nuclei runs, fallparams runs,
# reflection checks, path/header injection, heavy re-fuzz, ...).
rate_limiter = RateLimiter(rate_limit)

INJECTIONS = [f"%27{parameter}", f'%22{parameter}', f"%3E{parameter}"]
INJECTION_RESULTS = [f"'{parameter}".lower(), f'"{parameter}'.lower(), f">{parameter}".lower()]

# structured findings, populated by record_finding() - exported as JSON at the end if -jo is set
findings_data = []

# every parameter fallparams has discovered, kept in memory so --heavy works
# even when -po/--params-output was never given
discovered_parameters = set()

# per-url map: url -> list of parameters fallparams found on THAT specific
# url. This is what lets fuzz_phase fuzz each url with parameters that
# actually exist on it, instead of a meaningless canary-as-param guess.
discovered_by_url = {}

# extra parameter names seeded from -w/--wordlist (if given), loaded once in
# main() and merged into discovery results for every url's fuzz pass.
wordlist_seed = []

# global concurrency limiter, driven by --threads
sem = asyncio.Semaphore(thread)

# serializes writes to the -o JSON(L) output file so concurrent findings
# never interleave/corrupt each other's lines
json_write_lock = asyncio.Lock()

# requests.Session reused across the run for connection pooling
session = requests.Session()

# --- Live ffuf-style progress state -----------------------------------
# Each pipeline stage (discovery/dom-scan/fuzz/path/header/heavy) calls
# run_phase() with its own list of tasks; run_phase resets these counters
# and prints a live-updating progress line - percentage, ACTUAL measured
# req/s (not just the -rl ceiling), and elapsed time - as tasks complete.
# All of it is a no-op when -s/--silent is set.
progress_lock = asyncio.Lock()
progress_done = 0
progress_total = 0
current_phase = ""
phase_start_time = 0.0

# One-line plain-English explanation of what each phase is actually doing,
# printed once when the phase starts so the output is self-explanatory
# without needing to read the source or guess what e.g. "Heavy Reflix" means.
PHASE_INFO = {
    "Parameter Discovery": "running fallparams on every URL to find real parameter names",
    "DOM Scan":             "keyword-scanning response bodies for DOM XSS source/sink patterns",
    "Reflection Fuzz":      "injecting discovered/seeded parameters, checking for reflection via nuclei",
    "Path Injection":       "injecting the canary into the URL path, checking for reflection",
    "Header Injection":     "injecting the canary into common request headers, checking for reflection",
    "Heavy Reflix":         "cross-testing every URL against ALL parameters discovered this run",
}


def format_duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _progress_line():
    pct = (progress_done / progress_total * 100) if progress_total else 0
    elapsed = max(time.monotonic() - phase_start_time, 0.001)
    rate = progress_done / elapsed
    bar_width = 24
    filled = int(bar_width * progress_done / progress_total) if progress_total else 0
    bar = f"{green}{'█' * filled}{dim}{'░' * (bar_width - filled)}{reset}"
    return (f"\r  {bar} {bold}{progress_done}/{progress_total}{reset} ({pct:5.1f}%)  "
            f"{cyan}{rate:5.1f} req/s{reset}  {dim}elapsed {format_duration(elapsed)}{reset}   ")


async def bump_progress():
    global progress_done
    async with progress_lock:
        progress_done += 1
        if not silent and progress_total:
            print(_progress_line(), end='', flush=True)


async def run_phase(tasks, phase_name, desc_override=None):
    """Run a batch of sem_task-wrapped coroutines while showing a live,
    ffuf-style progress line (percentage / measured req/s / elapsed time)
    - unless --silent. Prints a short heading with a plain-English
    description of the phase before starting, and a done-in-Xs summary
    line after, so the output is self-explanatory at a glance."""
    global progress_done, progress_total, current_phase, phase_start_time
    progress_done = 0
    progress_total = len(tasks)
    current_phase = phase_name
    phase_start_time = time.monotonic()
    if not tasks:
        return
    if not silent:
        desc = desc_override if desc_override is not None else PHASE_INFO.get(phase_name, "")
        heading = f"\n{magenta}▶{reset} {bold}{phase_name}{reset}"
        if desc:
            heading += f" {dim}— {desc}{reset}"
        print(heading)
        print(_progress_line(), end='', flush=True)
    await asyncio.gather(*tasks)
    if not silent:
        elapsed = time.monotonic() - phase_start_time
        print(f"\r  {green}✓{reset} {bold}{progress_total}/{progress_total}{reset} (100.0%)  "
              f"{dim}finished in {format_duration(elapsed)}{reset}" + " " * 20)


def show_status():
    """Print an ffuf-style pre-run summary: target file, wordlist, threads,
    rate limit, delay, methods, etc. Skipped entirely when --silent."""
    if silent:
        return
    wl_display = wordlist_parameters if wordlist_parameters else "(none - auto-discovery only via fallparams)"
    rate_display = f"~{rate_limit:.0f} req/s" if rate_limit > 0 else "unlimited"
    if delay_range == (0.0, 0.0):
        delay_display = "0s"
    elif delay_range[0] == delay_range[1]:
        delay_display = f"{delay_range[0]}s (fixed)"
    else:
        delay_display = f"{delay_range[0]}-{delay_range[1]}s (random)"

    lines = [
        f" :: URL list     : {urls_path}",
        f" :: Wordlist     : {wl_display}",
        f" :: Canary       : {parameter}",
        f" :: Methods      : {','.join(methods)}",
        f" :: Threads      : {thread}",
        f" :: Rate limit   : {rate_display}",
        f" :: Delay        : {delay_display}",
        f" :: Chunk size   : {chunk}",
    ]
    extra_modules = []
    if dom:
        extra_modules.append("dom-scan")
    if xss:
        extra_modules.append("xss-test")
    if pathinjection:
        extra_modules.append("path-injection")
    if headerinjection:
        extra_modules.append("header-injection")
    if heavy:
        extra_modules.append("heavy")
    if quiet:
        extra_modules.append("quiet-findings (console)")
    if extra_modules:
        lines.append(f" :: Modules      : {', '.join(extra_modules)}")
    if proxy:
        lines.append(f" :: Proxy        : {proxy}")

    print(f"{cyan}{'-' * 60}{reset}")
    for line in lines:
        print(f"{cyan}{line}{reset}")
    print(f"{cyan}{'-' * 60}{reset}\n")


async def append_json_line(path, obj):
    """Append a single finding to `path` as one JSON object per line
    (JSON Lines format), immediately as it's found - so nothing is lost
    if the run is interrupted partway through. Writes are serialized via
    json_write_lock so concurrent findings can't interleave mid-line."""
    line = json.dumps(obj, ensure_ascii=False)

    def _append():
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')

    async with json_write_lock:
        await asyncio.to_thread(_append)


async def dump_findings_json(path):
    """Write the full findings_data list out as one clean, pretty-printed
    JSON array. Used for -jo/--json-output (a single complete array written
    once at the end of the run, separate from the streaming JSONL that -o
    writes when given a .json path)."""
    def _dump():
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(findings_data, f, indent=2, ensure_ascii=False, sort_keys=False)
    await asyncio.to_thread(_dump)


async def sem_task(coro):
    """Run coroutine under the global concurrency limit AND the global rate
    limiter (--rate-limit, default 70 req/s), applying --delay (fixed or
    randomized within the given range) afterwards, then bump the live
    progress counter."""
    async with sem:
        await rate_limiter.acquire()
        try:
            result = await coro
        finally:
            lo, hi = delay_range
            if hi > 0:
                wait_for = random.uniform(lo, hi) if hi > lo else lo
                await asyncio.sleep(wait_for)
            await bump_progress()
        return result


def build_proxies(proxy_):
    if not proxy_:
        return None
    return {"http": proxy_, "https": proxy_}


def http_request(url, method="GET", req_headers=None, data=None, proxy_="", timeout_=15):
    """
    Plain HTTP request helper used for every reflection check.
    Returns (body_text, response_headers_dict, status_code) or (None, {}, None) on failure.
    """
    req_headers = dict(req_headers or {})
    req_headers.setdefault("User-Agent", DEFAULT_UA)
    try:
        resp = session.request(
            method.upper(), url,
            headers=req_headers,
            data=data,
            proxies=build_proxies(proxy_),
            timeout=timeout_,
            verify=False,
            allow_redirects=True,
        )
        return resp.text, dict(resp.headers), resp.status_code
    except requests.exceptions.RequestException as e:
        sendmessage(f"[ERROR] Request failed for {url}: {str(e)}", colour="RED", logger=logger, silent=silent)
        return None, {}, None


def generate_injected_urls(base_urls, generate_mode_, value_mode_, parameter_, wordlist_parameters_, chunk_):
    """
    In-process replacement for the old external `injector` tool.
    Builds candidate URLs with the fuzz parameter injected in different ways:
      - combine : append/replace the value of parameters already present in the query string
      - root    : strip the existing query string and append wordlist parameters
      - ignore  : keep the existing query string and append wordlist parameters
      - all     : run all three modes and merge the results
    Returns a de-duplicated, order-preserved list of URLs.

    For root/ignore, every parameter batched into the same chunked request
    gets its own numbered canary value (param1=nexovir1&param2=nexovir2...)
    instead of an identical one - this is still exactly ONE request per
    chunk, nothing extra is sent. The mapping of which parameter got which
    numbered value is recorded in url_param_canaries so a match can later be
    traced back to the exact parameter(s) that reflected.
    """
    chunk_size = max(1, int(chunk_))
    generated = []

    def value_mode_generate(url):
        out = []
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for i in range(len(query_pairs)):
            modified_pairs = query_pairs.copy()
            key, value = modified_pairs[i]
            modified_pairs[i] = (key, value + parameter_) if value_mode_ == 'append' else (key, parameter_)
            new_query = urlencode(modified_pairs)
            out.append(urlunparse(parsed._replace(query=new_query)))
        return out

    def append_wordlist_params(target_urls, params):
        out = []
        if not params:
            return out
        for url in target_urls:
            for i in range(0, len(params), chunk_size):
                chunk_params = params[i:i + chunk_size]
                pairs = []
                canary_map = {}
                for p in chunk_params:
                    # each parameter in this chunk gets its own numbered
                    # canary - same single request, just distinguishable
                    # values, so a hit can be attributed to the right param.
                    value = f"{parameter_}{next(param_canary_counter)}"
                    pairs.append(f"{p}={value}")
                    canary_map[p] = value
                query_string = '&'.join(pairs)
                sep = '&' if '?' in url else '?'
                new_url = f"{url}{sep}{query_string}"
                url_param_canaries[new_url] = canary_map
                out.append(new_url)
        return out

    def combine_mode():
        for url in base_urls:
            if '?' in url:
                generated.extend(value_mode_generate(url))

    def root_mode():
        stripped = list(dict.fromkeys(u.split('?')[0] for u in base_urls))
        generated.extend(append_wordlist_params(stripped, wordlist_parameters_))

    def ignore_mode():
        generated.extend(append_wordlist_params(base_urls, wordlist_parameters_))

    if generate_mode_ == 'combine':
        combine_mode()
    elif generate_mode_ == 'root':
        root_mode()
    elif generate_mode_ == 'ignore':
        ignore_mode()
    else:  # 'all'
        combine_mode()
        root_mode()
        ignore_mode()

    return list(dict.fromkeys(generated))


async def record_finding(method, severity, place, url, http_type="http", content_type="", size_page=None):
    """Print+log a finding in the standard line format, and keep a structured
    copy for --json-output. Used by every reflection check in the tool.

    content_type / size_page are optional metadata about the response that
    triggered the finding - when given, they're shown as extra
    [content_type] [size_pageb] tags in the console line and stored as
    "content_type"/"size_page" fields in the JSON/JSONL output."""
    sev_color = cyan if severity == "info" else red

    meta_tags = ""
    if content_type:
        meta_tags += f" [{blue}{content_type}{reset}]"
    if size_page is not None:
        meta_tags += f" [{magenta}{size_page}b{reset}]"

    output_line = (f"[{green}{method.upper()}{reset}] [{blue}{http_type}{reset}] "
                   f"[{sev_color}{severity}{reset}] [{yellow}{place}{reset}]{meta_tags} {url}")
    # -q/--quiet-findings: keep banner/status/progress on screen but never
    # print the actual finding line to the console (it's still recorded
    # below and still written to -o/-jo/-lf regardless of this flag).
    if not silent and not quiet:
        # Move off the live progress line before printing a finding so it
        # doesn't get overwritten mid-line, then let the progress line resume.
        if progress_total:
            print()
        print(output_line)
    finding = {
        "method": method.upper(),
        "severity": severity,
        "place": place,
        "url": url,
        "content_type": content_type,
        "size_page": size_page,
    }
    if output:
        if is_json_output_path(output):
            await append_json_line(output, finding)
        else:
            await read_write_list([output_line], output, 'a')
    findings_data.append(finding)


async def read_write_list(list_data, file: str, type: str):
    def _read():
        if not os.path.exists(file):
            return []
        with open(file, 'r') as f:
            return list(set(line.strip() for line in f.read().splitlines() if line.strip()))

    def _write():
        d = os.path.dirname(file)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(file, 'w') as f:
            for item in set(list_data):
                f.write(item.strip() + '\n')

    def _append():
        d = os.path.dirname(file)
        if d:
            os.makedirs(d, exist_ok=True)
        try:
            with open(file, 'r') as f:
                existing_items = set(f.read().splitlines())
        except FileNotFoundError:
            existing_items = set()
        with open(file, 'a') as f:
            for item in set(list_data):
                if item.strip() and item not in existing_items:
                    f.write(item.strip() + '\n')

    try:
        if type in ("read", "r"):
            return await asyncio.to_thread(_read)
        elif type in ("write", "w"):
            await asyncio.to_thread(_write)
            return
        elif type in ("append", "a"):
            await asyncio.to_thread(_append)
            return
    except Exception:
        return []


async def try_to_xss(url: str, method, reflection_place):
    """On a confirmed reflection, swap the canary for ' " > payloads and see
    if any come back unescaped in the body."""
    if parameter not in url:
        return
    for injection_element in INJECTIONS:
        target_url = url.replace(parameter, injection_element)
        await rate_limiter.acquire()
        html, resp_headers, _ = await asyncio.to_thread(http_request, target_url, method, headers, None, proxy, timeout)
        if html is None:
            continue
        lowered_html = html.lower()
        for inject_elm in INJECTION_RESULTS:
            if inject_elm in lowered_html:
                content_type, size_page = extract_meta(html, resp_headers)
                await record_finding(method, "medium", reflection_place, target_url,
                                      content_type=content_type, size_page=size_page)
                break


async def run_nuclei_scan(target_url, method='GET', req_headers=None, post_data=None, search_word="nexovir",
                           proxy_=''):
    http_block = {
        'method': method.upper(),
        'path': ["{{BaseURL}}"],
        'headers': dict(req_headers or {}),
        'matchers': [
            {'type': 'word', 'words': [search_word], 'part': 'body'}
        ]
    }
    if method.upper() == 'POST':
        http_block['body'] = post_data or ''
        if 'Content-Type' not in http_block['headers']:
            http_block['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

    template = {
        'id': f'reflix-{method.lower()}',
        'info': {
            'name': f'Reflix ({method.upper()})',
            'author': 'Reflix',
            'severity': 'info',
        },
        'http': [http_block],
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
        yaml.dump(template, temp_file)
        temp_path = temp_file.name

    try:
        # -jsonl + -irr: nuclei emits one JSON object per match, including
        # the raw request/response it already captured - so content-type and
        # body size for the finding come straight out of that JSON, with
        # ZERO extra HTTP requests to the target (faster, less load, and no
        # separate rate-limiter slot needed for metadata alone).
        cmd = ['nuclei', '-u', target_url, '-t', temp_path, '-duc', '-silent', '-jsonl', '-irr']
        if proxy_:
            cmd.extend(['-proxy', proxy_])

        result = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True)

        if result.returncode == 0:
            raw_lines = [l for l in result.stdout.splitlines() if l.strip()]
            raw_output = []

            for line in raw_lines:
                try:
                    match = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                content_type, size_page = parse_raw_http_response(match.get('response', ''))
                matched_at = match.get('matched-at') or target_url

                # Only on a confirmed match: check the raw body nuclei
                # already captured (no extra request) against the per-param
                # canary map built when this url was generated, so we can
                # say exactly which parameter(s) reflected.
                raw_body = extract_raw_body(match.get('response', ''))
                canary_map = url_param_canaries.get(target_url)
                reflected_params = []
                if canary_map and raw_body:
                    lowered_body = raw_body.lower()
                    reflected_params = [p for p, v in canary_map.items() if v.lower() in lowered_body]
                place_label = f"HTML[{','.join(reflected_params)}]" if reflected_params else "HTML"

                meta_tags = ""
                if content_type:
                    meta_tags += f" [{blue}{content_type}{reset}]"
                meta_tags += f" [{magenta}{size_page}b{reset}]"

                display_line = (f"[{green}{method.upper()}{reset}] [{blue}http{reset}] "
                                 f"[{cyan}info{reset}] [{yellow}{place_label}{reset}]{meta_tags} {matched_at}")
                raw_output.append(display_line)

                if not silent and not quiet:
                    if progress_total:
                        print()
                    print(display_line)

                finding = {
                    "method": method.upper(),
                    "severity": "info",
                    "place": place_label,
                    "url": matched_at,
                    "content_type": content_type,
                    "size_page": size_page,
                    "reflected_params": reflected_params,
                }
                if output:
                    if is_json_output_path(output):
                        await append_json_line(output, finding)
                    else:
                        await read_write_list([display_line], output, 'a')
                findings_data.append(finding)

            if raw_output and xss:
                await try_to_xss(target_url, method, 'HTML')
            return {'success': True, 'raw_results': raw_output, 'stats': f"line count: {len(raw_output)}"}
        else:
            if result.stderr.strip():
                sendmessage(f"  [ERROR] Nuclei error: {result.stderr}", colour="RED", logger=logger,
                            telegram=notification, silent=silent)
            return {'success': False, 'error': result.stderr}
    finally:
        try:
            os.unlink(temp_path)
        except Exception:
            pass


async def run_fallparams(url, proxy_, method, req_headers):
    sendmessage(f"  [INFO] Starting parameter discovery (method: {method}) {url}", colour="YELLOW", logger=logger,
                silent=silent)

    def _run():
        command = ["fallparams", "-u", url, "-X", method, '-silent', '-duc']
        if proxy_:
            command.extend(["-x", proxy_])
        for key, value in req_headers.items():
            command.extend(["-H", f"{key}: {value}"])
        result = subprocess.run(command, shell=False, check=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        return [l for l in result.stdout.splitlines() if l.strip()]

    await rate_limiter.acquire()
    try:
        parameters = await asyncio.to_thread(_run)
        sendmessage(f"      [INFO] {len(parameters)} parameters found", logger=logger, silent=silent)
        return parameters
    except FileNotFoundError:
        sendmessage("  [ERROR] 'fallparams' binary not found on PATH", colour="RED", logger=logger, silent=silent)
        return []
    except Exception as e:
        sendmessage(f"  [ERROR] Error fallparams URL {url}: {str(e)}", colour="RED", logger=logger, silent=silent)
        return []


async def explore_dom_sinks(url, req_headers, method):
    """Fetch the raw page over HTTP (no browser/rendering) and keyword-scan
    the body for known DOM source/sink API names, reporting the exact line
    number(s) each keyword was found on so it can be located quickly."""
    sendmessage(f"  [INFO] Starting DOM sinks/sources exploration url: {url}", colour="YELLOW", logger=logger,
                silent=silent)
    html, resp_headers, _ = await asyncio.to_thread(http_request, url, method, req_headers, None, proxy, timeout)
    if html is None:
        return {"success": False, "url": url}

    content_type, size_page = extract_meta(html, resp_headers)
    lines = html.splitlines()
    lowered_lines = [l.lower() for l in lines]

    for category, items in DOM_SOURCES_AND_SINKS.items():
        matches = []  # list of (keyword, [line_numbers])
        for item in items:
            item_lower = item.lower()
            hit_lines = [i + 1 for i, l in enumerate(lowered_lines) if item_lower in l]
            if hit_lines:
                matches.append((item.replace('(', ''), hit_lines))

        if not matches:
            continue

        # e.g. "eval@L12,45 innerHTML@L3"  - keeps console output compact
        # while still pinpointing exactly where each hit is.
        display_parts = []
        for keyword, hit_lines in matches:
            shown = hit_lines[:5]
            more = f"+{len(hit_lines) - 5} more" if len(hit_lines) > 5 else ""
            line_str = ",".join(str(n) for n in shown) + (f",{more}" if more else "")
            display_parts.append(f"{keyword}@L{line_str}")
        sinks_str = " ".join(display_parts)

        meta_tags = ""
        if content_type:
            meta_tags += f" [{blue}{content_type}{reset}]"
        meta_tags += f" [{magenta}{size_page}b{reset}]"

        output_line = (f"[{green}{method.upper()}{reset}] [{blue}http{reset}] [{cyan}info{reset}] "
                        f"[{yellow}{category}: {red}{sinks_str}{reset}]{meta_tags} {url}")
        if not silent and not quiet:
            if progress_total:
                print()
            print(output_line)
        finding = {
            "method": method.upper(),
            "severity": "info",
            "place": category,
            "url": url,
            "content_type": content_type,
            "size_page": size_page,
            "sinks": [{"keyword": keyword, "lines": hit_lines} for keyword, hit_lines in matches],
        }
        if output:
            if is_json_output_path(output):
                await append_json_line(output, finding)
            else:
                await read_write_list([output_line], output, 'a')
        findings_data.append(finding)
    return {"success": True, "url": url}


async def discover_one(url, method):
    """Run fallparams on a single url+method, and fold any parameters found
    into both the global `discovered_parameters` set (used by --heavy and
    the final summary) and the per-url `discovered_by_url` map (used by
    fuzz_phase to fuzz *this* url with the params that were actually found
    on it, instead of a meaningless canary-as-param guess)."""
    parameters = await run_fallparams(url, proxy, method, headers)
    if not parameters:
        return
    discovered_parameters.update(parameters)
    existing = discovered_by_url.setdefault(url, [])
    for p in parameters:
        if p not in existing:
            existing.append(p)
    if params_output:
        await read_write_list(parameters, params_output, 'a')


async def discovery_phase(urls, methods):
    """PHASE 1 - Parameter discovery. Runs fallparams on every non-binary URL
    (including .js/.css - that's exactly where fallparams tends to find real
    API param names) for every method, before any fuzzing happens. This is
    what lets fuzz_phase fuzz each URL with parameters that actually exist
    on it, instead of falling back to a meaningless canary-as-param guess
    when no -w/--wordlist is given."""
    tasks = [sem_task(discover_one(url, method)) for url in urls for method in methods]
    await run_phase(tasks, "Parameter Discovery")
    if not silent:
        print(f"  {dim}→ {len(discovered_parameters)} unique parameter(s) found across "
              f"{len(discovered_by_url)}/{len(urls)} URL(s){reset}")


async def dom_scan_phase(urls):
    """Optional (-sd/--dom-scan) recon pass: keyword-scan every non-binary
    URL's raw body for known DOM source/sink API names. Independent of
    fuzzing - just static analysis of what's already on the page/script."""
    tasks = [sem_task(explore_dom_sinks(url, headers, 'GET')) for url in urls]
    await run_phase(tasks, "DOM Scan")


async def fuzz_one_url(url, method):
    """PHASE 2 - Reflection fuzz for a single url+method.

    The parameter set used for the root/ignore injection modes is built
    from what's actually meaningful for THIS url:
      - the -w/--wordlist seed list (if the user gave one), plus
      - whatever fallparams found on this exact url during discovery_phase

    If that combined set is empty (no -w given and fallparams found nothing
    on this url), generate_injected_urls naturally skips root/ignore entirely
    for it - no meaningless 'canary=canary' request gets sent. The 'combine'
    mode (mutating a param the url's query string already has) still runs
    regardless, since it never depended on a wordlist to begin with.
    """
    own_params = list(dict.fromkeys(wordlist_seed + discovered_by_url.get(url, [])))
    try:
        candidate_urls = await asyncio.to_thread(
            generate_injected_urls, [url], generate_mode, value_mode, parameter, own_params, chunk)
    except Exception as e:
        sendmessage(f"[ERROR] URL generation failed for {url}: {str(e)}", colour="RED", logger=logger,
                    silent=silent)
        return
    for candidate_url in candidate_urls:
        await run_nuclei_scan(candidate_url, method, headers, None, parameter, proxy)


async def fuzz_phase(urls, methods):
    """PHASE 2 driver - only runs against the fuzzable subset (binary assets
    and static .js/.css/.map files were already filtered out by main(), since
    query params on those never reflect anything no matter what's sent)."""
    tasks = [sem_task(fuzz_one_url(url, method)) for url in urls for method in methods]
    await run_phase(tasks, "Reflection Fuzz")


async def heavy_one(url, method):
    """Cross-pollination fuzz: test THIS url against the full UNION of every
    parameter discovered across ALL urls this run (plus the -w seed list),
    not just the ones found on this specific url. Only runs under -hv/--heavy
    since it's the most request-expensive stage by design."""
    all_params = list(dict.fromkeys(wordlist_seed + sorted(discovered_parameters)))
    if not all_params:
        return
    try:
        candidate_urls = await asyncio.to_thread(
            generate_injected_urls, [url], 'ignore', value_mode, parameter, all_params, chunk)
    except Exception as e:
        sendmessage(f"[ERROR] URL generation failed for {url}: {str(e)}", colour="RED", logger=logger,
                    silent=silent)
        return
    for candidate_url in candidate_urls:
        await run_nuclei_scan(candidate_url, method, headers, None, parameter, proxy)


async def heavy_reflix(urls, methods):
    # Use whatever fallparams has found so far this run, regardless of
    # whether -po/--params-output was set (that flag only controls whether
    # it's *also* written to disk), plus anything persisted from a previous run.
    if params_output:
        on_disk = await read_write_list('', params_output, 'r')
        for p in on_disk:
            discovered_parameters.add(p)
    if not discovered_parameters and not wordlist_seed:
        if not silent:
            print(f"\n{magenta}▶{reset} {bold}Heavy Reflix{reset} {dim}— skipped: "
                  f"no parameters discovered and no -w wordlist given{reset}")
        return
    tasks = [sem_task(heavy_one(url, method)) for url in urls for method in methods]
    await run_phase(tasks, "Heavy Reflix")


async def run_path_reflection(url, parameter_, method="GET"):
    parsed = urlparse(url)
    path_parts = parsed.path.strip("/").split("/")
    if path_parts and path_parts[0] != '':
        path_parts[-1] = path_parts[-1] + parameter_
    else:
        path_parts = [parameter_]
    new_path = "/" + "/".join(path_parts)
    injected_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
    if parsed.query:
        injected_url += f"?{parsed.query}"

    html, resp_headers, status = await asyncio.to_thread(
        http_request, injected_url, method, headers, None, proxy, timeout)
    if html is None:
        return {"success": False, "url": injected_url}

    content_type, size_page = extract_meta(html, resp_headers)
    found_html = parameter_.lower() in html.lower()
    found_header = any(parameter_.lower() in str(v).lower() for v in resp_headers.values())

    if found_html:
        await record_finding(method, "info", "PATH-BODY", injected_url,
                              content_type=content_type, size_page=size_page)
        if xss:
            await try_to_xss(injected_url, method, 'PATH-BODY')
    if found_header:
        await record_finding(method, "info", "PATH-HEADER", injected_url,
                              content_type=content_type, size_page=size_page)
    return {"success": True, "url": injected_url}


async def path_injection_reflix(urls, methods, parameter_):
    tasks = [sem_task(run_path_reflection(url, parameter_, method)) for url in urls for method in methods]
    await run_phase(tasks, "Path Injection")


async def load_header_test_keys(extra_path):
    """Merge the built-in HEADER_TEST_KEYS with any user-supplied header
    names, so -hi can probe an arbitrary number of custom headers at once."""
    keys = list(HEADER_TEST_KEYS)
    if extra_path:
        extra = await read_write_list("", extra_path, 'r')
        for k in extra:
            if k and k not in keys:
                keys.append(k)
    return keys


async def run_header_reflection(url, parameter_, method="GET", header_keys=None):
    test_headers = dict(headers or {})
    for hk in (header_keys or HEADER_TEST_KEYS):
        test_headers[hk] = parameter_

    html, resp_headers, status = await asyncio.to_thread(
        http_request, url, method, test_headers, None, proxy, timeout)
    if html is None:
        return {"success": False, "url": url}

    content_type, size_page = extract_meta(html, resp_headers)
    found_html = parameter_.lower() in html.lower()
    found_header = any(parameter_.lower() in str(v).lower() for v in resp_headers.values())

    if found_html:
        await record_finding(method, "info", "HEADER-BODY", url,
                              content_type=content_type, size_page=size_page)
        if xss:
            await try_to_xss(url, method, 'HEADER-BODY')
    if found_header:
        await record_finding(method, "info", "HEADER-RESPONSE", url,
                              content_type=content_type, size_page=size_page)
    return {"success": True, "url": url}


async def header_injection_reflix(urls, methods, parameter_):
    header_keys = await load_header_test_keys(header_wordlist_path)
    tasks = [sem_task(run_header_reflection(url, parameter_, method, header_keys))
             for url in urls for method in methods]
    desc = f"{PHASE_INFO['Header Injection']} ({len(header_keys)} header names/request)"
    await run_phase(tasks, "Header Injection", desc_override=desc)


async def main():
    try:
        if not silent:
            show_banner()
        run_start_time = time.monotonic()
        all_urls = await read_write_list("", urls_path, 'r')
        if not all_urls:
            sendmessage("[ERROR] No URLs loaded from urls_path", colour="RED", logger=logger)
            return

        # Drop pure binary assets (images/fonts/media/archives/docs) from the
        # whole pipeline - nothing textual to discover or reflect there.
        urls = [u for u in all_urls if not is_binary_asset(u)]
        # Fuzzable subset: everything except binaries AND static JS/CSS/map
        # files, which get discovery only, not fuzzing (see fuzz_phase/main).
        fuzzable_urls = [u for u in urls if is_fuzzable(u)]

        skipped_binary = len(all_urls) - len(urls)
        skipped_static = len(urls) - len(fuzzable_urls)
        if not silent:
            print(f"{green}✓{reset} Loaded {bold}{len(all_urls)}{reset} URL(s) "
                  f"({len(fuzzable_urls)} fuzzable", end="")
            if skipped_binary or skipped_static:
                print(f", {skipped_binary} binary skipped, {skipped_static} static "
                      f"JS/CSS/map kept for discovery-only)")
            else:
                print(")")

        show_status()

        # If -o points at a .json file, start it clean so this run's JSONL
        # stream (one finding per line, written live as things are found)
        # doesn't get appended onto a previous run's leftovers.
        if output and is_json_output_path(output):
            d = os.path.dirname(output)
            if d:
                os.makedirs(d, exist_ok=True)
            open(output, 'w', encoding='utf-8').close()

        # Load the -w/--wordlist seed list once (if given). This is merged
        # per-url with whatever fallparams discovers on that url in
        # discovery_phase - it's an *extra* seed now, not the sole source of
        # truth, so omitting -w no longer means "guess a fake canary param".
        global wordlist_seed
        if wordlist_parameters:
            wordlist_seed = await read_write_list("", wordlist_parameters, 'r')
            if not silent:
                print(f"{green}✓{reset} Loaded {bold}{len(wordlist_seed)}{reset} seed parameter(s) from -w wordlist")
        elif not silent:
            print(f"{dim}ℹ No -w/--wordlist given - relying entirely on fallparams auto-discovery{reset}")

        # PHASE 1: discover real parameters on every non-binary URL (incl.
        # .js/.css - fallparams pulls real API/param names out of JS source).
        await discovery_phase(urls, ['GET'])

        # Optional recon: DOM source/sink keyword scan.
        if dom:
            await dom_scan_phase(urls)

        # PHASE 2: reflection fuzz - only the fuzzable subset, using each
        # url's own discovered params (+ -w seed) rather than a fake canary.
        await fuzz_phase(fuzzable_urls, methods)

        if pathinjection:
            await path_injection_reflix(fuzzable_urls, methods, parameter)
        if headerinjection:
            await header_injection_reflix(fuzzable_urls, methods, parameter)
        if heavy:
            await heavy_reflix(fuzzable_urls, methods)

        # -o/--output when the path ends in .json was already streamed live,
        # one JSON object per line, by append_json_line() as findings came
        # in - nothing left to write here.

        # -jo/--json-output: always a full clean JSON array, written once at
        # the end, independent of -o.
        if json_output:
            try:
                await dump_findings_json(json_output)
            except Exception as e:
                sendmessage(f"[ERROR] Failed to write JSON output: {str(e)}", colour="RED", logger=logger,
                            silent=silent)

        if not silent:
            total_elapsed = time.monotonic() - run_start_time
            print(f"\n{cyan}{'-' * 60}{reset}")
            sev_summary = f"{bold}{len(findings_data)}{reset} finding(s)"
            print(f"{green}✓{reset} Done in {bold}{format_duration(total_elapsed)}{reset} — {sev_summary}, "
                  f"{bold}{len(discovered_parameters)}{reset} parameter(s) discovered")
            if output:
                if is_json_output_path(output):
                    print(f"  {dim}→ findings streamed live to {output} (JSON Lines){reset}")
                else:
                    print(f"  {dim}→ findings also written to {output}{reset}")
            if params_output:
                print(f"  {dim}→ parameters also written to {params_output}{reset}")
            if json_output:
                print(f"  {dim}→ full JSON array written to {json_output}{reset}")
            print(f"{cyan}{'-' * 60}{reset}")

    except KeyboardInterrupt:
        sendmessage("[ERROR] Process interrupted by user.", telegram=notification, colour="RED", logger=logger,
                    silent=silent)
    except Exception as e:
        sendmessage(f"[ERROR] An error occurred: {str(e)}", telegram=notification, colour="RED", logger=logger,
                    silent=silent)


if __name__ == "__main__":
    asyncio.run(main())
