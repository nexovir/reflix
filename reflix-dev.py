#!/usr/bin/env python3
"""
Reflix - Smart parameter injection and reflection fuzzing tool
Fixed/completed version (no headless browser).

Requires external tools on PATH: fallparams, nuclei
(URL-injection generation is now built in - no external `injector` tool needed)
Requires: pyfiglet, colorama, pyyaml, requests
    pip install pyfiglet colorama pyyaml requests --break-system-packages

NOTE: This version no longer depends on Playwright / a headless browser.
All reflection checks (body, path, header, DOM source/sink keyword scan) are
done with plain HTTP requests against the raw response body/headers, which is
enough for keyword-based reflection detection and is much faster/lighter than
spinning up a browser for every URL.
"""

import colorama
import time
import subprocess
import requests
import argparse
import os
import pyfiglet
import yaml
import tempfile
import asyncio
import json
import urllib3
from colorama import Fore, Style
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, parse_qsl

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


VERSION = "1.1.0"

parser = argparse.ArgumentParser(description='Reflix - Smart parameter injection and reflection fuzzing tool')
parser.add_argument('--version', action='version', version=f'Reflix v{VERSION}')

# --- Input ---
input_group = parser.add_argument_group('Input')
input_group.add_argument('-l', '--urls-path', dest='urlspath', required=True,
                          help='Path to file containing the list of target URLs')
input_group.add_argument('-p', '--parameter', default='nexovir', required=False,
                          help='Canary value used to detect reflection (default: "nexovir")')
input_group.add_argument('-w', '--wordlist', required=False,
                          help='Path to a file containing extra parameter names to fuzz')

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
ratelimit_group.add_argument('-rd', '--delay', type=int, default=0, required=False,
                              help='Seconds to wait after each task completes (default: 0)')

# --- Notification & Logging ---
notif_group = parser.add_argument_group('Notification & Logging')
notif_group.add_argument('-n', '--notify', action='store_true', default=False, required=False,
                          help='Send errors/summary to Telegram (needs BOT_TOKEN and BOT_CHAT_ID env vars)')
notif_group.add_argument('-lf', '--log-file', dest='logger', type=str, default=None, required=False,
                          help='Optional log file path (off by default). Console output is controlled '
                               'by -v/--verbose, not by this flag.')
notif_group.add_argument('-s', '--silent', action='store_true', default=False, required=False,
                          help='Suppress the banner and informational console output')
notif_group.add_argument('-v', '--verbose', dest='debug', action='store_true', default=False, required=False,
                          help='Print INFO/DEBUG level status messages to the console (findings are always printed)')

# --- Outputs ---
output_group = parser.add_argument_group('Outputs')
output_group.add_argument('-o', '--output', type=str, default=None, required=False,
                           help='Optional file to also write confirmed findings to (off by default; '
                                'findings are always printed to the console)')
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
delay = args.delay
value_mode = args.valuemode
generate_mode = args.generatemode
pathinjection = args.pathinjection
headerinjection = args.headerinjection
header_wordlist_path = args.headerwordlist
notification = args.notify
logger = args.logger
silent = args.silent
debug = args.debug
output = args.output
params_output = args.paramsoutput
json_output = args.jsonoutput
timeout = args.timeout

INJECTIONS = [f"%27{parameter}", f'%22{parameter}', f"%3E{parameter}"]
INJECTION_RESULTS = [f"'{parameter}".lower(), f'"{parameter}'.lower(), f"&gt;{parameter}".lower()]

# structured findings, populated by record_finding() - exported as JSON at the end if -jo is set
findings_data = []

# every parameter fallparams has discovered, kept in memory so --heavy works
# even when -po/--params-output was never given
discovered_parameters = set()

# global concurrency limiter, driven by --threads
sem = asyncio.Semaphore(thread)

# requests.Session reused across the run for connection pooling
session = requests.Session()


async def sem_task(coro):
    """Run coroutine under the global concurrency limit, applying --delay afterwards."""
    async with sem:
        try:
            result = await coro
        finally:
            if delay:
                await asyncio.sleep(delay)
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
                query_string = '&'.join(f"{p}={parameter_}" for p in chunk_params)
                sep = '&' if '?' in url else '?'
                out.append(f"{url}{sep}{query_string}")
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


async def record_finding(method, severity, place, url, http_type="http"):
    """Print+log a finding in the standard line format, and keep a structured
    copy for --json-output. Used by every reflection check in the tool."""
    sev_color = cyan if severity == "info" else red
    output_line = (f"[{green}{method.upper()}{reset}] [{blue}{http_type}{reset}] "
                   f"[{sev_color}{severity}{reset}] [{yellow}{place}{reset}] {url}")
    print(output_line)
    if output:
        await read_write_list([output_line], output, 'a')
    findings_data.append({
        "method": method.upper(),
        "severity": severity,
        "place": place,
        "url": url,
    })


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
        html, _, _ = await asyncio.to_thread(http_request, target_url, method, headers, None, proxy, timeout)
        if html is None:
            continue
        lowered_html = html.lower()
        for inject_elm in INJECTION_RESULTS:
            if inject_elm in lowered_html:
                await record_finding(method, "medium", reflection_place, target_url)
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
        cmd = ['nuclei', '-u', target_url, '-t', temp_path, '-duc', '-silent', '-fhr']
        if proxy_:
            cmd.extend(['-proxy', proxy_])

        result = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True)

        if result.returncode == 0:
            raw_output = [l for l in result.stdout.splitlines() if l.strip()]
            for line in raw_output:
                parts = line.split('] ')
                if len(parts) >= 3:
                    new_line = '] '.join(parts[:3]) + f'] [{yellow}HTML{reset}] ' + '] '.join(parts[3:])
                else:
                    new_line = line
                print(new_line)
            if raw_output:
                if output:
                    await read_write_list(raw_output, output, 'a')
                findings_data.append({
                    "method": method.upper(),
                    "severity": "info",
                    "place": "HTML",
                    "url": target_url,
                    "nuclei_lines": raw_output,
                })
                if xss:
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


async def static_reflix(base_urls, generate_mode_: str, value_mode_: str, parameter_: str,
                         wordlist_parameters_path, chunk_, proxy_):
    sendmessage("[INFO] Starting Static Reflix ...", colour="YELLOW", logger=logger, telegram=notification,
                silent=silent)

    wl_params = await read_write_list("", wordlist_parameters_path, 'r') if wordlist_parameters_path else []
    if not wl_params:
        # No wordlist given: still let root/ignore modes produce something
        # by fuzzing with the single target parameter instead of doing nothing.
        wl_params = [parameter_]

    sendmessage("   [INFO] Generating candidate URLs ...", colour="YELLOW", logger=logger, silent=silent)
    try:
        urls = await asyncio.to_thread(generate_injected_urls, base_urls, generate_mode_, value_mode_,
                                        parameter_, wl_params, chunk_)
    except Exception as e:
        sendmessage(f"  [ERROR] URL generation failed: {str(e)}", colour="RED", logger=logger, silent=silent)
        return

    sendmessage(f"   [SUCCESS] Generated {len(urls)} candidate URLs", colour="GREEN", logger=logger, silent=silent)
    sendmessage(f"  [INFO] Running nuclei scan on {len(urls)} generated urls & methods: {methods} ...",
                colour="YELLOW", logger=logger, silent=silent)

    tasks = [sem_task(run_nuclei_scan(url, method, headers, None, parameter_, proxy_))
             for url in urls for method in methods]
    if tasks:
        await asyncio.gather(*tasks)


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


async def run_x8(url, parameters, proxy_, method, req_headers, chunk_, parameter_):
    try:
        sendmessage(f"  [INFO] Start fuzzing {len(parameters)} parameters (method: {method}) {url}",
                    colour="YELLOW", logger=logger, silent=silent)
        if not parameters:
            return []
        chunk_size = max(1, int(chunk_))
        chunked_params = [parameters[i:i + chunk_size] for i in range(0, len(parameters), chunk_size)]
        parsed = urlparse(url)
        base_query = parse_qs(parsed.query)

        for group in chunked_params:
            current_params = base_query.copy()
            for param in group:
                current_params[param] = parameter_
            new_query = urlencode(current_params, doseq=True)
            full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query,
                                    parsed.fragment))
            await run_nuclei_scan(full_url, method, req_headers, None, parameter_, proxy_)
    except Exception as e:
        sendmessage(f"[ERROR] Error in run_x8 with URL {url}: {str(e)}", colour="RED", logger=logger, silent=silent)
        return []


async def explore_dom_sinks(url, req_headers, method):
    """Fetch the raw page over HTTP (no browser/rendering) and keyword-scan
    the body for known DOM source/sink API names, reporting the exact line
    number(s) each keyword was found on so it can be located quickly."""
    sendmessage(f"  [INFO] Starting DOM sinks/sources exploration url: {url}", colour="YELLOW", logger=logger,
                silent=silent)
    html, _, _ = await asyncio.to_thread(http_request, url, method, req_headers, None, proxy, timeout)
    if html is None:
        return {"success": False, "url": url}

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

        output_line = (f"[{green}{method.upper()}{reset}] [{blue}http{reset}] [{cyan}info{reset}] "
                        f"[{yellow}{category}: {red}{sinks_str}{reset}] {url}")
        print(output_line)
        if output:
            await read_write_list([output_line], output, 'a')
        findings_data.append({
            "method": method.upper(),
            "severity": "info",
            "place": category,
            "url": url,
            "sinks": [{"keyword": keyword, "lines": hit_lines} for keyword, hit_lines in matches],
        })
    return {"success": True, "url": url}


async def process_url_method(url, method):
    # Parameter discovery runs on every non-binary URL, including .js/.css -
    # that's exactly where fallparams tends to find real API param names.
    parameters = await run_fallparams(url, proxy, method, headers)
    if not parameters:
        return
    discovered_parameters.update(parameters)
    if params_output:
        await read_write_list(parameters, params_output, 'a')

    # But actually injecting/fuzzing those params only makes sense against
    # fuzzable endpoints - a static .js/.css file won't reflect a query
    # param back no matter what you send it.
    if not is_fuzzable(url):
        sendmessage(f"  [INFO] Skipping fuzz on static asset (discovery only): {url}",
                    colour="YELLOW", logger=logger, silent=silent)
        return
    await run_x8(url, parameters, proxy, method, headers, chunk, parameter)


async def light_reflix(urls, methods):
    sendmessage("[INFO] Starting Light Reflix ...", colour="YELLOW", logger=logger, silent=silent)
    tasks = []
    for url in urls:
        if dom:
            tasks.append(sem_task(explore_dom_sinks(url, headers, 'GET')))
        for method in methods:
            tasks.append(sem_task(process_url_method(url, method)))
    if tasks:
        await asyncio.gather(*tasks)


async def heavy_reflix(urls, methods):
    sendmessage("[INFO] Starting Heavy Reflix ...", colour="YELLOW", logger=logger, silent=silent)
    # Use whatever fallparams has found so far this run, regardless of
    # whether -po/--params-output was set (that flag only controls whether
    # it's *also* written to disk).
    parameters = list(discovered_parameters)
    if params_output:
        # merge in anything from a previous run that was persisted to disk
        on_disk = await read_write_list('', params_output, 'r')
        for p in on_disk:
            if p not in discovered_parameters:
                parameters.append(p)
    if not parameters:
        return
    tasks = [sem_task(run_x8(url, parameters, proxy, method, headers, chunk, parameter))
             for url in urls for method in methods]
    if tasks:
        await asyncio.gather(*tasks)


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

    found_html = parameter_.lower() in html.lower()
    found_header = any(parameter_.lower() in str(v).lower() for v in resp_headers.values())

    if found_html:
        await record_finding(method, "info", "PATH-BODY", injected_url)
        if xss:
            await try_to_xss(injected_url, method, 'PATH-BODY')
    if found_header:
        await record_finding(method, "info", "PATH-HEADER", injected_url)
    return {"success": True, "url": injected_url}


async def path_injection_reflix(urls, methods, parameter_):
    sendmessage("[INFO] Starting PATH Reflection Reflix ...", colour="YELLOW", logger=logger, silent=silent)
    tasks = [sem_task(run_path_reflection(url, parameter_, method)) for url in urls for method in methods]
    if tasks:
        await asyncio.gather(*tasks)


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

    found_html = parameter_.lower() in html.lower()
    found_header = any(parameter_.lower() in str(v).lower() for v in resp_headers.values())

    if found_html:
        await record_finding(method, "info", "HEADER-BODY", url)
        if xss:
            await try_to_xss(url, method, 'HEADER-BODY')
    if found_header:
        await record_finding(method, "info", "HEADER-RESPONSE", url)
    return {"success": True, "url": url}


async def header_injection_reflix(urls, methods, parameter_):
    sendmessage("[INFO] Starting HEADER Reflection Reflix ...", colour="YELLOW", logger=logger, silent=silent)
    header_keys = await load_header_test_keys(header_wordlist_path)
    sendmessage(f"   [INFO] Testing {len(header_keys)} header names per request", colour="YELLOW",
                logger=logger, silent=silent)
    tasks = [sem_task(run_header_reflection(url, parameter_, method, header_keys))
             for url in urls for method in methods]
    if tasks:
        await asyncio.gather(*tasks)


async def main():
    try:
        if not silent:
            show_banner()
        all_urls = await read_write_list("", urls_path, 'r')
        if not all_urls:
            sendmessage("[ERROR] No URLs loaded from urls_path", colour="RED", logger=logger)
            return

        # Drop pure binary assets (images/fonts/media/archives/docs) from the
        # whole pipeline - nothing textual to discover or reflect there.
        urls = [u for u in all_urls if not is_binary_asset(u)]
        # Fuzzable subset: everything except binaries AND static JS/CSS/map
        # files, which get discovery only (see process_url_method).
        fuzzable_urls = [u for u in urls if is_fuzzable(u)]

        skipped_binary = len(all_urls) - len(urls)
        skipped_static = len(urls) - len(fuzzable_urls)
        if not silent and (skipped_binary or skipped_static):
            print(f"[{yellow}*{reset}] {len(all_urls)} URLs loaded — "
                  f"{skipped_binary} binary asset(s) skipped entirely, "
                  f"{skipped_static} static JS/CSS/map file(s) kept for "
                  f"parameter discovery only (no fuzzing).")

        await static_reflix(fuzzable_urls, generate_mode, value_mode, parameter, wordlist_parameters, chunk, proxy)
        await light_reflix(urls, methods)

        if pathinjection:
            await path_injection_reflix(fuzzable_urls, methods, parameter)
        if headerinjection:
            await header_injection_reflix(fuzzable_urls, methods, parameter)
        if heavy:
            await heavy_reflix(fuzzable_urls, methods)

        if json_output:
            try:
                def _dump():
                    with open(json_output, 'w') as f:
                        json.dump(findings_data, f, indent=2, ensure_ascii=False, sort_keys=False)
                await asyncio.to_thread(_dump)
                if not silent:
                    print(f"[{green}+{reset}] {len(findings_data)} findings written to {json_output}")
            except Exception as e:
                sendmessage(f"[ERROR] Failed to write JSON output: {str(e)}", colour="RED", logger=logger,
                            silent=silent)

        if not silent:
            print(f"\n[{green}+{reset}] Done. {len(findings_data)} finding(s), "
                  f"{len(discovered_parameters)} parameter(s) discovered.")
            if output:
                print(f"[{green}+{reset}] Findings also written to {output}")
            if params_output:
                print(f"[{green}+{reset}] Parameters also written to {params_output}")

    except KeyboardInterrupt:
        sendmessage("[ERROR] Process interrupted by user.", telegram=notification, colour="RED", logger=logger,
                    silent=silent)
    except Exception as e:
        sendmessage(f"[ERROR] An error occurred: {str(e)}", telegram=notification, colour="RED", logger=logger,
                    silent=silent)


if __name__ == "__main__":
    asyncio.run(main())
