import colorama, time, subprocess, requests , argparse, os , re , pyfiglet , yaml , tempfile, json
from yaspin import yaspin # type: ignore
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse , parse_qs
from typing import List, Dict


def show_banner():
    banner = pyfiglet.figlet_format("Reflix")
    twitter = Style.BRIGHT + Fore.CYAN + "X.com: @nexovir" + Style.RESET_ALL
    version = Fore.LIGHTBLACK_EX + "v1.0.0" + Style.RESET_ALL

    total_width = 20
    twitter_centered = twitter.center(total_width)
    version_right = version.rjust(total_width)

    print(banner + twitter_centered  + version_right + "\n")


def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: bool = True , silent : bool = False):
    color = getattr(colorama.Fore, colour, colorama.Fore.YELLOW)
    if not silent:
        print(color + message + colorama.Style.RESET_ALL)
    time_string = time.strftime("%d/%m/%Y, %H:%M:%S", time.localtime())
    if logger:
        with open('logger.txt', 'a') as file:
            file.write(message + ' -> ' + time_string + '\n')

    if telegram:
        token_bot = {YOUR_TOKEN_BOT} 
        chat_id = "5028701156"
        url = f"https://api.telegram.org/bot{token_bot}/sendMessage"
        payload = {'chat_id': chat_id, 'text': message}

        try:
            response = requests.post(url, data=payload)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Telegram message failed: {e}")

def log_event(message: str, level: str = "INFO", telegram: bool = False):
    levels = {
        "INFO": "YELLOW",
        "SUCCESS": "GREEN",
        "WARNING": "MAGENTA",
        "ERROR": "RED",
        "DEBUG": "BLUE"
    }
    prefix = {
        "INFO": "[*] ",
        "SUCCESS": "[+] ",
        "WARNING": "[!] ",
        "ERROR": "[-] ",
        "DEBUG": "[#] "
    }

    colour = levels.get(level.upper(), "YELLOW")
    prefix_msg = prefix.get(level.upper(), "")
    sendmessage(
        prefix_msg + message,
        telegram=telegram,
        colour=colour,
        logger=logger,
        silent=silent
    )



parser = argparse.ArgumentParser(description='Reflix - Smart parameter injection and fuzzing tool')

# --- Input Group ---
input_group = parser.add_argument_group('Input Options')
input_group.add_argument('-l', '--urlspath', help='Path to file containing list of target URLs for discovery. Note: During parameter discovery, the tool will request and analyze the full content of each URL. However, during parameter fuzzing, URLs with certain file extensions (e.g., .js, .png, .jpg, .ttf, etc.) will be automatically excluded.', required=True)
input_group.add_argument('-p', '--parameter', help='Comma-separated parameter to test for reflection (default: "nexovir")', default='nexovir', required=False)
input_group.add_argument('-w', '--wordlist',    help='Path to a file containing parameters to fuzz for reflection',required=False)


# --- Configurations ---
notif_group = parser.add_argument_group('Configurations')
notif_group.add_argument('-X', '--methods', help='HTTP methods to use for requests (e.g., GET,POST) (default "GET,POST")', type=str, default="GET,POST", required=False)
notif_group.add_argument('-H', '--headers',help='Custom headers to include in requests (format: "Header: value" support multi -H)',action='append',required=False,default=[])
notif_group.add_argument('-x', '--proxy', help='HTTP proxy to use (e.g., http://127.0.0.1:8080)', type=str, default='', required=False)
input_group.add_argument('-c', '--chunk', help='Number of URLs to process per batch (default: 25)',type=str,  default='25', required=False)


# --- Rate Limit Options ---
ratelimit_group = parser.add_argument_group('Rate Limit Options')
ratelimit_group.add_argument('-t', '--thread',type=int,help='Number of concurrent threads to use (default: 1)',default=1,required=False)
ratelimit_group.add_argument('-rd', '--delay',type=int,help='Delay (in seconds) between requests (default: 0)',default=0,required=False)


# --- Notification & Logging Group ---
notif_group = parser.add_argument_group('Notification & Logging')
notif_group.add_argument('-n', '--notify', help='Enable notifications', action='store_true', default=False, required=False)
notif_group.add_argument('-g', '--logger', help='Enable logger', action='store_true', default=False, required=False)
notif_group.add_argument('-s', '--silent', help='Disable prints output to the command line (default: False)', action='store_true', default=False, required=False)


# --- Output ---
notif_group = parser.add_argument_group('Outputs')
notif_group.add_argument('-po', '--paramsoutput', help='Path to file where discovered parameters will be saved (default: paramters.txt)', required=False , default='all_params.txt')
notif_group.add_argument('-o', '--output',help='output file to write found issues/vulnerabilities ', type=str ,required=False)
notif_group.add_argument('-jo', '--jsonoutput',help='file to export results in JSON format',type=str ,required=False)

args = parser.parse_args()

#Input & Group
urls_path = args.urlspath
parameter = args.parameter
wordlist_parameters = args.wordlist

#Configuration
methods = args.methods.split(',')
headers = {}
if args.headers:
    for header in args.headers:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()

proxy = args.proxy
chunk = args.chunk

#Ratelimit Option
thread = args.thread
delay = args.delay

#Injector Mode 
value_mode = 'append'
generate_mode = 'all'

#Notification
notification = args.notify
logger = args.logger
silent = args.silent

#Output
params_output = args.paramsoutput
output = args.output
json_output = args.jsonoutput

def read_write_list(list_data: list, file: str, type: str):

    objects = []
    
    if type == "read" or type == 'r':
        with open(file, 'r') as f:
            objects = list(set(line.strip() for line in f.read().splitlines() if line.strip()))
        return objects

    
    elif type == "write" or type == 'w': 
        with open(file, 'w') as f:
            for item in set(list_data):
                f.write(item.strip() + '\n')


    elif type == "append" or type == 'a':
        try:
            with open(file, 'r') as f:
                existing_items = set(f.read().splitlines())
        except FileNotFoundError:
            existing_items = set()
        
        with open(file, 'a') as f:
            for item in set(list_data):
                if item.strip() and item not in existing_items:
                    f.write(item.strip() + '\n')


def run_nuclei_scan(target_url, method='GET', headers=None, post_data=None, search_word = "nexovir" , proxy =''):  
    
    template = {
            'id': f'{method.upper()}',
            'info': {
                'name': f'Reflix ({method.upper()})',
                'author': 'Reflix',
                'severity': 'info',
            },
            'requests': [
                {
                    'method': method.upper(),
                    'path': ["{{BaseURL}}"],
                    'headers': headers or {},
                    'matchers': [
                        {
                            'type': 'word',
                            'words': [search_word],
                            'part': 'body'
                        }
                    ]
                }
            ]
    }
        
    if method.upper() == 'POST':
        template['requests'][0]['body'] = post_data
        if 'Content-Type' not in template['requests'][0]['headers']:
            template['requests'][0]['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
        
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
        yaml.dump(template, temp_file)
        temp_path = temp_file.name
    try:
        cmd = ['nuclei', '-u', target_url, '-t', temp_path, '-duc', '-silent' , '-p' , proxy]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            raw_output = result.stdout.splitlines()
            for line in raw_output:
                sendmessage(line)
                
            return {
                'success': True,
                'raw_results': raw_output,
                'stats': f"line count: {len(raw_output)}"
            }
        else:
            sendmessage(f"  [-] Nuclei error: {result.stderr}", colour="RED")
            return {
                'success': False,
                'error': result.stderr
            }
    finally:
        os.unlink(temp_path)
    

def static_reflix (urls_path : str , generate_mode : str , value_mode : str , parameter : str , wordlist_parameters : list , chunk : int , proxy):
    
    sendmessage("[*] Starting Static Reflix ...", colour="YELLOW")

    try : 
        command = [
        "injector",
        "-l",urls_path,
        "-p",parameter,
        "-c",chunk,
        "-vm",value_mode,
        "-gm",generate_mode,
        '-s'
        ]
        print(command)
        if wordlist_parameters: 
            command.extend(["-w", wordlist_parameters])
        
        sendmessage("   [*] Running injector ...", colour="YELLOW")

        result = subprocess.run(
            command,
            shell=False,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        sendmessage("   [+] Injector finished successfully", colour="GREEN")

    except subprocess.CalledProcessError as e:
        sendmessage(f"  [-] Injector failed: {e.stderr}", colour="RED")
        return
    except Exception as e:
        sendmessage(f"  [-] Unexpected error during injector: {str(e)}", colour="RED")
        return
        
    urls = result.stdout.splitlines()
    sendmessage(f"  [*] Running nuclei scan on {len(urls)} generated urls & methods: {methods} ...", colour="YELLOW")
    for url in urls :      
        for method in methods:
            run_nuclei_scan(url , method , headers , None , parameter , proxy)


def run_fallparams(url, proxy, thread, delay, method , headers):
    
    try:
        
        command = [
        "fallparams",
        "-u",url,
        "-x",proxy if proxy else '',
        "-X",method,
        '-silent',
        '-duc',
        ]
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
        result = subprocess.run(
            command,
            shell=False,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        return result.stdout.splitlines()
    except Exception as e:
        sendmessage(f"  [-] Error fallparams URL {url}: {str(e)}", colour="RED", logger=logger, silent=silent)
        return


def run_x8(url, parameters, proxy, thread, delay, method, headers, chunk , parameter):
    try:
        chunked_params = [parameters[i:i + int(chunk)] for i in range(0, len(parameters), int(chunk))]

        parsed = urlparse(url)
        base_query = parse_qs(parsed.query)

        for group in chunked_params:
            current_params = base_query.copy()
            for param in group:
                current_params[param] = parameter

            new_query = urlencode(current_params, doseq=True)
            full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            run_nuclei_scan(full_url , method , headers , None , parameter , proxy)
            
    except Exception as e:
        sendmessage(f"Error in run_x8 with URL {url}: {str(e)}", colour="RED")
        return []


def light_reflix (urls, proxy, thread, delay, methods):

    sendmessage("[*] Starting Light Reflix ...", colour="YELLOW")
    for url in urls :
        for method in methods:
            sendmessage(f"   [*] Starting parameter discovery and check reflection (method: {method}) {url}...", colour="YELLOW")
            parameters = run_fallparams(url, proxy, thread, delay, method, headers)
            
            # save paramters output for client
            read_write_list(parameters , params_output , 'a')

            run_x8(url , parameters,  proxy , thread , delay , method, headers, chunk , parameter)
            time.sleep(delay)


def main():
    try:
        show_banner() if not silent else None
        urls = read_write_list("", urls_path, 'r')
        static_reflix (urls_path, generate_mode ,value_mode ,parameter , wordlist_parameters , chunk , proxy)
        light_reflix(urls, proxy, thread, delay, methods)

    except KeyboardInterrupt:
        sendmessage(
            "Process interrupted by user.",
            telegram=notification,
            colour="RED",
            logger=logger,
            silent=silent
        )
    except Exception as e:
        sendmessage(
            f"An error occurred: {str(e)}",
            telegram=notification,
            colour="RED",
            logger=logger,
            silent=silent
        )


if __name__ == "__main__":
    main()