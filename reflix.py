import colorama, time, subprocess, requests , argparse, os
from yaspin import yaspin # type: ignore


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


def str2bool(v):
    return str(v).lower() in ("yes", "true", "t", "1")


parser = argparse.ArgumentParser(description='Reflix - Smart parameter injection and fuzzing tool')

# --- Input Group ---
input_group = parser.add_argument_group('Input Options')
input_group.add_argument('-l', '--urlspath', help='Path to file containing list of target URLs', required=True)
input_group.add_argument('-p', '--parameters', help='Comma-separated parameters to test for reflection (default: "nexovir")', default='nexovir', required=False)
input_group.add_argument('-c', '--chunk', help='Number of URLs to process per batch (default: 25)', default=25, required=False)

# --- Modes ---
notif_group = parser.add_argument_group('Mode')
notif_group.add_argument('-vm' , '--valuemode' ,help='How to apply valuemode: {"append" , "replace"} (default \"append\")',choices=['append', 'replace'],default='append',required=False)
notif_group.add_argument('-gm', '--generatemode',help='Control how parameters are generated: {"normal", "ignore", "combine", "all"} (default: "all")',choices=['normal', 'ignore', 'combine', 'all'],default='all',required=False)

# --- Configurations ---
notif_group = parser.add_argument_group('Configurations')
notif_group.add_argument('-X', '--methods', help='HTTP methods to use for requests (e.g., GET,POST) (default "GET")', type=str, default='GET', required=False)
notif_group.add_argument('-H', '--header', help='Custom headers to include in requests (format: "Header1: value1; Header2: value2")', type=str, default='', required=False)
notif_group.add_argument('-x', '--proxy', help='HTTP proxy to use (e.g., http://127.0.0.1:8080)', type=str, default='', required=False)

# --- Rate Limit Options ---
ratelimit_group = parser.add_argument_group('Rate Limit Options')
ratelimit_group.add_argument('-t', '--thread',type=int,help='Number of concurrent threads to use (default: 1)',default=5,required=False)
ratelimit_group.add_argument('-rd', '--delay',type=int,help='Delay (in seconds) between requests (default: 0)',default=0,required=False)

# --- Notification & Logging Group ---
notif_group = parser.add_argument_group('Notification & Logging')
notif_group.add_argument('-n', '--notify', help='Enable notifications', action='store_true', default=False, required=False)
notif_group.add_argument('-g', '--logger', help='Enable logger', action='store_true', default=False, required=False)
notif_group.add_argument('-s', '--silent', help='Disable prints output to the command line (default False)', action='store_true', default=False, required=False)

# --- Output ---
notif_group = parser.add_argument_group('Outputs')
notif_group.add_argument('-po', '--paramsoutput', help='Show discovered parameters in Telegram notification', required=False)


args = parser.parse_args()

#Input & Group
urls_path = args.urlspath
parameters = args.parameters
chunk = args.chunk

#Mode
value_mode = args.valuemode
generate_mode = args.generatemode

#Configuration
methods = args.methods.split(',')
header = args.header.split(',')
proxy = args.proxy

#Ratelimit Option
thread = args.thread
delay = args.delay

#Notification
notification = args.notify
logger = args.logger
silent = args.silent

#Output
params_output = args.paramsoutput

def read_write_list(list_data: list, file: str, type: str):

    objects = []
    
    if type == "read" or type == 'r':
        with open(file, 'r') as f:
            objects = set(f.read().splitlines())
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



def light_reflector(urls: list):
    def validate_header(headers: list) -> str:
        return ' '.join([f'-H "{header}"' for header in headers]) if headers else ''

    sendmessage(
        "[INFO] Starting Detective Light Reflection",
        telegram=notification,
        colour="YELLOW",
        logger=logger,
        silent=silent
    )

    for url in urls:
        try:
            url_switch = f'-u "{url}"' if url else ''
            proxy_switch = f'-x {proxy}' if proxy else ''
            header_switch = validate_header(header)
            thread_switch = f'-t {thread}' if thread else ''
            delay_switch = f'-rd {delay}' if delay else ''

            sendmessage(
                f"  [INFO] Starting Discover Parameters for URL: {url}",
                telegram=notification,
                colour="WHITE",
                logger=logger,
                silent=silent
            )

            discovered_parameters = []

            for method in methods:
                fallparams_cmd = f'fallparams {url_switch} -silent {proxy_switch} {delay_switch} {thread_switch} {header_switch} -X {method} -o /dev/null 2>&1 '
                
                try:
                    fallparams_output = os.popen(fallparams_cmd).read()
                    if fallparams_output:
                        params = [p.strip() for p in fallparams_output.split('\n') if p.strip()]
                        discovered_parameters.extend(params)
                except Exception as e:
                    sendmessage(
                        f"  [ERROR] Failed to run fallparams for method {method}: {e}",
                        telegram=notification,
                        colour="RED",
                        logger=logger,
                        silent=silent
                    )

            discovered_parameters = list(set(discovered_parameters))
            all_parameters.extend(discovered_parameters)
            all_parameters[:] = list(set(all_parameters))

            read_write_list (discovered_parameters , 'params.temp' , 'w')
            read_write_list(all_parameters , f"{params_output}", 'a')

        except KeyError as e:
            sendmessage(
                f"[ERROR] Missing config key: {e}",
                telegram=notification,
                colour="RED",
                logger=logger,
                silent=silent
            )
        except Exception as e:
            sendmessage(
                f"  [ERROR] Failed to process URL: {url} - {e}",
                telegram=notification,
                colour="RED",
                logger=logger,
                silent=silent
            )


try:
    all_parameters = []
    urls = read_write_list("", urls_path, 'r')
    light_reflector(urls)

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