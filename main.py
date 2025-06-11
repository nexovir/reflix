import colorama, time, subprocess, requests , argparse, os



def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: bool = True):
    color = getattr(colorama.Fore, colour, colorama.Fore.YELLOW)
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
notif_group.add_argument('-n', '--notify', help='Enable or disable notifications (true/false)', action='store_true', default=False, required=False)
notif_group.add_argument('-g', '--logger', help='Enable or disable logger (true/false)', action='store_true', default=False, required=False)
notif_group.add_argument('-s', '--silent', help='Disable prints output to the command line (default False)', action='store_true', default=False, required=False)

args = parser.parse_args()

#Input & Group
urls_path = args.urlspath
parameters = args.parameters
chunk = args.chunk

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


def file_reader(file_name : str) -> list:
    urls = []
    try :
        with open(file_name , 'r') as file :
            [urls.append(line.strip()) for line in file]
        return urls
    except Exception as e :
        sendmessage(f"An error occurred : {str(e)}" , telegram= notification , colour="RED" , logger=logger)


    

def light_reflector(urls : list):

    def validate_header(headers : list) -> str:
        valid_header = ""
        for header in headers :
            valid_header += f' -H \"{header}\"'
        return valid_header
    
    for url in urls : 
        if url != "":
            try :
                for method in methods : 
                    print(method)
                    fallparams_req = f'fallparams -u {url} -x {proxy} {validate_header(header)} -X {method} -silent'
                    print(fallparams_req)
                    fallparams = os.popen(fallparams_req).read()

                flush (f"fallparams (POST,GET) at -> {url} was successfully done \n" , colour="GREEN")

                all_parameters = fallparams_get.splitlines() + fallparams_post.splitlines()

                read_write_list(all_parameters ,'parameters.txt' , type='w')

                read_write_list(all_parameters, '../../../word_lists/special-parameters.txt' , type='a')
                
                x8_req= "sudo x8 -u \""+url.strip()+"\" -w "+"parameters.txt " + f"-m {int(chunk)}"+" -X GET POST  --output-format json --output x8.json"
                x8 = os.popen(x8_req).read()
                flush (f"x8 (POST,GET) at -> {url} was successfully done \n" , colour="GREEN")
                time.sleep(1)
                extract_json()

                with open ('checked_urls.txt' , 'a') as file:
                    file.write(url.strip()+'\n')
                
            except KeyError as e:
                sendmessage(str(e),telegram=False , logger=True)


try : 
    sendmessage("Reflix - Smart parameter injection and fuzzing tool", telegram=False, colour="YELLOW", logger=True)
    
    urls = file_reader(urls_path)
    light_reflector(urls)
    

except KeyboardInterrupt:
    sendmessage("Process interrupted by user.", telegram= notification, colour="RED", logger=logger)
except Exception as e:
    sendmessage(f"An error occurred: {str(e)}", telegram= notification, colour="RED", logger=logger)