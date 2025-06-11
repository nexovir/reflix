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
input_group.add_argument('-l', '--urlslist', help='Path to file containing list of target URLs', metavar='', required=True)
input_group.add_argument('-p', '--parameters', help='Comma-separated parameters to test for reflection (default: "nexovir")', default='nexovir', metavar='', required=False)
input_group.add_argument('-c', '--chunk', help='Number of URLs to process per batch (default: 25)', default=25, metavar='', required=False)

# --- Notification & Logging Group ---
notif_group = parser.add_argument_group('Notification & Logging')
notif_group.add_argument('-notif', '--notify', help='Enable or disable notifications (true/false)', type=str2bool, default=False, metavar='', required=False)
notif_group.add_argument('-g', '--logger', help='Enable or disable logger (true/false)', type=str2bool, default=False, metavar='', required=False)


args = parser.parse_args()
urls_list = args.urlslist
parameters = args.parameters
chunk = args.chunk
notification = args.notify
logger = args.logger


def file_reader(file_name : str) -> list:
    urls = []
    try :
        with open(file_name , 'r') as file :
            urls.append(file.writelines)
        return urls
    except Exception as e :
        sendmessage(f"An error occurred : {str(e)}" , telegram= notification , colour="RED" , logger=logger)

try : 
    sendmessage("Reflix - Smart parameter injection and fuzzing tool", telegram=False, colour="YELLOW", logger=True)
    print(notification)
    print(urls)
    light_xss(urls)
    

except KeyboardInterrupt:
    sendmessage("Process interrupted by user.", telegram= notification, colour="RED", logger=logger)
except Exception as e:
    sendmessage(f"An error occurred: {str(e)}", telegram= notification, colour="RED", logger=logger)