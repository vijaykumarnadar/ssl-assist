import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import ipaddress
import argparse
import signal
import glob
import threading
from queue import Queue
import shutil
import csv
import datetime
import logging


# Constants
LOG_FILE = 'script_activity.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
CSV_DIR = "./csv_outputs"
SCREEN_DIR = "./screen_outputs"
DONE_FILE = 'done.txt'
nmap_ips = "nmap-ips.txt"
nessus_ips = "nessus-ips.txt"

# Regex Patterns
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?')
SUBNET_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}')
HOSTNAME_REGEX = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?::\d{1,5})?')
URL_REGEX = re.compile(r'(?:http[s]?:\/\/)?([^\/\s:]+(?::\d{1,5})?)(?:\/|\s|$)')
IP_RANGE_REGEX = re.compile(r'(\b(?:\d{1,3}\.){3}\d{1,3})\s*-\s*(\b(?:\d{1,3}\.){3}\d{1,3}\b)')



# Thread lock
progress_lock = Lock()

# Add this utility function somewhere at the top of your script
def cprint(message, nature="info", **kwargs):
    """Prints a message in color according to its nature, with additional print options."""
    colors = {
        "info": "\033[94m",  # Blue
        "success": "\033[92m",  # Green
        "error": "\033[91m",  # Red
        "warning": "\033[93m",  # Yellow
    }
    reset = "\033[0m"  # Resets the color to default
    color_code = colors.get(nature, reset)
    print(f"{color_code}{message}{reset}", **kwargs)



def signal_handler(sig, frame):
    cprint('[!] Ctrl+C pressed, terminating the script!', 'warning', flush=True)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def extract_data(file_path):
    logging.info("Starting data extraction from file.")
    cprint(f"[+] Starting data extraction from file.", 'info', flush=True)
    try:
        with open(file_path, 'r') as file:
            text = file.read()
    except FileNotFoundError:
        cprint(f"[-]  Error: Input file not found.", 'error', flush=True)
        sys.exit(1)
    except IOError as e:
        cprint(f"[-]  IO error occurred: {e}", 'error', flush=True)
        sys.exit(1)


    ips = IP_REGEX.findall(text)
    subnets = SUBNET_REGEX.findall(text)
    hostnames = HOSTNAME_REGEX.findall(text)
    urls = URL_REGEX.findall(text)
    ip_ranges = IP_RANGE_REGEX.findall(text)

    domains = [HOSTNAME_REGEX.search(url).group() for url in urls if HOSTNAME_REGEX.search(url)]
    

    # Resolve CIDR notations
    resolved_ips = []
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet)
            resolved_ips.extend([str(ip) for ip in network])
        except ValueError:
            cprint(f"[-] Invalid CIDR block: {subnet}", 'error', flush=True)

    # Resolve IP ranges
    for start_ip, end_ip in ip_ranges:
        try:
            start_ip_int = int(ipaddress.IPv4Address(start_ip))
            end_ip_int = int(ipaddress.IPv4Address(end_ip))
            resolved_ips.extend([str(ipaddress.IPv4Address(ip)) for ip in range(start_ip_int, end_ip_int + 1)])
        except ValueError as e:
            cprint(f"[-] Invalid IP range: {start_ip}-{end_ip}", 'error', flush=True)

    for ip in resolved_ips:
        logging.debug(f"IP resolved from subnet: {ip}")

    extracted_data = list(set(ips + resolved_ips + hostnames + domains))
    logging.info(f"Consolidated {len(extracted_data)} unique items (IPs, resolved IPs, hostnames, domains).")
    logging.info(f"Extracted IPs {extracted_data}")
    cprint(f"[+] Consolidated {len(extracted_data)} unique items (IPs, resolved IPs, hostnames, domains).", 'info', flush=True)
    with open('temp-ips.txt', 'w') as f:
        f.writelines(f"{ip}\n" for ip in extracted_data)


    ssl_confirm("temp-ips.txt", "host-data.txt")

    line_count = subprocess.check_output(f"wc -l < host-data.txt", shell=True).strip()
    cprint(f"[+] {line_count.decode()} unique hosts with ssl enabled found in the input file", 'success', flush=True)
    os.remove('temp-ips.txt')

def is_ip_done(ip):
    with open(DONE_FILE, 'r') as file:
        done_ips = file.read().splitlines()
    return ip in done_ips

def mark_ip_done(ip):
    with open(DONE_FILE, 'a') as file:
        file.write(ip + '\n')

def process_ip(ip):
    logging.debug(f"Processing IP: {ip}.")
    if is_ip_done(ip):
        cprint(f"[!] Skipping {ip}, already processed.", 'warning', flush=True)
        logging.debug(f"Skipping already processed IP: {ip}.")
        return

    cprint(f"[+] Processing {ip}...", 'info', flush=True)
    filename = ip.replace(':', '_').replace('/', '_')
    csv_file = os.path.join(CSV_DIR, f"{filename}.csv")
    screen_file = os.path.join(SCREEN_DIR, f"{filename}.screen.txt")

    # Check if output files exist and delete them if they do
    if os.path.exists(csv_file):
        os.remove(csv_file)
        cprint(f"[!] Existing CSV file {csv_file} deleted.", 'warning', flush=True)
    if os.path.exists(screen_file):
        os.remove(screen_file)
        cprint(f"[!] Existing screen output file {screen_file} deleted.", 'warning', flush=True)

    command = f"testssl --csvfile '{csv_file}' '{ip}' 2>&1 | tee '{screen_file}'"
    try:
        process = subprocess.run(command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.SubprocessError as e:
        cprint(f"[-] Subprocess error occurred: {e}", 'error', flush=True)
        return

    with progress_lock:
        if process.returncode == 0:
            mark_ip_done(ip)
        else:
            cprint(f"[-] Error processing {ip}. Command failed with return code {process.returncode}", flush=True)



def parse_arguments():
    parser = argparse.ArgumentParser(description='Extract SSL/TLS IPs from Nmap .gnmap files')
    parser.add_argument('--nmap', help='Path to Nmap file or folder', required=True)
    return parser.parse_args()

def extract_ssl_ips(file_path):
    global all_ssl_ips
    ssl_ips = set()

    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Host:'):
                parts = line.split()
                host = parts[1].split('(')[0]  # Extracting the IP address
                services = parts[2:]

                for service in services:
                    # Extracting the port number
                    port = service.split('/')[0]

                    # Check if the service part contains 'ssl', 'tls', or is port 443
                    if '443' == port or '/ssl' in service.lower() or '/tls' in service.lower():
                        ssl_ips.add(f"{host}:{port}")

    return ssl_ips

def save_ssl_ips(file_name):
    global all_ssl_ips
    if os.path.isdir(args.nmap):
        for filename in glob.glob(os.path.join(args.nmap, '*.gnmap')):
            ssl_ips = extract_ssl_ips(filename)
            all_ssl_ips.update(ssl_ips)
    elif os.path.isfile(args.nmap):
        all_ssl_ips = extract_ssl_ips(args.nmap)
    else:
        cprint("[-] Invalid path provided.", 'error', flush=True)
        return

    with open(file_name, 'w') as file:
        for ip in sorted(all_ssl_ips):
            file.write(ip + '\n')
    with open(file_name, 'r') as file:
            content = file.read()
            logging.info(f"IPs found in nmap file:\n\n{content}")

    ssl_confirm(file_name, nmap_ips)
    with open(nmap_ips, 'r') as file:
            content = file.read()
            logging.info(f"SSL/TLS enabled IPs found in nmap file:\n\n{content}")
    line_count = subprocess.check_output(f"wc -l < {nmap_ips}", shell=True).strip()
    cprint(f"[+] {line_count.decode()} SSL/TLS enabled hosts found in Nmap file.", 'info', flush=True)



def parse_nessus_file(path):
    unique_entries = set()

    # Determine if path is a directory or a single CSV file
    is_directory = os.path.isdir(path)
    combined_filename = 'combined-unique-open-ports.txt' if is_directory else None

    csv_files = glob.glob(os.path.join(path, '*.csv')) if is_directory else [path]

    for csv_filename in csv_files:
        out_open_ports = f'{os.path.splitext(csv_filename)[0]}-open.ports.txt'
        open_ports = []

        with open(csv_filename, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                plugin_output = row['Plugin Output']
                if 'was found to be open' in plugin_output:
                    host = row['Host']
                    port = row['Port']
                    protocol = row['Protocol']
                    entry = f'{host}:{port}'
                    open_ports.append(entry)
                    unique_entries.add(entry)

        with open(out_open_ports, 'w', encoding='utf-8') as f:
            for entry in open_ports:
                f.write(f"{entry}\n")

        cprint(f"[+] Open ports information written to {out_open_ports}", 'success', flush=True)
        cprint(f"[+] Total entries: {len(open_ports)}", 'info', flush=True)

    # Combine unique entries if multiple CSV files
    if is_directory and csv_files:
        combined_filename = os.path.join(path, combined_filename)
        with open(combined_filename, 'w', encoding='utf-8') as f:
            for entry in unique_entries:
                f.write(f"{entry}\n")
        cprint(f"[+] Combined unique open ports information written to {combined_filename}", 'success', flush=True)
        cprint(f"[+] Total unique entries: {len(unique_entries)}", 'info', flush=True)

    # Invoke the ssl_check function with the appropriate file
    file_to_check = combined_filename if is_directory else out_open_ports
    with open(file_to_check, 'r') as file:
            content = file.read()
            logging.info(f"IPs found in nessus file:\n\n{content}")

    ssl_confirm(file_to_check, nessus_ips)
    with open(nessus_ips, 'r') as file:
            content = file.read()
            logging.info(f"SSL/TLS enabled IPs found in nessus file:\n\n{content}")
    line_count = subprocess.check_output(f"wc -l < {nessus_ips}", shell=True).strip()
    cprint(f"[+] {line_count.decode()} SSL/TLS enabled hosts found in Nessus file.", 'info', flush=True)


def check_tls_ssl_enabled(host_port):
    # Split the input by ':' to separate host and port, default port to 443 if not specified
    parts = host_port.split(':')
    host = parts[0]
    port = parts[1] if len(parts) > 1 else "443"
    
    try:
        # Prepare the OpenSSL command
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}"]
        # Execute the command, suppressing stderr, and capture stdout
        result = subprocess.run(cmd, input=b'', stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=20)
        # Check if the output contains the start of the SSL/TLS certificate
        if b'BEGIN CERTIFICATE' in result.stdout:
            return 1
        else:
            return 0
    except Exception as e:
        cprint(f"[-] An error occurred: {e}", 'error', flush=True)
        return 0
    


def ssl_confirm(input_file, output_file):
    logging.info("Starting SSL/TLS confirmation for IPs.")
    cprint(f"[+] Starting SSL/TLS confirmation for IPs; It might take some time...", 'info', flush=True)
    def check_tls_ssl_enabled(host_port):
        parts = host_port.rsplit(':', 1)  # Split from the right, to get the last colon as the separator
        host = parts[0]
        port = parts[1] if len(parts) > 1 else '443'
        try:
            cmd = ["openssl", "s_client", "-connect", f"{host}:{port}"]
            result = subprocess.run(cmd, input=b'', stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=20)
            return b'BEGIN CERTIFICATE' in result.stdout
        except Exception as e:
            cprint(f"[-] Error checking {host_port}: {e}", 'error', flush=True)
            return False

    def worker():
        while True:
            host_port = queue.get()
            if host_port is None:  # Break if None is received, indicating no more work
                break
            if check_tls_ssl_enabled(host_port):
                with lock:  # Ensure thread-safe addition to the output list
                    output_list.append(f"{host_port}\n")
                    logging.debug(f"SSL/TLS confirmed for IP: {host_port}.")
            else:
                logging.debug(f"SSL/TLS not enabled for IP: {host_port}.")
            with lock:  # Ensure thread-safe progress update
                progress[0] += 1
                blue_color = "\033[92m"
                reset_color = "\033[0m"
                print(f"{blue_color}Progress: {progress[0]}/{progress[1]}{reset_color}", end='\r', flush=True)
            queue.task_done()

    num_threads = 10
    queue = Queue()
    threads = []
    output_list = []
    lock = threading.Lock()

    with open(input_file, 'r') as file:
        ips = file.readlines()

    progress = [0, len(ips)]  # Initialize progress counter

    for _ in range(num_threads):  # Start threads
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for ip in ips:  # Enqueue work
        queue.put(ip.strip())

    queue.join()  # Wait for all work to be done

    for _ in range(num_threads):  # Signal threads to exit
        queue.put(None)
    for t in threads:  # Wait for all threads to finish
        t.join()

    with open(output_file, 'w') as file:  # Write results to file
        file.writelines(output_list)

    cprint(f"[+] Finished. Extracted hosts have been saved to {output_file}.", 'success', flush=True)
    

def main(file_path, threads):
    os.makedirs(CSV_DIR, exist_ok=True)
    os.makedirs(SCREEN_DIR, exist_ok=True)
    global all_ssl_ips
    all_ssl_ips = set()

    

    if not os.path.exists(DONE_FILE):
        open(DONE_FILE, 'a').close()



    if args.nmap is not None and args.nessus is None:
        all_ssl_ips = set()
        save_ssl_ips("temp_ips.txt")
        shutil.copyfile(nmap_ips, 'host-data.txt')
        os.remove(nmap_ips)
        line_count = subprocess.check_output(f"wc -l < host-data.txt", shell=True).strip()
        cprint(f"[+] {line_count.decode()} hosts with ssl/tls enabled found in Nmap file.", 'info', flush=True)




    if args.nmap is None and args.nessus is not None:
        parse_nessus_file(args.nessus)
        shutil.copyfile(nessus_ips, 'host-data.txt')
        os.remove(nessus_ips)
        line_count = subprocess.check_output(f"wc -l < host-data.txt", shell=True).strip()
        cprint(f"[+] {line_count.decode()} hosts with ssl/tls enabled found in Nessus file.", 'info', flush=True)
        




    if args.nmap is not None and args.nessus is not None:
        all_ssl_ips = set()
        parse_nessus_file(args.nessus)
        save_ssl_ips("temp_ips.txt")
        unique_ips = set()

        with open(nmap_ips, "r") as file:
            for line in file:
                unique_ips.add(line.strip())

        with open(nessus_ips, "r") as file:
            for line in file:
                unique_ips.add(line.strip())

        with open("host-data.txt", "w") as file:
            for ip in unique_ips:
                file.write(ip + "\n")

        line_count = subprocess.check_output(f"wc -l < {nmap_ips}", shell=True).strip()
        line_count1 = subprocess.check_output(f"wc -l < {nessus_ips}", shell=True).strip()
        with open("host-data.txt", 'r') as file:
            content = file.read()
            logging.info(f"SSL/TLS enabled IPs found in both nessus and nmap files:\n\n{content}")
        cprint(f"[+] {line_count.decode()} hosts found in Nmap file and {line_count1.decode()} hosts found in Nessus file", 'info', flush=True)
        line_count = subprocess.check_output(f"wc -l < host-data.txt", shell=True).strip()
        cprint(f"[+] {line_count.decode()} Unique hosts found in both Nmap and Nessus file", 'info', flush=True)


        os.remove(nmap_ips)
        os.remove(nessus_ips)






    if args.nmap is None and args.nessus is None:
        extract_data(file_path)
    


    with open('host-data.txt', 'r') as file:
        ips = file.read().splitlines()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(process_ip, ip) for ip in ips]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                cprint(f"[-] An error occurred in thread: {e}", 'error', flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    This script is designed to process and analyze network data from a specified text file. Its key features and functionalities include:


    Usage:
    Run the script with optional arguments for file path and number of threads.
    Examples: 1. testssl-assist scan -t 4 --nmap nmap.gnmap --nessus nessus.csv
             2. testssl-assist scan -t 6 -f unprocessed.txt 
    """, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-t", "--threads", type=int, default=1, 
                        help="Number of threads to use for processing IPs. Default is 1.")
    parser.add_argument("-f","--file", type=str, default="raw.txt",
                        help="File name to extract the hosts from. Default is 'raw.txt'")
    parser.add_argument("--nmap", type=str, default=None,
                        help="Optional: Path to Grepable Nmap(gnmap) file or folder for additional processing.")
    parser.add_argument("--nessus", type=str, default=None,
                        help="Optional: Path to Nessus CSV file or folder for additional processing.")
    


    args = parser.parse_args()

    main(args.file, args.threads)

