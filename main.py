import argparse
import subprocess
import sys
import os

def run_script(script_name, args):
    try:
        # Get the directory of the main file
        dir_path = os.path.dirname(os.path.abspath(__file__))

        # Build the path to the script file
        script_path = os.path.join(dir_path, script_name)

        # Build the command to execute the script with its arguments
        command = ["python3", script_path] + args
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: The script {script_name} exited with an error.")
        print(f"Error message: {e}")
    except FileNotFoundError:
        print(f"Error: The script {script_name} was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    # Check if any command is provided
    if len(sys.argv) <= 1:
        print("""
Usage: testssl-assist {scan/parse} [...args]

Usage examples:
testssl-assist scan -f ips.txt -t 4 --nmap {nmap-file-name/directory-of-nmap-files} --nessus {nessus-csv-file/directory-of-csv-files}
testssl-assist parse
              """)
        sys.exit(1)

    # Extract the command and its arguments
    command = sys.argv[1]
    args = sys.argv[2:]

    if command == 'parse':
        # Check if csv_outputs directory exists
        if os.path.exists('csv_outputs'):
            run_script('parse.py', args)
        else:
            print("csv_outputs directory does not exist, Please run the scan command first!")
    elif command == 'scan':
            run_script('scan.py', args)
    else:
        print("Invalid command. Available commands: parse, scan")
        sys.exit(1)

if __name__ == "__main__":
    main()
