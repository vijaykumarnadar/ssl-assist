import argparse
import sys
help_message = """

"""

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Flask Web Application for Network Data Analysis', add_help=False)
parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit')
args = parser.parse_args()

# Check if help argument is present
if args.help:
    print(help_message)
    sys.exit()

from flask import Flask, render_template, request, jsonify
import pandas as pd
import os
import glob
import csv
import webbrowser
import threading
import logging

app = Flask(__name__)

# CSV file name
CSV_FILE_NAME = 'summary.csv'

current_dir = os.getcwd()
directory = os.path.join(current_dir, "csv_outputs")

unique_ids = []
ids_to_remove = ['clientsimulation-android_60', 'cert_expirationStatus', 'cipher_xc012', 'cipher_x0a', 'cipher_x16', 'clientsimulation-android_70', 'clientsimulation-android_81', 'clientsimulation-android_90', 'clientsimulation-android_X', 'clientsimulation-android_11', 'clientsimulation-android_12', 'clientsimulation-chrome_79_win10', 'clientsimulation-chrome_101_win10', 'clientsimulation-firefox_66_win81', 'clientsimulation-firefox_100_win10', 'clientsimulation-ie_6_xp', 'clientsimulation-ie_8_win7', 'clientsimulation-ie_8_xp', 'clientsimulation-ie_11_win7', 'clientsimulation-ie_11_win81', 'clientsimulation-ie_11_winphone81', 'clientsimulation-ie_11_win10', 'clientsimulation-edge_15_win10', 'clientsimulation-edge_101_win10_21h2', 'clientsimulation-safari_121_ios_122', 'clientsimulation-safari_130_osx_10146', 'clientsimulation-safari_154_osx_1231', 'clientsimulation-java_7u25', 'clientsimulation-java_8u161', 'clientsimulation-java1102', 'clientsimulation-java1703', 'clientsimulation-go_1178', 'clientsimulation-libressl_283', 'clientsimulation-openssl_102e', 'clientsimulation-openssl_110l', 'clientsimulation-openssl_111d', 'clientsimulation-openssl_303', 'clientsimulation-apple_mail_16_0', 'clientsimulation-thunderbird_91_9','cert_serialNumber', 'cert_serialNumberLen', 'cert_fingerprintSHA1', 'cert_fingerprintSHA256', 'cert', 'cert_commonName', 'cert_commonName_wo_SNI', 'cert_subjectAltName','cert_notBefore', 'cert_notAfter', 'cert_validityPeriod', 'DROWN_hint', 'cipher_xc030', 'cipher_xc014', 'cipher_x9f', 'cipher_x39', 'cipher_x9d', 'cipher_x3d', 'cipher_x35', 'cipher_xc02f', 'cipher_xc013', 'cipher_x9e', 'cipher_x33', 'cipher_x9c', 'cipher_x3c', 'cipher_xc028', 'cipher_x6b', 'cipher_xc027', 'cipher_x67', 'cipher_x1302', 'cipher_x1303', 'cipher_xcca8', 'cipher_xccaa', 'cipher_xc0a3', 'cipher_xc09f', 'cipher_xc077', 'cipher_xc4', 'cipher_x88', 'cipher_xc0a1', 'cipher_xc09d', 'cipher_xc0', 'cipher_x84', 'cipher_xc051', 'cipher_xc053', 'cipher_xc061', 'cipher_x1301', 'cipher_xc0a2', 'cipher_xc09e', 'cipher_xc0a0', 'cipher_xc09c', 'cipher_xc076', 'cipher_xbe', 'cipher_x45', 'cipher_xba', 'cipher_x41', 'cipher_xc050', 'cipher_xc052', 'cipher_xc060', 'cipher_xc011', 'cipher_x05']
global filtered_ids

def open_browser():
    try:
        webbrowser.open("http://127.0.0.1:5000")
    except Exception as e:
        logging.error(f"Failed to open web browser: {e}")

def load_and_sort_csv():
    try:
        df = pd.read_csv(CSV_FILE_NAME)
        sort_order = ['FATAL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'OK', 'WARN', 'DEBUG']
        df['severity'] = pd.Categorical(df['severity'], categories=sort_order, ordered=True)
        return df.sort_values(by=['severity', 'id'])
    except Exception as e:
        logging.error(f"Error loading and sorting CSV: {e}")
        return pd.DataFrame()  # Return an empty DataFrame on failure




@app.route('/')
def home():
    try:
        data = load_and_sort_csv()
        return render_template('table.html', data=data)
    except Exception as e:
        logging.error(f"Error in home route: {e}")
        return "Error loading data", 500

@app.route('/process_request', methods=['POST'])
def process_request():
    try:
        id = request.form.get('id')
        finding = request.form.get('finding')
        current_dir = os.getcwd()
        directory = os.path.join(current_dir, "csv_outputs")
        all_files = [os.path.join(directory, file) for file in os.listdir(directory) if file.endswith('.csv')]
        combined_df = pd.concat([pd.read_csv(file) for file in all_files], ignore_index=True)
        filtered_df = combined_df[(combined_df['id'] == id) & (combined_df['finding'] == finding)]
        ip_port_list = [f"{ip.split('/')[0]}:{port}" for ip, port in zip(filtered_df['fqdn/ip'], filtered_df['port'])]
        response = f"Received ID: {id}, Finding: {finding}"
        return jsonify({'response': ip_port_list})
    
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({'error': 'An error occurred'}), 500



def extract_uniqueids():
    global filtered_ids
    try:
        for filename in os.listdir(directory):
            if filename.endswith('.csv'):
                filepath = os.path.join(directory, filename)
                
                # Read the 'id' column from the CSV file
                try:
                    df = pd.read_csv(filepath, usecols=['id'])
                    for id_val in df['id']:
                        if id_val not in unique_ids:
                            unique_ids.append(id_val)
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")

    except Exception as e:
        logging.error(f"Error extracting unique IDs: {e}")


    # Remove specified IDs from the unique_ids list
    filtered_ids = [id_val for id_val in unique_ids if id_val not in ids_to_remove]

    # Print or process the unique IDs
    # print("Unique IDs across all files, after filtering:")
    # print(filtered_ids)

def extract_ips_from_csvs1(directory):
    # List all files in the directory
    all_files = [os.path.join(directory, file) for file in os.listdir(directory) if file.endswith('.csv')]

    # Load all CSV files into DataFrames and combine them
    combined_df = pd.concat([pd.read_csv(file) for file in all_files], ignore_index=True)

    # Filter the DataFrame based on the criteria
    filtered_df = combined_df[combined_df['id'].isin(filtered_ids)]

    # Group by id, finding, and severity, then extract the IP and port for each group
    grouped = filtered_df.groupby(['id', 'finding', 'severity'])
    results = []
    for (id_val, finding_val, severity_val), group in grouped:
        results.append({
            "id": id_val,
            "finding": finding_val,
            "severity": severity_val,
            "count": len(group)
        })

    return results

def filter_data_if_contains(file, id_column, finding_column, id_value, finding_values):
    # Load CSV file into DataFrame
    df = pd.read_csv(file)

    # Filter the DataFrame based on the criteria
    return df[df[id_column].str.contains(id_value, na=False) & df[finding_column].apply(lambda x: isinstance(x, str) and any(finding in x for finding in finding_values))]


def extract_ips_from_csvs_if_contains(id_value, finding_values, output_file):
    # Define the directory paths
    script_dir = os.getcwd()
    csv_dir = os.path.join(script_dir, 'csv_outputs')
    findings_dir = os.path.join(script_dir, 'findings')

    # Create 'findings' directory if it doesn't exist
    if not os.path.exists(findings_dir):
        os.makedirs(findings_dir)

    # List all files in the csv_outputs directory
    id_column = 'id'
    finding_column = 'finding'
    all_files = [os.path.join(csv_dir, file) for file in os.listdir(csv_dir) if file.endswith('.csv')]

    # Apply the filter_data_if_contains function to each file and combine results
    combined_df = pd.concat([filter_data_if_contains(file, id_column, finding_column, id_value, finding_values) for file in all_files], ignore_index=True)

    # Extract the IP and port, and format them as 'IP:port'
    combined_df['ip_port'] = combined_df['fqdn/ip'].str.split('/').str[0] + ':' + combined_df['port'].astype(str)
    ip_port_list = combined_df['ip_port'].drop_duplicates().tolist()


    # Save the results to a file in the 'findings' directory
    output_path = os.path.join(findings_dir, output_file)
    if not ip_port_list:
        # print(f"No data to write to the file for ID: {output_file}.")
        sdfs = 1
    else:
        # Save the results to a file in the 'findings' directory
        output_path = os.path.join(findings_dir, output_file)
        with open(output_path, 'w') as file:
            for ip_port in ip_port_list:
                file.write(ip_port + '\n')

    return ip_port_list


def filter_data(file, id_column, finding_column, id_value, finding_values):
    # Load CSV file into DataFrame
    df = pd.read_csv(file)

    # Filter the DataFrame based on the exact match criteria
    return df[df[id_column].str.contains(id_value, na=False) & df[finding_column].isin(finding_values)]




def extract_ips_from_csvs(id_value, finding_values, output_file):
    # Define the directory paths
    script_dir = os.getcwd()
    csv_dir = os.path.join(script_dir, 'csv_outputs')
    findings_dir = os.path.join(script_dir, 'findings')

    # Create 'findings' directory if it doesn't exist
    if not os.path.exists(findings_dir):
        os.makedirs(findings_dir)

    # List all files in the csv_outputs directory
    id_column = 'id'
    finding_column = 'finding'
    all_files = [os.path.join(csv_dir, file) for file in os.listdir(csv_dir) if file.endswith('.csv')]

    # Apply the filter_data function to each file and combine results
    combined_df = pd.concat([filter_data(file, id_column, finding_column, id_value, finding_values) for file in all_files], ignore_index=True)

    # Extract the IP and port, and format them as 'IP:port'

    combined_df['ip_port'] = combined_df['fqdn/ip'].str.split('/').str[0] + ':' + combined_df['port'].astype(str)
    ip_port_list = combined_df['ip_port'].drop_duplicates().tolist()



    # Save the results to a file in the 'findings' directory
    output_path = os.path.join(findings_dir, output_file)
    if not ip_port_list:
        # print(f"No data to write to the file for ID: {output_file}.")
        sdfsasd = 1
    else:
        # Save the results to a file in the 'findings' directory
        output_path = os.path.join(findings_dir, output_file)
        with open(output_path, 'w') as file:
            for ip_port in ip_port_list:
                file.write(ip_port + '\n')

    return ip_port_list



def cbc_ciphers_function():
    script_directory = os.getcwd()
    output_directory = script_directory + '/findings/ciphers'
    # print(f"Script Directory: {script_directory}")
    csv_directory = os.path.join(script_directory, 'csv_outputs')
    # print(f"CSV Directory: {csv_directory}")
    if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    cbc_cipher_ids = ['cipher_x05', 'cipher_x0a', 'cipher_x1301', 'cipher_x1302', 'cipher_x1303', 'cipher_x16', 'cipher_x2f', 'cipher_x33', 'cipher_x33', 'cipher_x33', 'cipher_x35', 'cipher_x39', 'cipher_x39', 'cipher_x39', 'cipher_x3c', 'cipher_x3d', 'cipher_x41', 'cipher_x45', 'cipher_x67', 'cipher_x67', 'cipher_x67', 'cipher_x6b', 'cipher_x6b', 'cipher_x6b', 'cipher_x84', 'cipher_x88', 'cipher_x9c', 'cipher_x9d', 'cipher_x9e', 'cipher_x9e', 'cipher_x9e', 'cipher_x9f', 'cipher_x9f', 'cipher_x9f', 'cipher_xba', 'cipher_xbe', 'cipher_xc0', 'cipher_xc011', 'cipher_xc012', 'cipher_xc013', 'cipher_xc013', 'cipher_xc013', 'cipher_xc014', 'cipher_xc014', 'cipher_xc014', 'cipher_xc027', 'cipher_xc027', 'cipher_xc027', 'cipher_xc028', 'cipher_xc028', 'cipher_xc028', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc030', 'cipher_xc030', 'cipher_xc030', 'cipher_xc050', 'cipher_xc051', 'cipher_xc052', 'cipher_xc053', 'cipher_xc060', 'cipher_xc061', 'cipher_xc076', 'cipher_xc077', 'cipher_xc09c', 'cipher_xc09d', 'cipher_xc09e', 'cipher_xc09f', 'cipher_xc0a0', 'cipher_xc0a1', 'cipher_xc0a2', 'cipher_xc0a3', 'cipher_xc4', 'cipher_xcca8', 'cipher_xccaa']
    output_text = ''
    for file_name in glob.glob(os.path.join(csv_directory, '*.csv')):
        df = pd.read_csv(file_name)
        cbc_ciphers_df = df[df['id'].isin(cbc_cipher_ids) & df['finding'].str.contains('CBC')]
        #cbc_ciphers_df = df[df['id'].isin(cbc_cipher_ids) & df['finding'].str.contains('CBC') & df['finding'].str.contains('DHE')]
        cbc_ciphers_df = cbc_ciphers_df.copy()
        cbc_ciphers_df.loc[:, 'ip'] = cbc_ciphers_df['fqdn/ip'].str.extract(r'([^/]+)')[0]
        # cbc_ciphers_df.loc[:, 'ip'] = cbc_ciphers_df['fqdn/ip'].str.extract(r'([^/]*)')[0]
        cbc_ciphers_df.loc[:, 'port'] = cbc_ciphers_df['port'].astype(str)
        cbc_ciphers_df.loc[:, 'cbc_cipher'] = cbc_ciphers_df['finding'].str.extract(r'(\S*_CBC_\S*)')
        grouped_output = cbc_ciphers_df.groupby(['ip', 'port'])['cbc_cipher'].apply(lambda x: '\n'.join(x.drop_duplicates().astype(str))).reset_index()
        for index, row in grouped_output.iterrows():
            output_text += f"**{row['ip']}:{row['port']}**\n\n"
            output_text += '```\n' + row['cbc_cipher'].replace('\n', '\n') + '\n```\n-----------'
            output_text += '\n\n'
    output_file_path = os.path.join(output_directory, 'cbc_ciphers.txt')
    with open(output_file_path, 'w') as file:
        file.write(output_text)
    # print(f"Output File Path: {output_file_path}")   



def dhe_ciphers_function():
    script_directory = os.getcwd()
    output_directory = script_directory + '/findings/ciphers'
    # print(f"Script Directory: {script_directory}")
    csv_directory = os.path.join(script_directory, 'csv_outputs')
    # print(f"CSV Directory: {csv_directory}")
    if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    dhe_cipher_ids = ['cipher_x05', 'cipher_x0a', 'cipher_x1301', 'cipher_x1302', 'cipher_x1303', 'cipher_x16', 'cipher_x2f', 'cipher_x33', 'cipher_x33', 'cipher_x33', 'cipher_x35', 'cipher_x39', 'cipher_x39', 'cipher_x39', 'cipher_x3c', 'cipher_x3d', 'cipher_x41', 'cipher_x45', 'cipher_x67', 'cipher_x67', 'cipher_x67', 'cipher_x6b', 'cipher_x6b', 'cipher_x6b', 'cipher_x84', 'cipher_x88', 'cipher_x9c', 'cipher_x9d', 'cipher_x9e', 'cipher_x9e', 'cipher_x9e', 'cipher_x9f', 'cipher_x9f', 'cipher_x9f', 'cipher_xba', 'cipher_xbe', 'cipher_xc0', 'cipher_xc011', 'cipher_xc012', 'cipher_xc013', 'cipher_xc013', 'cipher_xc013', 'cipher_xc014', 'cipher_xc014', 'cipher_xc014', 'cipher_xc027', 'cipher_xc027', 'cipher_xc027', 'cipher_xc028', 'cipher_xc028', 'cipher_xc028', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc030', 'cipher_xc030', 'cipher_xc030', 'cipher_xc050', 'cipher_xc051', 'cipher_xc052', 'cipher_xc053', 'cipher_xc060', 'cipher_xc061', 'cipher_xc076', 'cipher_xc077', 'cipher_xc09c', 'cipher_xc09d', 'cipher_xc09e', 'cipher_xc09f', 'cipher_xc0a0', 'cipher_xc0a1', 'cipher_xc0a2', 'cipher_xc0a3', 'cipher_xc4', 'cipher_xcca8', 'cipher_xccaa']
    output_text = ''
    for file_name in glob.glob(os.path.join(csv_directory, '*.csv')):
        df = pd.read_csv(file_name)
        dhe_ciphers_df = df[df['id'].isin(dhe_cipher_ids) & df['finding'].str.contains(r'\b(?:DHE|ECDHE)\b')]
        #dhe_ciphers_df = df[df['id'].isin(dhe_cipher_ids) & df['finding'].str.contains('dhe') & df['finding'].str.contains('DHE')]
        dhe_ciphers_df = dhe_ciphers_df.copy()
        dhe_ciphers_df.loc[:, 'ip'] = dhe_ciphers_df['fqdn/ip'].str.extract(r'([^/]+)')[0]
        dhe_ciphers_df.loc[:, 'port'] = dhe_ciphers_df['port'].astype(str)
        dhe_ciphers_df.loc[:, 'dhe_cipher'] = dhe_ciphers_df['finding'].str.extract(r'(\S*_(?:DHE|ECDHE)_\S*)')
        grouped_output = dhe_ciphers_df.groupby(['ip', 'port'])['dhe_cipher'].apply(lambda x: '\n'.join(x.drop_duplicates().astype(str))).reset_index()
        for index, row in grouped_output.iterrows():
            output_text += f"**{row['ip']}:{row['port']}**\n\n"
            output_text += '```\n' + row['dhe_cipher'].replace('\n', '\n') + '\n```\n-----------'
            output_text += '\n\n'
    output_file_path = os.path.join(output_directory, 'dhe_ciphers.txt')
    with open(output_file_path, 'w') as file:
        file.write(output_text)
    # print(f"Output File Path: {output_file_path}") 



def DES_ciphers_function():
    script_directory = os.getcwd()
    output_directory = script_directory + '/findings/ciphers'
    # print(f"Script Directory: {script_directory}")
    csv_directory = os.path.join(script_directory, 'csv_outputs')
    # print(f"CSV Directory: {csv_directory}")
    if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    DES_cipher_ids = ['cipher_x05', 'cipher_x0a', 'cipher_x1301', 'cipher_x1302', 'cipher_x1303', 'cipher_x16', 'cipher_x2f', 'cipher_x33', 'cipher_x33', 'cipher_x33', 'cipher_x35', 'cipher_x39', 'cipher_x39', 'cipher_x39', 'cipher_x3c', 'cipher_x3d', 'cipher_x41', 'cipher_x45', 'cipher_x67', 'cipher_x67', 'cipher_x67', 'cipher_x6b', 'cipher_x6b', 'cipher_x6b', 'cipher_x84', 'cipher_x88', 'cipher_x9c', 'cipher_x9d', 'cipher_x9e', 'cipher_x9e', 'cipher_x9e', 'cipher_x9f', 'cipher_x9f', 'cipher_x9f', 'cipher_xba', 'cipher_xbe', 'cipher_xc0', 'cipher_xc011', 'cipher_xc012', 'cipher_xc013', 'cipher_xc013', 'cipher_xc013', 'cipher_xc014', 'cipher_xc014', 'cipher_xc014', 'cipher_xc027', 'cipher_xc027', 'cipher_xc027', 'cipher_xc028', 'cipher_xc028', 'cipher_xc028', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc030', 'cipher_xc030', 'cipher_xc030', 'cipher_xc050', 'cipher_xc051', 'cipher_xc052', 'cipher_xc053', 'cipher_xc060', 'cipher_xc061', 'cipher_xc076', 'cipher_xc077', 'cipher_xc09c', 'cipher_xc09d', 'cipher_xc09e', 'cipher_xc09f', 'cipher_xc0a0', 'cipher_xc0a1', 'cipher_xc0a2', 'cipher_xc0a3', 'cipher_xc4', 'cipher_xcca8', 'cipher_xccaa']
    output_text = ''
    for file_name in glob.glob(os.path.join(csv_directory, '*.csv')):
        df = pd.read_csv(file_name)
        DES_ciphers_df = df[df['id'].isin(DES_cipher_ids) & df['finding'].str.contains('3DES')]
        #DES_ciphers_df = df[df['id'].isin(DES_cipher_ids) & df['finding'].str.contains('DES') & df['finding'].str.contains('DHE')]
        DES_ciphers_df = DES_ciphers_df.copy()
        DES_ciphers_df.loc[:, 'ip'] = DES_ciphers_df['fqdn/ip'].str.extract(r'([^/]+)')[0]
        DES_ciphers_df.loc[:, 'port'] = DES_ciphers_df['port'].astype(str)
        DES_ciphers_df.loc[:, 'DES_cipher'] = DES_ciphers_df['finding'].str.extract(r'(\S*_3DES_\S*)')
        grouped_output = DES_ciphers_df.groupby(['ip', 'port'])['DES_cipher'].apply(lambda x: '\n'.join(x.drop_duplicates().astype(str))).reset_index()
        for index, row in grouped_output.iterrows():
            output_text += f"**{row['ip']}:{row['port']}**\n\n"
            output_text += '```\n' + row['DES_cipher'].replace('\n', '\n') + '\n```\n-----------'
            output_text += '\n\n'
    output_file_path = os.path.join(output_directory, 'DES_ciphers.txt')
    with open(output_file_path, 'w') as file:
        file.write(output_text)
    # print(f"Output File Path: {output_file_path}")   



def rc4_ciphers_function():
    script_directory = os.getcwd()
    output_directory = script_directory + '/findings/ciphers'
    # print(f"Script Directory: {script_directory}")
    csv_directory = os.path.join(script_directory, 'csv_outputs')
    # print(f"CSV Directory: {csv_directory}")
    if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    RC4_cipher_ids = ['cipher_x05', 'cipher_x0a', 'cipher_x1301', 'cipher_x1302', 'cipher_x1303', 'cipher_x16', 'cipher_x2f', 'cipher_x33', 'cipher_x33', 'cipher_x33', 'cipher_x35', 'cipher_x39', 'cipher_x39', 'cipher_x39', 'cipher_x3c', 'cipher_x3d', 'cipher_x41', 'cipher_x45', 'cipher_x67', 'cipher_x67', 'cipher_x67', 'cipher_x6b', 'cipher_x6b', 'cipher_x6b', 'cipher_x84', 'cipher_x88', 'cipher_x9c', 'cipher_x9d', 'cipher_x9e', 'cipher_x9e', 'cipher_x9e', 'cipher_x9f', 'cipher_x9f', 'cipher_x9f', 'cipher_xba', 'cipher_xbe', 'cipher_xc0', 'cipher_xc011', 'cipher_xc012', 'cipher_xc013', 'cipher_xc013', 'cipher_xc013', 'cipher_xc014', 'cipher_xc014', 'cipher_xc014', 'cipher_xc027', 'cipher_xc027', 'cipher_xc027', 'cipher_xc028', 'cipher_xc028', 'cipher_xc028', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc02f', 'cipher_xc030', 'cipher_xc030', 'cipher_xc030', 'cipher_xc050', 'cipher_xc051', 'cipher_xc052', 'cipher_xc053', 'cipher_xc060', 'cipher_xc061', 'cipher_xc076', 'cipher_xc077', 'cipher_xc09c', 'cipher_xc09d', 'cipher_xc09e', 'cipher_xc09f', 'cipher_xc0a0', 'cipher_xc0a1', 'cipher_xc0a2', 'cipher_xc0a3', 'cipher_xc4', 'cipher_xcca8', 'cipher_xccaa']
    output_text = ''
    for file_name in glob.glob(os.path.join(csv_directory, '*.csv')):
        df = pd.read_csv(file_name)
        RC4_ciphers_df = df[df['id'].isin(RC4_cipher_ids) & df['finding'].str.contains('RC4')]
        #RC4_ciphers_df = df[df['id'].isin(RC4_cipher_ids) & df['finding'].str.contains('RC4') & df['finding'].str.contains('RC4')]
        RC4_ciphers_df = RC4_ciphers_df.copy()
        RC4_ciphers_df.loc[:, 'ip'] = RC4_ciphers_df['fqdn/ip'].str.extract(r'([^/]+)')[0]
        RC4_ciphers_df.loc[:, 'port'] = RC4_ciphers_df['port'].astype(str)
        RC4_ciphers_df.loc[:, 'RC4_cipher'] = RC4_ciphers_df['finding'].str.extract(r'(\S*_RC4_\S*)')
        grouped_output = RC4_ciphers_df.groupby(['ip', 'port'])['RC4_cipher'].apply(lambda x: '\n'.join(x.drop_duplicates().astype(str))).reset_index()
        for index, row in grouped_output.iterrows():
            output_text += f"**{row['ip']}:{row['port']}**\n\n"
            output_text += '```\n' + row['RC4_cipher'].replace('\n', '\n') + '\n```\n-----------'
            output_text += '\n\n'
    output_file_path = os.path.join(output_directory, 'rc4_ciphers.txt')
    with open(output_file_path, 'w') as file:
        file.write(output_text)
    # print(f"Output File Path: {output_file_path}") 

if __name__ == "__main__":
    try:
        current_dir = os.getcwd()
        directory = os.path.join(current_dir, "csv_outputs")
        output_file = os.path.join(current_dir, "summary.csv")
        extract_uniqueids()
        categorized_results = extract_ips_from_csvs1(directory)

        # Writing to CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["id", "finding", "severity", "count"])
            writer.writeheader()
            for row in categorized_results:
                writer.writerow(row)

        # print(f"Output saved to {output_file}")
        extract_ips_from_csvs('cert_expirationStatus', ['expired'], 'certificates_expired.txt')
        extract_ips_from_csvs('cert_chain_of_trust', ['failed (chain incomplete).', 'failed (expired).', 'failed (self signed CA in chain).', 'failed (self signed).'], 'cert_chain_of_trust_failed.txt')
        extract_ips_from_csvs_if_contains('RC4', ['VULNERABLE'], 'RC4_cipher_used.txt')
        extract_ips_from_csvs_if_contains('cert_expirationStatus', ['expires < 30 days'], 'cert_expires_in_less_than_30days.txt')
        extract_ips_from_csvs_if_contains('cert_subjectAltName', ['No SAN'], 'no_subject_alt_name.txt')
        extract_ips_from_csvs_if_contains('cert_commonName_wo_SNI', ['*'], 'wildcard_certificate_withoutSNI.txt')
        extract_ips_from_csvs_if_contains('cert_subjectAltName', ['*'], 'wildcard_certificate_withSNI.txt')
        extract_ips_from_csvs_if_contains('cert_commonName', ['*'], 'wildcard_certificate_in_common_name.txt')
        extract_ips_from_csvs_if_contains('LUCKY13', ['potentially vulnerable'], 'lucky_potentially_vulnerable.txt')
        extract_ips_from_csvs_if_contains('DH_groups', ['1024 bits'], 'dh_groups_1024bits.txt')
        extract_ips_from_csvs_if_contains('LOGJAM', ['no DH EXPORT ciphers, no common prime but Unknown DH group has only 1024 bits'], 'LOGJAM.txt')
        extract_ips_from_csvs_if_contains('SSLv2', ['vulnerable'], 'SSLv2_vulnerable.txt')
        extract_ips_from_csvs_if_contains('SSLv3', ['vulnerable'], 'SSLv3_vulnerable.txt')
        extract_ips_from_csvs('SSLv2', ['offered'], 'SSLv2_offered.txt')
        extract_ips_from_csvs('SSLv3', ['offered'], 'SSLv3_offered.txt')
        extract_ips_from_csvs('cert_trust', ['certificate does not match supplied URI'], 'certificates_does_not_match_URI.txt')
        extract_ips_from_csvs('secure_client_renego', ['VULNERABLE, DoS threat'], 'secure_client_renego_vulnerable.txt')
        extract_ips_from_csvs_if_contains('cert_keySize', ['RSA 1024 bits'], 'cert_RSA_1024.txt')
        extract_ips_from_csvs('BEAST', ['VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)'], 'beast_vulneable_supports_higher_protocols.txt')
        extract_ips_from_csvs('SWEET32', ['uses 64 bit block ciphers'], 'sweet32_vulnerable.txt')
        extract_ips_from_csvs('TLS1', ['offered (deprecated)'], 'TLS_1.0_offered.txt')
        extract_ips_from_csvs('TLS1_1', ['offered (deprecated)'], 'TLS_1.1_offered.txt')
        extract_ips_from_csvs('TLS1_2', ['not offered'], 'TLS_1.2_not_offered.txt')
        extract_ips_from_csvs('cipherlist_AVERAGE', ['offered'], 'CBC_offered.txt')
        extract_ips_from_csvs_if_contains('BREACH', ['potentially VULNERABLE'], 'BREACH_potentially_vulnerable.txt')
        extract_ips_from_csvs('cert_signatureAlgorithm', ['SHA1 with RSA'], 'SHA1_RSA_signed_cert.txt')
        extract_ips_from_csvs('secure_client_renego', ['VULNERABLE, potential DoS threat'], 'secure_client_renego_potentially_vulnerable.txt')
        extract_ips_from_csvs('cipherlist_3DES_IDEA', ['offered'], '3DES_IDEA_offered.txt')
        dhe_ciphers_function()
        cbc_ciphers_function()
        rc4_ciphers_function()
        DES_ciphers_function()


    except Exception as e:
        logging.error(f"Unhandled exception in main: {e}")

    threading.Thread(target=open_browser).start()
    app.run(debug=False)

