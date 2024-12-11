# SSL Assist

## Description
TestSSL Assist is a tool designed to enhance the efficiency of SSL/TLS testing, particularly using the `testssl` utility. It provides a comprehensive approach to scanning and analyzing the output for efficient reporting.

The ssl-assist tool is exclusively designed for Linux environments, as the `testssl` utility is not available for Windows.

## Installation



Clone the repository using:

```bash
git clone https://github.com/vijaykumarnadar/ssl-assist.git
cd ssl-assist
python3 setup.py
```


## Main Features

### Scan Function

#### Overview
The scan function of SSL Assist is a feature that allows users to perform concurrent scans on multiple hosts. It efficiently handles a variety of data types including IP addresses, subnets, hostnames, and URLs. Now supporting import from Nmap (gnmap) and Nessus files to extract IPs for processing.

#### Key Features

1. **Multi-threading**: Utilizes multi-threading to enable simultaneous scanning of multiple hosts, significantly speeding up the process. Users can specify the number of threads.

2. **Data Extraction**: Extracts data from a specified text file, supporting different formats with regex patterns:
   - **IP Addresses**: Matches individual IP addresses (e.g., `192.168.1.1`).
   - **Subnets**: Finds subnets in CIDR notation (e.g., `192.168.1.0/24`).
   - **Hostnames**: Identifies hostnames (e.g., `example.com`).
   - **URLs**: Extracts URLs and derives hostnames from them (e.g., `http://example.com`).
   - **IP Ranges**: Captures IP ranges (e.g., `192.168.1.1-192.168.1.10`).

3. **Nmap/Nessus Imports**: Allows importing IPs directly from nmap (.gnmap) and Nessus files using `--nmap` and `--nessus` options, respectively, for flexible processing.

4. **Efficient Processing**: 
   - Employs threads for large-scale IP address processing.
   - Skips already processed IPs.
   - Maintains a log of processed IPs and on restarting the script continues from where it left.

5. **Output Management**:
   - Saves results in CSV format.
   - Captures screen outputs for review.


6. **Error Handling and Logging**: Includes comprehensive error handling and logs the status of each processed IP.

#### Usage

Run the script with optional argument for the number of threads. The default thread count is 1 and the default file is `raw.txt`

Example:

```bash
testssl-assist scan -t <no-of-threads> -f <filename> --nmap <nmap_filename> --nessus <nessus_filename>
```

### Parse Function

#### Overview
The parse function processes testssl scan output, identifying and categorizing vulnerabilities for review.

### Usage

Execute the parse function to start a local web server, open a browser, and access the processed data through the `findings` folder:

```bash
testssl-assist parse
```

## How It Works

**testssl assist** operates in a straightforward, two-step process to analyze network vulnerabilities:

### Step 1: Scanning

Specify the input file `-f` and the number of threads (`-t`) or use `--nmap` or `--nessus` options for direct import from nmap or Nessus files.
The script will extract the ips that has SSl/TLS services enabled and will run testssl on it.
As soon as the scan function is initiated, an `host-data.txt` file is generated. Users can check this file to verify the extracted IPs during the scan itself and can see the completed ips list in `done.txt` file.

```bash
testssl-assist scan -t <no-of-threads> -f <filename> --nmap <nmap_filename> --nessus <nessus_filename>

```


### Step 2: Parsing and Review

After scanning, initiate parsing. The parse function creates a findings folder with categorized vulnerabilities. A browser tab opens for manual verification, ensuring thorough review.

```bash
testssl-assist parse
```


## Example screenshots

#### Multithreaded scanning also demonstration the processing of IP, skipping which has already finished and deleting the premature output file (Scan function)

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/scan.png">
</a>
</p>

#### List of findings (After running parse function)

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/findings.png">
</a>
</p>

#### List of IPs in each finding's file

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/findings-ips-list.png">
</a>
</p>

#### List of Vulnerable ciphers

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/ciphers.png">
</a>
</p>

#### List of vulnerable ciphers in each IP.

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/vulnerable-ciphers.png">
</a>
</p>

#### List of all unique ID and their unique values (Should be viewed to ensure no findings are missed - each row is clickable and the ips having the id-value pair are listed)

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/parse.png">
</a>
</p>

#### List of ips in each id-value pair.

<p align="center">
  <img src="https://github.com/vijaykumarnadar/ssl-assist/-/raw/main/examples/parse-ip.png">
</a>
</p>

| :exclamation:  **Disclaimer**  |
|---------------------------------|
| The conditions and analysis within **testssl-assist** tool are based on outputs derived from tests. While these conditions are crafted to accurately identify and categorize network vulnerabilities, they are influenced by the specific contexts and scenarios encountered in previous use cases. |
| Users are strongly encouraged to manually review result of a sample of the IPs shown in each finding. This sampling process is crucial to ensure the accuracy and relevance of the results specific to their network environment. |

## Feedback and Contributions

Suggestions, feedback, or ideas for improvement from users are crucial for the ongoing development and enhancement of the tool. Users are encouraged to share their insights and contribute to the project's growth.

### Providing Feedback

- **Suggestions or Feedback**: Users are invited to open an issue in the repository to share their experiences, ideas, or report any issues encountered while using the tool.

### Contributing

- **Merge Requests**: Contributions to the development of **testssl-assist** are warmly welcomed. Users interested in contributing, whether through bug fixes, new features, or documentation improvements, can significantly aid in the tool's advancement.

  - Contributors should fork the repository, implement their changes, and submit a merge request for review.
  - It is recommended that contributions adhere to the existing code style and standards.
  - Detailed descriptions of changes and their motivations should be included in merge requests.

User contributions and feedback not only enhance the tool itself but also benefit the broader organization. Collaborative efforts are key to making **testssl-assist** more robust and efficient.
