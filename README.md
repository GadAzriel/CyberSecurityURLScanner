# CyberSecurity-URL-Scanner

This project is an automation script designed to interact with cybersecurity-related APIs, specifically VirusTotal, to scan URLs for potential threats, analyze the retrieved data, and generate detailed reports. The script also includes security measures to protect sensitive information and prevent unauthorized access.

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Description

This script allows you to:
1. Validate and use a VirusTotal API key.
2. Validate and scan URLs using the VirusTotal API.
3. Retrieve and analyze scan reports for potential threats.
4. Generate detailed text reports and visualizations (pie charts) of the scan results.
5. Compress and password-protect the generated files.

## Features

- **API Integration**: Integrates with the VirusTotal API to retrieve URL scan data.
- **Data Analysis**: Analyzes scan data to identify potential threats.
- **Reporting**: Generates detailed text reports and visual pie charts summarizing the findings.
- **Security Controls**: Implements best practices for secure coding and protects generated files with a password.

## Requirements

- Python 3.x
- `requests` library
- `validators` library
- `matplotlib` library
- `pyminizip` library
- A valid VirusTotal API key

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/CyberSecurity-URL-Scanner.git
    cd CyberSecurity-URL-Scanner
    ```

2. Install the required Python packages:
    ```sh
    pip install requests validators matplotlib pyminizip
    ```

## Usage

1. Run the script:
    ```sh
    python script.py
    ```

2. Enter your VirusTotal API key when prompted.
3. Enter the URL you wish to scan.
4. Follow the prompts to generate and secure the report.

## Examples

Here's an example of how to use the script:

```sh
$ python script.py
Enter your VirusTotal API key: [your_api_key]
Enter a URL to scan: https://example.com
The report was exported successfully
Enter password for zip file: [your_password]
Files have been compressed and locked with a password.
