import requests
import validators
import matplotlib.pyplot as plt
import pyminizip
import os

#Description: Function to validate and get a working VirusTotal API key
def checkAPI():
    try:
        apiKey = input("Enter your VirusTotal API key: ")
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': apiKey, 'resource': "https://google.com"}
        response = requests.get(url, params=params)
        if response.status_code == 200: ## If the response status is 200 so the API key is valid
            return apiKey
        else:
            print("That API key does not seem to be valid, please try again.")
            return checkAPI()
    except Exception as e:
        print("An error occurred:", e)
        return checkAPI()

#Description: Function to validate and get a URL to scan
def checkURL():
    try:
        urlInput = input("Enter a URL to scan: ")
        if not urlInput.startswith("http"):
            urlInput = "http://" + urlInput # Add 'http://' if not present
        if validators.url(urlInput):  # Validate the URL
            try:
                response = requests.get(urlInput)
                if response.status_code == 200:
                    return urlInput # Return the URL if reachable
                else:
                    print("The URL is not reachable, please try again.")
                    return checkURL()
            except:
                print("The URL is not reachable, please try again.")
                return checkURL()
        else:
            print("Invalid URL, please try again.")
            return checkURL()
    except Exception as e:
        print("An error occurred:", e)
        return checkURL()

# Description: Function to perform a scan on a URL using the VirusTotal API
def performScan(urlInput, apiKey):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apiKey, 'url': urlInput}
    response = requests.post(url, data=params)
    id = response.json().get('scan_id') 
    return id

#Description: Function to retrieve the scan report from VirusTotal using the scan id
def report(id, apiKey):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apiKey, 'resource': id}
    response = requests.get(url, params=params)
    data = response.json() # Convert the response to JSON format
    return data

#Description: Function to analyze the scan report data and generate insights
def analyze_data(data,urlInput):
    positives = data.get('positives', 0) #If the "positives" key doesn't exist in the data dictionary, it assigns the default value 0 to the positives variable.
    total = data.get('total', 0)
    scan_date = data.get('scan_date', '--')
    scans = data.get('scans', {})

    # Analysis for potential threats and anomalies
    suspicious_engines = []
    safe_engines = []
    for engine, result in scans.items():
        if result['detected']:
            suspicious_engines.append(engine) #Engines that detected threats
        else:
            safe_engines.append(engine)
    report_export(scan_date, positives, total, suspicious_engines, scans,urlInput)

#Description: Generates a text report summarizing scan results.
def report_export(scan_date, positives, total, suspicious_engines, scans,urlInput):
    reportText = "Report Summary\n"
    reportText += f"URL: {urlInput}\n"
    reportText += "==============\n"
    reportText += f"Scan Date: {scan_date}\n"
    reportText += f"Positives: {positives}/{total} (Detected threats/Total scans)\n\n"
    reportText += "\nDetailed Scan Results:\n"

    for engine, result in scans.items():
        reportText += f"    Engine name: {engine}:\n"
        for key, value in result.items():
            reportText += f"        {key}: {value}\n"

    reportText += "\nAnalysis:\n"
    if positives > 0:
        reportText += "Potential Threats Detected!\n"
        reportText += f"{positives} out of {total} scans detected the URL as malicious.\n"
        reportText += "Engines that detected threats:\n"
        for engine in suspicious_engines:
            reportText += f" - {engine}\n"
    else:
        reportText += "No threats detected by any engine. The URL appears to be SAFE.\n"

     # Save report to a file
    with open('report.txt', 'w') as file:
        file.write(reportText)
    generate_report(positives, total,urlInput)

#Description: Generates a pie chart summarizing threat detection results.
def generate_report(positives, total,urlInput):
    if total == 0:
        print("Error: Total scans is zero, cannot generate report.")
        return
    labels = 'Safe', 'Detected Threats'
    sizes = [total - positives, positives]
    colors = ['green', 'red']
    explode = (0, 0.1)  # Explode the 2nd slice (Detected Threats) for emphasis
    plt.figure(figsize=(10, 6))      # Create a matplotlib figure
    # Generate pie chart
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
    plt.axis("equal")   # Set aspect ratio for a circular pie chart
    plt.title(f'Threat Detection Summary\n\nURL: {urlInput}')
    plt.savefig("threat_detection_summary.png")     # Save the chart as a PNG image
    print("The report was exported successfully\n")
    compress_and_protect_files()
    
# Description: Compresses and password-protects the generated files.
def compress_and_protect_files():
    input_files = ["./report.txt", "./threat_detection_summary.png"]   # Relative paths to the files
    prefixes = ["", ""]  # List of empty prefixes
    output_zip = "./output.zip" # Path for the output zip file
    # If the output file exists, remove it
    if os.path.exists(output_zip):
        os.remove(output_zip)
    password = input("Enter password for zip file: ")
    com_lvl = 5 # Compression level
    try:
        pyminizip.compress_multiple(input_files, prefixes, output_zip, password, com_lvl) # Compress the files and protect with password
        print("Files have been compressed and locked with a password.")
    except ValueError as e:
        print(f"An error occurred: {e}")

    # Delete the original files
    for file_path in input_files:
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            print(f"The file {file_path} does not exist.")



apiKey = checkAPI()
urlInput = checkURL()
id = performScan(urlInput, apiKey)
data = report(id, apiKey)
analyze_data(data,urlInput)