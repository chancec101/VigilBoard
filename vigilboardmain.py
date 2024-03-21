import tkinter as tk                #using tkinter as our gui
from tkinter import messagebox
from tkinter import Scrollbar
from tkinter import simpledialog
import nmap                         #nmap for port scanning
import socket
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse
from threading import Thread
import os
import re
import json
import boto3
import hashlib
import hmac
import base64
import botocore


# Get the directory of the current Python script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the file paths for CSS file and icon
css_file_path = os.path.join(script_dir, "HTML Elements", "styles.css")
icon_file_path = os.path.join(script_dir, "HTML Elements", "vigilboard.ico")

# Define the path to the Logs folder
logs_folder = os.path.join(script_dir, "Logs")

# Check if the Logs folder exists, and create it if not
if not os.path.exists(logs_folder):
    os.makedirs(logs_folder)

# Global variables
SCAN_TYPE_NAMES = {
    "performScan": "Basic Security Scan",
    "nmapVulners": "Vulners Scan",
    "nmapVuln": "Vulnerability Scan"
}

scan_thread = None
result_text = None

###################################################################################################################
#                                               log/helper functions                                              #
###################################################################################################################

#function that will make a log file named "scanlog{date} {time}" and put the text box info inside of it
#it will then either create a new log folder to place logs into, or it will detect a log folder exists and put the log file into it
def save_to_file(content, prefix="scanlog"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H%M%S")
    log_folder = os.path.join(script_dir, "Logs", "VigilBoard_Scan_Logs")

    # Check if the log folder exists, and create it if not
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    filename = os.path.join(log_folder, f"{prefix}{timestamp}.txt")

    with open(filename, "w") as file:
        file.write(content)

#function that will pop open an explorer window with your log files there when you press "View Logs"
def view_logs():
    #get the directory of the currently running script
    log_folder = os.path.join(script_dir, "Logs")

    # Open the file explorer at the log folder
    os.system(f'explorer {log_folder}')

#function to check if the content of the text box is empty
def is_text_box_empty():
    return result_text.compare("end-1c", "==", "1.0")

#######################################
#         HTML Website Functions      #
#######################################

# Function to save scan result to HTML file for instant viewing on a web browser upon completion of a scan and ensures the most updated HTML information is displayed
def save_to_html(content, filename="scan_result.html"):
     # Define the path to the HTML file in the same directory as the script
    html_folder = os.path.join(script_dir, "HTML Elements")

    # Write the content to the HTML file, overwriting any existing content
    with open(os.path.join(html_folder, filename), "w") as file:
        file.write(content)

# Function that will save the scan results to an HTML file and store it as a unique HTML file log
def save_to_html_log(content, prefix="html_log"):
    # Generate a timestamp for the unique filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    # Define the directory for HTML logs
    log_folder = os.path.join(script_dir, "Logs", "VigilBoard_HTML_Logs")

    # Check if the log folder exists, and create it if not
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    # Define the filename with timestamp
    log_filename = f"{prefix}_{timestamp}.html"
    log_file_path = os.path.join(log_folder, log_filename)

    # Write the content to the HTML log file
    with open(log_file_path, "w") as file:
        file.write(content)

# Function to open the directory containing HTML logs
def view_html_logs():
    # Get the directory of the HTML logs
    html_logs_directory = os.path.join(script_dir, "Logs", "VigilBoard_HTML_Logs")
    
    # Check if the directory exists
    if os.path.exists(html_logs_directory):
        # open file explorer at specified directory
        os.system(f'explorer {html_logs_directory}')
    else:
        messagebox.showinfo("HTML Logs", "No HTML logs found.")

#############################################
#           Port Scan HTML functions        #
#############################################

def parse_scan_results(scan_result):
    parsed_results = []

    # Extract open ports
    open_ports_match = re.search(r'Open ports:\n(.+?)\n', scan_result, re.DOTALL)
    if open_ports_match:
        open_ports = open_ports_match.group(1).split(', ')
        parsed_results.append(f"Open ports: {', '.join(open_ports)}")

    # Extract service details for each open port
    service_details_match = re.findall(r'Port (\d+): Service=(.*?), Product=(.*?), Version=(.*?)\n', scan_result)
    if service_details_match:
        for port, service, product, version in service_details_match:
            parsed_results.append(f"Port {port}: Service={service}, Product={product}, Version={version}")

    # Extract OS information
    os_info_match = re.search(r'OS Fingerprinting Results:\n(.+?)\n\n', scan_result, re.DOTALL)
    if os_info_match:
        os_info = os_info_match.group(1).strip()
        parsed_results.append("OS Fingerprinting Results:")
        parsed_results.append(os_info)

    return parsed_results

# Function to generate HTML content
def generate_html_content(target_ip, target_url, scan_start_time, scan_finish_time, scan_elapsed_time, open_ports, os_guess, scan_type):
    # Extract date portion from scan start time
    scan_date = scan_start_time.strftime("%Y-%m-%d")

    # Format scan start time and finish time to display only the time portion
    scan_start_time_formatted = scan_start_time.strftime("%H:%M:%S")  
    scan_finish_time_formatted = scan_finish_time.strftime("%H:%M:%S")

    # Generate HTML content
    html_content = f"""
<!DOCTYPE html>
<html>
    <head>
        <title>Security Scan Results</title>
        <link rel="stylesheet" type="text/css" href="{css_file_path}">
        <link rel="icon" type="image/x-icon" href="{icon_file_path}">
    </head>
    <body>
        <img src="HTML Elements/ai-art.jpg" class="left-image" alt="Left Image" width="300" height="300">
        <img src="HTML Elements/ai-art.jpg" class="right-image" alt="Right Image" width="300" height="300">
        <div class="container">
            <h1 class="title">Security Scan Results</h1>
            <p><strong class="target-info">Target IP:</strong> {target_ip}</p>
            <p><strong class="target-info">Target URL:</strong> {target_url}</p>
            <p><strong class="scan-info">Scan Type:</strong> {SCAN_TYPE_NAMES.get(scan_type)}</p>
            <p><strong class="timestamp">Scan Date:</strong> {scan_date}</p>
            <p><strong class="timestamp">Scan Start Time:</strong> {scan_start_time_formatted}</p>
            <p><strong class="timestamp">Scan Finish Time:</strong> {scan_finish_time_formatted}</p>
            <p><strong class="timestamp">Scan Elapsed Time:</strong> {scan_elapsed_time}</p>
        </div>
    </body>
</html>
"""

    # Add table for open ports
    html_content += "<h2>Open Ports:</h2>"
    if open_ports:
        html_content += "<table border='1'><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>"
        for port, details in open_ports.items():
            html_content += f"<tr><td>{port}</td><td>{details['name']}</td><td>{details['product']}</td><td>{details['version']}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No open ports found.</p>"

    # Add table for OS Fingerprinting Results
    html_content += "<h2>OS Fingerprinting Results:</h2>"
    if os_guess:
        html_content += "<table border='1'><tr><th>OS Name</th><th>Accuracy</th></tr>"
        for os_result in os_guess:
            html_content += f"<tr><td>{os_result['name']}</td><td>{os_result['accuracy']}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No OS fingerprinting results found.</p>"

    return html_content

def on_scan_complete(scan_result, scan_start_time, scan_finish_time, selected_scan_type):
    scan_elapsed_time = scan_finish_time - scan_start_time

    # Extract relevant information from the scan result
    target_ip = url_or_ip_entry.get()  # Get the target IP from the entry box
    target_url = ""  # Initialize target URL as an empty string (modify if needed)

    # Check if the input is a valid URL
    parsed_url = urlparse(target_ip)
    if parsed_url.netloc:
        target_url = target_ip  # Set target URL if the input is a valid URL
        target_ip = socket.gethostbyname(parsed_url.netloc)  # Resolve URL to IP

    # Extract open ports and OS guesses from the scan result
    open_ports = {}  # Placeholder for open ports dictionary
    os_guess = []    # Placeholder for OS guesses list

    # Update the parsing of scan_result to extract open ports and OS guesses
    if 'scan' in scan_result and target_ip in scan_result['scan'] and 'tcp' in scan_result['scan'][target_ip]:
        open_ports = scan_result['scan'][target_ip]['tcp']
    
    if 'scan' in scan_result and target_ip in scan_result['scan'] and 'osmatch' in scan_result['scan'][target_ip]:
        os_guess = scan_result['scan'][target_ip]['osmatch']

    # Fetch user-friendly scan type name
    scan_type = selected_scan_type

    # Generate HTML content
    html_content = generate_html_content(target_ip, target_url, scan_start_time, scan_finish_time, scan_elapsed_time, open_ports, os_guess, scan_type)
    
    # Save HTML content to file that will be updated and opened
    html_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_result.html")
    save_to_html(html_content, html_file_path)

    # Save HTML content to a file as a log
    save_to_html_log(html_content, prefix="html_log")

    # Check if the HTML file exists before attempting to open it
    if os.path.exists(html_file_path):
        # Open HTML file in default web browser
        os.startfile(html_file_path)
    else:
        messagebox.showerror("HTML File Not Found", "The HTML file could not be found.")

####################################################
#         Vulners/Vunerability HTML functions      #
####################################################

# Define the parse_vulners_info function
def parse_vulners_vuln_info(vulnerability_info):
    # Regular expression patterns
    url_pattern = r'https?://vulners\.com/\w+/[^ \t\n\r\f\v]+'
    vulnerability_pattern = r'(CVE-\d{4}-\d{4,7})'
    score_pattern = r'\b(\d+\.\d+)\b(?=\s+https?://)'

    # Initialize lists to store URLs, vulnerability names, and scores
    urls = []
    vulnerability_names = []
    scores = []

    # Iterate over each line of vulnerability_info
    for line in vulnerability_info:
        url_match = re.search(url_pattern, line)
        vulnerability_match = re.search(vulnerability_pattern, line)
        score_match = re.search(score_pattern, line)

        if url_match and vulnerability_match and score_match:
            urls.append(url_match.group(0))
            vulnerability_names.append(vulnerability_match.group(0))
            score = score_match.group(1)  # Extract the matched group 1 (the score)
            scores.append(score)
    
    return urls, vulnerability_names, scores


# Function to generate HTML content
def generate_vulners_vuln_html_content(target_ip, target_url, scan_start_time, scan_finish_time, scan_elapsed_time, open_ports, os_guess, scan_type, result, ip_address, vulnerability_info_dict):
    # Extract date portion from scan start time
    scan_date = scan_start_time.strftime("%Y-%m-%d")

    # Format scan start time and finish time to display only the time portion
    scan_start_time_formatted = scan_start_time.strftime("%H:%M:%S")  
    scan_finish_time_formatted = scan_finish_time.strftime("%H:%M:%S")

    # Generate HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>Security Scan Results</title>
            <link rel="stylesheet" type="text/css" href="{css_file_path}">
            <link rel="icon" type="image/x-icon" href="{icon_file_path}">
        </head>
        <body>
            <img src="HTML Elements/ai-art.jpg" class="left-image" alt="Left Image" width="300" height="300">
            <img src="HTML Elements/ai-art.jpg" class="right-image" alt="Right Image" width="300" height="300">
            <div class="container">
                <h1 class="title">Security Scan Results</h1>
                <p><strong class="target-info">Target IP:</strong> {target_ip}</p>
                <p><strong class="target-info">Target URL:</strong> {target_url}</p>
                <p><strong class="scan-info">Scan Type:</strong> {SCAN_TYPE_NAMES.get(scan_type)}</p>
                <p><strong class="timestamp">Scan Date:</strong> {scan_date}</p>
                <p><strong class="timestamp">Scan Start Time:</strong> {scan_start_time_formatted}</p>
                <p><strong class="timestamp">Scan Finish Time:</strong> {scan_finish_time_formatted}</p>
                <p><strong class="timestamp">Scan Elapsed Time:</strong> {scan_elapsed_time}</p>
            </div>
        </body>
    </html>
    """

    # Add table for open ports
    html_content += "<h2>Open Ports:</h2>"
    if open_ports:
        html_content += "<table border='1'><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>"
        for port, details in open_ports.items():
            html_content += f"<tr><td>{port}</td><td>{details['name']}</td><td>{details['product']}</td><td>{details['version']}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No open ports found.</p>"

    # Add table for OS Fingerprinting Results
    html_content += "<h2>OS Fingerprinting Results:</h2>"
    if os_guess:
        html_content += "<table border='1'><tr><th>OS Name</th><th>Accuracy</th></tr>"
        for os_result in os_guess:
            html_content += f"<tr><td>{os_result['name']}</td><td>{os_result['accuracy']}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No OS fingerprinting results found.</p>"

    # Add title for Vulnerabilities table
    html_content += "<h2>Vulnerabilities:</h2>"

    # Add table for vulnerabilities
    html_content += "<table border='1'><tr><th>Port</th><th>Vulnerability</th><th>CVSS Score (range: 0 (low) to 10 (severe))</th><th>URL</th></tr>"
    for port, vulnerabilities in vulnerability_info_dict.items():
        for vulnerability in vulnerabilities:
            # Extract vulnerability information
            port_number = vulnerability['port']
            vulnerability_name = vulnerability['vulnerability']
            cvss_score = vulnerability['cvss_score']
            vulnerability_url = vulnerability['url']
            
            # Ensure cvss_score is numeric
            cvss_score = float(cvss_score) if cvss_score is not None else None
            
            # Format CVSS score (round to 1 decimal place) or set to "N/A"
            formatted_cvss_score = f"{cvss_score:.1f}" if cvss_score is not None else "N/A"
            
            # Add row to the table
            html_content += f"<tr><td>{port_number}</td><td>{vulnerability_name}</td><td>{formatted_cvss_score}</td><td><a href='{vulnerability_url}'>{vulnerability_url}</a></td></tr>"
    html_content += "</table>"

    return html_content

def on_vulners_vuln_scan_complete(html_content):
    
    # Save HTML content to file that will be updated and opened
    html_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_result.html")
    save_to_html(html_content, html_file_path)

    # Save HTML content to a file as a log
    save_to_html_log(html_content, prefix="html_log")

    # Check if the HTML file exists before attempting to open it
    if os.path.exists(html_file_path):
        # Open HTML file in default web browser
        os.startfile(html_file_path)
    else:
        messagebox.showerror("HTML File Not Found", "The HTML file could not be found.")

###################################################################################################################
#                                               nmap functionality                                                #
###################################################################################################################

#function will validate a given url or ip address and then run a simple port scan 
def check_security():

    #ensures that there is no text when starting a scan, and if there is text in the box, it will be cleared in order to show the output of a fresh new scan
    result_text.config(state="normal")
    result_text.delete("1.0", "end")
    result_text.config(state="disabled")

    #used to get scan from radio button selection
    selected_scan = scan_var.get()  # Get the selected scan type

    #pop up warning for user that they need to choose a scan before continuing
    if selected_scan == "none_selected":
        messagebox.showinfo("Select Scan Option", "A scan option must be selected.")
        return

    ##########################################################
    #               SCAN OPTION 1: NMAP SCAN                 #
    ##########################################################

    #function that will perform only the port scanning necessary when the first option is selected
    def perform_security_scan():
        input_text = url_or_ip_entry.get()

        #check if it's a URL or IP address
        parsed_url = urlparse(input_text)

        if parsed_url.netloc:
            #the input is a URL so resolve to an IP address
            try:
                ip_address = socket.gethostbyname(parsed_url.netloc)
            except socket.gaierror:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return
        else:
            #the input is an IPv4 address so verify it
            try:
                socket.inet_pton(socket.AF_INET, input_text)
                ip_address = input_text
            except socket.error:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return

        #create an nmap PortScanner instance
        nm = nmap.PortScanner()

        #change the button text
        test_button.config(text="Scanning target")
        test_button.config(state="disabled")  #disable the button

        result_text.config(state="normal")

        global scan_start_time
        scan_start_time = datetime.now()

        t1 = datetime.now()
        result_text.insert("end", "Scan conducted on: ")
        result_text.insert("end", t1)
        result_text.insert("end", "\nTarget IP: ")
        result_text.insert("end", ip_address)

        #check if the input is a URL and display it along with the IP. If there is no URL associated with it, then it will ignore displaying the URL
        if parsed_url.netloc:
            result_text.insert("end", "\nTarget URL: ")
            result_text.insert("end", parsed_url.netloc)

        result_text.insert("end", "\n\nThis scan can take a few minutes, thank you for your patience.")
        result_text.insert("end", "\n\nRunning basic port scan...\n\n")

        result_text.config(state="disabled")

        #utilize the scan that the user chose
        if selected_scan == "performScan":
            result = nm.scan(hosts=ip_address, arguments='-O -sV -F')

        #check if the 'scan' and 'tcp' keys exist in the result dictionary
        if 'scan' in result and ip_address in result['scan'] and 'tcp' in result['scan'][ip_address]:
            open_ports = result['scan'][ip_address]['tcp'].keys()
        else:
            #handle the case when the expected keys are not present
            result_text.config(state="normal")
            result_text.insert("end", "Error in scanning. Check the input and try again, otherwise there may be no detectable open ports.\n")
            result_text.config(state="disabled")
            test_button.config(text="Perform Security Test")
            test_button.config(state="normal")
            return

        os_guess = result['scan'][ip_address]['osmatch']

        result_text.config(state="normal")

        #get the results from the scans
        if open_ports:
            result_text.insert("end", f"Open ports:\n{', '.join(map(str, open_ports))}")
            result_text.insert("end", "\n")
            for port in open_ports:
                service = result['scan'][ip_address]['tcp'][port]['name']
                product = result['scan'][ip_address]['tcp'][port]['product']
                version = result['scan'][ip_address]['tcp'][port]['version']
                result_text.insert("end", f"Port {port}: Service={service}, Product={product}, Version={version}\n")
            result_text.insert("end", "OS Fingerprinting Results:\n")
            for os in os_guess:
                os_name = os['name']
                os_accuracy = os['accuracy']
                result_text.insert("end", f"  OS Name: {os_name}, Accuracy: {os_accuracy}\n")
        else:
            result_text.insert("end", "No open ports found.")

        result_text.insert("end", "\n\nPort scan has been completed.\n")

        t2 = datetime.now()
        result_text.insert("end", "Scan completed at: ")
        result_text.insert("end", t2)

        #writing the text box to a log file

        result_text.config(state="normal")
    
        #save the content of the text box to a file only if it's not empty
        if not is_text_box_empty():
            save_to_file(result_text.get("1.0", "end-1c"))

        # Convert the scan result dictionary to a string for parsing
        scan_result = str(result)

        # Call the callback function with the scan result and finish time
        on_scan_complete(result, scan_start_time, datetime.now(), selected_scan)

        result_text.config(state="disabled")

        #change the button text back 
        test_button.config(text="Perform Security Test")
        test_button.config(state="normal")  #re-enable the button

    ##########################################################
    #               SCAN OPTION 2: VULNERS SCAN              #
    ##########################################################

    #function that will run the vulners scan, which is option 2
    def perform_vulners_scan():
        input_text = url_or_ip_entry.get()

        #check if it's a URL or IP address
        parsed_url = urlparse(input_text)

        if parsed_url.netloc:
            #the input is a URL so resolve to an IP address
            try:
                ip_address = socket.gethostbyname(parsed_url.netloc)
            except socket.gaierror:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return
        else:
            #the input is an IPv4 address so verify it
            try:
                socket.inet_pton(socket.AF_INET, input_text)
                ip_address = input_text
            except socket.error:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return

        #create an nmap PortScanner instance
        nm = nmap.PortScanner()

        #change the button text
        test_button.config(text="Scanning target")
        test_button.config(state="disabled")  #disable the button

        result_text.config(state="normal")

        t1 = datetime.now()
        result_text.insert("end", "Scan conducted on: ")
        result_text.insert("end", t1)
        result_text.insert("end", "\nTarget IP: ")
        result_text.insert("end", ip_address)

        #check if the input is a URL and display it along with the IP. If there is no URL associated with it, then it will ignore displaying the URL
        if parsed_url.netloc:
            result_text.insert("end", "\nTarget URL: ")
            result_text.insert("end", parsed_url.netloc)

        result_text.insert("end", "\n\nThis scan can take a few minutes, thank you for your patience.")
        result_text.insert("end", "\n\nRunning vulners scan...\n\n")

        result_text.config(state="disabled")

        if selected_scan == "nmapVulners":
            result = nm.scan(hosts=ip_address, arguments='-O -sV -F --script vulners')

        #check if the 'scan' and 'tcp' keys exist in the result dictionary
        if 'scan' in result and ip_address in result['scan'] and 'tcp' in result['scan'][ip_address]:
            open_ports = result['scan'][ip_address]['tcp'].keys()
        else:
            #handle the case when the expected keys are not present
            result_text.config(state="normal")
            result_text.insert("end", "\nError in scanning. Check the input and try again, otherwise there may be no detectable open ports.\n")
            result_text.config(state="disabled")
            test_button.config(text="Perform Security Test")
            test_button.config(state="normal")
            return

        os_guess = result['scan'][ip_address]['osmatch']

        result_text.config(state="normal")

        #get the results from the scans
        if open_ports:
            result_text.insert("end", f"Open ports:\n{', '.join(map(str, open_ports))}")
            result_text.insert("end", "\n")
            for port in open_ports:
                service = result['scan'][ip_address]['tcp'][port]['name']
                product = result['scan'][ip_address]['tcp'][port]['product']
                version = result['scan'][ip_address]['tcp'][port]['version']
                result_text.insert("end", f"Port {port}: Service={service}, Product={product}, Version={version}\n")
            result_text.insert("end", "OS Fingerprinting Results:\n")
            for os in os_guess:
                os_name = os['name']
                os_accuracy = os['accuracy']
                result_text.insert("end", f"  OS Name: {os_name}, Accuracy: {os_accuracy}\n")
            if selected_scan == "nmapVulners" or selected_scan == "nmapVuln":
                for port, port_info in result['scan'][ip_address]['tcp'].items():
                    result_text.insert("end", f"{port}/tcp   {port_info['state']}  {port_info['name']}\n")
                    if 'script' in port_info and 'vulners' in port_info['script']:
                        result_text.insert("end", f"| vulners:\n")
                        for vuln in port_info['script']['vulners'].split('\n'):
                            result_text.insert("end", f"|   {vuln}\n")
        else:
            result_text.insert("end", "No open ports found.")

        result_text.insert("end", "\n\nVulners scan has been completed.\n")

        t2 = datetime.now()
        result_text.insert("end", "Scan completed at: ")
        result_text.insert("end", t2)

        result_text.config(state="normal")

        # Initialize an empty list to store vulnerability information
        vulnerability_info = []

        # Iterate over the open ports and collect vulnerability information
        for port, port_info in result['scan'][ip_address]['tcp'].items():
            if 'script' in port_info and 'vulners' in port_info['script']:
                for vuln in port_info['script']['vulners'].split('\n'):
                    vulnerability_info.append(vuln)

        # Convert open_ports to a dictionary
        open_ports_dict = {port: result['scan'][ip_address]['tcp'][port] for port in open_ports}

        # Initialize an empty dictionary to store vulnerability information by port
        vulnerability_info_dict = {}

       # Iterate over the open ports and collect vulnerability information
        for port, port_info in result['scan'][ip_address]['tcp'].items():
            if 'script' in port_info and 'vulners' in port_info['script']:
                for vuln in port_info['script']['vulners'].split('\n'):
                    # Parse the vulnerability information string
                    urls, names, scores = parse_vulners_vuln_info([vuln])

                    # Add the parsed information to the vulnerability_info_dict
                    if port not in vulnerability_info_dict:
                        vulnerability_info_dict[port] = []
                    for url, name, score in zip(urls, names, scores):
                        vulnerability_info_dict[port].append({
                            'port': port,  # Include the 'port' key
                            'vulnerability': name,
                            'cvss_score': score,
                            'url': url
                        })

        # Call generate_vulners_html_content function with vulnerability_info_dict
        html_content = generate_vulners_vuln_html_content(ip_address, parsed_url.netloc if parsed_url.netloc else "", t1, t2, t2 - t1, open_ports_dict, os_guess, selected_scan, result, ip_address, vulnerability_info_dict)

        on_vulners_vuln_scan_complete(html_content)

        #save the content of the text box to a file only if it's not empty
        if not is_text_box_empty():
            save_to_file(result_text.get("1.0", "end-1c"))

        result_text.config(state="disabled")

        #change the button text back 
        test_button.config(text="Perform Security Test")
        test_button.config(state="normal")  #re-enable the button

    ##########################################################
    #               SCAN OPTION 3: VULN SCAN                 #
    ##########################################################

    #function that will run the vulnerability scan, or option 3, when selected
    def perform_vuln_scan():
        input_text = url_or_ip_entry.get()

        #check if it's a URL or IP address
        parsed_url = urlparse(input_text)

        if parsed_url.netloc:
            #the input is a URL so resolve to an IP address
            try:
                ip_address = socket.gethostbyname(parsed_url.netloc)
            except socket.gaierror:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return
        else:
            #the input is an IPv4 address so verify it
            try:
                socket.inet_pton(socket.AF_INET, input_text)
                ip_address = input_text
            except socket.error:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address. For URL, ensure you include http:// or https// in the URL.")
                return

        #create an nmap PortScanner instance
        nm = nmap.PortScanner()

        #change the button text
        test_button.config(text="Scanning target")
        test_button.config(state="disabled")  #disable the button

        result_text.config(state="normal")

        t1 = datetime.now()
        result_text.insert("end", "Scan conducted on: ")
        result_text.insert("end", t1)
        result_text.insert("end", "\nTarget IP: ")
        result_text.insert("end", ip_address)

        #check if the input is a URL and display it along with the IP. If there is no URL associated with it, then it will ignore displaying the URL
        if parsed_url.netloc:
            result_text.insert("end", "\nTarget URL: ")
            result_text.insert("end", parsed_url.netloc)

        result_text.insert("end", "\n\nThis scan can take up to a few minutes, thank you for your patience.")
        result_text.insert("end", "\n\nRunning vulnerability script...\n\n")

        result_text.config(state="disabled")

        if selected_scan == "nmapVuln":
            confirmed = messagebox.askyesno("Confirmation", "Running the vuln script scan may be disruptive and crash the target. Are you sure you want to continue?")
            #cancel the scan if the user selects NO
            if not confirmed:
                result_text.config(state="normal")
                result_text.insert("end", "\nScan canceled by user.\n")
                result_text.config(state="disabled")
                test_button.config(text="Perform Security Test")
                test_button.config(state="normal")
                return
            elif confirmed:
                result = nm.scan(hosts=ip_address, arguments='-O -sV -F --script vuln')

        #check if the 'scan' and 'tcp' keys exist in the result dictionary
        if 'scan' in result and ip_address in result['scan'] and 'tcp' in result['scan'][ip_address]:
            open_ports = result['scan'][ip_address]['tcp'].keys()
        else:
            #handle the case when the expected keys are not present
            result_text.config(state="normal")
            result_text.insert("end", "Error in scanning. Check the input and try again, otherwise there may be no detectable open ports.\n")
            result_text.config(state="disabled")
            test_button.config(text="Perform Security Test")
            test_button.config(state="normal")
            return

        os_guess = result['scan'][ip_address]['osmatch']

        result_text.config(state="normal")

        #get the results from the scans
        if open_ports:
            result_text.insert("end", f"Open ports:\n{', '.join(map(str, open_ports))}")
            result_text.insert("end", "\n")
            for port in open_ports:
                service = result['scan'][ip_address]['tcp'][port]['name']
                product = result['scan'][ip_address]['tcp'][port]['product']
                version = result['scan'][ip_address]['tcp'][port]['version']
                result_text.insert("end", f"Port {port}: Service={service}, Product={product}, Version={version}\n")
            result_text.insert("end", "OS Fingerprinting Results:\n")
            for os in os_guess:
                os_name = os['name']
                os_accuracy = os['accuracy']
                result_text.insert("end", f"  OS Name: {os_name}, Accuracy: {os_accuracy}\n")
            if selected_scan == "nmapVulners" or selected_scan == "nmapVuln":
                for port, port_info in result['scan'][ip_address]['tcp'].items():
                    result_text.insert("end", f"{port}/tcp   {port_info['state']}  {port_info['name']}\n")
                    if 'script' in port_info and 'vulners' in port_info['script']:
                        result_text.insert("end", f"| vulners:\n")
                        for vuln in port_info['script']['vulners'].split('\n'):
                            result_text.insert("end", f"|   {vuln}\n")
        else:
            result_text.insert("end", "No open ports found.")

        result_text.insert("end", "\n\nVulnerability scan has been completed.\n")

        t2 = datetime.now()
        result_text.insert("end", "Scan completed at: ")
        result_text.insert("end", t2)

        result_text.config(state="normal")

        # Initialize an empty list to store vulnerability information
        vulnerability_info = []

        # Iterate over the open ports and collect vulnerability information
        for port, port_info in result['scan'][ip_address]['tcp'].items():
            if 'script' in port_info and 'vulners' in port_info['script']:
                for vuln in port_info['script']['vulners'].split('\n'):
                    vulnerability_info.append(vuln)

        # Convert open_ports to a dictionary
        open_ports_dict = {port: result['scan'][ip_address]['tcp'][port] for port in open_ports}

        # Initialize an empty dictionary to store vulnerability information by port
        vulnerability_info_dict = {}

       # Iterate over the open ports and collect vulnerability information
        for port, port_info in result['scan'][ip_address]['tcp'].items():
            if 'script' in port_info and 'vulners' in port_info['script']:
                for vuln in port_info['script']['vulners'].split('\n'):
                    # Parse the vulnerability information string
                    urls, names, scores = parse_vulners_vuln_info([vuln])

                    # Add the parsed information to the vulnerability_info_dict
                    if port not in vulnerability_info_dict:
                        vulnerability_info_dict[port] = []
                    for url, name, score in zip(urls, names, scores):
                        vulnerability_info_dict[port].append({
                            'port': port,  # Include the 'port' key
                            'vulnerability': name,
                            'cvss_score': score,
                            'url': url
                        })

        # Call generate_vulners_html_content function with vulnerability_info_dict
        html_content = generate_vulners_vuln_html_content(ip_address, parsed_url.netloc if parsed_url.netloc else "", t1, t2, t2 - t1, open_ports_dict, os_guess, selected_scan, result, ip_address, vulnerability_info_dict)

        on_vulners_vuln_scan_complete(html_content)
    
        #save the content of the text box to a file only if it's not empty
        if not is_text_box_empty():
            save_to_file(result_text.get("1.0", "end-1c"))

        result_text.config(state="disabled")

        #change the button text back 
        test_button.config(text="Perform Security Test")
        test_button.config(state="normal")  #re-enable the button

    #use a thread to keep the GUI responsive
    #mapping between scan types and functions
    scan_functions = {
        "performScan": perform_security_scan,
        "nmapVulners": perform_vulners_scan,
        "nmapVuln": perform_vuln_scan,
    }

    #use the selected scan type to get the corresponding function
    selected_function = scan_functions.get(selected_scan)

    #check if a valid function is found
    if selected_function:
        #create a thread with the selected function
        scan_thread = Thread(target=selected_function)
        scan_thread.start()
    else:
        #handle the case when an invalid scan type is selected
        messagebox.showerror("Invalid Scan Type", "Invalid scan type selected.")

def close_window():
    root.destroy()

###################################################################################################################
#                                               Login Functionality                                               #
###################################################################################################################

# AWS Cognito configuration
cognito_user_pool_id = 'us-east-2_3kyYLaR4e'
cognito_client_id = '3boqnps5uqd0tu07rr2p20fbvo'
cognito_client_secret = '1e7i1uk9qad51ll1n6tokveutq5eg1g4oc6mnfj89nms1otnjfk'
region_name = 'us-east-2'
user_pool_client = boto3.client('cognito-idp', region_name=region_name)

# Function to authenticate the user using AWS Cognito
# Function to authenticate the user using AWS Cognito


def authenticate_user(username, password):
    try:
        secret_hash = calculate_secret_hash(username)
        response = user_pool_client.initiate_auth(
            ClientId=cognito_client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientMetadata={
                'username': username,
                'password': password
            }
        )
        return response['AuthenticationResult']['AccessToken']
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NotAuthorizedException':
            print("NotAuthorizedException:", e)
        elif error_code == 'UserNotConfirmedException':
            print("UserNotConfirmedException:", e)
        else:
            print("Unexpected error:", e)
        return None
    except Exception as e:
        messagebox.showerror("Authentication Error", f"Failed to authenticate user: {e}")
        return None




def calculate_secret_hash(username):
    message = username + cognito_client_id
    dig = hmac.new(str(cognito_client_secret).encode('utf-8'), msg=str(message).encode('utf-8'), digestmod=hashlib.sha256).digest()
    secret_hash = base64.b64encode(dig).decode()
    return secret_hash

def sign_up_user(username, password, email):
    try:
        secret_hash = calculate_secret_hash(username)
        response = user_pool_client.sign_up(
            ClientId=cognito_client_id,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                },
                {
                    'Name': 'preferred_username',  # Add the required attributes
                    'Value': username
                },
                {
                    'Name': 'name',
                    'Value': username
                }
            ],
            SecretHash=secret_hash
        )
        print(f"User {username} successfully signed up!")
        return True
    except Exception as e:
        print(f"Error signing up user: {e}")
        return False

def confirm_signup(username, confirmation_code):
    try:
        secret_hash = calculate_secret_hash(username)
        response = user_pool_client.confirm_sign_up(
            ClientId=cognito_client_id,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=secret_hash  # Include the secret hash
        )
        print(f"User {username} confirmed sign up!")
        return True
    except Exception as e:
        print(f"Error confirming sign up: {e}")
        return False

# Function to switch to the login page
def switch_to_login():
    signup_frame.grid_forget()  # Hide signup frame
    main_frame.grid_forget()  # Hide main frame
    login_frame.grid()  # Show login frame

# Function to switch to the main page after successful login
def switch_to_main_page():
    login_frame.grid_forget()  # Hide login frame
    signup_frame.grid_forget()  # Hide signup frame
    main_frame.grid()  # Show main frame

# Function to handle login button click
def handle_login():
    username = login_username_entry.get()
    password = login_password_entry.get()

    # Authenticate the user using Cognito
    access_token = authenticate_user(username, password)

    if access_token:
        print(f"Authenticated! Access Token: {access_token}")
        switch_to_main_page()
    else:
        messagebox.showinfo("Authentication", "User authentication failed. Please check your credentials.")

# Function to handle signup button click
def handle_signup():
    username = signup_username_entry.get()
    password = signup_password_entry.get()
    email = signup_email_entry.get()

    # Sign up the new user using Cognito
    if sign_up_user(username, password, email):
        confirmation_code = simpledialog.askstring("Confirmation Code", "Enter confirmation code sent to your email:")
        if confirmation_code:
            if confirm_signup(username, confirmation_code):
                messagebox.showinfo("Signup", f"User {username} successfully signed up and confirmed!")
            else:
                messagebox.showinfo("Signup", f"Failed to confirm sign up. Please check your information.")
        else:
            messagebox.showinfo("Signup", "Confirmation code is required.")
    else:
        messagebox.showinfo("Signup", f"Failed to sign up user. Please check your information.")

# Function to switch to the signup page
def switch_to_signup():
    login_frame.grid_forget()  # Hide login frame
    main_frame.grid_forget()  # Hide main frame
    signup_frame.grid()  # Show signup frame

###################################################################################################################
#                                               GUI Display                                                       #
###################################################################################################################

#create the main window
root = tk.Tk()
root.title("VigilBoard by VigilNet")
root.configure(bg="white")

# Create frames for login, signup, and main pages
login_frame = tk.Frame(root)
signup_frame = tk.Frame(root)
main_frame = tk.Frame(root)

#create the VigilBoard logo
label = tk.Label(main_frame, text="VigilBoard by VigilNet", bg="white", fg="blue")
label.grid(row=0, column=0, columnspan=5, padx=40, pady=10)
label.config(anchor="center")

#entry for URL or IP address
url_or_ip_label = tk.Label(main_frame, text="Enter URL or IP Address:")
url_or_ip_label.grid(row=1, column=0, padx=10, pady=10)
url_or_ip_entry = tk.Entry(main_frame, width=50)
url_or_ip_entry.grid(row=1, column=1, padx=10, pady=10)

# Add radio buttons for scan options
scan_var = tk.StringVar(value="none_selected")
perform_scan_radio = tk.Radiobutton(main_frame, text="Perform Security Scan", variable=scan_var, value="performScan")
perform_scan_radio.grid(row=2, column=0, padx=10, pady=10)
nmap_vulners_radio = tk.Radiobutton(main_frame, text="Vulners Scripting Scan", variable=scan_var, value="nmapVulners")
nmap_vulners_radio.grid(row=2, column=1, padx=10, pady=10)
nmap_vuln_radio = tk.Radiobutton(main_frame, text="Vuln Scripting Scan", variable=scan_var, value="nmapVuln")
nmap_vuln_radio.grid(row=2, column=2, padx=10, pady=10)

#create a button to perform the security test
test_button = tk.Button(main_frame, text="Perform Security Test", command=check_security)
test_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#create a button to view logs
view_logs_button = tk.Button(main_frame, text="View Logs", command=view_logs)
view_logs_button.grid(row=3, column=1, columnspan=2, padx=10, pady=10)

# Create the "View HTML Logs" button
view_html_logs_button = tk.Button(main_frame, text="View HTML Logs", command=view_html_logs)
view_html_logs_button.grid(row=3, column=2, padx=10, pady=10)

#create a text box to display port scan results
result_text = tk.Text(main_frame, height=20, width=80, state="disabled")
result_text.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

#create a scrollbar for when the output gets long in the text box
scrollbar = Scrollbar(main_frame, command=result_text.yview)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.grid(row=4, column=3, sticky="ns")

#add description label
description_text = "VigilBoard is a security tool that performs port scanning and provides information about open ports and the target's operating system. We do not encourage the use of this tool in a malicious manner. Use responsibly."
description_label = tk.Label(main_frame, text=description_text, bg="white", wraplength=400)
description_label.grid(row=5, column=1, columnspan=1, padx=10, pady=10)

# Widgets for the login page
login_username_label = tk.Label(login_frame, text="Username:")
login_username_label.grid(pady=40)  # Adjust pady for spacing
login_username_entry = tk.Entry(login_frame, width=90)  # Adjust width
login_username_entry.grid(pady=40)

login_password_label = tk.Label(login_frame, text="Password:")
login_password_label.grid(pady=20)  # Adjust pady for spacing
login_password_entry = tk.Entry(login_frame, width=40, show="*")  # Adjust width
login_password_entry.grid(pady=20)

# create a button to perform the login
login_button = tk.Button(login_frame, text="Login", command=handle_login)
login_button.grid(pady=20)

# Create a button to switch to the signup page from the login frame
switch_to_signup_button = tk.Button(login_frame, text="Switch to Signup", command=switch_to_signup)
switch_to_signup_button.grid(pady=10)

# Widgets for the signup page
signup_username_label = tk.Label(signup_frame, text="Username:")
signup_username_label.grid(pady=40)
signup_username_entry = tk.Entry(signup_frame, width=90)
signup_username_entry.grid(pady=40)

signup_password_label = tk.Label(signup_frame, text="Password:")
signup_password_label.grid(pady=10)
signup_password_entry = tk.Entry(signup_frame, width=30, show="*")
signup_password_entry.grid(pady=10)

signup_email_label = tk.Label(signup_frame, text="Email:")
signup_email_label.grid(pady=10)
signup_email_entry = tk.Entry(signup_frame, width=30)
signup_email_entry.grid(pady=10)

signup_button = tk.Button(signup_frame, text="Sign Up", command=handle_signup)
signup_button.grid(pady=10)

# Create a button to switch to the login page from signup
switch_to_login_button = tk.Button(signup_frame, text="Switch to Login", command=switch_to_login)
switch_to_login_button.grid(pady=10)

#start the GUI
switch_to_login()  # Start with the login page
root.protocol("WM_DELETE_WINDOW", close_window)
root.mainloop()