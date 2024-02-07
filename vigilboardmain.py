import tkinter as tk                #using tkinter as our gui
from tkinter import messagebox
from tkinter import Scrollbar
import nmap                         #nmap for port scanning
import socket
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse
from threading import Thread
import os
import re
import json

###################################################################################################################
#                                               log/helper functions                                              #
###################################################################################################################

# Global variable
SCAN_TYPE_NAMES = {
    "performScan": "Basic Security Scan",
    "nmapVulners": "Vulners Scan",
    "nmapVuln": "Vulnerability Scan"
}

#function that will make a log file named "scanlog{date} {time}" and put the text box info inside of it
#it will then either create a new log folder to place logs into, or it will detect a log folder exists and put the log file into it
def save_to_file(content, prefix="scanlog"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H%M%S")
    log_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VigilBoard_Scan_Logs")

    # Check if the log folder exists, and create it if not
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    filename = os.path.join(log_folder, f"{prefix}{timestamp}.txt")

    with open(filename, "w") as file:
        file.write(content)

#function that will pop open an explorer window with your log files there when you press "View Logs"
def view_logs():
    #get the directory of the currently running script
    script_directory = os.path.dirname(os.path.abspath(__file__))
    
    #open the file explorer at the script directory
    os.system(f'explorer {script_directory}')

#function to check if the content of the text box is empty
def is_text_box_empty():
    return result_text.compare("end-1c", "==", "1.0")

# Global variables
scan_thread = None
result_text = None

# Function to save scan result to HTML file
def save_to_html(content, filename="scan_result.html"):
    with open(filename, "w") as file:
        file.write(content)

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

    # Generate HTML content
    html_content = f"""
    <h1>Security Scan Results</h1>
    <p>Scan conducted on: {scan_date}</p>
    <p>Scan Start Time: {scan_start_time.strftime('%H:%M:%S.%f')}</p>
    <p>Scan Finish Time: {scan_finish_time.strftime('%H:%M:%S.%f')}</p>
    <p>Scan Elapsed Time: {scan_elapsed_time}</p>
    <p>Target IP: {target_ip}</p>
    <p>Target URL: {target_url}</p>
    <p>Scan Type: {scan_type}</p>
    <h2>Open Ports:</h2>
    <ul>
    """

    # Check if there are open ports
    if open_ports:
        for port, details in open_ports.items():
            html_content += f"<li>Port {port}: Service={details['name']}, Product={details['product']}, Version={details['version']}</li>"
    else:
        html_content += "<li>No open ports found.</li>"

    html_content += "</ul>"
    
    html_content += "<h2>OS Fingerprinting Results:</h2>"
    html_content += "<ul>"
    if os_guess:
        for os_result in os_guess:
            html_content += f"<li>OS Name: {os_result['name']}, Accuracy: {os_result['accuracy']}</li>"
    else:
        html_content += "<li>No OS fingerprinting results found.</li>"
    html_content += "</ul>"

    return html_content

def on_scan_complete(scan_result, scan_start_time, scan_finish_time):
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
    scan_type = SCAN_TYPE_NAMES.get(scan_var.get(), "Unknown Scan")

    # Generate HTML content
    html_content = generate_html_content(target_ip, target_url, scan_start_time, scan_finish_time, scan_elapsed_time, open_ports, os_guess, scan_type)
    
    # Save HTML content to file
    save_to_html(html_content)
    
    # Open HTML file in default web browser
    os.system("start scan_result.html")

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
        result_text.insert("end", "\n\nRunning nmap scan...\n\n")

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

        result_text.insert("end", "\n\nSecurity scan has been completed.\n")

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
        on_scan_complete(result, scan_start_time, datetime.now())

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
        result_text.insert("end", "\n\nRunning nmap scan...\n\n")

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

        result_text.insert("end", "\n\nSecurity scan has been completed.\n")

        t2 = datetime.now()
        result_text.insert("end", "Scan completed at: ")
        result_text.insert("end", t2)

        #writing the text box to a log file

        result_text.config(state="normal")
    
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

        result_text.insert("end", "\n\nThis scan can take a few minutes, thank you for your patience.")
        result_text.insert("end", "\n\nRunning nmap scan...\n\n")

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

        result_text.insert("end", "\n\nSecurity scan has been completed.\n")

        t2 = datetime.now()
        result_text.insert("end", "Scan completed at: ")
        result_text.insert("end", t2)

        #writing the text box to a log file

        result_text.config(state="normal")
    
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
#                                               GUI Display                                                       #
###################################################################################################################

#create the main window
root = tk.Tk()
root.title("VigilBoard Prototype 1.0 by VigilNet")
root.configure(bg="white")

#create the VigilBoard logo
label = tk.Label(root, text="VigilBoard Prototype 1.0 by VigilNet", bg="white", fg="blue")
label.grid(row=0, column=0, columnspan=5, padx=40, pady=10)
label.config(anchor="center")

#entry for URL or IP address
url_or_ip_label = tk.Label(root, text="Enter URL or IP Address:")
url_or_ip_label.grid(row=1, column=0, padx=10, pady=10)
url_or_ip_entry = tk.Entry(root, width=50)
url_or_ip_entry.grid(row=1, column=1, padx=10, pady=10)

# Add radio buttons for scan options
scan_var = tk.StringVar(value="none_selected")
perform_scan_radio = tk.Radiobutton(root, text="Perform Security Scan", variable=scan_var, value="performScan")
perform_scan_radio.grid(row=2, column=0, padx=10, pady=10)
nmap_vulners_radio = tk.Radiobutton(root, text="Vulners Scripting Scan", variable=scan_var, value="nmapVulners")
nmap_vulners_radio.grid(row=2, column=1, padx=10, pady=10)
nmap_vuln_radio = tk.Radiobutton(root, text="Vuln Scripting Scan", variable=scan_var, value="nmapVuln")
nmap_vuln_radio.grid(row=2, column=2, padx=10, pady=10)

#create a button to perform the security test
test_button = tk.Button(root, text="Perform Security Test", command=check_security)
test_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#create a button to view logs
view_logs_button = tk.Button(root, text="View Logs", command=view_logs)
view_logs_button.grid(row=3, column=1, columnspan=2, padx=10, pady=10)

#create a text box to display port scan results
result_text = tk.Text(root, height=20, width=80, state="disabled")
result_text.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

#create a scrollbar for when the output gets long in the text box
scrollbar = Scrollbar(root, command=result_text.yview)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.grid(row=4, column=3, sticky="ns")

#add description label
description_text = "VigilBoard Prototype 1.0 is a security tool that performs port scanning and provides information about open ports and the target's operating system. We do not encourage the use of this tool in a malicious manner. Use responsibly."
description_label = tk.Label(root, text=description_text, bg="white", wraplength=400)
description_label.grid(row=5, column=1, columnspan=1, padx=10, pady=10)

#start the GUI
root.protocol("WM_DELETE_WINDOW", close_window)
root.mainloop()