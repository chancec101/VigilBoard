import tkinter as tk                #using tkinter as our gui
from tkinter import messagebox
from tkinter import Scrollbar
import nmap                         #nmap for port scanning
import socket
from datetime import datetime
from urllib.parse import urlparse
from threading import Thread
import os
global scan_thread
###################################################################################################################
#                                               log/helper functions                                              #
###################################################################################################################

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

        t1 = datetime.now()
        result_text.insert("end", "Scan conducted on: ")
        result_text.insert("end", t1)
        result_text.insert("end", "\n\nRunning nmap scan...\n")

        result_text.config(state="disabled")

        #utilize the scan that the user chose
        if selected_scan == "performScan":
            result = nm.scan(hosts=ip_address, arguments='-O -sV -F')
        elif selected_scan == "nmapVulners":
            result = nm.scan(hosts=ip_address, arguments='-O -sV -F --script vulners')
        #provides warning to user that vuln scipt is invasive/disruptive
        elif selected_scan == "nmapVuln":
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

        open_ports = result['scan'][ip_address]['tcp'].keys()
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
    scan_thread = Thread(target=perform_security_scan)
    scan_thread.start()

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