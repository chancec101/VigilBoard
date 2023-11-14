import tkinter as tk                #using tkinter as our gui
from tkinter import messagebox
from tkinter import Scrollbar
import nmap                         #nmap for port scanning
import socket
from datetime import datetime
from urllib.parse import urlparse
from threading import Thread
import subprocess                   #used for nikto scanning

#function that will make a log file named "scan_log_{date} {time}", put the text box info inside of it, and place it inside of the same file path that this program is in
def save_to_file(content, prefix="scan_log_"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H_%M_%S")
    filename = f"{prefix}{timestamp}.txt"
    
    with open(filename, "w") as file:
        file.write(content)

###################################################################################################################
#                                               nmap functionality                                                #
###################################################################################################################

#function will validate a given url or ip address and then run a simple port scan 
def check_security():
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

        #perform a quick scan through nmap
        result = nm.scan(hosts=ip_address, arguments='-O -sV -F')

        open_ports = result['scan'][ip_address]['tcp'].keys()
        os_guess = result['scan'][ip_address]['osmatch']

        result_text.config(state="normal")
        #result_text.delete("1.0", "end")
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
        result_text.config(state="disabled")

        ###################################################################################################################
        #                                               nikto functionality                                               #
        ###################################################################################################################

        #perform a simple scan using nikto
        #list variable that will attempt to scan all of the open ports found. If no open ports were found, then make the list only contain port 80 just to try something
        if open_ports:
            open_ports_list = ",".join(map(str, open_ports))
        else:
            open_ports_list = "80"

        #for the following nikto_command variable, you have to set the path of where nikto.pl is on your host system. I want to try to change this but as long as it runs it should be okay for now.
        #for chance testing path: C:\\Users\\currib\\Desktop\\UNT Code\\VigilBoardProj\\Nikto\\nikto\\program\\nikto.pl
        nikto_command = ["perl", "C:\\Users\\currib\\Desktop\\UNT Code\\VigilBoardProj\\Nikto\\nikto\\program\\nikto.pl", "-h", ip_address, "-p", open_ports_list]
        
        result_text.config(state="normal")    #enable the text box
        result_text.insert("end", "\nRunning Nikto scan...\n")
        result_text.config(state="disabled")  #disable the text box

        #execute the Nikto command
        result = subprocess.run(nikto_command, capture_output=True, text=True)

        #check the exit code and print Nikto output in the console
        print("Nikto exit code:", result.returncode)
        print("Nikto stdout:", result.stdout)
        print("Nikto stderr:", result.stderr)

        if result.returncode == 0:
            result_text.config(state="normal")  #enable the text box
            result_text.insert("end", "Nikto scan completed successfully.\n")

            #display Nikto scan results
            nikto_output = result.stdout
            result_text.insert("end", "Nikto Scan Results:\n")
            result_text.insert("end", nikto_output)
        else:
            result_text.config(state="normal")  #enable the text box
            result_text.insert("end", "Nikto scan failed.\n")
            result_text.insert("end", result.stderr)

        result_text.insert("end", "\n\nSecurity scan has been completed.\n")

        #writing the text box to a log file

        result_text.config(state="normal")
    
        # Save the content of the text box to a file
        save_to_file(result_text.get("1.0", "end-1c"))

        result_text.config(state="disabled")

        #change the button text back 
        test_button.config(text="Perform Security Test")
        test_button.config(state="normal")  #re-enable the button

    #use a thread to keep the GUI responsive
    scan_thread = Thread(target=perform_security_scan)
    scan_thread.start()

def close_window():
    #save the content of the text box to a file before closing the window
    save_to_file(result_text.get("1.0", "end-1c"))
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
label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
label.config(anchor="center")

#entry for URL or IP address
url_or_ip_label = tk.Label(root, text="Enter URL or IP Address:")
url_or_ip_label.grid(row=1, column=0, padx=10, pady=10)
url_or_ip_entry = tk.Entry(root, width=50)
url_or_ip_entry.grid(row=1, column=1, padx=10, pady=10)

#create a button to perform the security test
test_button = tk.Button(root, text="Perform Security Test", command=check_security)
test_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

#create a text box to display port scan results
result_text = tk.Text(root, height=20, width=80, state="disabled")
result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#create a scrollbar for when the output gets long in the text box
scrollbar = Scrollbar(root, command=result_text.yview)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.grid(row=3, column=2, sticky="ns")

#add description label
description_text = "VigilBoard Prototype 1.0 is a security tool that performs port scanning and provides information about open ports and the target's operating system. We do not encourage the use of this tool in a malicious manner. Use responsibly."
description_label = tk.Label(root, text=description_text, bg="white", wraplength=400)
description_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

#start the GUI
root.protocol("WM_DELETE_WINDOW", close_window)
root.mainloop()