import tkinter as tk #using tkinter as our gui
from tkinter import messagebox
import nmap #nmap for port scanning
import socket
from urllib.parse import urlparse
from threading import Thread


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
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address.")
                return
        else:
            #the input is an IPv4 address so verify it
            try:
                socket.inet_pton(socket.AF_INET, input_text)
                ip_address = input_text
            except socket.error:
                messagebox.showerror("Security Test", "Invalid URL or IPv4 address.")
                return

        #create an nmap PortScanner instance
        nm = nmap.PortScanner()

        #change the button text
        test_button.config(text="Scanning target")
        test_button.config(state="disabled")  # Disable the button

        #perform a quick scan
        result = nm.scan(hosts=ip_address, arguments='-O -sV -F')
        
        open_ports = result['scan'][ip_address]['tcp'].keys()
        os_guess = result['scan'][ip_address]['osmatch']

        result_text.config(state="normal")
        result_text.delete("1.0", "end")
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

        #change the button text back 
        test_button.config(text="Perform Security Test")
        test_button.config(state="normal")  #re-enable the button


    #use a thread to keep the GUI responsive
    scan_thread = Thread(target=perform_security_scan)
    scan_thread.start()

def close_window():
    root.destroy()

#create the main window
root = tk.Tk()
root.title("VigilBoard by VigilNet")
root.configure(bg="white")

#create the VigilBoard logo
label = tk.Label(root, text="VigilBoard by VigilNet", bg="white", fg="blue")
label.grid(row=0, column=1, padx=10, pady=10)

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

#start the GUI
root.protocol("WM_DELETE_WINDOW", close_window)
root.mainloop()
