import tkinter as tk
from tkinter import messagebox
import requests


API_KEY = '27388ff3d306f4f0fb7a67793b7d20a68784addcc1dbf852e6f4df41d9c09fb4'
VT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def check_link(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(VT_URL, params=params)
    result = response.json()
    
    if result['response_code'] == 1:
        positives = result['positives']
        total = result['total']
        if positives > 0:
            return f"URL is malicious. {positives}/{total} scans detected it as harmful."
        else:
            return "URL is clean. No issues detected."
    else:
        return "URL check failed. It might not be in the VirusTotal database."

def on_check_button_click():
    url = entry.get()
    if url:
        result = check_link(url)
        messagebox.showinfo("Result", result)
    else:
        messagebox.showwarning("Input Error", "Please enter a URL.")

# Create the main window
root = tk.Tk()
root.title("Malicious Link Checker")

# Create and place the URL entry
entry_label = tk.Label(root, text="Enter URL:")
entry_label.pack(pady=10)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

# Create and place the Check button
check_button = tk.Button(root, text="Check", command=on_check_button_click)
check_button.pack(pady=20)

# Run the main event loop
root.mainloop()
