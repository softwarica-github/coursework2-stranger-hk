import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import threading

class SimpleAntiVirus:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Anti-Virus")
        self.root.geometry("700x555")

        # Variables
        self.virus_count = 0
        self.scan_process_text = tk.StringVar()
        self.selected_directory = ""

        # Labels
        self.title_label = tk.Label(root, text="Simple Anti-Virus", font=("Helvetica", 16, "bold"))
        self.title_label.pack(pady=10)

        self.subtitle_label = tk.Label(root, text="Which directory to scan?", font=("Helvetica", 12))
        self.subtitle_label.pack(pady=5)

        self.result_label = tk.Label(root, text="Virus Detected: 0")
        self.result_label.pack(pady=10)

        # Buttons
        self.button1 = tk.Button(root, text="Scan Local Disk C", command=self.scan_local_disk_c)
        self.button1.pack(padx=10, pady=10)

        self.button2 = tk.Button(root, text="Scan Local Disk E", command=self.scan_local_disk_e)
        self.button2.pack(padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_directory)
        self.browse_button.pack(padx=10, pady=10)

        self.scan_button = tk.Button(root, text="Scan Directory", command=self.start_scan_thread)
        self.scan_button.pack(padx=10, pady=10)

        self.cancel_button = tk.Button(root, text="Cancel", command=self.cancel_scan)
        self.cancel_button.pack(side="left", padx=5, pady=10)

        self.close_button = tk.Button(root, text="Close", command=root.destroy)
        self.close_button.pack(side="right", padx=5, pady=10)

        # Text Widget for process display
        self.process_text_widget = tk.Text(root, height=8, width=70)
        self.process_text_widget.pack(pady=10)
        self.process_text_widget.insert(tk.END, "Scan Process:\n")

        # Set up threading variables
        self.scan_thread = None
        self.cancelled = False

    def calculate_file_hash(self, file_path):
        hasher = hashlib.sha1()
        with open(file_path, 'rb') as file:
            buf = file.read()
            hasher.update(buf)
        return hasher.hexdigest()

    def remove(self, file_path):
        os.remove(file_path)

    def scan_file_for_virus(self, file_path):
        file_hash = self.calculate_file_hash(file_path)
        self.process_text_widget.insert(tk.END, f"Scanning {file_path}...\n")

        if file_hash in known_virus_signatures:
            self.process_text_widget.insert(tk.END, f"WARNING: Virus detected in file: {file_path}\n")
            self.virus_count += 1
            return True
        else:
            self.process_text_widget.insert(tk.END, f"File {file_path} is safe.\n")
            return False

    def scan_directory(self, directory_path):
        for dirpath, _, filenames in os.walk(directory_path):
            for file in filenames:
                file_path = os.path.join(dirpath, file)
                if self.cancelled:
                    return
                if self.scan_file_for_virus(file_path):
                    self.result_label.config(text=f"Virus Detected: {self.virus_count}")
                    # Ask if the user wants to remove the virus
                    user_response = messagebox.askyesno("Remove Virus", f"Do you want to remove the virus in {file_path}?")
                    if user_response:
                        self.remove(file_path)
                        self.process_text_widget.insert(tk.END, f"Virus removed: {file_path}\n")
                    else:
                        self.process_text_widget.insert(tk.END, f"Virus not removed: {file_path}\n")
        self.process_text_widget.insert(tk.END, "Scanning Completed!\n")

    def scan_local_disk_c(self):
        directory_to_scan = 'C:/'
        self.start_scan(directory_to_scan)

    def scan_local_disk_e(self):
        directory_to_scan = 'E:/'
        self.start_scan(directory_to_scan)

    def start_scan_thread(self):
        # Start the scanning process in a separate thread
        self.scan_thread = threading.Thread(target=self.start_scan_threaded)
        self.scan_thread.start()

    def start_scan_threaded(self):
        self.cancelled = False
        self.process_text_widget.delete("1.0", tk.END)
        self.process_text_widget.insert(tk.END, "Scan Process:\n")
        self.scan_directory(self.selected_directory)

    def start_scan(self, directory_path):
        # Start the scanning process
        self.cancelled = False
        self.process_text_widget.delete("1.0", tk.END)
        self.process_text_widget.insert(tk.END, "Scan Process:\n")
        self.scan_directory(directory_path)

    def cancel_scan(self):
        # Cancel the scanning process
        self.cancelled = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join()  # Wait for the thread to finish
        messagebox.showinfo("Scan Cancelled", "Scanning process has been cancelled.")

    def browse_directory(self):
        self.selected_directory = filedialog.askdirectory(title="Select Directory to Scan")
        self.process_text_widget.insert(tk.END, f"Selected Directory: {self.selected_directory}\n")

if __name__ == "__main__":
    known_virus_signatures = [
        'X5O!P%@AP[4/PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
        '356a192b7913b04c54574d18c28d46e6395428ab',
        'a954a35485c54bc8505c57f5b8f854a35485c54bc8505c57f5b8f854',
        '2f5f654a35485c54bc8505c57f5b8f854a35485c54bc8505c57f5b8f8'
    ]

    root = tk.Tk()
    app = SimpleAntiVirus(root)
    root.mainloop()
