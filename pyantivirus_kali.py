#!/usr/bin/env python3
"""
PyAntivirus for Kali Linux
A comprehensive antivirus solution built specifically for Kali Linux
Includes signature scanning, heuristic analysis, and real-time monitoring
"""

import os
import sys
import hashlib
import json
import time
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path

class KaliAntivirus:
    def __init__(self):
        self.malware_signatures = set()
        self.suspicious_patterns = [
            b"eval(", b"exec(", b"system(", b"chmod 777", 
            b"base64_decode", b"shell_exec", b"passthru",
            b"proc_open", b"popen", b"curl_exec", b"wget",
            b"rm -rf", b":(){ :|:& };:", b"fork bomb"
        ]
        self.quarantine_dir = "/tmp/pyantivirus_quarantine"
        self.log_file = "/var/log/pyantivirus.log"
        self.scanning = False
        self.realtime_monitoring = False
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Load malware signatures
        self.load_signatures()

    def load_signatures(self):
        """Load malware signatures from built-in database"""
        # Common malware hashes (this would be expanded in a real implementation)
        builtin_signatures = {
            "d41d8cd98f00b204e9800998ecf8427e",  # Empty file (often used in attacks)
            "5d41402abc4b2a76b9719d911017c592",  # "hello" md5
            "098f6bcd4621d373cade4e832627b4f6",  # "test" md5
        }
        
        # Try to load external signature file
        signature_files = [
            "/usr/share/pyantivirus/signatures.txt",
            "/etc/pyantivirus/signatures.txt",
            "./malware_signatures.txt"
        ]
        
        for sig_file in signature_files:
            try:
                if os.path.exists(sig_file):
                    with open(sig_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if len(line) == 32:  # MD5 hash length
                                builtin_signatures.add(line)
                    print(f"Loaded signatures from {sig_file}")
            except Exception as e:
                print(f"Error loading {sig_file}: {e}")
        
        self.malware_signatures = builtin_signatures

    def calculate_hash(self, file_path, hash_type="md5"):
        """Calculate file hash"""
        try:
            if hash_type == "md5":
                hash_obj = hashlib.md5()
            elif hash_type == "sha256":
                hash_obj = hashlib.sha256()
            else:
                hash_obj = hashlib.md5()
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None

    def heuristic_analysis(self, file_path):
        """Perform heuristic analysis on file"""
        suspicious_score = 0
        findings = []
        
        try:
            # Check file permissions (too permissive)
            stat_info = os.stat(file_path)
            if stat_info.st_mode & 0o777 == 0o777:  # rwxrwxrwx
                suspicious_score += 30
                findings.append("File has overly permissive permissions (777)")
            
            # Check file extension vs content type
            file_cmd = subprocess.run(['file', file_path], capture_output=True, text=True)
            if "executable" in file_cmd.stdout and not file_path.endswith(('.exe', '.bin', '')):
                suspicious_score += 20
                findings.append("Executable file with unexpected extension")
            
            # Check for suspicious patterns in content
            with open(file_path, "rb") as f:
                content = f.read(8192)  # Read first 8KB
                
                for pattern in self.suspicious_patterns:
                    if pattern in content:
                        suspicious_score += 10
                        findings.append(f"Suspicious pattern found: {pattern.decode('utf-8', errors='ignore')}")
            
            # Check file size (very small or very large executables)
            file_size = os.path.getsize(file_path)
            if file_size < 100 and file_path.endswith(('.sh', '.py', '.exe')):
                suspicious_score += 15
                findings.append("Suspiciously small executable file")
                
        except Exception as e:
            print(f"Heuristic analysis error for {file_path}: {e}")
        
        return suspicious_score, findings

    def quarantine_file(self, file_path):
        """Move file to quarantine"""
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{filename}")
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            
            # Log the action
            self.log_event(f"QUARANTINED: {file_path} -> {quarantine_path}")
            
            return True
        except Exception as e:
            print(f"Error quarantining {file_path}: {e}")
            return False

    def log_event(self, message):
        """Log event to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        
        print(log_message)
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_message + "\n")
        except Exception as e:
            print(f"Error writing to log: {e}")

    def scan_file(self, file_path):
        """Scan a single file"""
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}
        
        results = {
            "file": file_path,
            "hash_md5": self.calculate_hash(file_path, "md5"),
            "hash_sha256": self.calculate_hash(file_path, "sha256"),
            "signature_detected": False,
            "heuristic_score": 0,
            "heuristic_findings": [],
            "status": "clean"
        }
        
        # Signature-based detection
        if results["hash_md5"] in self.malware_signatures:
            results["signature_detected"] = True
            results["status"] = "malicious"
        
        # Heuristic analysis
        score, findings = self.heuristic_analysis(file_path)
        results["heuristic_score"] = score
        results["heuristic_findings"] = findings
        
        if score > 30:  # Threshold for heuristic detection
            results["status"] = "suspicious"
        
        return results

    def scan_directory(self, directory_path):
        """Scan all files in directory recursively"""
        if not os.path.exists(directory_path):
            return {"status": "error", "message": "Directory not found"}
        
        scan_results = {
            "scanned_files": 0,
            "clean_files": 0,
            "suspicious_files": 0,
            "malicious_files": 0,
            "details": []
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if self.scanning:  # Allow stopping the scan
                        file_path = os.path.join(root, file)
                        result = self.scan_file(file_path)
                        
                        scan_results["scanned_files"] += 1
                        
                        if result["status"] == "clean":
                            scan_results["clean_files"] += 1
                        elif result["status"] == "suspicious":
                            scan_results["suspicious_files"] += 1
                        elif result["status"] == "malicious":
                            scan_results["malicious_files"] += 1
                        
                        scan_results["details"].append(result)
                    else:
                        break
        except Exception as e:
            scan_results["status"] = "error"
            scan_results["message"] = str(e)
        
        return scan_results

    def start_realtime_monitoring(self, directory_path):
        """Start real-time file system monitoring"""
        # This would use inotify or similar in a real implementation
        # For simplicity, we'll simulate with periodic scanning
        def monitor():
            while self.realtime_monitoring:
                results = self.scan_directory(directory_path)
                if results["malicious_files"] > 0 or results["suspicious_files"] > 0:
                    self.log_event(f"Real-time alert: {results['malicious_files']} malicious, {results['suspicious_files']} suspicious files found")
                time.sleep(300)  # Check every 5 minutes
        
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyAntivirus for Kali Linux")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        self.antivirus = KaliAntivirus()
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = tk.Label(main_frame, text="PyAntivirus for Kali Linux", 
                              font=("Arial", 16, "bold"), fg="#ecf0f1", bg="#2c3e50")
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Scan section
        scan_frame = ttk.LabelFrame(main_frame, text="File Scanning", padding="10")
        scan_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10, padx=5)
        
        ttk.Button(scan_frame, text="Select File to Scan", 
                  command=self.select_file).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(scan_frame, text="Select Directory to Scan", 
                  command=self.select_directory).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(scan_frame, text="Quick System Scan", 
                  command=lambda: self.scan_directory("/tmp")).grid(row=0, column=2, padx=5, pady=5)
        
        # Real-time monitoring
        monitor_frame = ttk.LabelFrame(main_frame, text="Real-time Monitoring", padding="10")
        monitor_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10, padx=5)
        
        self.monitor_var = tk.BooleanVar()
        ttk.Checkbutton(monitor_frame, text="Enable Real-time Monitoring", 
                       variable=self.monitor_var, 
                       command=self.toggle_monitoring).grid(row=0, column=0, padx=5, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10, padx=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=70)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select file to scan")
        if file_path:
            self.scan_file(file_path)
    
    def select_directory(self):
        dir_path = filedialog.askdirectory(title="Select directory to scan")
        if dir_path:
            self.scan_directory(dir_path)
    
    def scan_file(self, file_path):
        self.status_var.set(f"Scanning file: {file_path}")
        self.results_text.delete(1.0, tk.END)
        
        result = self.antivirus.scan_file(file_path)
        self.display_results([result])
        
        self.status_var.set("Scan completed")
    
    def scan_directory(self, directory_path):
        self.antivirus.scanning = True
        self.status_var.set(f"Scanning directory: {directory_path}")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Scanning {directory_path}...\n\n")
        self.root.update()
        
        # Run scan in separate thread to avoid GUI freeze
        def scan_thread():
            results = self.antivirus.scan_directory(directory_path)
            self.root.after(0, lambda: self.display_results(results))
            self.antivirus.scanning = False
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def display_results(self, results):
        if isinstance(results, dict) and "details" in results:
            # Directory scan results
            self.results_text.insert(tk.END, f"Scan Summary:\n")
            self.results_text.insert(tk.END, f"Files scanned: {results['scanned_files']}\n")
            self.results_text.insert(tk.END, f"Clean files: {results['clean_files']}\n")
            self.results_text.insert(tk.END, f"Suspicious files: {results['suspicious_files']}\n")
            self.results_text.insert(tk.END, f"Malicious files: {results['malicious_files']}\n\n")
            
            for result in results["details"]:
                if result["status"] != "clean":
                    self.results_text.insert(tk.END, f"FILE: {result['file']}\n")
                    self.results_text.insert(tk.END, f"STATUS: {result['status'].upper()}\n")
                    if result["signature_detected"]:
                        self.results_text.insert(tk.END, "✓ Signature match detected\n")
                    if result["heuristic_score"] > 0:
                        self.results_text.insert(tk.END, f"Heuristic score: {result['heuristic_score']}\n")
                        for finding in result["heuristic_findings"]:
                            self.results_text.insert(tk.END, f"  - {finding}\n")
                    self.results_text.insert(tk.END, "\n")
        else:
            # Single file results
            self.results_text.insert(tk.END, f"FILE: {results['file']}\n")
            self.results_text.insert(tk.END, f"MD5: {results['hash_md5']}\n")
            self.results_text.insert(tk.END, f"SHA256: {results['hash_sha256']}\n")
            self.results_text.insert(tk.END, f"STATUS: {results['status'].upper()}\n")
            
            if results["signature_detected"]:
                self.results_text.insert(tk.END, "✓ Signature match detected\n")
            
            if results["heuristic_score"] > 0:
                self.results_text.insert(tk.END, f"Heuristic score: {results['heuristic_score']}\n")
                for finding in results["heuristic_findings"]:
                    self.results_text.insert(tk.END, f"  - {finding}\n")
            
            if results["status"] != "clean":
                if messagebox.askyesno("Quarantine", "Move this file to quarantine?"):
                    if self.antivirus.quarantine_file(results["file"]):
                        self.results_text.insert(tk.END, "\nFile moved to quarantine\n")
    
    def toggle_monitoring(self):
        if self.monitor_var.get():
            self.antivirus.realtime_monitoring = True
            self.antivirus.start_realtime_monitoring("/")
            self.status_var.set("Real-time monitoring enabled")
        else:
            self.antivirus.realtime_monitoring = False
            self.status_var.set("Real-time monitoring disabled")

def main():
    """Main function with CLI interface"""
    if len(sys.argv) > 1:
        # CLI mode
        antivirus = KaliAntivirus()
        
        if sys.argv[1] == "scan":
            if len(sys.argv) > 2:
                path = sys.argv[2]
                if os.path.isfile(path):
                    result = antivirus.scan_file(path)
                    print(json.dumps(result, indent=2))
                elif os.path.isdir(path):
                    result = antivirus.scan_directory(path)
                    print(json.dumps(result, indent=2))
                else:
                    print("Path not found")
            else:
                print("Usage: pyantivirus_kali.py scan <file_or_directory>")
        
        elif sys.argv[1] == "monitor":
            print("Starting real-time monitoring...")
            antivirus.realtime_monitoring = True
            antivirus.start_realtime_monitoring("/")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
        
        else:
            print("Usage: pyantivirus_kali.py [scan|monitor] [path]")
    
    else:
        # GUI mode
        root = tk.Tk()
        app = AntivirusGUI(root)
        root.mainloop()

if __name__ == "__main__":
    # Check if running on Linux
    if os.name != 'posix':
        print("This antivirus is designed for Linux systems")
        sys.exit(1)
    
    # Check if running as root for certain operations
    if os.geteuid() != 0:
        print("Warning: Some features may require root privileges")
    
    main()

