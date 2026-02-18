#!/usr/bin/env python3
"""
Network Scanner GUI
Simple graphical interface for network scanning.
For authorized security testing only.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
from datetime import datetime
from network_scanner import NetworkScanner

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner - Authorized Testing Only")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔍 Network Scanner", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Disclaimer
        disclaimer = ttk.Label(main_frame, 
                              text="⚠️ For Authorized Security Testing Only",
                              foreground="red", font=('Arial', 10, 'bold'))
        disclaimer.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Target input
        ttk.Label(main_frame, text="Target:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(main_frame, width=40)
        self.target_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        self.target_entry.insert(0, "192.168.1.1")
        ttk.Label(main_frame, text="(IP or CIDR)").grid(row=2, column=2, sticky=tk.W, padx=5)
        
        # Port range
        ttk.Label(main_frame, text="Port Range:").grid(row=3, column=0, sticky=tk.W, pady=5)
        port_frame = ttk.Frame(main_frame)
        port_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.start_port = ttk.Entry(port_frame, width=10)
        self.start_port.pack(side=tk.LEFT)
        self.start_port.insert(0, "1")
        
        ttk.Label(port_frame, text=" to ").pack(side=tk.LEFT)
        
        self.end_port = ttk.Entry(port_frame, width=10)
        self.end_port.pack(side=tk.LEFT)
        self.end_port.insert(0, "1000")
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        self.banner_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Enable Banner Grabbing", 
                       variable=self.banner_var).pack(anchor=tk.W)
        
        timeout_frame = ttk.Frame(options_frame)
        timeout_frame.pack(anchor=tk.W, pady=5)
        ttk.Label(timeout_frame, text="Timeout (seconds):").pack(side=tk.LEFT)
        self.timeout_entry = ttk.Entry(timeout_frame, width=10)
        self.timeout_entry.pack(side=tk.LEFT, padx=5)
        self.timeout_entry.insert(0, "1.0")
        
        threads_frame = ttk.Frame(options_frame)
        threads_frame.pack(anchor=tk.W, pady=5)
        ttk.Label(threads_frame, text="Max Threads:").pack(side=tk.LEFT)
        self.threads_entry = ttk.Entry(threads_frame, width=10)
        self.threads_entry.pack(side=tk.LEFT, padx=5)
        self.threads_entry.insert(0, "100")
        
        # Output area
        output_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        output_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                     width=80, height=20, 
                                                     font=('Courier', 9))
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                      command=self.start_scan, width=15)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", 
                                      command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Output", 
                  command=self.clear_output, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Export JSON", 
                  command=self.export_json, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Exit", 
                  command=self.root.quit, width=15).pack(side=tk.LEFT, padx=5)
    
    def log(self, message):
        """Add message to output text."""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_output(self):
        """Clear the output text area."""
        self.output_text.delete(1.0, tk.END)
    
    def validate_inputs(self):
        """Validate user inputs."""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or CIDR range")
            return False
        
        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
            if start > end:
                raise ValueError("Start port must be <= end port")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port range: {e}")
            return False
        
        try:
            timeout = float(self.timeout_entry.get())
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout value")
            return False
        
        try:
            threads = int(self.threads_entry.get())
            if threads <= 0:
                raise ValueError("Threads must be positive")
        except ValueError:
            messagebox.showerror("Error", "Invalid thread count")
            return False
        
        return True
    
    def start_scan(self):
        """Start the network scan."""
        if not self.validate_inputs():
            return
        
        # Confirm authorization
        response = messagebox.askyesno(
            "Authorization Required",
            "Do you have authorization to scan this network?\n\n"
            "Unauthorized scanning may be illegal."
        )
        
        if not response:
            self.log("[!] Scan cancelled - Authorization required")
            return
        
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
    
    def run_scan(self):
        """Execute the scan (runs in separate thread)."""
        try:
            target = self.target_entry.get().strip()
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            timeout = float(self.timeout_entry.get())
            threads = int(self.threads_entry.get())
            grab_banners = self.banner_var.get()
            
            self.log(f"\n{'='*60}")
            self.log(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.log(f"Target: {target}")
            self.log(f"Port Range: {start_port}-{end_port}")
            self.log(f"{'='*60}\n")
            
            # Create scanner
            self.scanner = NetworkScanner(timeout=timeout, max_workers=threads)
            
            # Override display method to use GUI logging
            original_display = self.scanner.display_results
            self.scanner.display_results = lambda: self.display_gui_results()
            
            # Run scan
            import ipaddress
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            
            for ip in hosts:
                if not self.is_scanning:
                    self.log("\n[!] Scan stopped by user")
                    break
                
                result = self.scanner.scan_host(ip, (start_port, end_port), grab_banners)
                if result['alive']:
                    self.scanner.results.append(result)
                    self.log(f"[+] Found active host: {ip}")
            
            if self.is_scanning:
                self.display_gui_results()
                self.log(f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        except Exception as e:
            self.log(f"\n[!] Error during scan: {e}")
        
        finally:
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.is_scanning = False
    
    def display_gui_results(self):
        """Display results in GUI format."""
        if not self.scanner or not self.scanner.results:
            self.log("\n[!] No active hosts found")
            return
        
        self.log(f"\n{'='*60}")
        self.log("SCAN RESULTS")
        self.log(f"{'='*60}\n")
        
        for host in self.scanner.results:
            self.log(f"Host: {host['ip']}")
            self.log(f"Status: ALIVE")
            
            if host['open_ports']:
                self.log(f"Open Ports ({len(host['open_ports'])}):")
                for port_info in host['open_ports']:
                    banner = port_info['banner'][:30] if port_info['banner'] else 'N/A'
                    self.log(f"  {port_info['port']:<8} {port_info['service']:<20} {banner}")
            else:
                self.log("  No open ports found")
            self.log("")
    
    def stop_scan(self):
        """Stop the current scan."""
        self.is_scanning = False
        self.log("\n[!] Stopping scan...")
    
    def export_json(self):
        """Export results to JSON file."""
        if not self.scanner or not self.scanner.results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scanner.results, f, indent=2)
                self.log(f"\n[+] Results exported to {filename}")
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

def main():
    """Main function to run the GUI."""
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
