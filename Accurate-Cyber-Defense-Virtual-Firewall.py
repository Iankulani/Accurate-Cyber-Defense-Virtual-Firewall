import sys
import socket
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import platform
import subprocess
import requests
import json
from datetime import datetime
import psutil
import netifaces
import queue
import os
from collections import defaultdict

class VirtualFirewall:
    def __init__(self):
        self.monitored_ips = set()
        self.traffic_data = defaultdict(lambda: {'in': 0, 'out': 0, 'timestamps': []})
        self.running = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.alert_threshold = 1000  # KB threshold for alerts
        self.log_queue = queue.Queue()
        
    def start_monitoring(self, ip):
        """Start monitoring a specific IP address"""
        if ip not in self.monitored_ips:
            self.monitored_ips.add(ip)
            self.log(f"Started monitoring IP: {ip}")
            return True
        return False
    
    def stop_monitoring(self, ip):
        """Stop monitoring a specific IP address"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.log(f"Stopped monitoring IP: {ip}")
            return True
        return False
    
    def ping(self, ip):
        """Ping an IP address to check connectivity"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def traceroute(self, ip):
        """Perform a traceroute to an IP address"""
        param = '-d' if platform.system().lower() == 'windows' else ''
        command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        return netifaces.interfaces()
    
    def monitor_traffic(self):
        """Monitor network traffic for the tracked IPs"""
        old_stats = psutil.net_io_counters(pernic=True)
        
        while self.running:
            time.sleep(5)  # Check every 5 seconds
            new_stats = psutil.net_io_counters(pernic=True)
            
            for interface in new_stats:
                if interface in old_stats:
                    bytes_sent = new_stats[interface].bytes_sent - old_stats[interface].bytes_sent
                    bytes_recv = new_stats[interface].bytes_recv - old_stats[interface].bytes_recv
                    
                    # Convert to KB
                    kb_sent = bytes_sent / 1024
                    kb_recv = bytes_recv / 1024
                    
                    # Log traffic for each monitored IP (simplified - in real app you'd track per IP)
                    for ip in self.monitored_ips:
                        self.traffic_data[ip]['in'] += kb_recv
                        self.traffic_data[ip]['out'] += kb_sent
                        self.traffic_data[ip]['timestamps'].append(datetime.now())
                        
                        # Check for threshold alerts
                        if kb_recv > self.alert_threshold or kb_sent > self.alert_threshold:
                            alert_msg = f"ALERT: High traffic detected for {ip} - In: {kb_recv:.2f}KB, Out: {kb_sent:.2f}KB"
                            self.log(alert_msg)
                            if self.telegram_token and self.telegram_chat_id:
                                self.send_telegram_alert(alert_msg)
            
            old_stats = new_stats
    
    def send_telegram_alert(self, message):
        """Send alert via Telegram"""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        data = {
            "chat_id": self.telegram_chat_id,
            "text": message
        }
        try:
            requests.post(url, data=data)
        except Exception as e:
            self.log(f"Failed to send Telegram alert: {str(e)}")
    
    def get_status(self):
        """Get current firewall status"""
        status = {
            'monitored_ips': list(self.monitored_ips),
            'telegram_configured': bool(self.telegram_token and self.telegram_chat_id),
            'is_running': self.running,
            'alert_threshold': self.alert_threshold
        }
        return status
    
    def log(self, message):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.log_queue.put(log_message)
    
    def clear_logs(self):
        """Clear the log queue"""
        while not self.log_queue.empty():
            self.log_queue.get()
    
    def generate_traffic_report(self, ip):
        """Generate traffic report for a specific IP"""
        if ip in self.traffic_data:
            return {
                'ip': ip,
                'total_in_kb': self.traffic_data[ip]['in'],
                'total_out_kb': self.traffic_data[ip]['out'],
                'last_updated': self.traffic_data[ip]['timestamps'][-1] if self.traffic_data[ip]['timestamps'] else None
            }
        return None

class FirewallCLI:
    def __init__(self, firewall):
        self.firewall = firewall
        self.running = True
        self.commands = {
            'help': self.show_help,
            'ping': self.ping_ip,
            'start': self.start_monitoring,
            'stop': self.stop_monitoring,
            'exit': self.exit_cli,
            'clear': self.clear_screen,
            'view': self.view_data,
            'status': self.show_status,
            'traceroute': self.trace_route,
            'add': self.add_ip,
            'remove': self.remove_ip,
            'config': self.config_telegram,
            'dashboard': self.launch_gui
        }
    
    def run(self):
        print("Accurate Cyber Defense Virtual Firewall CLI - Type 'help' for commands")
        while self.running:
            try:
                user_input = input("firewall> ").strip().split()
                if not user_input:
                    continue
                
                command = user_input[0].lower()
                args = user_input[1:]
                
                if command in self.commands:
                    self.commands[command](args)
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
            except Exception as e:
                print(f"Error: {str(e)}")
    
    def show_help(self, args):
        """Display help information"""
        print("\nAvailable Commands:")
        print("  help - Show this help message")
        print("  ping <ip> - Ping an IP address")
        print("  start <ip> - Start monitoring an IP")
        print("  stop <ip> - Stop monitoring an IP")
        print("  exit - Exit the CLI")
        print("  clear - Clear the screen")
        print("  view - View collected data")
        print("  status - Show firewall status")
        print("  traceroute <ip> - Perform a traceroute")
        print("  add <ip> - Add an IP to monitor")
        print("  remove <ip> - Remove an IP from monitoring")
        print("  config telegram <token> <chat_id> - Configure Telegram alerts")
        print("  dashboard - Launch the GUI dashboard\n")
    
    def ping_ip(self, args):
        """Ping an IP address"""
        if len(args) != 1:
            print("Usage: ping <ip>")
            return
        
        ip = args[0]
        print(f"Pinging {ip}...")
        result = self.firewall.ping(ip)
        print(result)
    
    def start_monitoring(self, args):
        """Start monitoring an IP"""
        if len(args) != 1:
            print("Usage: start <ip>")
            return
        
        ip = args[0]
        if self.firewall.start_monitoring(ip):
            print(f"Started monitoring {ip}")
        else:
            print(f"Already monitoring {ip}")
    
    def stop_monitoring(self, args):
        """Stop monitoring an IP"""
        if len(args) != 1:
            print("Usage: stop <ip>")
            return
        
        ip = args[0]
        if self.firewall.stop_monitoring(ip):
            print(f"Stopped monitoring {ip}")
        else:
            print(f"Was not monitoring {ip}")
    
    def exit_cli(self, args):
        """Exit the CLI"""
        self.running = False
        print("Exiting Virtual Firewall CLI...")
    
    def clear_screen(self, args):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def view_data(self, args):
        """View collected data"""
        if not self.firewall.monitored_ips:
            print("No IPs being monitored")
            return
        
        print("\nMonitored IPs and Traffic Data:")
        for ip in self.firewall.monitored_ips:
            report = self.firewall.generate_traffic_report(ip)
            if report:
                print(f"\nIP: {report['ip']}")
                print(f"  Total In: {report['total_in_kb']:.2f} KB")
                print(f"  Total Out: {report['total_out_kb']:.2f} KB")
                print(f"  Last Updated: {report['last_updated']}")
    
    def show_status(self, args):
        """Show firewall status"""
        status = self.firewall.get_status()
        print("\nFirewall Status:")
        print(f"Running: {'Yes' if status['is_running'] else 'No'}")
        print(f"Telegram Alerts: {'Configured' if status['telegram_configured'] else 'Not Configured'}")
        print(f"Alert Threshold: {status['alert_threshold']} KB")
        print("\nMonitored IPs:")
        for ip in status['monitored_ips']:
            print(f"  {ip}")
    
    def trace_route(self, args):
        """Perform a traceroute"""
        if len(args) != 1:
            print("Usage: traceroute <ip>")
            return
        
        ip = args[0]
        print(f"Tracing route to {ip}...")
        result = self.firewall.traceroute(ip)
        print(result)
    
    def add_ip(self, args):
        """Add an IP to monitor"""
        if len(args) != 1:
            print("Usage: add <ip>")
            return
        
        ip = args[0]
        self.firewall.start_monitoring(ip)
        print(f"Added and started monitoring {ip}")
    
    def remove_ip(self, args):
        """Remove an IP from monitoring"""
        if len(args) != 1:
            print("Usage: remove <ip>")
            return
        
        ip = args[0]
        self.firewall.stop_monitoring(ip)
        print(f"Removed and stopped monitoring {ip}")
    
    def config_telegram(self, args):
        """Configure Telegram alerts"""
        if len(args) < 3 or args[0].lower() != 'telegram':
            print("Usage: config telegram <token> <chat_id>")
            return
        
        token = args[1]
        chat_id = args[2]
        self.firewall.telegram_token = token
        self.firewall.telegram_chat_id = chat_id
        print("Telegram alerts configured successfully")
    
    def launch_gui(self, args):
        """Launch the GUI dashboard"""
        print("Launching GUI dashboard...")
        root = tk.Tk()
        app = FirewallGUI(root, self.firewall)
        root.mainloop()

class FirewallGUI:
    def __init__(self, root, firewall):
        self.root = root
        self.firewall = firewall
        self.root.title("Virtual Firewall Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c001e')
        
        # Apply red theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#2c001e', foreground='white')
        style.configure('TFrame', background='#2c001e')
        style.configure('TLabel', background='#2c001e', foreground='white')
        style.configure('TButton', background='#cc0000', foreground='white')
        style.configure('TEntry', fieldbackground='#4a4a4a', foreground='white')
        style.configure('TCombobox', fieldbackground='#4a4a4a', foreground='white')
        style.configure('TNotebook', background='#2c001e')
        style.configure('TNotebook.Tab', background='#cc0000', foreground='white')
        style.map('TButton', background=[('active', '#ff3333')])
        
        self.create_menu()
        self.create_main_frame()
        
        # Start monitoring thread if not already running
        if not self.firewall.running:
            self.firewall.running = True
            monitor_thread = threading.Thread(target=self.firewall.monitor_traffic, daemon=True)
            monitor_thread.start()
        
        # Start log updater
        self.update_logs()
    
    def create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_tool)
        tools_menu.add_command(label="Network Interfaces", command=self.show_network_interfaces)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Traffic Charts", command=self.show_traffic_charts)
        view_menu.add_command(label="Firewall Status", command=self.show_status)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_main_frame(self):
        """Create the main application frame"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # IP Monitoring frame
        ip_frame = ttk.LabelFrame(self.dashboard_frame, text="IP Monitoring")
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(ip_frame, text="Add IP", command=self.add_ip).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(ip_frame, text="Remove IP", command=self.remove_ip).grid(row=0, column=3, padx=5, pady=5)
        ttk.Button(ip_frame, text="Ping IP", command=self.ping_ip_gui).grid(row=0, column=4, padx=5, pady=5)
        
        # Monitored IPs list
        self.monitored_list = tk.Listbox(ip_frame, height=5, bg='#4a4a4a', fg='white')
        self.monitored_list.grid(row=1, column=0, columnspan=5, sticky='ew', padx=5, pady=5)
        self.update_monitored_list()
        
        # Telegram Configuration frame
        telegram_frame = ttk.LabelFrame(self.dashboard_frame, text="Telegram Alerts")
        telegram_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(telegram_frame, text="Token:").grid(row=0, column=0, padx=5, pady=5)
        self.token_entry = ttk.Entry(telegram_frame)
        self.token_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(telegram_frame, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5)
        self.chat_id_entry = ttk.Entry(telegram_frame)
        self.chat_id_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Button(telegram_frame, text="Save", command=self.save_telegram_config).grid(row=1, column=2, padx=5, pady=5)
        
        # Logs frame
        log_frame = ttk.LabelFrame(self.dashboard_frame, text="Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, bg='#4a4a4a', fg='white')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def update_monitored_list(self):
        """Update the list of monitored IPs"""
        self.monitored_list.delete(0, tk.END)
        for ip in self.firewall.monitored_ips:
            self.monitored_list.insert(tk.END, ip)
    
    def add_ip(self):
        """Add an IP to monitor"""
        ip = self.ip_entry.get().strip()
        if ip:
            if self.firewall.start_monitoring(ip):
                self.update_monitored_list()
                self.ip_entry.delete(0, tk.END)
                self.firewall.log(f"Added IP to monitoring: {ip}")
            else:
                messagebox.showwarning("Warning", f"Already monitoring {ip}")
    
    def remove_ip(self):
        """Remove an IP from monitoring"""
        selection = self.monitored_list.curselection()
        if selection:
            ip = self.monitored_list.get(selection[0])
            if self.firewall.stop_monitoring(ip):
                self.update_monitored_list()
                self.firewall.log(f"Removed IP from monitoring: {ip}")
    
    def ping_ip_gui(self):
        """Ping an IP from the GUI"""
        ip = self.ip_entry.get().strip()
        if ip:
            result = self.firewall.ping(ip)
            self.show_result_dialog("Ping Results", result)
    
    def save_telegram_config(self):
        """Save Telegram configuration"""
        token = self.token_entry.get().strip()
        chat_id = self.chat_id_entry.get().strip()
        
        if token and chat_id:
            self.firewall.telegram_token = token
            self.firewall.telegram_chat_id = chat_id
            self.firewall.log("Telegram alert configuration updated")
            messagebox.showinfo("Success", "Telegram configuration saved")
    
    def clear_logs(self):
        """Clear the logs"""
        self.firewall.clear_logs()
        self.log_text.delete(1.0, tk.END)
    
    def update_logs(self):
        """Update the log display"""
        while not self.firewall.log_queue.empty():
            log_message = self.firewall.log_queue.get()
            self.log_text.insert(tk.END, log_message + "\n")
            self.log_text.see(tk.END)
        
        self.root.after(1000, self.update_logs)
    
    def show_ping_tool(self):
        """Show the ping tool dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping Tool")
        dialog.geometry("500x400")
        dialog.configure(bg='#2c001e')
        
        ttk.Label(dialog, text="Enter IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        result_text = scrolledtext.ScrolledText(dialog, height=15, bg='#4a4a4a', fg='white')
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def do_ping():
            ip = ip_entry.get().strip()
            if ip:
                result = self.firewall.ping(ip)
                result_text.insert(tk.END, result + "\n")
                result_text.see(tk.END)
        
        ttk.Button(dialog, text="Ping", command=do_ping).pack(pady=5)
    
    def show_traceroute_tool(self):
        """Show the traceroute tool dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Traceroute Tool")
        dialog.geometry("500x400")
        dialog.configure(bg='#2c001e')
        
        ttk.Label(dialog, text="Enter IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        result_text = scrolledtext.ScrolledText(dialog, height=15, bg='#4a4a4a', fg='white')
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def do_traceroute():
            ip = ip_entry.get().strip()
            if ip:
                result = self.firewall.traceroute(ip)
                result_text.insert(tk.END, result + "\n")
                result_text.see(tk.END)
        
        ttk.Button(dialog, text="Traceroute", command=do_traceroute).pack(pady=5)
    
    def show_network_interfaces(self):
        """Show network interfaces dialog"""
        interfaces = self.firewall.get_network_interfaces()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Network Interfaces")
        dialog.geometry("400x300")
        dialog.configure(bg='#2c001e')
        
        listbox = tk.Listbox(dialog, bg='#4a4a4a', fg='white')
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for interface in interfaces:
            listbox.insert(tk.END, interface)
    
    def show_traffic_charts(self):
        """Show traffic data charts"""
        if not self.firewall.monitored_ips:
            messagebox.showwarning("Warning", "No IPs being monitored")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Traffic Charts")
        dialog.geometry("800x600")
        dialog.configure(bg='#2c001e')
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Pie chart tab
        pie_frame = ttk.Frame(notebook)
        notebook.add(pie_frame, text="Traffic Distribution")
        
        fig, ax = plt.subplots(figsize=(6, 4), facecolor='#2c001e')
        fig.patch.set_facecolor('#2c001e')
        
        ips = list(self.firewall.monitored_ips)
        in_traffic = [self.firewall.traffic_data[ip]['in'] for ip in ips]
        out_traffic = [self.firewall.traffic_data[ip]['out'] for ip in ips]
        
        ax.pie(in_traffic, labels=ips, autopct='%1.1f%%', startangle=90)
        ax.set_title('Inbound Traffic Distribution', color='white')
        
        for text in ax.texts:
            text.set_color('white')
        
        canvas = FigureCanvasTkAgg(fig, master=pie_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Bar chart tab
        bar_frame = ttk.Frame(notebook)
        notebook.add(bar_frame, text="Traffic Comparison")
        
        fig2, ax2 = plt.subplots(figsize=(6, 4), facecolor='#2c001e')
        fig2.patch.set_facecolor('#2c001e')
        
        x = range(len(ips))
        width = 0.35
        
        ax2.bar(x, in_traffic, width, label='Inbound', color='#cc0000')
        ax2.bar([p + width for p in x], out_traffic, width, label='Outbound', color='#ff6666')
        
        ax2.set_xticks([p + width/2 for p in x])
        ax2.set_xticklabels(ips, color='white')
        ax2.set_ylabel('Traffic (KB)', color='white')
        ax2.set_title('Inbound vs Outbound Traffic', color='white')
        ax2.legend()
        
        ax2.tick_params(colors='white')
        ax2.set_facecolor('#2c001e')
        
        for spine in ax2.spines.values():
            spine.set_color('white')
        
        canvas2 = FigureCanvasTkAgg(fig2, master=bar_frame)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def show_status(self):
        """Show firewall status dialog"""
        status = self.firewall.get_status()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Firewall Status")
        dialog.geometry("400x300")
        dialog.configure(bg='#2c001e')
        
        frame = ttk.Frame(dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Firewall Status:").grid(row=0, column=0, sticky='w', pady=5)
        ttk.Label(frame, text="Running" if status['is_running'] else "Stopped").grid(row=0, column=1, sticky='w', pady=5)
        
        ttk.Label(frame, text="Telegram Alerts:").grid(row=1, column=0, sticky='w', pady=5)
        ttk.Label(frame, text="Configured" if status['telegram_configured'] else "Not Configured").grid(row=1, column=1, sticky='w', pady=5)
        
        ttk.Label(frame, text="Alert Threshold:").grid(row=2, column=0, sticky='w', pady=5)
        ttk.Label(frame, text=f"{status['alert_threshold']} KB").grid(row=2, column=1, sticky='w', pady=5)
        
        ttk.Label(frame, text="Monitored IPs:").grid(row=3, column=0, sticky='nw', pady=5)
        
        ip_frame = ttk.Frame(frame)
        ip_frame.grid(row=3, column=1, sticky='w')
        
        for ip in status['monitored_ips']:
            ttk.Label(ip_frame, text=ip).pack(anchor='w')
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", "Accurate Cyber Defense Virtual Firewall Cybersecurity Tool\nVersion 1.0\n\nA comprehensive network monitoring solution")
    
    def show_result_dialog(self, title, message):
        """Show a dialog with results"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("600x400")
        dialog.configure(bg='#2c001e')
        
        text = scrolledtext.ScrolledText(dialog, bg='#4a4a4a', fg='white')
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, message)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)

def main():
    firewall = VirtualFirewall()
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'cli':
        cli = FirewallCLI(firewall)
        cli.run()
    else:
        root = tk.Tk()
        app = FirewallGUI(root, firewall)
        root.mainloop()
        
        # Stop monitoring when GUI closes
        firewall.running = False

if __name__ == "__main__":
    main()