import tkinter as tk
from tkinter import messagebox, Toplevel
from tkinter import ttk  # For modern themed widgets
import random
import string
import time
import threading
from datetime import datetime, timedelta
import logging
import json  # For saving device data to a file
import hashlib
import os
from ping3 import ping  # For pinging devices
from scapy.all import ARP, Ether, srp  # For real-time IP scanning
import socket  # To get the local IP

# Set up logging with file rotation
LOG_FILE = 'iot_management.log'
MAX_LOG_SIZE = 1024 * 1024  # 1 MB
DEVICE_DATA_FILE = 'device_data.json'
USERS_FILE = 'users.json'

def setup_logging():
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= MAX_LOG_SIZE:
        base, ext = os.path.splitext(LOG_FILE)
        os.rename(LOG_FILE, f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}")

    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                        format='%(asctime)s - %(levelname)s - %(message)s')

setup_logging()

# Function to hash passwords (Same for both admin and device passwords)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Device class representing an IoT device
class Device:
    def __init__(self, name, model, role, firmware_version, status='Offline'):
        self.name = name
        self.model = model
        self.role = role
        self.firmware_version = firmware_version
        self.status = status

class IoTManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IoTPULSE")
        self.is_authenticated = False
        self.user_role = None  # Will be set after login
        self.network_devices = []  # Initialize device list
        self.load_devices()  # Load devices at startup
        self.style = ttk.Style()
        self.theme = 'default'  # Starting theme
        self.apply_theme(self.theme)
        self.inactivity_timeout = timedelta(minutes=5)  # Admin session timeout: 5 minutes
        self.last_activity_time = datetime.now()
        self.check_inactivity()
        self.load_users()  # Load users from the file
        self.show_login_screen()

    # Check for inactivity and log out after timeout
    def check_inactivity(self):
        if self.is_authenticated and datetime.now() - self.last_activity_time > self.inactivity_timeout:
            self.logout_admin()
        self.root.after(60000, self.check_inactivity)  # Check every 60 seconds

    # Method to apply the selected theme
    def apply_theme(self, theme_name):
        self.style.theme_use(theme_name)
        if theme_name == 'default':
            self.root.configure(bg='#f0f0f0')
        else:
            self.root.configure(bg='#2e2e2e')

    # Method to save devices to a JSON file
    def save_devices(self):
        with open(DEVICE_DATA_FILE, 'w') as file:
            json.dump([device.__dict__ for device in self.network_devices], file)
        logging.info("Device data saved.")

    # Method to load devices from a JSON file
    def load_devices(self):
        if os.path.exists(DEVICE_DATA_FILE):
            with open(DEVICE_DATA_FILE, 'r') as file:
                devices_data = json.load(file)
                self.network_devices = [Device(**device) for device in devices_data]
            logging.info("Device data loaded.")

    # Load users from a JSON file
    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as file:
                self.users = json.load(file)
        else:
            # Initial setup with only admin user if no file exists
            self.users = {
                'admin': {'password': hash_password('admin123'), 'role': 'admin'}
            }
            self.save_users()

    # Save users to a JSON file
    def save_users(self):
        with open(USERS_FILE, 'w') as file:
            json.dump(self.users, file)

    # Admin login screen
    def show_login_screen(self):
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(self.login_frame, text="Admin Login", font=("Helvetica", 20, "bold"))
        title.grid(row=0, columnspan=2, pady=20)

        ttk.Label(self.login_frame, text="Username:", font=("Helvetica", 12)).grid(row=1, column=0, sticky="e", pady=10)
        self.username_entry = ttk.Entry(self.login_frame, font=("Helvetica", 12))
        self.username_entry.grid(row=1, column=1, pady=10)

        ttk.Label(self.login_frame, text="Password:", font=("Helvetica", 12)).grid(row=2, column=0, sticky="e", pady=10)
        self.password_entry = ttk.Entry(self.login_frame, font=("Helvetica", 12), show="*")
        self.password_entry.grid(row=2, column=1, pady=10)

        login_button = ttk.Button(self.login_frame, text="Login", command=self.authenticate)
        login_button.grid(row=3, columnspan=2, pady=20)

        # Center the login frame
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - self.login_frame.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - self.login_frame.winfo_height()) // 3
        self.root.geometry(f"+{x}+{y}")

    # Authentication logic
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.users and hash_password(password) == self.users[username]['password']:
            self.is_authenticated = True
            self.user_role = self.users[username]['role']  # Set the role (admin or user)
            self.last_activity_time = datetime.now()  # Update last activity time
            logging.info(f"{username} ({self.user_role}) logged in.")
            messagebox.showinfo("Success", "Login Successful!")
            self.login_frame.destroy()
            self.create_main_layout()  # Load the main app layout after successful login
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            messagebox.showerror("Error", "Invalid username or password!")

    # Admin logout due to inactivity
    def logout_admin(self):
        self.is_authenticated = False
        messagebox.showinfo("Session Timeout", "You have been logged out due to inactivity.")
        logging.info(f"Admin session logged out due to inactivity.")
        self.main_frame.destroy()
        self.show_login_screen()

    # Main system interface (only accessible after login)
    def create_main_layout(self):
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(self.main_frame, text="IoT Management System", font=("Helvetica", 20, "bold"))
        title.grid(row=0, columnspan=3, pady=20)

        # Dashboard and log-in device features are available for both roles
        dashboard_button = ttk.Button(self.main_frame, text="View Device Dashboard", command=self.view_dashboard)
        dashboard_button.grid(row=1, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)
        CreateToolTip(dashboard_button, "View the dashboard with all devices.")

        login_button = ttk.Button(self.main_frame, text="Login to Device", command=self.login_to_device)
        login_button.grid(row=2, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)
        CreateToolTip(login_button, "Log in to a device to perform actions.")

        # Admin features are restricted based on roles
        if self.user_role == 'admin':
            add_button = ttk.Button(self.main_frame, text="Add Device", command=self.add_device)
            add_button.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
            CreateToolTip(add_button, "Add a new device to the network.")

            remove_button = ttk.Button(self.main_frame, text="Remove Device", command=self.remove_device)
            remove_button.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")
            CreateToolTip(remove_button, "Remove an existing device from the network.")

            modify_button = ttk.Button(self.main_frame, text="Modify Device Role", command=self.modify_role)
            modify_button.grid(row=4, column=0, padx=10, pady=10, sticky="nsew")
            CreateToolTip(modify_button, "Change the role of a device.")

        # Network Scan Button
        scan_button = ttk.Button(self.main_frame, text="Scan Network", command=self.scan_network)
        scan_button.grid(row=5, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)
        CreateToolTip(scan_button, "Scan the network for devices.")

        exit_button = ttk.Button(self.main_frame, text="Exit", command=self.root.quit)
        exit_button.grid(row=6, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)
        CreateToolTip(exit_button, "Exit the application.")

        # Make the grid expand with window resizing
        for i in range(2):
            self.main_frame.columnconfigure(i, weight=1)
        for i in range(8):
            self.main_frame.rowconfigure(i, weight=1)

    # Method to display the dashboard with color-coded device statuses
    def view_dashboard(self):
        self.last_activity_time = datetime.now()  # Update last activity time
        dashboard_window = Toplevel(self.root)
        dashboard_window.title("Device Dashboard")
        dashboard_window.geometry("800x600")
        self.style.configure('Treeview', rowheight=30)  # Adjust row height for readability
        self.device_tree = ttk.Treeview(dashboard_window, columns=('Name', 'Model', 'Status', 'Role', 'Firmware Version'), show='headings')
        self.device_tree.heading('Name', text='Name')
        self.device_tree.heading('Model', text='Model')
        self.device_tree.heading('Status', text='Status')
        self.device_tree.heading('Role', text='Role')
        self.device_tree.heading('Firmware Version', text='Firmware Version')
        self.device_tree.pack(fill=tk.BOTH, expand=True)

        # Load devices and populate the dashboard
        for device in self.network_devices:
            status_color = '#28a745' if device.status == 'Online' else '#dc3545'  # Green for online, red for offline
            self.device_tree.insert('', 'end', values=(device.name, device.model, device.status, device.role, device.firmware_version))

    # Method to scan the network for devices in real time using ARP scanning
    def scan_network(self):
        self.last_activity_time = datetime.now()  # Update last activity time
        scan_window = Toplevel(self.root)
        scan_window.title("Network Scan")

        scan_label = ttk.Label(scan_window, text="Scanning network, please wait...")
        scan_label.pack(pady=20)

        # Create a Treeview to display the scanned devices
        self.scan_tree = ttk.Treeview(scan_window, columns=('IP Address', 'MAC Address', 'Status'), show='headings')
        self.scan_tree.heading('IP Address', text='IP Address')
        self.scan_tree.heading('MAC Address', text='MAC Address')
        self.scan_tree.heading('Status', text='Status')
        self.scan_tree.pack(fill=tk.BOTH, expand=True)

        # Perform the network scan in a separate thread to avoid blocking the UI
        scan_thread = threading.Thread(target=self.perform_network_scan)
        scan_thread.start()

    # Get the local IP range
    def get_local_ip_range(self):
        """Get the local IP range based on the machine's current IP."""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return network_prefix

    # Perform network scan using ARP
    def perform_network_scan(self):
        ip_range = self.get_local_ip_range()
        arp_request = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request

        # Send the packet and capture the response
        result = srp(packet, timeout=2, verbose=0)[0]

        # Process the response and update the scan_tree widget
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            self.add_scanned_device(ip, mac, "Online")

    # Add scanned devices to the Treeview
    def add_scanned_device(self, ip_address, mac_address, status):
        # Insert the scanned device into the Treeview on the scan window
        self.scan_tree.insert('', 'end', values=(ip_address, mac_address, status))

    # Adding a device
    def add_device(self):
        self.last_activity_time = datetime.now()  # Update last activity time

        # Create a dialog for adding a device
        add_window = Toplevel(self.root)
        add_window.title("Add Device")

        # Labels and Entries for device details
        ttk.Label(add_window, text="Device Name:").grid(row=0, column=0, padx=10, pady=5)
        name_entry = ttk.Entry(add_window)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="Model:").grid(row=1, column=0, padx=10, pady=5)
        model_entry = ttk.Entry(add_window)
        model_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="Role:").grid(row=2, column=0, padx=10, pady=5)
        role_entry = ttk.Entry(add_window)
        role_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="Firmware Version:").grid(row=3, column=0, padx=10, pady=5)
        firmware_entry = ttk.Entry(add_window)
        firmware_entry.grid(row=3, column=1, padx=10, pady=5)

        def add_to_network():
            # Get the values from the entries
            name = name_entry.get()
            model = model_entry.get()
            role = role_entry.get()
            firmware_version = firmware_entry.get()

            if name and model and role and firmware_version:
                # Check for duplicate device names
                if any(device.name == name for device in self.network_devices):
                    messagebox.showerror("Error", "A device with this name already exists.")
                    return

                # Create a new device and add it to the network
                new_device = Device(name, model, role, firmware_version, status="Online")
                self.network_devices.append(new_device)
                self.save_devices()  # Save the updated device list
                logging.info(f"Device {name} added to the network.")
                messagebox.showinfo("Success", "Device added successfully.")
                add_window.destroy()
                self.view_dashboard()  # Refresh the dashboard
            else:
                messagebox.showerror("Error", "All fields are required.")

        # Add Button
        ttk.Button(add_window, text="Add Device", command=add_to_network).grid(row=4, columnspan=2, pady=10)

    # Removing a device
    def remove_device(self):
        self.last_activity_time = datetime.now()  # Update last activity time

        if not self.network_devices:
            messagebox.showinfo("Info", "No devices to remove.")
            return

        # Create a dialog for removing a device
        remove_window = Toplevel(self.root)
        remove_window.title("Remove Device")

        # List of device names
        device_names = [device.name for device in self.network_devices]

        ttk.Label(remove_window, text="Select Device to Remove:").grid(row=0, column=0, padx=10, pady=5)
        device_var = tk.StringVar(value=device_names[0])
        device_menu = ttk.OptionMenu(remove_window, device_var, device_names[0], *device_names)
        device_menu.grid(row=0, column=1, padx=10, pady=5)

        def remove_selected_device():
            selected_device_name = device_var.get()
            for device in self.network_devices:
                if device.name == selected_device_name:
                    self.network_devices.remove(device)
                    self.save_devices()  # Save the updated device list
                    logging.info(f"Device {selected_device_name} removed from the network.")
                    messagebox.showinfo("Success", f"Device {selected_device_name} removed.")
                    remove_window.destroy()
                    self.view_dashboard()  # Refresh the dashboard
                    return

        # Remove Button
        ttk.Button(remove_window, text="Remove Device", command=remove_selected_device).grid(row=1, columnspan=2, pady=10)

    # Modifying device role
    def modify_role(self):
        self.last_activity_time = datetime.now()  # Update last activity time

        if not self.network_devices:
            messagebox.showinfo("Info", "No devices to modify.")
            return

        modify_window = Toplevel(self.root)
        modify_window.title("Modify Device Role")

        device_names = [device.name for device in self.network_devices]

        ttk.Label(modify_window, text="Select Device:").grid(row=0, column=0, padx=10, pady=5)
        device_var = tk.StringVar(value=device_names[0])
        device_menu = ttk.OptionMenu(modify_window, device_var, device_names[0], *device_names)
        device_menu.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(modify_window, text="New Role:").grid(row=1, column=0, padx=10, pady=5)
        role_entry = ttk.Entry(modify_window)
        role_entry.grid(row=1, column=1, padx=10, pady=5)

        def modify_device_role():
            selected_device_name = device_var.get()
            new_role = role_entry.get()
            if new_role:
                for device in self.network_devices:
                    if device.name == selected_device_name:
                        device.role = new_role
                        self.save_devices()  # Save the updated device list
                        logging.info(f"Device {selected_device_name} role changed to {new_role}.")
                        messagebox.showinfo("Success", f"Role for {selected_device_name} modified to {new_role}.")
                        modify_window.destroy()
                        self.view_dashboard()  # Refresh the dashboard
                        return
            else:
                messagebox.showerror("Error", "Role field cannot be empty.")

        # Modify Button
        ttk.Button(modify_window, text="Modify Role", command=modify_device_role).grid(row=2, columnspan=2, pady=10)

    # Simulate login to a device
    def login_to_device(self):
        self.last_activity_time = datetime.now()  # Update last activity time

        if not self.network_devices:
            messagebox.showinfo("Info", "No devices to log into.")
            return

        login_window = Toplevel(self.root)
        login_window.title("Login to Device")

        device_names = [device.name for device in self.network_devices]

        ttk.Label(login_window, text="Select Device:").grid(row=0, column=0, padx=10, pady=5)
        device_var = tk.StringVar(value=device_names[0])
        device_menu = ttk.OptionMenu(login_window, device_var, device_names[0], *device_names)
        device_menu.grid(row=0, column=1, padx=10, pady=5)

        def login_device():
            selected_device_name = device_var.get()
            messagebox.showinfo("Login", f"Logged into {selected_device_name}.")
            logging.info(f"Logged into device {selected_device_name}.")
            login_window.destroy()

        # Login Button
        ttk.Button(login_window, text="Login", command=login_device).grid(row=1, columnspan=2, pady=10)

# Tooltip class to provide hints for buttons
class CreateToolTip(object):
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(tw, text=self.text, background="#ffffe0", relief='solid', borderwidth=1)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

# Main Application
if __name__ == "__main__":
    root = tk.Tk()
    app = IoTManagementApp(root)
    root.mainloop()
