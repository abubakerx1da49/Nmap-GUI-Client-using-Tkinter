#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext

class NmapGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Nmap GUI - Made by @abubakerx1da49")
        self.geometry("750x700")
        self.create_widgets()

    def create_widgets(self):
        # -- Target Specification Frame --
        target_frame = tk.LabelFrame(self, text="Target Specification", padx=10, pady=10)
        target_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(target_frame, text="Target (hostname/IP):").grid(row=0, column=0, sticky="w")
        self.target_entry = tk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(target_frame, text="Input File (-iL):").grid(row=1, column=0, sticky="w")
        self.input_file_entry = tk.Entry(target_frame, width=40)
        self.input_file_entry.grid(row=1, column=1, padx=5, pady=2)

        # -- Host Discovery Options Frame --
        host_frame = tk.LabelFrame(self, text="Host Discovery", padx=10, pady=10)
        host_frame.pack(fill="x", padx=10, pady=5)

        self.sn_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-sn (Ping Scan)", variable=self.sn_var).grid(row=0, column=0, sticky="w", padx=5)
        self.sL_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-sL (List Scan)", variable=self.sL_var).grid(row=0, column=1, sticky="w", padx=5)
        self.Pn_var = tk.BooleanVar()
        tk.Checkbutton(host_frame, text="-Pn (Treat all hosts as online)", variable=self.Pn_var).grid(row=0, column=2, sticky="w", padx=5)

        # -- Scan Techniques Frame --
        scan_frame = tk.LabelFrame(self, text="Scan Techniques", padx=10, pady=10)
        scan_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(scan_frame, text="Scan Type:").grid(row=0, column=0, sticky="w")
        self.scan_type = tk.StringVar(value="-sS")
        scan_types = [
            "-sS (TCP SYN scan)",
            "-sT (TCP Connect scan)",
            "-sU (UDP scan)",
            "-sA (TCP ACK scan)"
        ]
        self.scan_combo = ttk.Combobox(scan_frame, values=scan_types, state="readonly", width=30)
        self.scan_combo.current(0)
        self.scan_combo.grid(row=0, column=1, padx=5, pady=2)

        # -- Port Specification Frame --
        port_frame = tk.LabelFrame(self, text="Port Specification", padx=10, pady=10)
        port_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(port_frame, text="Ports (-p):").grid(row=0, column=0, sticky="w")
        self.port_entry = tk.Entry(port_frame, width=20)
        self.port_entry.grid(row=0, column=1, padx=5, pady=2)

        # -- Service/Version & OS Detection Frame --
        service_frame = tk.LabelFrame(self, text="Service/Version & OS Detection", padx=10, pady=10)
        service_frame.pack(fill="x", padx=10, pady=5)

        self.sV_var = tk.BooleanVar()
        tk.Checkbutton(service_frame, text="-sV (Service/Version detection)", variable=self.sV_var).grid(row=0, column=0, sticky="w", padx=5)
        self.O_var = tk.BooleanVar()
        tk.Checkbutton(service_frame, text="-O (OS detection)", variable=self.O_var).grid(row=0, column=1, sticky="w", padx=5)

        # -- Script Scan Frame --
        script_frame = tk.LabelFrame(self, text="Script Scan", padx=10, pady=10)
        script_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(script_frame, text="Scripts (--script):").grid(row=0, column=0, sticky="w")
        self.script_entry = tk.Entry(script_frame, width=40)
        self.script_entry.grid(row=0, column=1, padx=5, pady=2)

        # -- Timing & Misc Frame --
        misc_frame = tk.LabelFrame(self, text="Timing and Miscellaneous Options", padx=10, pady=10)
        misc_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(misc_frame, text="Timing Template (-T0 to -T5):").grid(row=0, column=0, sticky="w")
        self.timing_entry = tk.Entry(misc_frame, width=5)
        self.timing_entry.grid(row=0, column=1, padx=5, pady=2)

        self.ipv6_var = tk.BooleanVar()
        tk.Checkbutton(misc_frame, text="-6 (IPv6)", variable=self.ipv6_var).grid(row=0, column=2, sticky="w", padx=5)

        # -- Custom Options Frame --
        custom_frame = tk.LabelFrame(self, text="Additional Custom Options", padx=10, pady=10)
        custom_frame.pack(fill="x", padx=10, pady=5)

        self.custom_entry = tk.Entry(custom_frame, width=70)
        self.custom_entry.grid(row=0, column=0, padx=5, pady=2)

        # -- Sudo Option Frame --
        sudo_frame = tk.Frame(self)
        sudo_frame.pack(fill="x", padx=10, pady=5)
        self.sudo_var = tk.BooleanVar()
        tk.Checkbutton(sudo_frame, text="Run with sudo", variable=self.sudo_var).pack(anchor="w")

        # -- Run Button --
        run_button = tk.Button(self, text="Run Nmap Scan", command=self.run_scan)
        run_button.pack(pady=10)

        # -- Output Text Area --
        output_frame = tk.LabelFrame(self, text="Output", padx=10, pady=10)
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(fill="both", expand=True)

    def run_scan(self):
        # Build the nmap command based on user input
        cmd = ["nmap"]

        # Target or input file
        target = self.target_entry.get().strip()
        input_file = self.input_file_entry.get().strip()
        if input_file:
            cmd += ["-iL", input_file]
        elif target:
            cmd.append(target)
        else:
            messagebox.showerror("Error", "Please specify a target or an input file!")
            return

        # Host Discovery Options
        if self.sn_var.get():
            cmd.append("-sn")
        if self.sL_var.get():
            cmd.append("-sL")
        if self.Pn_var.get():
            cmd.append("-Pn")

        # Scan Type
        scan_choice = self.scan_combo.get()
        if scan_choice.startswith("-sS"):
            cmd.append("-sS")
        elif scan_choice.startswith("-sT"):
            cmd.append("-sT")
        elif scan_choice.startswith("-sU"):
            cmd.append("-sU")
        elif scan_choice.startswith("-sA"):
            cmd.append("-sA")

        # Port Specification
        ports = self.port_entry.get().strip()
        if ports:
            cmd += ["-p", ports]

        # Service/Version detection
        if self.sV_var.get():
            cmd.append("-sV")

        # OS detection
        if self.O_var.get():
            cmd.append("-O")

        # Script Scan
        script_opts = self.script_entry.get().strip()
        if script_opts:
            cmd += ["--script", script_opts]

        # Timing Template
        timing = self.timing_entry.get().strip()
        if timing:
            cmd.append("-T" + timing)

        # IPv6
        if self.ipv6_var.get():
            cmd.append("-6")

        # Additional Custom Options
        custom_opts = self.custom_entry.get().strip()
        if custom_opts:
            # Split custom options by whitespace
            cmd += custom_opts.split()

        # If sudo is selected, adjust command accordingly
        if self.sudo_var.get():
            if os.geteuid() != 0:
                sudo_password = simpledialog.askstring("Sudo Password", "Enter sudo password:", show="*")
                if sudo_password is None:
                    messagebox.showerror("Error", "Sudo password is required!")
                    return
                cmd = ["sudo", "-S"] + cmd
                use_sudo = True
            else:
                use_sudo = False
        else:
            use_sudo = False

        # Debug: Print the command in the output area
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "Running command:\n" + " ".join(cmd) + "\n\n")

        # Run the command
        try:
            if use_sudo:
                # Provide the sudo password via stdin
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = process.communicate(sudo_password + "\n")
            else:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = process.communicate()

            # Display the output
            self.output_text.insert(tk.END, out)
            if err:
                self.output_text.insert(tk.END, "\nErrors:\n" + err)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{e}")

if __name__ == "__main__":
    app = NmapGUI()
    app.mainloop()
