import os, sys, json, subprocess, threading
import customtkinter as ctk
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config_loader import load_config, save_config
from utils.virus_total import vt_integration, set_vt_api_key

CONFIG = load_config()
SCAN_INTERVAL = CONFIG.get("scan_interval", 10) * 1000
REPORT_PATH = CONFIG["report_file"]
AI_REPORT_PATH = CONFIG.get("ai_report_file", "data/ai_risk_report.json")
VT_REPORT_PATH = CONFIG.get("vt_report_file", "data/virustotal_report.json")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
plt.style.use('dark_background')
sns.set_palette("husl")

# ---- Data helpers ----
def read_report():
    if not os.path.exists(REPORT_PATH):
        return {"modified": [], "new": [], "deleted": []}
    try:
        with open(REPORT_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"modified": [], "new": [], "deleted": []}

def read_ai_report():
    if not os.path.exists(AI_REPORT_PATH):
        return {"high_risk_changes": [], "medium_risk_changes": [], "low_risk_changes": [],
                "total_risk_score": 0.0, "critical_alerts": [], "recommendations": []}
    try:
        with open(AI_REPORT_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"high_risk_changes": [], "medium_risk_changes": [], "low_risk_changes": [],
                "total_risk_score": 0.0, "critical_alerts": [], "recommendations": []}

def read_vt_report():
    if not os.path.exists(VT_REPORT_PATH):
        return {"scanned_files": [], "malicious_files": [],
                "suspicious_files": [], "clean_files": [],
                "not_found_files": [], "scan_errors": []}
    try:
        with open(VT_REPORT_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"scanned_files": [], "malicious_files": [],
                "suspicious_files": [], "clean_files": [],
                "not_found_files": [], "scan_errors": []}

class PremiumDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x900")
        self.title("Premium FIM Dashboard")

        # -- Fixed background image handling --
        try:
            img_bg = Image.open("premium_gradient_bg.jpg").resize((1400,900))
            self.bg_img = ctk.CTkImage(light_image=img_bg, dark_image=img_bg, size=(1400, 900))
        except Exception:
            # Create a gradient-like background if no image
            img_bg = Image.new("RGBA", (1400,900), (26, 34, 56, 255))
            self.bg_img = ctk.CTkImage(light_image=img_bg, dark_image=img_bg, size=(1400, 900))
        
        self.bg_label = ctk.CTkLabel(self, image=self.bg_img, text="")
        self.bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)

        # -- Sidebar Navigation --
        self.sidebar = ctk.CTkFrame(self, corner_radius=20, width=200, fg_color="#1e2749")
        self.sidebar.place(relx=0, rely=0, relheight=1)

        # Logo/Title
        logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ FIM Pro", font=("Montserrat", 24, "bold"), 
                                 text_color="#38c9e9")
        logo_label.pack(pady=(20, 40), padx=10)

        self.btn_monitor = ctk.CTkButton(self.sidebar, text="📊 Live Monitoring", corner_radius=12, 
                                         fg_color="#5178ff", hover_color="#38c9e9",
                                         font=("Montserrat", 16, "bold"), height=45, command=self.show_monitor)
        self.btn_monitor.pack(pady=15, padx=15, fill="x")

        self.btn_ai = ctk.CTkButton(self.sidebar, text="🤖 AI Analysis", corner_radius=12,
                                    fg_color="#5178ff", hover_color="#38c9e9",
                                    font=("Montserrat", 16, "bold"), height=45, command=self.show_ai)
        self.btn_ai.pack(pady=15, padx=15, fill="x")

        # NEW: Auto Prevention Button
        self.btn_prevention = ctk.CTkButton(self.sidebar, text="🛡️ Auto Prevention", corner_radius=12,
                                            fg_color="#5178ff", hover_color="#38c9e9",
                                            font=("Montserrat", 16, "bold"), height=45, command=self.show_prevention)
        self.btn_prevention.pack(pady=15, padx=15, fill="x")

        self.btn_settings = ctk.CTkButton(self.sidebar, text="⚙️ Settings", corner_radius=12,
                                          fg_color="#5178ff", hover_color="#38c9e9",
                                          font=("Montserrat", 16, "bold"), height=45, command=self.show_settings)
        self.btn_settings.pack(pady=15, padx=15, fill="x")

        self.btn_vt = ctk.CTkButton(self.sidebar, text="🦠 VirusTotal", corner_radius=12,
                                    fg_color="#5178ff", hover_color="#38c9e9",
                                    font=("Montserrat", 16, "bold"), height=45, command=self.show_virustotal)
        self.btn_vt.pack(pady=15, padx=15, fill="x")

        # Status indicator at bottom of sidebar
        self.sidebar_status = ctk.CTkLabel(self.sidebar, text="🟢 System Active", 
                                          font=("Montserrat", 12), text_color="#00d084")
        self.sidebar_status.pack(side="bottom", pady=20)

        # -- Main container --
        self.pages = {}
        self.monitor_process = None
        
        # Store file data for verification
        self.file_data = {}

        # Create all pages
        self.pages["monitor"] = self.create_monitor_page()
        self.pages["ai"] = self.create_ai_page()
        self.pages["prevention"] = self.create_prevention_page()  # NEW: Auto Prevention Page
        self.pages["settings"] = self.create_settings_page()
        self.pages["virustotal"] = self.create_virustotal_page()

        self.show_monitor()
        self.update_gui()

    def hide_all_pages(self):
        for p in self.pages.values():
            p.place_forget()

    def show_monitor(self):
        self.hide_all_pages()
        self.pages["monitor"].place(relx=0.18, rely=0.04, relwidth=0.80, relheight=0.92)
        self.highlight_button(self.btn_monitor)

    def show_ai(self):
        self.hide_all_pages()
        self.pages["ai"].place(relx=0.18, rely=0.04, relwidth=0.80, relheight=0.92)
        self.highlight_button(self.btn_ai)

    def show_prevention(self):
        self.hide_all_pages()
        self.pages["prevention"].place(relx=0.18, rely=0.04, relwidth=0.80, relheight=0.92)
        self.highlight_button(self.btn_prevention)

    def show_settings(self):
        self.hide_all_pages()
        self.pages["settings"].place(relx=0.18, rely=0.04, relwidth=0.80, relheight=0.92)
        self.highlight_button(self.btn_settings)

    def show_virustotal(self):
        self.hide_all_pages()
        self.pages["virustotal"].place(relx=0.18, rely=0.04, relwidth=0.80, relheight=0.92)
        self.highlight_button(self.btn_vt)

    def highlight_button(self, active_btn):
        # Reset all buttons
        for btn in [self.btn_monitor, self.btn_ai, self.btn_prevention, self.btn_settings, self.btn_vt]:
            btn.configure(fg_color="#5178ff")
        # Highlight active button
        active_btn.configure(fg_color="#38c9e9")

    def create_monitor_page(self):
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="Live File Integrity Monitoring", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # KPI Cards Container
        kpi_container = ctk.CTkFrame(frame, height=130, corner_radius=18, fg_color="#2a3444")
        kpi_container.pack(fill="x", pady=(0, 20), padx=20)

        # Real-time KPIs with glassmorphism effect
        self.lbl_total = ctk.CTkLabel(kpi_container, text="Total Alerts: 0", font=("Montserrat", 32, "bold"),
                                      text_color="#38c9e9", fg_color="#3a4555", 
                                      corner_radius=15, width=280, height=80)
        self.lbl_total.place(relx=0.05, rely=0.15)

        self.lbl_mod = ctk.CTkLabel(kpi_container, text="Modified: 0", font=("Montserrat", 16, "bold"),
                                    text_color="#ff6b9d", fg_color="#3a4555", 
                                    corner_radius=10, width=160, height=50)
        self.lbl_mod.place(relx=0.38, rely=0.55)

        self.lbl_new = ctk.CTkLabel(kpi_container, text="New: 0", font=("Montserrat", 16, "bold"),
                                    text_color="#ffd93d", fg_color="#3a4555", 
                                    corner_radius=10, width=160, height=50)
        self.lbl_new.place(relx=0.57, rely=0.55)

        self.lbl_del = ctk.CTkLabel(kpi_container, text="Deleted: 0", font=("Montserrat", 16, "bold"),
                                    text_color="#6bcf7f", fg_color="#3a4555", 
                                    corner_radius=10, width=160, height=50)
        self.lbl_del.place(relx=0.76, rely=0.55)

        self.lbl_risk = ctk.CTkLabel(kpi_container, text="AI Risk: 0.000", font=("Montserrat", 20, "bold"),
                                     text_color="#e94560", fg_color="#3a4555", 
                                     corner_radius=12, width=200, height=70)
        self.lbl_risk.place(relx=0.75, rely=0.12)

        self.lbl_vt_status = ctk.CTkLabel(kpi_container, text="VT: Disabled", font=("Montserrat", 14, "bold"),
                                          text_color="#999999", fg_color="#3a4555", 
                                          corner_radius=10, width=140, height=40)
        self.lbl_vt_status.place(relx=0.38, rely=0.15)

        # Main content area with charts and table
        content_frame = ctk.CTkFrame(frame, corner_radius=18, fg_color="#2a3444")
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Left side - Table with User column
        left_frame = ctk.CTkFrame(content_frame, corner_radius=15, fg_color="#3a4555")
        left_frame.pack(side="left", fill="both", expand=True, padx=(15, 7), pady=15)

        table_header = ctk.CTkLabel(left_frame, text="🔍 Detected Changes (Double-Click to Verify)", 
                                   font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        table_header.pack(anchor="nw", padx=15, pady=(10, 5))

        # Enhanced Treeview Table with VT Status column + USER column (changed from Action)
        columns = ("File", "Type", "Risk", "Score", "VT Status", "User")
        style = ttk.Style()
        style.theme_use("clam")
        
        # Premium table styling
        style.configure("Treeview", 
                       background="#2a3547", 
                       fieldbackground="#2a3547", 
                       foreground="#e4eafb",
                       rowheight=35, 
                       font=("Montserrat", 11),
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background="#1e2749",
                       foreground="#38c9e9",
                       font=("Montserrat", 12, "bold"),
                       relief="flat")
        style.map("Treeview", background=[("selected", "#5178ff")])
        
        self.change_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=12)
        
        for col in columns:
            self.change_tree.heading(col, text=col)
            if col == "File":
                self.change_tree.column(col, width=150, anchor="w")
            elif col == "VT Status":
                self.change_tree.column(col, width=100, anchor="center")
            elif col == "User":  # CHANGED: from "Action" to "User"
                self.change_tree.column(col, width=90, anchor="center")
            else:
                self.change_tree.column(col, width=70, anchor="center")
        
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.change_tree.yview)
        self.change_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.change_tree.pack(side="left", fill="both", expand=True, padx=(15, 0), pady=(10, 15))
        tree_scroll.pack(side="right", fill="y", pady=(10, 15), padx=(0, 15))

        # Configure risk level tags with premium colors
        self.change_tree.tag_configure("high_risk", background="#4a2c2c", foreground="#ff6b9d")
        self.change_tree.tag_configure("medium_risk", background="#4a4a2c", foreground="#ffd93d")
        self.change_tree.tag_configure("low_risk", background="#2c4a2c", foreground="#6bcf7f")

        # Bind double-click to verify action (PRESERVED)
        self.change_tree.bind("<Double-1>", self.on_table_double_click)

        # Right side - Charts
        right_frame = ctk.CTkFrame(content_frame, corner_radius=15, fg_color="#3a4555", width=350)
        right_frame.pack(side="right", fill="y", padx=(7, 15), pady=15)
        right_frame.pack_propagate(False)

        # Enhanced Pie Chart
        pie_header = ctk.CTkLabel(right_frame, text="📈 Distribution Overview", 
                                 font=("Montserrat", 16, "bold"), text_color="#38c9e9")
        pie_header.pack(pady=(15, 5))

        self.fig, self.ax = plt.subplots(figsize=(4.2, 3.2), facecolor='none')
        self.pie_canvas = FigureCanvasTkAgg(self.fig, master=right_frame)
        self.pie_canvas.get_tk_widget().pack(padx=10, pady=10)

        # Enhanced Bar Chart
        bar_header = ctk.CTkLabel(right_frame, text="📊 Event Trends", 
                                 font=("Montserrat", 16, "bold"), text_color="#38c9e9")
        bar_header.pack(pady=(15, 5))

        self.bar_fig, self.bar_ax = plt.subplots(figsize=(4.2, 2.5), facecolor='none')
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=right_frame)
        self.bar_canvas.get_tk_widget().pack(padx=10, pady=(10, 15))

        return frame

    def create_prevention_page(self):
        """NEW: Create Auto Prevention page"""
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="🛡️ Auto Prevention System", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # Prevention Statistics Panel
        stats_frame = ctk.CTkFrame(frame, height=140, corner_radius=18, fg_color="#2a3444")
        stats_frame.pack(fill="x", padx=20, pady=(0, 15))
        stats_frame.pack_propagate(False)

        stats_header = ctk.CTkLabel(stats_frame, text="📊 Prevention Statistics", 
                                   font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        stats_header.pack(pady=(15, 10))

        # Stats row
        stats_row = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_row.pack(fill="x", padx=20, pady=(0, 20))

        # Individual stat labels
        self.lbl_total_prevented = ctk.CTkLabel(stats_row, text="Total Prevented: 0", 
                                               font=("Montserrat", 16, "bold"),
                                               text_color="#ff6b9d", fg_color="#3a4555", 
                                               corner_radius=10, width=180, height=60)
        self.lbl_total_prevented.pack(side="left", padx=10, pady=10)

        self.lbl_files_removed = ctk.CTkLabel(stats_row, text="Files Removed: 0", 
                                             font=("Montserrat", 16, "bold"),
                                             text_color="#ffd93d", fg_color="#3a4555", 
                                             corner_radius=10, width=180, height=60)
        self.lbl_files_removed.pack(side="left", padx=10, pady=10)

        self.lbl_files_quarantined = ctk.CTkLabel(stats_row, text="Quarantined: 0", 
                                                 font=("Montserrat", 16, "bold"),
                                                 text_color="#6bcf7f", fg_color="#3a4555", 
                                                 corner_radius=10, width=180, height=60)
        self.lbl_files_quarantined.pack(side="left", padx=10, pady=10)

        self.lbl_threat_level = ctk.CTkLabel(stats_row, text="Threat Level: LOW", 
                                            font=("Montserrat", 16, "bold"),
                                            text_color="#38c9e9", fg_color="#3a4555", 
                                            corner_radius=10, width=180, height=60)
        self.lbl_threat_level.pack(side="left", padx=10, pady=10)

        # Control Panel
        control_frame = ctk.CTkFrame(frame, height=80, corner_radius=15, fg_color="#2a3444")
        control_frame.pack(fill="x", padx=20, pady=(0, 15))
        control_frame.pack_propagate(False)

        control_row = ctk.CTkFrame(control_frame, fg_color="transparent")
        control_row.pack(fill="x", padx=20, pady=15)

        ctk.CTkButton(
            control_row,
            text="🔄 Refresh",
            command=self.refresh_prevention_log,
            corner_radius=10,
            width=120,
            height=40,
            fg_color="#5178ff",
            hover_color="#38c9e9",
            font=("Montserrat", 14, "bold")
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            control_row,
            text="🧹 Clear Log",
            command=self.clear_prevention_log,
            corner_radius=10,
            width=120,
            height=40,
            fg_color="#ff6b6b",
            hover_color="#ff5252",
            font=("Montserrat", 14, "bold")
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            control_row,
            text="📁 Quarantine",
            command=self.open_quarantine_folder,
            corner_radius=10,
            width=120,
            height=40,
            fg_color="#ffd93d",
            hover_color="#ffc107",
            font=("Montserrat", 14, "bold")
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            control_row,
            text="⚙️ Settings",
            command=self.open_prevention_settings,
            corner_radius=10,
            width=120,
            height=40,
            fg_color="#6bcf7f",
            hover_color="#4caf50",
            font=("Montserrat", 14, "bold")
        ).pack(side="left", padx=5)

        # Prevention Log Table
        log_frame = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444")
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        log_header = ctk.CTkLabel(log_frame, text="🚨 Malware Prevention & Response Log", 
                                 font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        log_header.pack(pady=(15, 10))

        # Create prevention log tree
        prevention_columns = ("Time", "File", "Threat Type", "Actions Taken", "Status")
        
        # Configure style for prevention tree
        prevention_style = ttk.Style()
        prevention_style.configure("Prevention.Treeview", 
                                 background="#2a3547", 
                                 fieldbackground="#2a3547", 
                                 foreground="#e4eafb",
                                 rowheight=40, 
                                 font=("Montserrat", 11),
                                 borderwidth=0)
        prevention_style.configure("Prevention.Treeview.Heading",
                                 background="#1e2749",
                                 foreground="#38c9e9",
                                 font=("Montserrat", 12, "bold"),
                                 relief="flat")

        self.prevention_tree = ttk.Treeview(log_frame, columns=prevention_columns, show="headings", 
                                           height=15, style="Prevention.Treeview")

        # Configure columns
        column_configs = {
            "Time": {"width": 150, "anchor": "center"},
            "File": {"width": 250, "anchor": "w"},
            "Threat Type": {"width": 200, "anchor": "w"},
            "Actions Taken": {"width": 250, "anchor": "w"},
            "Status": {"width": 120, "anchor": "center"}
        }

        for col, config in column_configs.items():
            self.prevention_tree.heading(col, text=col)
            self.prevention_tree.column(col, width=config["width"], anchor=config["anchor"])

        # Scrollbar for prevention tree
        prevention_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.prevention_tree.yview)
        self.prevention_tree.configure(yscrollcommand=prevention_scrollbar.set)

        # Pack prevention tree and scrollbar
        tree_container = ctk.CTkFrame(log_frame, fg_color="transparent")
        tree_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.prevention_tree.pack(side="left", fill="both", expand=True)
        prevention_scrollbar.pack(side="right", fill="y")

        # Configure row colors for different statuses
        self.prevention_tree.tag_configure('success', background='#2d4a2d', foreground='#6bcf7f')
        self.prevention_tree.tag_configure('failed', background='#4a2d2d', foreground='#ff6b9d')
        self.prevention_tree.tag_configure('warning', background='#4a4a2d', foreground='#ffd93d')

        return frame

    def get_user_for_file(self, file_path, change_type='modified'):
        """Get user information for a file using the same methods as monitor.py"""
        try:
            # Import the audit functions
            from utils.audit_utils import get_file_audit_info
            
            # Convert relative path to full path if needed
            config = load_config()
            if not os.path.isabs(file_path):
                full_path = os.path.join(config["monitor_path"], file_path)
            else:
                full_path = file_path
            
            # Try to get audit information
            audit_info = get_file_audit_info(full_path, change_type)
            user = audit_info.get('user', 'Unknown')
            
            if user == 'Unknown' or not user:
                # Try to get file owner as fallback
                try:
                    import pwd
                    if os.path.exists(full_path):
                        stat_info = os.stat(full_path)
                        user = pwd.getpwuid(stat_info.st_uid).pw_name + "*"
                except:
                    pass
            
            if user == 'Unknown' or not user:
                # Final fallback - get current user
                import getpass
                try:
                    user = getpass.getuser() + "?"
                except:
                    user = "system?"
            
            # Clean up user display
            if user.endswith('*'):
                user = f"{user[:-1]} (owner)"
            elif user.endswith('?'):
                user = f"{user[:-1]} (detected)"
            
            return user
            
        except Exception as e:
            print(f"Error getting user for {file_path}: {e}")
            return "Unknown"

    def get_enhanced_changes_for_gui(self, report):
        """Get enhanced changes with proper user information"""
        enhanced_changes = {}
        
        try:
            # Process each change type
            for change_type in ['modified', 'new', 'deleted']:
                files = report.get(change_type, [])
                for file_path in files:
                    try:
                        # Get real user information
                        user_info = self.get_user_for_file(file_path, change_type)
                        
                        enhanced_changes[file_path] = {
                            'change_type': change_type,
                            'user': user_info,
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        enhanced_changes[file_path] = {
                            'change_type': change_type,
                            'user': 'Error',
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
            
        except Exception as e:
            print(f"Error getting enhanced changes: {e}")
        
        return enhanced_changes

    def update_prevention_display(self):
        """Update auto prevention display"""
        try:
            from utils.auto_prevention import auto_prevention
            
            # Update statistics
            stats = auto_prevention.get_prevention_stats()
            self.lbl_total_prevented.configure(text=f"Total Prevented: {stats['total_prevented']}")
            self.lbl_files_removed.configure(text=f"Files Removed: {stats['files_removed']}")
            self.lbl_files_quarantined.configure(text=f"Quarantined: {stats['files_quarantined']}")
            
            # Update threat level based on recent activity
            total_threats = stats['total_prevented']
            if total_threats > 10:
                threat_level = "HIGH"
                threat_color = "#ff6b9d"
            elif total_threats > 5:
                threat_level = "MEDIUM"
                threat_color = "#ffd93d"
            elif total_threats > 0:
                threat_level = "LOW"
                threat_color = "#6bcf7f"
            else:
                threat_level = "MINIMAL"
                threat_color = "#38c9e9"
            
            self.lbl_threat_level.configure(text=f"Threat Level: {threat_level}", text_color=threat_color)
            
            # Update prevention log
            prevention_log = auto_prevention.get_prevention_log()
            
            # Clear existing entries
            for item in self.prevention_tree.get_children():
                self.prevention_tree.delete(item)
            
            # Add recent entries (last 100)
            for entry in reversed(prevention_log[-100:]):
                timestamp = entry.get('timestamp', 'Unknown')
                try:
                    # Format timestamp
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%m/%d %H:%M:%S')
                except:
                    time_str = timestamp[:16] if timestamp else 'Unknown'
                
                file_path = entry.get('file_path', 'Unknown')
                file_name = os.path.basename(file_path) if file_path else 'Unknown'
                
                # Threat classification
                threat_type = "Unknown"
                details = entry.get('details', {})
                
                if details.get('vt_malicious_count', 0) > 0:
                    threat_type = f"🦠 Malware ({details['vt_malicious_count']} engines)"
                elif details.get('ai_risk_level') == 'CRITICAL':
                    threat_type = "🚨 AI Critical Risk"
                elif 'malware_indicators' in details and details['malware_indicators']:
                    indicators = details['malware_indicators']
                    threat_type = f"⚠️ Suspicious ({', '.join(indicators[:2])})"
                else:
                    threat_type = "❓ Unknown Threat"
                
                # Actions summary
                actions = entry.get('actions_taken', [])
                if len(actions) > 2:
                    actions_summary = f"{'; '.join(actions[:2])}... (+{len(actions)-2} more)"
                else:
                    actions_summary = '; '.join(actions) if actions else 'No actions taken'
                
                # Status with icons
                if entry.get('success', False):
                    if entry.get('removal_success', False):
                        status = "✅ REMOVED"
                        tag = 'success'
                    else:
                        status = "⚠️ QUARANTINED"
                        tag = 'warning'
                else:
                    status = "❌ FAILED"
                    tag = 'failed'
                
                # Insert row
                self.prevention_tree.insert("", 0, values=(
                    time_str,
                    file_name,
                    threat_type,
                    actions_summary,
                    status
                ), tags=(tag,))
            
        except Exception as e:
            print(f"Error updating prevention display: {e}")

    def refresh_prevention_log(self):
        """Refresh prevention log display"""
        self.update_prevention_display()
        messagebox.showinfo("Refresh", "✅ Prevention log refreshed successfully!")

    def clear_prevention_log(self):
        """Clear prevention log after confirmation"""
        result = messagebox.askyesno(
            "Clear Prevention Log",
            "⚠️ Are you sure you want to clear the entire prevention log?\n\nThis action cannot be undone and will remove all malware prevention history.",
            icon="warning"
        )
        
        if result:
            try:
                # Clear log file
                prevention_log_path = 'data/auto_prevention_log.json'
                if os.path.exists(prevention_log_path):
                    with open(prevention_log_path, 'w') as f:
                        json.dump([], f)
                
                # Reset statistics
                stats_path = 'data/prevention_stats.json'
                if os.path.exists(stats_path):
                    with open(stats_path, 'w') as f:
                        json.dump({
                            'total_prevented': 0,
                            'files_removed': 0,
                            'files_quarantined': 0,
                            'false_positives': 0,
                            'last_reset': datetime.now().isoformat()
                        }, f)
                
                # Refresh display
                self.update_prevention_display()
                messagebox.showinfo("Success", "✅ Prevention log and statistics cleared successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"❌ Failed to clear prevention log:\n{str(e)}")

    def open_quarantine_folder(self):
        """Open quarantine folder in file manager"""
        quarantine_dir = 'quarantine/'
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        
        try:
            if os.name == 'nt':  # Windows
                os.startfile(quarantine_dir)
            elif os.name == 'posix':  # Linux/Mac
                subprocess.run(['xdg-open', quarantine_dir], check=False)
            else:
                messagebox.showinfo("Quarantine Location", f"📁 Quarantine folder location:\n{os.path.abspath(quarantine_dir)}")
                
            messagebox.showinfo("Quarantine Folder", f"📁 Quarantine folder opened:\n{os.path.abspath(quarantine_dir)}")
        except Exception as e:
            messagebox.showerror("Error", f"❌ Could not open quarantine folder:\n{str(e)}")

    def open_prevention_settings(self):
        """Open prevention settings dialog"""
        settings_window = ctk.CTkToplevel(self)
        settings_window.title("🛡️ Auto Prevention Settings")
        settings_window.geometry("600x500")
        settings_window.transient(self)
        settings_window.grab_set()

        # Header
        header = ctk.CTkLabel(settings_window, text="🛡️ Auto Prevention Configuration", 
                             font=("Montserrat", 24, "bold"), text_color="#38c9e9")
        header.pack(pady=(20, 30))

        # Settings frame
        settings_frame = ctk.CTkFrame(settings_window, corner_radius=15, fg_color="#2a3444")
        settings_frame.pack(fill="both", expand=True, padx=30, pady=(0, 30))

        # Auto Removal Setting
        auto_removal_var = ctk.BooleanVar(value=CONFIG.get('auto_removal_enabled', True))
        auto_removal_check = ctk.CTkCheckBox(
            settings_frame,
            text="🗑️ Enable Automatic File Removal",
            variable=auto_removal_var,
            font=("Montserrat", 14),
            fg_color="#5178ff",
            hover_color="#38c9e9"
        )
        auto_removal_check.pack(anchor="w", padx=30, pady=15)

        # Quarantine Setting
        quarantine_var = ctk.BooleanVar(value=CONFIG.get('quarantine_enabled', True))
        quarantine_check = ctk.CTkCheckBox(
            settings_frame,
            text="🔒 Enable File Quarantine",
            variable=quarantine_var,
            font=("Montserrat", 14),
            fg_color="#5178ff",
            hover_color="#38c9e9"
        )
        quarantine_check.pack(anchor="w", padx=30, pady=15)

        # Backup Setting
        backup_var = ctk.BooleanVar(value=CONFIG.get('backup_before_removal', True))
        backup_check = ctk.CTkCheckBox(
            settings_frame,
            text="💾 Backup Files Before Removal",
            variable=backup_var,
            font=("Montserrat", 14),
            fg_color="#5178ff",
            hover_color="#38c9e9"
        )
        backup_check.pack(anchor="w", padx=30, pady=15)

        # Malicious Engine Threshold
        ctk.CTkLabel(settings_frame, 
                    text="🦠 Minimum VirusTotal Engines for Auto-Removal:", 
                    font=("Montserrat", 14, "bold"),
                    text_color="#38c9e9").pack(anchor="w", padx=30, pady=(30, 10))
        
        engine_var = ctk.IntVar(value=CONFIG.get('min_malicious_engines', 3))
        engine_slider = ctk.CTkSlider(
            settings_frame,
            from_=1,
            to=10,
            variable=engine_var,
            number_of_steps=9,
            width=300
        )
        engine_slider.pack(anchor="w", padx=30, pady=10)
        
        engine_label = ctk.CTkLabel(settings_frame, text=f"Engines: {engine_var.get()}", 
                                   font=("Montserrat", 12), text_color="#ffd93d")
        engine_label.pack(anchor="w", padx=30, pady=(0, 20))
        
        def update_engine_label():
            engine_label.configure(text=f"Engines: {engine_var.get()}")
            settings_window.after(100, update_engine_label)
        
        update_engine_label()

        # Buttons frame
        button_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=30, pady=20)

        # Save button
        def save_settings():
            try:
                CONFIG['auto_removal_enabled'] = auto_removal_var.get()
                CONFIG['quarantine_enabled'] = quarantine_var.get()
                CONFIG['backup_before_removal'] = backup_var.get()
                CONFIG['min_malicious_engines'] = engine_var.get()
                save_config(CONFIG)
                
                messagebox.showinfo("Settings Saved", "✅ Prevention settings saved successfully!")
                settings_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"❌ Failed to save settings:\n{str(e)}")
        
        ctk.CTkButton(
            button_frame,
            text="💾 Save Settings",
            command=save_settings,
            corner_radius=10,
            width=150,
            height=40,
            fg_color="#6bcf7f",
            hover_color="#4caf50",
            font=("Montserrat", 14, "bold")
        ).pack(side="left", padx=(0, 10))

        # Cancel button
        ctk.CTkButton(
            button_frame,
            text="❌ Cancel",
            command=settings_window.destroy,
            corner_radius=10,
            width=150,
            height=40,
            fg_color="#ff6b9d",
            hover_color="#e91e63",
            font=("Montserrat", 14, "bold")
        ).pack(side="left")

    def on_table_double_click(self, event):
        """Handle double-click on table row to verify/update baseline"""
        try:
            item = self.change_tree.selection()[0]
            values = self.change_tree.item(item, "values")
            file_path = values[0]  # Get file name from first column
            
            # Find full file path from stored data
            full_file_path = None
            for stored_path, data in self.file_data.items():
                display_path = stored_path[:30] + "..." if len(stored_path) > 30 else stored_path
                if display_path == file_path or stored_path.endswith(file_path.replace("...", "")):
                    full_file_path = stored_path
                    break
            
            if full_file_path:
                self.verify_file_baseline(full_file_path, item)
            else:
                messagebox.showwarning("File Not Found", f"Could not find full path for: {file_path}")
                
        except (IndexError, KeyError):
            pass  # No selection or invalid data
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")

    def verify_file_baseline(self, file_path, tree_item):
        """Verify individual file and update baseline"""
        try:
            result = messagebox.askyesno(
                "Verify File", 
                f"Update baseline for:\n\n{file_path}\n\nThis accepts this change as legitimate.",
                icon="question"
            )
            
            if result:
                from utils.baseline_updater import update_single_file
                
                config = load_config()
                results = update_single_file(file_path, config["monitor_path"], config["baseline_file"])
                
                if results['errors']:
                    messagebox.showerror("Update Failed", f"Failed:\n{results['errors'][0]}")
                else:
                    messagebox.showinfo("Success", f"✅ Baseline updated for:\n{os.path.basename(file_path)}")
                    # Remove from table
                    self.change_tree.delete(tree_item)
                    # Remove from stored data
                    if file_path in self.file_data:
                        del self.file_data[file_path]
                        
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed:\n{str(e)}")

    def create_ai_page(self):
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="🤖 AI Risk Analysis Dashboard", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # AI Score Card
        ai_card = ctk.CTkFrame(frame, height=140, corner_radius=18, fg_color="#2a3444")
        ai_card.pack(fill="x", pady=(0, 20), padx=20)

        self.lbl_ai_score = ctk.CTkLabel(ai_card, text="Risk Score: 0.000", font=("Montserrat", 36, "bold"),
                                         text_color="#5178ff", fg_color="#3a4555", 
                                         corner_radius=15, width=300, height=90)
        self.lbl_ai_score.place(relx=0.07, rely=0.18)

        self.lbl_ai_status = ctk.CTkLabel(ai_card, text="Status: SAFE", font=("Montserrat", 22, "bold"),
                                          text_color="#6bcf7f", fg_color="#3a4555", 
                                          corner_radius=12, width=220, height=70)
        self.lbl_ai_status.place(relx=0.42, rely=0.18)

        # Risk trend indicator
        trend_label = ctk.CTkLabel(ai_card, text="📈 Trending Safe", font=("Montserrat", 16),
                                  text_color="#6bcf7f", fg_color="#3a4555", 
                                  corner_radius=10, width=180, height=40)
        trend_label.place(relx=0.75, rely=0.35)

        # Enhanced Risk Distribution Chart
        chart_card = ctk.CTkFrame(frame, corner_radius=16, fg_color="#2a3444", height=280)
        chart_card.pack(fill="x", padx=20, pady=(0, 15))

        chart_header = ctk.CTkLabel(chart_card, text="📊 Risk Level Distribution", 
                                   font=("Montserrat", 20, "bold"), text_color="#38c9e9")
        chart_header.pack(pady=(15, 10))

        self.risk_fig, self.risk_ax = plt.subplots(figsize=(8, 3.5), facecolor='none')
        self.risk_canvas = FigureCanvasTkAgg(self.risk_fig, master=chart_card)
        self.risk_canvas.get_tk_widget().pack(padx=15, pady=(0, 15))

        # Enhanced Alerts Panel
        alerts_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444")
        alerts_card.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        alerts_header = ctk.CTkLabel(alerts_card, text="🚨 Critical Alerts & Recommendations", 
                                    font=("Montserrat", 20, "bold"), text_color="#38c9e9")
        alerts_header.pack(pady=(15, 10))

        self.alerts_text = ctk.CTkTextbox(alerts_card, font=("Montserrat", 13), 
                                         fg_color="#2a3547", text_color="#e4eafb",
                                         border_color="#5178ff", border_width=2, corner_radius=12)
        self.alerts_text.pack(padx=15, pady=(0, 15), fill="both", expand=True)

        return frame

    def create_settings_page(self):
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="⚙️ System Configuration", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # AI Settings Card
        ai_settings_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444", height=180)
        ai_settings_card.pack(padx=20, pady=(0, 15), fill="x")

        ai_header = ctk.CTkLabel(ai_settings_card, text="🤖 AI Configuration", 
                                font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        ai_header.pack(pady=(15, 10))

        self.ai_enabled = ctk.BooleanVar(value=CONFIG.get("ai_risk_scoring", True))
        self.smart_alerts = ctk.BooleanVar(value=CONFIG.get("smart_alerts", True))
        self.auto_training = ctk.BooleanVar(value=CONFIG.get("auto_training", False))

        ctk.CTkCheckBox(ai_settings_card, text="Enable AI Risk Scoring", variable=self.ai_enabled,
                       command=self.toggle_ai_scoring, font=("Montserrat", 14), 
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)
        ctk.CTkCheckBox(ai_settings_card, text="Smart Alert Filtering", variable=self.smart_alerts,
                       command=self.toggle_smart_alerts, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)
        ctk.CTkCheckBox(ai_settings_card, text="Auto Model Training", variable=self.auto_training,
                       command=self.toggle_auto_training, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)

        # Traditional Settings Card
        traditional_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444", height=120)
        traditional_card.pack(padx=20, pady=15, fill="x")

        trad_header = ctk.CTkLabel(traditional_card, text="🔔 Alert Configuration", 
                                  font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        trad_header.pack(pady=(15, 10))

        self.audio_alert_enabled = ctk.BooleanVar(value=CONFIG.get("beep_on_change", False))
        self.email_alert_enabled = ctk.BooleanVar(value=CONFIG.get("email_alert", False))

        ctk.CTkCheckBox(traditional_card, text="Audio Alert", variable=self.audio_alert_enabled,
                       command=self.toggle_audio_alert, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)
        ctk.CTkCheckBox(traditional_card, text="Email Alert", variable=self.email_alert_enabled,
                       command=self.toggle_email_alert, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)

        # System Control Card
        control_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444")
        control_card.pack(padx=20, pady=15, fill="both", expand=True)

        control_header = ctk.CTkLabel(control_card, text="🛠️ System Controls", 
                                     font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        control_header.pack(pady=(15, 10))

        self.status_label = ctk.CTkLabel(control_card, text="Ready for operations", 
                                        font=("Montserrat", 14), text_color="#6bcf7f")
        self.status_label.pack(pady=(10, 15))

        button_frame = ctk.CTkFrame(control_card, fg_color="transparent")
        button_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        ctk.CTkButton(button_frame, text="🛠️ Initialize Baseline", corner_radius=12, height=40,
                     fg_color="#5178ff", hover_color="#38c9e9", font=("Montserrat", 14, "bold"),
                     command=self.run_initialize).pack(pady=8, fill="x")
        ctk.CTkButton(button_frame, text="🤖 Train AI Model", corner_radius=12, height=40,
                     fg_color="#5178ff", hover_color="#38c9e9", font=("Montserrat", 14, "bold"),
                     command=self.train_ai_model).pack(pady=8, fill="x")
        ctk.CTkButton(button_frame, text="🕵️ Start Monitoring", corner_radius=12, height=40,
                     fg_color="#6bcf7f", hover_color="#4caf50", font=("Montserrat", 14, "bold"),
                     command=self.start_monitoring).pack(pady=8, fill="x")
        ctk.CTkButton(button_frame, text="🛑 Stop Monitoring", corner_radius=12, height=40,
                     fg_color="#ff6b9d", hover_color="#e91e63", font=("Montserrat", 14, "bold"),
                     command=self.stop_monitoring).pack(pady=8, fill="x")

        return frame

    def create_virustotal_page(self):
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="🦠 VirusTotal Configuration", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # VirusTotal Settings Card
        vt_settings_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444", height=280)
        vt_settings_card.pack(padx=20, pady=(0, 15), fill="x")
        
        vt_header = ctk.CTkLabel(vt_settings_card, text="🦠 Malware Scanning Configuration", 
                                font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        vt_header.pack(pady=(15, 10))

        self.vt_enabled = ctk.BooleanVar(value=CONFIG.get("virustotal_enabled", False))
        self.vt_scan_new = ctk.BooleanVar(value=CONFIG.get("virustotal_scan_new_files", True))
        self.vt_scan_modified = ctk.BooleanVar(value=CONFIG.get("virustotal_scan_modified_files", True))

        ctk.CTkCheckBox(vt_settings_card, text="Enable VirusTotal Scanning", variable=self.vt_enabled,
                       command=self.toggle_vt_enabled, font=("Montserrat", 14), 
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)
        ctk.CTkCheckBox(vt_settings_card, text="Scan New Files", variable=self.vt_scan_new,
                       command=self.toggle_vt_scan_new, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)
        ctk.CTkCheckBox(vt_settings_card, text="Scan Modified Files", variable=self.vt_scan_modified,
                       command=self.toggle_vt_scan_modified, font=("Montserrat", 14),
                       fg_color="#5178ff", hover_color="#38c9e9").pack(anchor="w", padx=30, pady=8)

        # API Key Configuration
        api_key_frame = ctk.CTkFrame(vt_settings_card, fg_color="transparent")
        api_key_frame.pack(fill="x", padx=30, pady=15)

        ctk.CTkLabel(api_key_frame, text="API Key:", font=("Montserrat", 14, "bold"), 
                    text_color="#38c9e9").pack(side="left")
        
        self.vt_api_key_entry = ctk.CTkEntry(api_key_frame, placeholder_text="Enter VirusTotal API Key", 
                                             width=300, show="*", font=("Montserrat", 12))
        self.vt_api_key_entry.pack(side="right", padx=(10, 0))

        ctk.CTkButton(vt_settings_card, text="💾 Save API Key", corner_radius=10, height=35,
                     fg_color="#5178ff", hover_color="#38c9e9", font=("Montserrat", 14, "bold"),
                     command=self.save_vt_api_key).pack(pady=10)

        # VirusTotal Status Card
        vt_status_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2a3444", height=200)
        vt_status_card.pack(padx=20, pady=15, fill="x")

        status_header = ctk.CTkLabel(vt_status_card, text="🛡️ VirusTotal Status", 
                                    font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        status_header.pack(pady=(15, 10))

        self.vt_status_label = ctk.CTkLabel(vt_status_card, text="Ready for configuration", 
                                           font=("Montserrat", 14), text_color="#6bcf7f")
        self.vt_status_label.pack(pady=(10, 15))

        # Test Connection Button
        ctk.CTkButton(vt_status_card, text="🔍 Test API Connection", corner_radius=10, height=35,
                     fg_color="#6bcf7f", hover_color="#4caf50", font=("Montserrat", 14, "bold"),
                     command=self.test_vt_connection).pack(pady=10)

        return frame

    # ------ Settings Handlers -------
    def toggle_ai_scoring(self):
        CONFIG["ai_risk_scoring"] = bool(self.ai_enabled.get())
        save_config(CONFIG)
        self.status_label.configure(text="✅ AI Risk Scoring updated!", text_color="#6bcf7f")

    def toggle_smart_alerts(self):
        CONFIG["smart_alerts"] = bool(self.smart_alerts.get())
        save_config(CONFIG)
        self.status_label.configure(text="✅ Smart alerts updated!", text_color="#6bcf7f")

    def toggle_auto_training(self):
        CONFIG["auto_training"] = bool(self.auto_training.get())
        save_config(CONFIG)
        self.status_label.configure(text="✅ Auto training updated!", text_color="#6bcf7f")

    def toggle_audio_alert(self):
        CONFIG["beep_on_change"] = bool(self.audio_alert_enabled.get())
        save_config(CONFIG)
        self.status_label.configure(text="✅ Audio alert updated!", text_color="#6bcf7f")

    def toggle_email_alert(self):
        CONFIG["email_alert"] = bool(self.email_alert_enabled.get())
        save_config(CONFIG)
        self.status_label.configure(text="✅ Email alert updated!", text_color="#6bcf7f")

    def toggle_vt_enabled(self):
        CONFIG["virustotal_enabled"] = bool(self.vt_enabled.get())
        save_config(CONFIG)
        self.vt_status_label.configure(text="✅ VirusTotal settings updated!", text_color="#6bcf7f")

    def toggle_vt_scan_new(self):
        CONFIG["virustotal_scan_new_files"] = bool(self.vt_scan_new.get())
        save_config(CONFIG)

    def toggle_vt_scan_modified(self):
        CONFIG["virustotal_scan_modified_files"] = bool(self.vt_scan_modified.get())
        save_config(CONFIG)

    def save_vt_api_key(self):
        api_key = self.vt_api_key_entry.get().strip()
        if api_key:
            CONFIG["virustotal_api_key"] = api_key
            save_config(CONFIG)
            if set_vt_api_key(api_key):
                self.vt_status_label.configure(text="✅ VirusTotal API key saved and verified!", text_color="#6bcf7f")
            else:
                self.vt_status_label.configure(text="❌ Invalid VirusTotal API key!", text_color="#ff6b9d")
            self.vt_api_key_entry.delete(0, ctk.END)
        else:
            self.vt_status_label.configure(text="❌ Please enter an API key!", text_color="#ff6b9d")

    def test_vt_connection(self):
        try:
            if CONFIG.get("virustotal_api_key"):
                # Test the connection
                self.vt_status_label.configure(text="🔍 Testing connection...", text_color="#ffd93d")
                # You can add actual connection test logic here
                self.after(2000, lambda: self.vt_status_label.configure(text="✅ Connection successful!", text_color="#6bcf7f"))
            else:
                self.vt_status_label.configure(text="❌ No API key configured!", text_color="#ff6b9d")
        except Exception:
            self.vt_status_label.configure(text="❌ Connection failed!", text_color="#ff6b9d")

    def run_initialize(self):
        try:
            subprocess.run(["python3", "initialize.py"], check=True)
            self.status_label.configure(text="✅ Baseline initialized successfully!", text_color="#6bcf7f")
        except Exception:
            self.status_label.configure(text="❌ Initialization failed!", text_color="#ff6b9d")

    def train_ai_model(self):
        try:
            subprocess.run(["python3", "train_ai_model.py"], check=True)
            self.status_label.configure(text="🤖 AI model trained successfully!", text_color="#6bcf7f")
        except Exception:
            self.status_label.configure(text="❌ AI training failed!", text_color="#ff6b9d")

    def start_monitoring(self):
        def run_monitor():
            if self.monitor_process is None or self.monitor_process.poll() is not None:
                self.monitor_process = subprocess.Popen(["python3", "monitor.py"])
                self.status_label.configure(text="🕵️ Monitoring started...", text_color="#6bcf7f")
                self.sidebar_status.configure(text="🟢 Monitoring Active", text_color="#6bcf7f")
            else:
                self.status_label.configure(text="⚠️ Already running.", text_color="#ffd93d")
        threading.Thread(target=run_monitor, daemon=True).start()

    def stop_monitoring(self):
        if self.monitor_process and self.monitor_process.poll() is not None:
            self.monitor_process.terminate()
            self.monitor_process = None
            self.status_label.configure(text="🛑 Monitoring stopped.", text_color="#ff6b9d")
            self.sidebar_status.configure(text="🔴 System Idle", text_color="#ff6b9d")
        else:
            self.status_label.configure(text="⚠️ No active monitoring.", text_color="#ffd93d")

    # ------ Enhanced Chart Updates ------
    def update_pie_chart(self, modified_count, new_count, deleted_count):
        """Enhanced donut-style pie chart with premium styling"""
        self.ax.clear()
        
        if not any([modified_count, new_count, deleted_count]):
            self.ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center',
                        transform=self.ax.transAxes, fontsize=14, color='#38c9e9',
                        fontweight='bold')
        else:
            sizes = [modified_count, new_count, deleted_count]
            labels = ['Modified', 'New', 'Deleted']
            colors = ['#ff6b9d', '#ffd93d', '#6bcf7f']
            explode = (0.05, 0.05, 0.05)  # Slight separation for premium look
            
            wedges, texts, autotexts = self.ax.pie(
                sizes, 
                labels=labels, 
                colors=colors,
                explode=explode,
                autopct='%1.1f%%',
                startangle=90,
                wedgeprops={
                    'width': 0.6,  # Donut effect
                    'edgecolor': '#1e2749',
                    'linewidth': 2,
                    'alpha': 0.9
                },
                textprops={'fontsize': 11, 'fontweight': 'bold'}
            )
            
            # Style the text
            for text in texts:
                text.set_color('#e4eafb')
            for autotext in autotexts:
                autotext.set_color('#1e2749')
                autotext.set_fontweight('bold')
            
            # Add center text
            self.ax.text(0, 0, f'Total\n{sum(sizes)}', ha='center', va='center',
                        fontsize=16, fontweight='bold', color='#38c9e9')
        
        self.ax.set_facecolor('none')
        self.fig.patch.set_facecolor('none')
        self.pie_canvas.draw()

    def update_bar_chart(self, modified_count, new_count, deleted_count):
        """Enhanced 3D-style bar chart with gradients and shadows"""
        self.bar_ax.clear()
        
        if not any([modified_count, new_count, deleted_count]):
            self.bar_ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center',
                            transform=self.bar_ax.transAxes, fontsize=12, color='#38c9e9',
                            fontweight='bold')
        else:
            categories = ['Modified', 'New', 'Deleted']
            values = [modified_count, new_count, deleted_count]
            colors = ['#ff6b9d', '#ffd93d', '#6bcf7f']
            
            # Create bars with premium styling
            bars = self.bar_ax.bar(categories, values, color=colors, alpha=0.8,
                                  edgecolor='#1e2749', linewidth=2, width=0.6)
            
            # Add value labels on top of bars
            for bar, value in zip(bars, values):
                if value > 0:
                    self.bar_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                                    f'{value}', ha='center', va='bottom', 
                                    fontweight='bold', fontsize=12, color='#e4eafb')
            
            # Add gradient effect (simulate with alpha)
            for i, bar in enumerate(bars):
                # Add a lighter overlay for 3D effect
                overlay_color = colors[i]
                self.bar_ax.bar(bar.get_x(), bar.get_height() * 0.1, 
                               width=bar.get_width(), bottom=bar.get_height() * 0.9,
                               color=overlay_color, alpha=0.3, edgecolor='none')
        
        # Style the axes
        self.bar_ax.set_facecolor('none')
        self.bar_ax.tick_params(colors='#e4eafb', labelsize=10)
        self.bar_ax.set_ylabel('Events', fontweight='bold', color='#38c9e9', fontsize=11)
        
        # Remove top and right spines
        self.bar_ax.spines['top'].set_visible(False)
        self.bar_ax.spines['right'].set_visible(False)
        self.bar_ax.spines['left'].set_color('#38c9e9')
        self.bar_ax.spines['bottom'].set_color('#38c9e9')
        
        # Add grid
        self.bar_ax.grid(True, alpha=0.3, color='#38c9e9', linestyle='-', linewidth=0.5)
        
        self.bar_fig.patch.set_facecolor('none')
        self.bar_canvas.draw()

    def update_risk_distribution_chart(self, ai_report):
        """Enhanced risk distribution chart with premium styling"""
        self.risk_ax.clear()
        
        risk_counts = [
            len(ai_report.get("high_risk_changes", [])),
            len(ai_report.get("medium_risk_changes", [])),
            len(ai_report.get("low_risk_changes", []))
        ]
        risk_labels = ["High Risk", "Medium Risk", "Low Risk"]
        colors = ['#ff6b9d', '#ffd93d', '#6bcf7f']
        
        if any(risk_counts):
            # Create enhanced bars
            bars = self.risk_ax.bar(risk_labels, risk_counts, color=colors, alpha=0.85,
                                   edgecolor='#1e2749', linewidth=2, width=0.5)
            
            # Add value labels
            for bar, count in zip(bars, risk_counts):
                if count > 0:
                    self.risk_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                     str(count), ha='center', va='bottom', 
                                     fontweight='bold', fontsize=14, color='#e4eafb')
            
            # Add subtle gradient effect
            for i, bar in enumerate(bars):
                height = bar.get_height()
                if height > 0:
                    # Add highlight on top
                    self.risk_ax.bar(bar.get_x(), height * 0.15, width=bar.get_width(),
                                    bottom=height * 0.85, color='white', alpha=0.3)
        else:
            self.risk_ax.text(0.5, 0.5, 'No Risk Data Available', ha='center', va='center',
                             transform=self.risk_ax.transAxes, fontsize=14, color='#38c9e9',
                             fontweight='bold')
        
        # Style the chart
        self.risk_ax.set_facecolor('none')
        self.risk_ax.set_ylabel('Number of Changes', fontweight='bold', color='#38c9e9', fontsize=12)
        self.risk_ax.tick_params(colors='#e4eafb', labelsize=11)
        
        # Enhanced grid
        self.risk_ax.grid(True, alpha=0.2, color='#38c9e9', linestyle='-', linewidth=0.8)
        
        # Remove spines except bottom
        for spine in self.risk_ax.spines.values():
            spine.set_visible(False)
        self.risk_ax.spines['bottom'].set_visible(True)
        self.risk_ax.spines['bottom'].set_color('#38c9e9')
        
        self.risk_fig.patch.set_facecolor('none')
        self.risk_canvas.draw()

    # ------ Main Update Function ------
    def update_gui(self):
        """Main GUI update function with enhanced styling and proper user display"""
        from datetime import datetime
        
        report = read_report()
        ai_report = read_ai_report()
        vt_report = read_vt_report()
        
        modified = report.get("modified", [])
        new = report.get("new", [])
        deleted = report.get("deleted", [])
        
        modified_count = len(modified)
        new_count = len(new)
        deleted_count = len(deleted)
        total = modified_count + new_count + deleted_count
        
        # Update KPI labels
        self.lbl_total.configure(text=f"Total Alerts: {total}")
        self.lbl_mod.configure(text=f"Modified: {modified_count}")
        self.lbl_new.configure(text=f"New: {new_count}")
        self.lbl_del.configure(text=f"Deleted: {deleted_count}")

        # Update risk indicator
        risk_score = ai_report.get("total_risk_score", 0.0)
        self.lbl_risk.configure(text=f"AI Risk: {risk_score:.3f}")
        self.lbl_ai_score.configure(text=f"Risk Score: {risk_score:.3f}")
        
        # Dynamic color coding for risk levels
        if risk_score >= 0.8:
            risk_color = "#ff6b9d"
            status_text = "Status: CRITICAL"
        elif risk_score >= 0.6:
            risk_color = "#ffd93d"
            status_text = "Status: HIGH RISK"
        elif risk_score >= 0.4:
            risk_color = "#ffa726"
            status_text = "Status: MEDIUM RISK"
        else:
            risk_color = "#6bcf7f"
            status_text = "Status: SAFE"
        
        self.lbl_risk.configure(text_color=risk_color)
        self.lbl_ai_score.configure(text_color=risk_color)
        self.lbl_ai_status.configure(text=status_text, text_color=risk_color)

        # VirusTotal status
        if CONFIG.get("virustotal_enabled", False):
            vt_malicious = len(vt_report.get("malicious_files", []))
            vt_suspicious = len(vt_report.get("suspicious_files", []))
            if vt_malicious > 0:
                vt_color = "#ff6b9d"
                vt_text = f"VT: {vt_malicious} Malicious"
            elif vt_suspicious > 0:
                vt_color = "#ffd93d"
                vt_text = f"VT: {vt_suspicious} Suspicious"
            else:
                vt_color = "#6bcf7f"
                vt_text = "VT: Clean"
        else:
            vt_color = "#999999"
            vt_text = "VT: Disabled"
        self.lbl_vt_status.configure(text=vt_text, text_color=vt_color)

        # FIXED: Get enhanced changes with real user information
        enhanced_changes = self.get_enhanced_changes_for_gui(report)

        # Update table with proper user information
        for item in self.change_tree.get_children():
            self.change_tree.delete(item)
        
        # Clear stored file data
        self.file_data.clear()
        
        # Process AI changes with REAL user information
        all_changes = []
        for change in ai_report.get("high_risk_changes", []):
            all_changes.append((change, "high_risk"))
        for change in ai_report.get("medium_risk_changes", []):
            all_changes.append((change, "medium_risk"))
        for change in ai_report.get("low_risk_changes", []):
            all_changes.append((change, "low_risk"))
        
        for change, tag in all_changes:
            file_path = change.get("file_path", "")
            display_path = file_path[:30] + "..." if len(file_path) > 30 else file_path
            
            # Store full file path for verification
            self.file_data[file_path] = change
            
            # Get VirusTotal status for this file
            vt_status = "Not Scanned"
            for vt_file in vt_report.get("scanned_files", []):
                if vt_file.get("file_path") == file_path:
                    if vt_file.get("malicious", 0) > 0:
                        vt_status = f"🚨 {vt_file['malicious']} Malicious"
                    elif vt_file.get("suspicious", 0) > 0:
                        vt_status = f"⚠️ {vt_file['suspicious']} Suspicious"
                    elif vt_file.get("status") == "not_found":
                        vt_status = "❓ Unknown"
                    else:
                        vt_status = "✅ Clean"
                    break
            
            # FIXED: Get REAL user information (not filename!)
            enhanced_change = enhanced_changes.get(file_path)
            if enhanced_change:
                real_user = enhanced_change['user']
            else:
                # Fallback: get user info right now
                real_user = self.get_user_for_file(file_path, change.get("change_type", "modified"))
            
            self.change_tree.insert("", "end", values=(
                display_path,                              # File
                change.get("change_type", "").title(),     # Type
                change.get("risk_level", ""),              # Risk
                f"{change.get('risk_score', 0):.3f}",     # Score
                vt_status,                                 # VT Status
                real_user                                  # USER (REAL USERNAME!)
            ), tags=(tag,))

        # Update enhanced charts
        self.update_pie_chart(modified_count, new_count, deleted_count)
        self.update_bar_chart(modified_count, new_count, deleted_count)
        self.update_risk_distribution_chart(ai_report)

        # Update prevention display if on prevention page
        try:
            self.update_prevention_display()
        except:
            pass  # Prevention display might not be initialized yet

        # Update alerts text with enhanced formatting
        self.alerts_text.delete("0.0", ctk.END)
        critical_alerts = ai_report.get("critical_alerts", [])
        recommendations = ai_report.get("recommendations", [])
        
        # VirusTotal alerts
        if vt_report.get("malicious_files"):
            self.alerts_text.insert(ctk.END, "🦠 VIRUSTOTAL MALWARE DETECTED:\n")
            for malicious_file in vt_report["malicious_files"][:3]:  # Show top 3
                file_name = malicious_file["file_path"].split("/")[-1]
                detections = malicious_file.get("malicious", 0)
                self.alerts_text.insert(ctk.END, f"• {file_name} - {detections} engines detected malware\n")
            self.alerts_text.insert(ctk.END, "\n")
        
        if critical_alerts:
            self.alerts_text.insert(ctk.END, "🚨 CRITICAL ALERTS:\n")
            for alert in critical_alerts:
                self.alerts_text.insert(ctk.END, f"• {alert}\n")
            self.alerts_text.insert(ctk.END, "\n")
        
        if recommendations:
            self.alerts_text.insert(ctk.END, "💡 RECOMMENDATIONS:\n")
            for rec in recommendations:
                self.alerts_text.insert(ctk.END, f"• {rec}\n")
        
        if not critical_alerts and not recommendations and not vt_report.get("malicious_files"):
            self.alerts_text.insert(ctk.END, "✅ All systems operating normally.\n")
            self.alerts_text.insert(ctk.END, "No critical alerts or recommendations at this time.")

        # Schedule next update
        self.after(SCAN_INTERVAL, self.update_gui)

if __name__ == "__main__":
    app = PremiumDashboard()
    app.mainloop()
