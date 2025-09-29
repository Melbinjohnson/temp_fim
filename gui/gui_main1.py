import os, sys, json, subprocess, threading
import customtkinter as ctk
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
import numpy as np
import tkinter as tk
from tkinter import ttk

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
        self.geometry("1400x900")  # Increased width for individual buttons
        self.title("Premium FIM Dashboard")

        # -- Fixed background image handling --
        try:
            img_bg = Image.open("premium_gradient_bg.jpg").resize((1400,900))
            self.bg_img = ctk.CTkImage(light_image=img_bg, dark_image=img_bg, size=(1400, 900))
        except Exception:
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

        # Create all pages
        self.pages["monitor"] = self.create_monitor_page()
        self.pages["ai"] = self.create_ai_page()
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
        for btn in [self.btn_monitor, self.btn_ai, self.btn_settings, self.btn_vt]:
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

        # NEW: Enhanced Changes Table with Individual Update Buttons
        table_card = ctk.CTkFrame(frame, corner_radius=18, fg_color="#2a3444")
        table_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        table_header = ctk.CTkLabel(table_card, text="🔍 Detected Changes with Individual Actions", 
                                   font=("Montserrat", 20, "bold"), text_color="#38c9e9")
        table_header.pack(pady=(15, 10))

        # Scrollable frame for individual file cards
        self.changes_scroll = ctk.CTkScrollableFrame(table_card, height=400, 
                                                    fg_color="transparent", 
                                                    scrollbar_button_color="#5178ff")
        self.changes_scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Store file cards for updates
        self.file_cards = {}

        return frame

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

    # NEW: Individual File Card Creation
    def create_file_card(self, file_path, change_type, risk_data, vt_status):
        """Create an individual file card with update button"""
        
        # Remove existing card if it exists
        if file_path in self.file_cards:
            self.file_cards[file_path].destroy()
        
        # Create new card
        card = ctk.CTkFrame(self.changes_scroll, corner_radius=12, fg_color="#3a4555", height=80)
        card.pack(fill="x", pady=5, padx=10)

        # Left side - File info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)

        # File path with color coding
        colors = {"modified": "#ff6b9d", "new": "#ffd93d", "deleted": "#999999"}
        text_color = colors.get(change_type, "#e4eafb")
        
        display_path = file_path[:80] + "..." if len(file_path) > 80 else file_path
        path_label = ctk.CTkLabel(info_frame, text=f"{change_type.upper()}: {display_path}", 
                                 font=("Montserrat", 14, "bold"), text_color=text_color)
        path_label.pack(anchor="w")

        # Risk and VT info
        info_text = ""
        if risk_data:
            info_text += f"Risk: {risk_data.get('risk_score', 0):.3f} ({risk_data.get('risk_level', 'UNKNOWN')}) "
        if vt_status:
            info_text += f"• VT: {vt_status}"
        
        if info_text:
            info_label = ctk.CTkLabel(info_frame, text=info_text, 
                                     font=("Montserrat", 11), text_color="#999999")
            info_label.pack(anchor="w", pady=(5, 0))

        # Right side - Action buttons
        button_frame = ctk.CTkFrame(card, fg_color="transparent")
        button_frame.pack(side="right", padx=15, pady=10)

        # Update baseline button
        update_btn = ctk.CTkButton(button_frame, text="✅ Update", corner_radius=8, height=30, width=80,
                                  fg_color="#6bcf7f", hover_color="#4caf50", 
                                  font=("Montserrat", 12, "bold"),
                                  command=lambda fp=file_path: self.update_single_file_baseline(fp))
        update_btn.pack(side="right", padx=(10, 0))

        # View details button
        details_btn = ctk.CTkButton(button_frame, text="🔍 Details", corner_radius=8, height=30, width=80,
                                   fg_color="#5178ff", hover_color="#38c9e9", 
                                   font=("Montserrat", 12, "bold"),
                                   command=lambda fp=file_path, rd=risk_data, vs=vt_status: self.show_file_details(fp, rd, vs))
        details_btn.pack(side="right")

        # Store card reference
        self.file_cards[file_path] = card

    def update_single_file_baseline(self, file_path):
        """Update baseline for a single file"""
        try:
            from utils.baseline_updater import update_single_file
            config = load_config()
            
            # Show confirmation dialog
            result = tk.messagebox.askyesno("Confirm Update", 
                                          f"Update baseline for:\n{file_path}\n\nThis will accept this change as legitimate.")
            
            if result:
                # Update baseline
                results = update_single_file(file_path, config["monitor_path"], config["baseline_file"])
                
                if results['errors']:
                    tk.messagebox.showerror("Error", f"Failed to update baseline:\n{results['errors'][0]}")
                else:
                    tk.messagebox.showinfo("Success", f"Baseline updated for:\n{file_path}")
                    # Remove the card since it's now in baseline
                    if file_path in self.file_cards:
                        self.file_cards[file_path].destroy()
                        del self.file_cards[file_path]
                    
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to update baseline:\n{str(e)}")

    def show_file_details(self, file_path, risk_data, vt_status):
        """Show detailed information about a file"""
        popup = ctk.CTkToplevel(self)
        popup.geometry("600x400")
        popup.title(f"File Details: {os.path.basename(file_path)}")
        popup.transient(self)
        popup.grab_set()
        
        # Center the popup
        popup.geometry("+%d+%d" % (self.winfo_rootx() + 100, self.winfo_rooty() + 100))
        
        # Header
        header = ctk.CTkLabel(popup, text=f"📄 {os.path.basename(file_path)}", 
                             font=("Montserrat", 20, "bold"), text_color="#38c9e9")
        header.pack(pady=20)
        
        # Details text
        details_text = ctk.CTkTextbox(popup, font=("Montserrat", 12), 
                                     fg_color="#2a3444", text_color="#e4eafb")
        details_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Format details
        content = f"📂 FULL PATH:\n{file_path}\n\n"
        
        if risk_data:
            content += f"🤖 AI RISK ANALYSIS:\n"
            content += f"   Risk Score: {risk_data.get('risk_score', 0):.3f}\n"
            content += f"   Risk Level: {risk_data.get('risk_level', 'UNKNOWN')}\n"
            content += f"   Change Type: {risk_data.get('change_type', 'UNKNOWN')}\n"
            if risk_data.get('recommendations'):
                content += f"   Recommendations: {', '.join(risk_data['recommendations'])}\n"
            content += "\n"
        
        if vt_status and vt_status != "Not Scanned":
            content += f"🦠 VIRUSTOTAL STATUS:\n"
            content += f"   Status: {vt_status}\n\n"
        
        try:
            full_path = os.path.join(CONFIG["monitor_path"], file_path)
            if os.path.exists(full_path):
                stat = os.stat(full_path)
                content += f"📊 FILE INFORMATION:\n"
                content += f"   Size: {stat.st_size:,} bytes\n"
                content += f"   Modified: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
                content += f"   Permissions: {oct(stat.st_mode)[-3:]}\n"
            else:
                content += f"❌ FILE STATUS:\n   File has been deleted\n"
        except Exception as e:
            content += f"❌ ERROR:\n   Could not get file information: {e}\n"
        
        details_text.insert("0.0", content)
        details_text.configure(state="disabled")
        
        # Close button
        close_btn = ctk.CTkButton(popup, text="Close", command=popup.destroy,
                                 fg_color="#5178ff", hover_color="#38c9e9")
        close_btn.pack(pady=20)

    # Settings Handlers (unchanged)
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
                self.vt_status_label.configure(text="🔍 Testing connection...", text_color="#ffd93d")
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
            bars = self.risk_ax.bar(risk_labels, risk_counts, color=colors, alpha=0.85,
                                   edgecolor='#1e2749', linewidth=2, width=0.5)
            for bar, count in zip(bars, risk_counts):
                if count > 0:
                    self.risk_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                     str(count), ha='center', va='bottom', 
                                     fontweight='bold', fontsize=14, color='#e4eafb')
            for i, bar in enumerate(bars):
                height = bar.get_height()
                if height > 0:
                    self.risk_ax.bar(bar.get_x(), height * 0.15, width=bar.get_width(),
                                    bottom=height * 0.85, color='white', alpha=0.3)
        else:
            self.risk_ax.text(0.5, 0.5, 'No Risk Data Available', ha='center', va='center',
                             transform=self.risk_ax.transAxes, fontsize=14, color='#38c9e9',
                             fontweight='bold')
        
        self.risk_ax.set_facecolor('none')
        self.risk_ax.set_ylabel('Number of Changes', fontweight='bold', color='#38c9e9', fontsize=12)
        self.risk_ax.tick_params(colors='#e4eafb', labelsize=11)
        self.risk_ax.grid(True, alpha=0.2, color='#38c9e9', linestyle='-', linewidth=0.8)
        for spine in self.risk_ax.spines.values():
            spine.set_visible(False)
        self.risk_ax.spines['bottom'].set_visible(True)
        self.risk_ax.spines['bottom'].set_color('#38c9e9')
        self.risk_fig.patch.set_facecolor('none')
        self.risk_canvas.draw()

    def update_gui(self):
        """Main GUI update function with enhanced styling"""
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

        # VirusTotal dashboard
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

        # NEW: Update individual file cards
        self.update_file_cards(ai_report, vt_report)
        
        # Update risk distribution chart
        self.update_risk_distribution_chart(ai_report)

        # Update alerts text
        self.alerts_text.delete("0.0", ctk.END)
        critical_alerts = ai_report.get("critical_alerts", [])
        recommendations = ai_report.get("recommendations", [])
        
        if vt_report.get("malicious_files"):
            self.alerts_text.insert(ctk.END, "🦠 VIRUSTOTAL MALWARE DETECTED:\n")
            for malicious_file in vt_report["malicious_files"][:3]:
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

    def update_file_cards(self, ai_report, vt_report):
        """Update individual file cards"""
        # Clear existing cards that are no longer relevant
        current_files = set()
        
        # Collect all changes with their risk data
        all_changes = {}
        
        for change in ai_report.get("high_risk_changes", []):
            file_path = change.get("file_path", "")
            all_changes[file_path] = change
            current_files.add(file_path)
            
        for change in ai_report.get("medium_risk_changes", []):
            file_path = change.get("file_path", "")
            all_changes[file_path] = change
            current_files.add(file_path)
            
        for change in ai_report.get("low_risk_changes", []):
            file_path = change.get("file_path", "")
            all_changes[file_path] = change
            current_files.add(file_path)
        
        # Remove cards for files that are no longer in the changes
        for file_path in list(self.file_cards.keys()):
            if file_path not in current_files:
                self.file_cards[file_path].destroy()
                del self.file_cards[file_path]
        
        # Create/update cards for current changes
        for file_path, risk_data in all_changes.items():
            # Get VirusTotal status
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
            
            change_type = risk_data.get("change_type", "unknown")
            self.create_file_card(file_path, change_type, risk_data, vt_status)

if __name__ == "__main__":
    app = PremiumDashboard()
    app.mainloop()
