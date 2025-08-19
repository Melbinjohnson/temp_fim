# gui/gui_main.py
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

CONFIG = load_config()
SCAN_INTERVAL = CONFIG.get("scan_interval", 10) * 1000
REPORT_PATH = CONFIG["report_file"]
AI_REPORT_PATH = CONFIG.get("ai_report_file", "data/ai_risk_report.json")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Set matplotlib style for premium look
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

class PremiumDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1280x900")
        self.title("Premium FIM Dashboard")

        # -- Fixed background image handling --
        try:
            img_bg = Image.open("premium_gradient_bg.jpg").resize((1280,900))
            self.bg_img = ctk.CTkImage(light_image=img_bg, dark_image=img_bg, size=(1280, 900))
        except Exception:
            # Create a gradient-like background if no image
            img_bg = Image.new("RGBA", (1280,900), (26, 34, 56, 255))
            self.bg_img = ctk.CTkImage(light_image=img_bg, dark_image=img_bg, size=(1280, 900))
        
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

        # Status indicator at bottom of sidebar
        self.sidebar_status = ctk.CTkLabel(self.sidebar, text="🟢 System Active", 
                                          font=("Montserrat", 12), text_color="#00d084")
        self.sidebar_status.pack(side="bottom", pady=20)

        # -- Main container --
        self.pages = {}
        self.monitor_process = None

        # Live Monitoring Page
        self.pages["monitor"] = self.create_monitor_page()
        # AI Analysis Page
        self.pages["ai"] = self.create_ai_page()
        # Settings Page
        self.pages["settings"] = self.create_settings_page()

        self.show_monitor()
        self.update_gui()

    def hide_all_pages(self):
        for p in self.pages.values():
            p.place_forget()

    def show_monitor(self):
        self.hide_all_pages()
        self.pages["monitor"].place(relx=0.21, rely=0.04, relwidth=0.77, relheight=0.92)
        self.highlight_button(self.btn_monitor)

    def show_ai(self):
        self.hide_all_pages()
        self.pages["ai"].place(relx=0.21, rely=0.04, relwidth=0.77, relheight=0.92)
        self.highlight_button(self.btn_ai)

    def show_settings(self):
        self.hide_all_pages()
        self.pages["settings"].place(relx=0.21, rely=0.04, relwidth=0.77, relheight=0.92)
        self.highlight_button(self.btn_settings)

    def highlight_button(self, active_btn):
        # Reset all buttons
        for btn in [self.btn_monitor, self.btn_ai, self.btn_settings]:
            btn.configure(fg_color="#5178ff")
        # Highlight active button
        active_btn.configure(fg_color="#38c9e9")

    def create_monitor_page(self):
        # Fixed: Use single "transparent" instead of tuple
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="Live File Integrity Monitoring", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # KPI Cards Container - Fixed color
        kpi_container = ctk.CTkFrame(frame, height=130, corner_radius=18, fg_color="#2a3444")
        kpi_container.pack(fill="x", pady=(0, 20), padx=20)

        # Real-time KPIs with glassmorphism effect - Fixed all colors
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

        # Main content area with charts and table - Fixed colors
        content_frame = ctk.CTkFrame(frame, corner_radius=18, fg_color="#2a3444")
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Left side - Table - Fixed colors
        left_frame = ctk.CTkFrame(content_frame, corner_radius=15, fg_color="#3a4555")
        left_frame.pack(side="left", fill="both", expand=True, padx=(15, 7), pady=15)

        table_header = ctk.CTkLabel(left_frame, text="🔍 Detected Changes", 
                                   font=("Montserrat", 18, "bold"), text_color="#38c9e9")
        table_header.pack(anchor="nw", padx=15, pady=(10, 5))

        # Enhanced Treeview Table
        columns = ("File", "Type", "Risk", "Score")
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
            self.change_tree.column(col, width=200 if col=="File" else 100, anchor="center" if col!="File" else "w")
        
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.change_tree.yview)
        self.change_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.change_tree.pack(side="left", fill="both", expand=True, padx=(15, 0), pady=(10, 15))
        tree_scroll.pack(side="right", fill="y", pady=(10, 15), padx=(0, 15))

        # Configure risk level tags with premium colors
        self.change_tree.tag_configure("high_risk", background="#4a2c2c", foreground="#ff6b9d")
        self.change_tree.tag_configure("medium_risk", background="#4a4a2c", foreground="#ffd93d")
        self.change_tree.tag_configure("low_risk", background="#2c4a2c", foreground="#6bcf7f")

        # Right side - Charts - Fixed colors
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

    def create_ai_page(self):
        # Fixed: Use single "transparent" instead of tuple
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="🤖 AI Risk Analysis Dashboard", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # AI Score Card - Fixed colors
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

        # Risk trend indicator - Fixed colors
        trend_label = ctk.CTkLabel(ai_card, text="📈 Trending Safe", font=("Montserrat", 16),
                                  text_color="#6bcf7f", fg_color="#3a4555", 
                                  corner_radius=10, width=180, height=40)
        trend_label.place(relx=0.75, rely=0.35)

        # Enhanced Risk Distribution Chart - Fixed colors
        chart_card = ctk.CTkFrame(frame, corner_radius=16, fg_color="#2a3444", height=280)
        chart_card.pack(fill="x", padx=20, pady=(0, 15))

        chart_header = ctk.CTkLabel(chart_card, text="📊 Risk Level Distribution", 
                                   font=("Montserrat", 20, "bold"), text_color="#38c9e9")
        chart_header.pack(pady=(15, 10))

        self.risk_fig, self.risk_ax = plt.subplots(figsize=(8, 3.5), facecolor='none')
        self.risk_canvas = FigureCanvasTkAgg(self.risk_fig, master=chart_card)
        self.risk_canvas.get_tk_widget().pack(padx=15, pady=(0, 15))

        # Enhanced Alerts Panel - Fixed colors
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
        # Fixed: Use single "transparent" instead of tuple
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        
        # Header
        header = ctk.CTkLabel(frame, text="⚙️ System Configuration", 
                             font=("Montserrat", 28, "bold"), text_color="#38c9e9")
        header.pack(pady=(10, 20))

        # AI Settings Card - Fixed colors
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

        # Traditional Settings Card - Fixed colors
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

        # System Control Card - Fixed colors
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
        if self.monitor_process and self.monitor_process.poll() is None:
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
        """Main GUI update function with enhanced styling"""
        report = read_report()
        ai_report = read_ai_report()
        
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

        # Update table with enhanced styling
        for item in self.change_tree.get_children():
            self.change_tree.delete(item)
        
        # Add changes with color coding
        all_changes = []
        for change in ai_report.get("high_risk_changes", []):
            all_changes.append((change, "high_risk"))
        for change in ai_report.get("medium_risk_changes", []):
            all_changes.append((change, "medium_risk"))
        for change in ai_report.get("low_risk_changes", []):
            all_changes.append((change, "low_risk"))
        
        for change, tag in all_changes:
            file_path = change.get("file_path", "")
            display_path = file_path[:50] + "..." if len(file_path) > 50 else file_path
            self.change_tree.insert("", "end", values=(
                display_path,
                change.get("change_type", "").title(),
                change.get("risk_level", ""),
                f"{change.get('risk_score', 0):.3f}"
            ), tags=(tag,))

        # Update enhanced charts
        self.update_pie_chart(modified_count, new_count, deleted_count)
        self.update_bar_chart(modified_count, new_count, deleted_count)
        self.update_risk_distribution_chart(ai_report)

        # Update alerts text with enhanced formatting
        self.alerts_text.delete("0.0", ctk.END)
        critical_alerts = ai_report.get("critical_alerts", [])
        recommendations = ai_report.get("recommendations", [])
        
        if critical_alerts:
            self.alerts_text.insert(ctk.END, "🚨 CRITICAL ALERTS:\n")
            for alert in critical_alerts:
                self.alerts_text.insert(ctk.END, f"• {alert}\n")
            self.alerts_text.insert(ctk.END, "\n")
        
        if recommendations:
            self.alerts_text.insert(ctk.END, "💡 RECOMMENDATIONS:\n")
            for rec in recommendations:
                self.alerts_text.insert(ctk.END, f"• {rec}\n")
        
        if not critical_alerts and not recommendations:
            self.alerts_text.insert(ctk.END, "✅ All systems operating normally.\n")
            self.alerts_text.insert(ctk.END, "No critical alerts or recommendations at this time.")

        # Schedule next update
        self.after(SCAN_INTERVAL, self.update_gui)

if __name__ == "__main__":
    app = PremiumDashboard()
    app.mainloop()
