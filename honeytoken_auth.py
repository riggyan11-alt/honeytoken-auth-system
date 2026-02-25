#!/usr/bin/env python3
"""
# Author     : Riggyan Parajuli
# Student ID : 250325
Enhanced Dynamic Honeytoken Authentication Tool with Advanced Security Features
A comprehensive GUI-based security tool with intrusion detection, analytics, and reporting
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import hashlib
import hmac
import json
import os
import time
import re
import socket
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import secrets
import csv

class EnhancedHoneytokenAuthTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Honeytoken Authentication System")
        self.root.geometry("1000x750")
        self.root.configure(bg="#1e1e2e")
        
        # Initialize encryption key
        self.master_key = self._load_or_create_master_key()
        self.cipher = Fernet(self.master_key)
        
        # Data storage files
        self.users_file = "users_data.enc"
        self.honeytokens_file = "honeytokens_data.enc"
        self.intrusion_log_file = "intrusion_log.txt"
        self.login_history_file = "login_history.enc"
        self.settings_file = "settings.enc"
        
        # Load data
        self.users = self._load_users()
        self.honeytokens = self._load_honeytokens()
        self.login_history = self._load_login_history()
        self.settings = self._load_settings()
        
        # Session management
        self.current_user = None
        self.session_start_time = None
        self.otp_refresh_job = None
        self.session_timeout_job = None
        self.session_timeout_minutes = self.settings.get("session_timeout", 15)
        
        # Statistics
        self.stats = {
            "total_logins": 0,
            "failed_attempts": 0,
            "intrusions_detected": 0
        }
        
        self._create_ui()
        
    def _load_or_create_master_key(self):
        """Load or create encryption master key"""
        key_file = "master.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key
    
    def _encrypt_data(self, data):
        """Encrypt data using Fernet"""
        json_data = json.dumps(data)
        return self.cipher.encrypt(json_data.encode())
    
    def _decrypt_data(self, encrypted_data):
        """Decrypt data using Fernet"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except:
            return {}
    
    def _load_users(self):
        """Load encrypted user data"""
        if os.path.exists(self.users_file):
            with open(self.users_file, "rb") as f:
                encrypted = f.read()
                return self._decrypt_data(encrypted)
        return {}
    
    def _save_users(self):
        """Save encrypted user data"""
        encrypted = self._encrypt_data(self.users)
        with open(self.users_file, "wb") as f:
            f.write(encrypted)
    
    def _load_honeytokens(self):
        """Load encrypted honeytoken data"""
        if os.path.exists(self.honeytokens_file):
            with open(self.honeytokens_file, "rb") as f:
                encrypted = f.read()
                return self._decrypt_data(encrypted)
        return {}
    
    def _save_honeytokens(self):
        """Save encrypted honeytoken data"""
        encrypted = self._encrypt_data(self.honeytokens)
        with open(self.honeytokens_file, "wb") as f:
            f.write(encrypted)
    
    def _load_login_history(self):
        """Load encrypted login history"""
        if os.path.exists(self.login_history_file):
            with open(self.login_history_file, "rb") as f:
                encrypted = f.read()
                return self._decrypt_data(encrypted)
        return []
    
    def _save_login_history(self):
        """Save encrypted login history"""
        encrypted = self._encrypt_data(self.login_history)
        with open(self.login_history_file, "wb") as f:
            f.write(encrypted)
    
    def _load_settings(self):
        """Load application settings"""
        if os.path.exists(self.settings_file):
            with open(self.settings_file, "rb") as f:
                encrypted = f.read()
                return self._decrypt_data(encrypted)
        return {"session_timeout": 15, "max_login_attempts": 3}
    
    def _save_settings(self):
        """Save application settings"""
        encrypted = self._encrypt_data(self.settings)
        with open(self.settings_file, "wb") as f:
            f.write(encrypted)
    
    def _get_local_ip(self):
        """Get local IP address"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except:
            return "127.0.0.1"
    
    def _log_intrusion(self, username, ip=None):
        """Log intrusion attempt with enhanced details"""
        if ip is None:
            ip = self._get_local_ip()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] ⚠️ INTRUSION DETECTED - Honeytoken: '{username}' | IP: {ip} | Status: BLOCKED\n"
        
        with open(self.intrusion_log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        self.stats["intrusions_detected"] += 1
        return log_entry
    
    def _log_login_attempt(self, username, success=True, reason=""):
        """Log all login attempts"""
        entry = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "ip": self._get_local_ip(),
            "reason": reason
        }
        self.login_history.append(entry)
        self._save_login_history()
        
        if success:
            self.stats["total_logins"] += 1
        else:
            self.stats["failed_attempts"] += 1
    
    def _check_password_strength(self, password):
        """Check password strength and return score and feedback"""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("At least 8 characters")
        
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Lowercase letter")
        
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Uppercase letter")
        
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Number")
        
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Special character")
        
        strength = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        return score, strength[score], feedback
    
    def _generate_otp(self, secret, counter=None):
# TOTP: divides Unix time into 30-second windows, applies HMAC-SHA1, truncates to 6 digits
        """Generate TOTP (Time-based OTP)"""
        if counter is None:
            counter = int(time.time() / 30)
        
        counter_bytes = counter.to_bytes(8, byteorder='big')
        hmac_hash = hmac.new(secret.encode(), counter_bytes, hashlib.sha1).digest()
        
        offset = hmac_hash[-1] & 0x0f
        code = (
            (hmac_hash[offset] & 0x7f) << 24 |
            (hmac_hash[offset + 1] & 0xff) << 16 |
            (hmac_hash[offset + 2] & 0xff) << 8 |
            (hmac_hash[offset + 3] & 0xff)
        )
        
        otp = str(code % 1000000).zfill(6)
        return otp
    
    def _hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${pwdhash.hex()}"
    
    def _verify_password(self, stored_password, provided_password):
        """Verify password against hash"""
        salt, pwdhash = stored_password.split('$')
        test_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000)
        return test_hash.hex() == pwdhash
    
    def _start_session_timeout(self):
        """Start session timeout timer"""
        if self.session_timeout_job:
            self.root.after_cancel(self.session_timeout_job)
        
        timeout_ms = self.session_timeout_minutes * 60 * 1000
        self.session_timeout_job = self.root.after(timeout_ms, self._handle_session_timeout)
    
    def _handle_session_timeout(self):
        """Handle session timeout"""
        messagebox.showwarning("Session Timeout", 
                              f"Your session has expired after {self.session_timeout_minutes} minutes of inactivity.")
        self._logout()
    
    def _reset_session_timer(self):
        """Reset session timeout timer on user activity"""
        if self.current_user:
            self._start_session_timeout()
    
    def _create_ui(self):
        """Create the main UI"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#1e1e2e")
        style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4", font=("Arial", 10))
        style.configure("TButton", background="#89b4fa", foreground="#1e1e2e", font=("Arial", 10, "bold"))
        style.configure("Header.TLabel", font=("Arial", 18, "bold"), foreground="#f38ba8")
        style.configure("Subheader.TLabel", font=("Arial", 12, "bold"), foreground="#89dceb")
        
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self._show_login_screen()
    
    def _clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    # ── SCREEN: LOGIN ────────────────────────────────────────────────────────────
    def _show_login_screen(self):
        """Display enhanced login screen"""
        self._clear_frame()
        
        # Header
        header = ttk.Label(self.main_frame, text="🔐 Enhanced Honeytoken Authentication System", 
                          style="Header.TLabel")
        header.pack(pady=20)
        
        subtitle = ttk.Label(self.main_frame, 
                            text="Advanced Security | Intrusion Detection | Session Management",
                            foreground="#89dceb")
        subtitle.pack(pady=5)
        
        # Login Frame
        login_frame = ttk.Frame(self.main_frame)
        login_frame.pack(pady=30)
        
        ttk.Label(login_frame, text="Username:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=10, padx=5)
        self.username_entry = ttk.Entry(login_frame, width=35, font=("Arial", 11))
        self.username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        ttk.Label(login_frame, text="Password:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=10, padx=5)
        self.password_entry = ttk.Entry(login_frame, width=35, show="*", font=("Arial", 11))
        self.password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        # Buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        login_btn = ttk.Button(btn_frame, text="🔓 Login", command=self._handle_login, width=15)
        login_btn.grid(row=0, column=0, padx=10)
        
        register_btn = ttk.Button(btn_frame, text="➕ Register", command=self._show_register_screen, width=15)
        register_btn.grid(row=0, column=1, padx=10)
        
        # Additional options
        options_frame = ttk.Frame(self.main_frame)
        options_frame.pack(pady=20)
        
        admin_btn = ttk.Button(options_frame, text="🍯 Manage Honeytokens", 
                               command=self._show_honeytoken_manager, width=20)
        admin_btn.grid(row=0, column=0, padx=10, pady=5)
        
        stats_btn = ttk.Button(options_frame, text="📊 View Statistics", 
                              command=self._show_statistics, width=20)
        stats_btn.grid(row=0, column=1, padx=10, pady=5)
        
        reports_btn = ttk.Button(options_frame, text="📄 Export Reports", 
                                command=self._show_export_menu, width=20)
        reports_btn.grid(row=1, column=0, padx=10, pady=5)
        
        settings_btn = ttk.Button(options_frame, text="⚙️ Settings", 
                                 command=self._show_settings, width=20)
        settings_btn.grid(row=1, column=1, padx=10, pady=5)
        
        # Status
        self.status_label = ttk.Label(self.main_frame, text="", foreground="#a6e3a1")
        self.status_label.pack(pady=10)
        
        # System info
        ip_info = ttk.Label(self.main_frame, text=f"System IP: {self._get_local_ip()}", 
                           foreground="#6c7086", font=("Arial", 9))
        ip_info.pack(side=tk.BOTTOM, pady=5)

    # ── SCREEN: REGISTRATION ─────────────────────────────────────────────────────
    def _show_register_screen(self):
        """Display enhanced registration screen"""
        self._clear_frame()
        
        header = ttk.Label(self.main_frame, text="➕ Register New User", style="Header.TLabel")
        header.pack(pady=20)
        
        register_frame = ttk.Frame(self.main_frame)
        register_frame.pack(pady=20)
        
        ttk.Label(register_frame, text="Username:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=10, padx=5)
        self.reg_username_entry = ttk.Entry(register_frame, width=35, font=("Arial", 11))
        self.reg_username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        ttk.Label(register_frame, text="Password:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=10, padx=5)
        self.reg_password_entry = ttk.Entry(register_frame, width=35, show="*", font=("Arial", 11))
        self.reg_password_entry.grid(row=1, column=1, pady=10, padx=10)
        self.reg_password_entry.bind("<KeyRelease>", self._update_password_strength)
        
        ttk.Label(register_frame, text="Confirm Password:", font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=10, padx=5)
        self.reg_confirm_entry = ttk.Entry(register_frame, width=35, show="*", font=("Arial", 11))
        self.reg_confirm_entry.grid(row=2, column=1, pady=10, padx=10)
        
        # Password strength indicator
        self.strength_label = ttk.Label(register_frame, text="", font=("Arial", 10))
        self.strength_label.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        self.strength_bar = ttk.Progressbar(register_frame, length=250, mode='determinate')
        self.strength_bar.grid(row=4, column=1, pady=5)
        
        self.strength_feedback = ttk.Label(register_frame, text="", foreground="#f9e2af", 
                                          font=("Arial", 9), wraplength=300)
        self.strength_feedback.grid(row=5, column=1, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        register_btn = ttk.Button(btn_frame, text="✅ Register", 
                                 command=self._handle_register, width=15)
        register_btn.grid(row=0, column=0, padx=10)
        
        back_btn = ttk.Button(btn_frame, text="← Back", 
                             command=self._show_login_screen, width=15)
        back_btn.grid(row=0, column=1, padx=10)
    
    def _update_password_strength(self, event=None):
        """Update password strength indicator in real-time"""
        password = self.reg_password_entry.get()
        
        if not password:
            self.strength_label.config(text="")
            self.strength_bar['value'] = 0
            self.strength_feedback.config(text="")
            return
        
        score, strength, feedback = self._check_password_strength(password)
        
        colors = {
            "Very Weak": "#f38ba8",
            "Weak": "#fab387",
            "Fair": "#f9e2af",
            "Good": "#a6e3a1",
            "Strong": "#94e2d5",
            "Very Strong": "#89b4fa"
        }
        
        self.strength_label.config(text=f"Strength: {strength}", 
                                  foreground=colors.get(strength, "#cdd6f4"))
        self.strength_bar['value'] = (score / 5) * 100
        
        if feedback:
            self.strength_feedback.config(text=f"Missing: {', '.join(feedback)}")
        else:
            self.strength_feedback.config(text="✅ Excellent password!")
    
    def _handle_register(self):
        """Handle user registration with validation"""
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if username in self.users or username in self.honeytokens:
            messagebox.showerror("Error", "Username already exists")
            return
        
        score, strength, _ = self._check_password_strength(password)
        if score < 3:
            result = messagebox.askyesno("Weak Password", 
                                        f"Password strength: {strength}\n\n"
                                        "This password is weak. Continue anyway?")
            if not result:
                return
        
        # Generate unique secret for OTP
        otp_secret = secrets.token_hex(20)
        
        # Store user
        self.users[username] = {
            "password": self._hash_password(password),
            "otp_secret": otp_secret,
            "created": datetime.now().isoformat(),
            "last_login": None,
            "login_count": 0
        }
        
        self._save_users()
        messagebox.showinfo("Success", 
                           f"User '{username}' registered successfully!\n\n"
                           "You can now login with your credentials.")
        self._show_login_screen()
    
    def _handle_login(self):
        """Handle login attempt with enhanced validation"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        
        # Check if honeytoken — alert triggers on username match alone.
        # Real attackers should never know which accounts are traps,
        # so any login attempt using a honeytoken username is flagged immediately.
        if username in self.honeytokens:
            log_entry = self._log_intrusion(username)
            self._log_login_attempt(username, success=False, reason="Honeytoken triggered")
            self.honeytokens[username]["triggered_count"] = \
                self.honeytokens[username].get("triggered_count", 0) + 1
            self._save_honeytokens()
            messagebox.showerror("🚨 SECURITY ALERT",
                                 f"Honeytoken Triggered!\n\n{log_entry}\n"
                                 "This incident has been logged and reported.\n"
                                 "System administrators have been notified.")
            self.password_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            return
        
        # Check legitimate user
        if username not in self.users:
            self._log_login_attempt(username, success=False, reason="Invalid username")
            messagebox.showerror("Error", "Invalid credentials")
            self.password_entry.delete(0, tk.END)
            return
        
        user = self.users[username]
        if not self._verify_password(user["password"], password):
            self._log_login_attempt(username, success=False, reason="Invalid password")
            messagebox.showerror("Error", "Invalid credentials")
            self.password_entry.delete(0, tk.END)
            return
        
        # Successful login - proceed to OTP
        self.current_user = username
        self.session_start_time = datetime.now()
        self._show_otp_screen()
    
    # ── SCREEN: OTP VERIFICATION ─────────────────────────────────────────────────
    def _show_otp_screen(self):
        """Display OTP verification screen"""
        self._clear_frame()
        
        header = ttk.Label(self.main_frame, text=f"🔑 Two-Factor Authentication", 
                          style="Header.TLabel")
        header.pack(pady=20)
        
        user_label = ttk.Label(self.main_frame, text=f"Authenticating: {self.current_user}", 
                              font=("Arial", 12), foreground="#89dceb")
        user_label.pack(pady=5)
        
        info_label = ttk.Label(self.main_frame, 
                               text="Your encrypted OTP code rotates every 30 seconds",
                               foreground="#a6e3a1")
        info_label.pack(pady=10)
        
        # OTP display
        otp_frame = ttk.Frame(self.main_frame)
        otp_frame.pack(pady=20)
        
        ttk.Label(otp_frame, text="Current OTP:", font=("Arial", 13, "bold")).grid(row=0, column=0, padx=10)
        
        self.otp_display = ttk.Label(otp_frame, text="------", 
                                     font=("Courier", 28, "bold"), 
                                     foreground="#f9e2af")
        self.otp_display.grid(row=0, column=1, padx=10)
        
        self.timer_label = ttk.Label(otp_frame, text="", foreground="#89dceb", font=("Arial", 11))
        self.timer_label.grid(row=1, column=1, pady=5)
        
        # Show OTP button
        show_otp_btn = ttk.Button(self.main_frame, text="👁️ Show My OTP Code", 
                                  command=self._show_current_otp, width=20)
        show_otp_btn.pack(pady=15)
        
        # Verification frame
        verify_frame = ttk.Frame(self.main_frame)
        verify_frame.pack(pady=20)
        
        ttk.Label(verify_frame, text="Enter OTP Code:", font=("Arial", 11)).grid(row=0, column=0, padx=10)
        self.otp_entry = ttk.Entry(verify_frame, width=20, font=("Courier", 16))
        self.otp_entry.grid(row=0, column=1, padx=10)
        
        verify_btn = ttk.Button(verify_frame, text="✅ Verify", command=self._verify_otp, width=12)
        verify_btn.grid(row=0, column=2, padx=10)
        
        # Back button
        back_btn = ttk.Button(self.main_frame, text="← Cancel", command=self._show_login_screen, width=15)
        back_btn.pack(pady=20)
    
    def _show_current_otp(self):
        """Display and auto-refresh OTP"""
        user = self.users[self.current_user]
        otp_secret = user["otp_secret"]
        
        def update_otp():
            current_otp = self._generate_otp(otp_secret)
            self.otp_display.config(text=current_otp)
            
            time_remaining = 30 - (int(time.time()) % 30)
            self.timer_label.config(text=f"⏱️ Expires in {time_remaining} seconds")
            
            self.otp_refresh_job = self.root.after(1000, update_otp)
        
        update_otp()
    
    def _verify_otp(self):
        """Verify entered OTP"""
        entered_otp = self.otp_entry.get().strip()
        
        if not entered_otp:
            messagebox.showerror("Error", "Please enter OTP code")
            return
        
        user = self.users[self.current_user]
        otp_secret = user["otp_secret"]
        
        current_counter = int(time.time() / 30)
        valid = False
        
        for offset in [0, -1]:
            expected_otp = self._generate_otp(otp_secret, current_counter + offset)
            if entered_otp == expected_otp:
                valid = True
                break
        
        if valid:
            if self.otp_refresh_job:
                self.root.after_cancel(self.otp_refresh_job)
            
            # Update user stats
            self.users[self.current_user]["last_login"] = datetime.now().isoformat()
            self.users[self.current_user]["login_count"] = user.get("login_count", 0) + 1
            self._save_users()
            
            self._log_login_attempt(self.current_user, success=True)
            
            messagebox.showinfo("✅ Success", 
                               f"Welcome back, {self.current_user}!\n\n"
                               f"Last login: {user.get('last_login', 'First time')}\n"
                               f"Total logins: {self.users[self.current_user]['login_count']}")
            
            self._start_session_timeout()
            self._show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid OTP code. Please try again.")
            self.otp_entry.delete(0, tk.END)
    
    # ── SCREEN: DASHBOARD ────────────────────────────────────────────────────────
    def _show_dashboard(self):
        """Display enhanced user dashboard"""
        self._clear_frame()
        
        header = ttk.Label(self.main_frame, text=f"✅ Welcome, {self.current_user}!", 
                          style="Header.TLabel")
        header.pack(pady=20)
        
        session_info = ttk.Label(self.main_frame, 
                                text=f"Session started: {self.session_start_time.strftime('%I:%M %p')} | "
                                     f"Auto-logout in {self.session_timeout_minutes} min",
                                foreground="#89dceb")
        session_info.pack(pady=5)
        
        # Quick stats
        stats_frame = ttk.Frame(self.main_frame)
        stats_frame.pack(pady=20)
        
        user = self.users[self.current_user]
        
        ttk.Label(stats_frame, text=f"📊 Your Account Statistics", 
                 style="Subheader.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(stats_frame, text=f"Account created:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text=user.get("created", "Unknown")[:10], 
                 foreground="#a6e3a1").grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(stats_frame, text=f"Total logins:", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text=str(user.get("login_count", 0)), 
                 foreground="#a6e3a1").grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(stats_frame, text=f"Last login:", font=("Arial", 10)).grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        last_login = user.get("last_login", "First time")
        if last_login != "First time":
            last_login = last_login[:19].replace("T", " ")
        ttk.Label(stats_frame, text=last_login, 
                 foreground="#a6e3a1").grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Action buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="👤 My Profile", 
                  command=self._show_profile, width=18).grid(row=0, column=0, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="📋 Login History", 
                  command=self._show_my_login_history, width=18).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="🚨 Intrusion Log", 
                  command=self._show_intrusion_log, width=18).grid(row=1, column=0, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="📊 System Stats", 
                  command=self._show_statistics, width=18).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="🔐 Change Password", 
                  command=self._show_change_password, width=18).grid(row=2, column=0, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="🚪 Logout", 
                  command=self._logout, width=18).grid(row=2, column=1, padx=10, pady=5)
    
    def _show_profile(self):
        """Display user profile"""
        profile_window = tk.Toplevel(self.root)
        profile_window.title(f"Profile - {self.current_user}")
        profile_window.geometry("500x400")
        profile_window.configure(bg="#1e1e2e")
        
        user = self.users[self.current_user]
        
        ttk.Label(profile_window, text=f"👤 User Profile", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        info_frame = ttk.Frame(profile_window)
        info_frame.pack(pady=20, padx=30, fill=tk.BOTH)
        
        details = [
            ("Username:", self.current_user),
            ("Account Created:", user.get("created", "Unknown")[:10]),
            ("Total Logins:", str(user.get("login_count", 0))),
            ("Last Login:", user.get("last_login", "N/A")[:19].replace("T", " ") if user.get("last_login") else "First time"),
            ("Current Session:", self.session_start_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("Session IP:", self._get_local_ip())
        ]
        
        for i, (label, value) in enumerate(details):
            ttk.Label(info_frame, text=label, font=("Arial", 11, "bold")).grid(row=i, column=0, sticky=tk.W, pady=8)
            ttk.Label(info_frame, text=value, foreground="#a6e3a1").grid(row=i, column=1, sticky=tk.W, pady=8, padx=20)
    
    def _show_my_login_history(self):
        """Display user's login history"""
        history_window = tk.Toplevel(self.root)
        history_window.title("My Login History")
        history_window.geometry("800x500")
        history_window.configure(bg="#1e1e2e")
        
        ttk.Label(history_window, text="📋 My Login History", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        # Filter for current user
        user_history = [entry for entry in self.login_history if entry["username"] == self.current_user]
        
        text_area = scrolledtext.ScrolledText(history_window, width=90, height=22, 
                                             bg="#313244", fg="#cdd6f4", font=("Courier", 10))
        text_area.pack(padx=20, pady=10)
        
        if user_history:
            text_area.insert(tk.END, f"{'Timestamp':<22} {'Success':<10} {'IP Address':<18} {'Reason'}\n")
            text_area.insert(tk.END, "="*80 + "\n")
            
            for entry in reversed(user_history[-50:]):  # Last 50 entries
                timestamp = entry["timestamp"][:19].replace("T", " ")
                success = "✅ Yes" if entry["success"] else "❌ No"
                ip = entry.get("ip", "Unknown")
                reason = entry.get("reason", "")
                
                text_area.insert(tk.END, f"{timestamp:<22} {success:<10} {ip:<18} {reason}\n")
        else:
            text_area.insert(tk.END, "No login history available.")
        
        text_area.config(state=tk.DISABLED)
    
    def _show_change_password(self):
        """Display change password dialog"""
        change_window = tk.Toplevel(self.root)
        change_window.title("Change Password")
        change_window.geometry("450x350")
        change_window.configure(bg="#1e1e2e")
        
        ttk.Label(change_window, text="🔐 Change Password", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        form_frame = ttk.Frame(change_window)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Current Password:").grid(row=0, column=0, sticky=tk.W, pady=10, padx=5)
        current_pw = ttk.Entry(form_frame, width=30, show="*")
        current_pw.grid(row=0, column=1, pady=10)
        
        ttk.Label(form_frame, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=10, padx=5)
        new_pw = ttk.Entry(form_frame, width=30, show="*")
        new_pw.grid(row=1, column=1, pady=10)
        
        ttk.Label(form_frame, text="Confirm New:").grid(row=2, column=0, sticky=tk.W, pady=10, padx=5)
        confirm_pw = ttk.Entry(form_frame, width=30, show="*")
        confirm_pw.grid(row=2, column=1, pady=10)
        
        def do_change():
            user = self.users[self.current_user]
            
            if not self._verify_password(user["password"], current_pw.get()):
                messagebox.showerror("Error", "Current password is incorrect")
                return
            
            if new_pw.get() != confirm_pw.get():
                messagebox.showerror("Error", "New passwords do not match")
                return
            
            if len(new_pw.get()) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
            
            self.users[self.current_user]["password"] = self._hash_password(new_pw.get())
            self._save_users()
            
            messagebox.showinfo("Success", "Password changed successfully!")
            change_window.destroy()
        
        ttk.Button(form_frame, text="✅ Change Password", command=do_change).grid(row=3, column=1, pady=20)
    
    def _show_intrusion_log(self):
        """Display intrusion log"""
        self._reset_session_timer()
        
        log_window = tk.Toplevel(self.root)
        log_window.title("Intrusion Detection Log")
        log_window.geometry("900x500")
        log_window.configure(bg="#1e1e2e")
        
        ttk.Label(log_window, text="🚨 Intrusion Detection Log", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        log_text = scrolledtext.ScrolledText(log_window, width=100, height=22, 
                                             bg="#313244", fg="#cdd6f4", font=("Courier", 10))
        log_text.pack(padx=20, pady=10)
        
        if os.path.exists(self.intrusion_log_file):
            with open(self.intrusion_log_file, "r", encoding="utf-8") as f:
                content = f.read()
                if content:
                    log_text.insert(tk.END, content)
                else:
                    log_text.insert(tk.END, "✅ No intrusions detected yet. System is secure!")
        else:
            log_text.insert(tk.END, "✅ No intrusions detected yet. System is secure!")
        
        log_text.config(state=tk.DISABLED)
    
    def _show_statistics(self):
        """Display system statistics"""
        self._reset_session_timer()
        
        stats_window = tk.Toplevel(self.root)
        stats_window.title("System Statistics")
        stats_window.geometry("600x550")
        stats_window.configure(bg="#1e1e2e")
        
        ttk.Label(stats_window, text="📊 System Statistics", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        stats_frame = ttk.Frame(stats_window)
        stats_frame.pack(pady=20, padx=30)
        
        # Calculate stats
        total_users = len(self.users)
        total_honeytokens = len(self.honeytokens)
        total_logins = sum(1 for entry in self.login_history if entry["success"])
        failed_logins = sum(1 for entry in self.login_history if not entry["success"])
        
        intrusions = 0
        if os.path.exists(self.intrusion_log_file):
            with open(self.intrusion_log_file, "r", encoding="utf-8") as f:
                intrusions = len(f.readlines())
        
        stats_data = [
            ("👥 Total Users:", str(total_users)),
            ("🍯 Active Honeytokens:", str(total_honeytokens)),
            ("✅ Successful Logins:", str(total_logins)),
            ("❌ Failed Attempts:", str(failed_logins)),
            ("🚨 Intrusions Detected:", str(intrusions)),
            ("📅 System Uptime:", "Active"),
            ("🌐 Server IP:", self._get_local_ip()),
            ("⏱️ Session Timeout:", f"{self.session_timeout_minutes} minutes")
        ]
        
        for i, (label, value) in enumerate(stats_data):
            ttk.Label(stats_frame, text=label, font=("Arial", 12, "bold")).grid(row=i, column=0, sticky=tk.W, pady=10)
            ttk.Label(stats_frame, text=value, font=("Arial", 12), 
                     foreground="#a6e3a1").grid(row=i, column=1, sticky=tk.W, pady=10, padx=30)
    
    def _show_export_menu(self):
        """Show export options"""
        self._reset_session_timer()
        
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Reports")
        export_window.geometry("500x400")
        export_window.configure(bg="#1e1e2e")
        
        ttk.Label(export_window, text="📄 Export Reports", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        ttk.Label(export_window, text="Choose what to export:", 
                 font=("Arial", 11)).pack(pady=10)
        
        btn_frame = ttk.Frame(export_window)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="📊 Export Login History (CSV)", 
                  command=lambda: self._export_to_csv("login_history"), 
                  width=30).pack(pady=10)
        
        ttk.Button(btn_frame, text="🚨 Export Intrusion Log (TXT)", 
                  command=lambda: self._export_to_csv("intrusions"), 
                  width=30).pack(pady=10)
        
        ttk.Button(btn_frame, text="📋 Export Full Report (CSV)", 
                  command=lambda: self._export_to_csv("full_report"), 
                  width=30).pack(pady=10)
    
    def _export_to_csv(self, export_type):
        """Export data to CSV file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv" if export_type != "intrusions" else ".txt",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"{export_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not filename:
            return
        
        try:
            if export_type == "login_history":
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Username", "Success", "IP Address", "Reason"])
                    
                    for entry in self.login_history:
                        writer.writerow([
                            entry["timestamp"],
                            entry["username"],
                            "Yes" if entry["success"] else "No",
                            entry.get("ip", "Unknown"),
                            entry.get("reason", "")
                        ])
            
            elif export_type == "intrusions":
                if os.path.exists(self.intrusion_log_file):
                    with open(self.intrusion_log_file, 'r', encoding='utf-8') as source:
                        with open(filename, 'w') as dest:
                            dest.write(source.read())
                else:
                    with open(filename, 'w') as f:
                        f.write("No intrusions detected yet.\n")
            
            elif export_type == "full_report":
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["System Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                    writer.writerow([])
                    writer.writerow(["Total Users:", len(self.users)])
                    writer.writerow(["Active Honeytokens:", len(self.honeytokens)])
                    writer.writerow(["Total Login Attempts:", len(self.login_history)])
                    writer.writerow([])
                    writer.writerow(["Username", "Created", "Login Count", "Last Login"])
                    
                    for username, data in self.users.items():
                        writer.writerow([
                            username,
                            data.get("created", "Unknown")[:10],
                            data.get("login_count", 0),
                            data.get("last_login", "Never")[:19] if data.get("last_login") else "Never"
                        ])
            
            messagebox.showinfo("Success", f"Report exported successfully to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def _show_settings(self):
        """Display settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x400")
        settings_window.configure(bg="#1e1e2e")
        
        ttk.Label(settings_window, text="⚙️ System Settings", 
                 font=("Arial", 16, "bold"), foreground="#f38ba8").pack(pady=20)
        
        settings_frame = ttk.Frame(settings_window)
        settings_frame.pack(pady=20, padx=30)
        
        ttk.Label(settings_frame, text="Session Timeout (minutes):", 
                 font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=15)
        
        timeout_var = tk.IntVar(value=self.session_timeout_minutes)
        timeout_spin = ttk.Spinbox(settings_frame, from_=5, to=60, textvariable=timeout_var, width=10)
        timeout_spin.grid(row=0, column=1, pady=15, padx=20)
        
        ttk.Label(settings_frame, text="Max Login Attempts:", 
                 font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=15)
        
        attempts_var = tk.IntVar(value=self.settings.get("max_login_attempts", 3))
        attempts_spin = ttk.Spinbox(settings_frame, from_=1, to=10, textvariable=attempts_var, width=10)
        attempts_spin.grid(row=1, column=1, pady=15, padx=20)
        
        def save_settings():
            self.session_timeout_minutes = timeout_var.get()
            self.settings["session_timeout"] = self.session_timeout_minutes
            self.settings["max_login_attempts"] = attempts_var.get()
            self._save_settings()
            
            messagebox.showinfo("Success", "Settings saved successfully!")
            settings_window.destroy()
        
        ttk.Button(settings_frame, text="💾 Save Settings", command=save_settings, 
                  width=20).grid(row=2, column=0, columnspan=2, pady=30)
    
    # ── SCREEN: HONEYTOKEN MANAGER ───────────────────────────────────────────────
    def _show_honeytoken_manager(self):
        """Display honeytoken management screen"""
        self._clear_frame()
        
        header = ttk.Label(self.main_frame, text="🍯 Honeytoken Manager", style="Header.TLabel")
        header.pack(pady=20)
        
        info = ttk.Label(self.main_frame, 
                        text="Create fake credentials that trigger security alerts when used",
                        foreground="#89dceb", font=("Arial", 11))
        info.pack(pady=10)
        
        # Create honeytoken frame
        create_frame = ttk.Frame(self.main_frame)
        create_frame.pack(pady=20)
        
        ttk.Label(create_frame, text="Fake Username:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=10, padx=5)
        self.honey_username_entry = ttk.Entry(create_frame, width=35, font=("Arial", 11))
        self.honey_username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        ttk.Label(create_frame, text="Fake Password:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=10, padx=5)
        self.honey_password_entry = ttk.Entry(create_frame, width=35, show="*", font=("Arial", 11))
        self.honey_password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        create_btn = ttk.Button(create_frame, text="➕ Create Honeytoken", 
                               command=self._create_honeytoken, width=20)
        create_btn.grid(row=2, column=1, pady=15)
        
        # List existing honeytokens
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(pady=20, fill=tk.BOTH, expand=True)
        
        ttk.Label(list_frame, text="Active Honeytokens:", 
                 font=("Arial", 13, "bold"), foreground="#f9e2af").pack(anchor=tk.W, pady=10)
        
        self.honeytoken_listbox = tk.Listbox(list_frame, width=70, height=10, 
                                             bg="#313244", fg="#cdd6f4", font=("Courier", 10))
        self.honeytoken_listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self._refresh_honeytoken_list()
        
        btn_frame = ttk.Frame(list_frame)
        btn_frame.pack(pady=10)
        
        delete_btn = ttk.Button(btn_frame, text="🗑️ Delete Selected", 
                               command=self._delete_honeytoken, width=18)
        delete_btn.grid(row=0, column=0, padx=10)
        
        back_btn = ttk.Button(btn_frame, text="← Back to Login", 
                             command=self._show_login_screen, width=18)
        back_btn.grid(row=0, column=1, padx=10)
    
    def _create_honeytoken(self):
        """Create a new honeytoken"""
        username = self.honey_username_entry.get().strip()
        password = self.honey_password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        
        if username in self.users or username in self.honeytokens:
            messagebox.showerror("Error", "Username already exists")
            return
        
        self.honeytokens[username] = {
            "password": self._hash_password(password),
            "created": datetime.now().isoformat(),
            "triggered_count": 0
        }
        
        self._save_honeytokens()
        messagebox.showinfo("Success", 
                           f"Honeytoken '{username}' created successfully!\n\n"
                           "Any login attempt with these credentials will trigger an intrusion alert.")
        
        self.honey_username_entry.delete(0, tk.END)
        self.honey_password_entry.delete(0, tk.END)
        self._refresh_honeytoken_list()
    
    def _refresh_honeytoken_list(self):
        """Refresh honeytoken listbox"""
        self.honeytoken_listbox.delete(0, tk.END)
        
        if not self.honeytokens:
            self.honeytoken_listbox.insert(tk.END, "No honeytokens created yet")
        else:
            for username, data in self.honeytokens.items():
                created = data["created"][:10]
                triggered = data.get("triggered_count", 0)
                entry = f"🍯 {username:<20} | Created: {created} | Triggered: {triggered} times"
                self.honeytoken_listbox.insert(tk.END, entry)
    
    def _delete_honeytoken(self):
        """Delete selected honeytoken"""
        selection = self.honeytoken_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a honeytoken to delete")
            return
        
        if not self.honeytokens:
            return
        
        selected_text = self.honeytoken_listbox.get(selection[0])
        if selected_text == "No honeytokens created yet":
            return
        
        username = selected_text.split()[1]
        
        if messagebox.askyesno("Confirm Deletion", 
                              f"Are you sure you want to delete honeytoken '{username}'?"):
            del self.honeytokens[username]
            self._save_honeytokens()
            self._refresh_honeytoken_list()
            messagebox.showinfo("Success", f"Honeytoken '{username}' deleted successfully")
    
    def _logout(self):
        """Logout current user"""
        if self.otp_refresh_job:
            self.root.after_cancel(self.otp_refresh_job)
        if self.session_timeout_job:
            self.root.after_cancel(self.session_timeout_job)
        
        messagebox.showinfo("Logged Out", f"Goodbye, {self.current_user}!")
        
        self.current_user = None
        self.session_start_time = None
        self._show_login_screen()

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedHoneytokenAuthTool(root)
    root.mainloop()