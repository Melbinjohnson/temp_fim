#!/bin/bash
echo "🔧 Setting up enhanced user detection for FIM..."

# Install required tools
echo "📦 Installing user detection tools..."
sudo apt-get update
sudo apt-get install -y auditd audispd-plugins lsof psmisc

# Start auditd
echo "🚀 Starting auditd..."
sudo systemctl start auditd
sudo systemctl enable auditd

# Add audit rules
echo "📋 Adding comprehensive audit rules..."
sudo auditctl -D  # Clear existing rules
sudo auditctl -w /etc -p wa -k track_mods
sudo auditctl -w /usr/bin -p wa -k track_mods  
sudo auditctl -w /usr/sbin -p wa -k track_mods
sudo auditctl -w /var -p wa -k track_mods
sudo auditctl -w /home -p wa -k track_mods
sudo auditctl -a always,exit -F arch=b64 -S open,openat,write -k track_mods
sudo auditctl -a always,exit -F arch=b64 -S unlink,rename -k track_mods

echo "✅ User detection system configured!"
echo "🔍 Available detection methods:"
echo "   - Audit logs (auditd)"  
echo "   - Open files (lsof)"
echo "   - Process users (fuser)"
echo "   - Login sessions (who)"
echo "   - File ownership (stat)"
echo "   - Environment variables"
