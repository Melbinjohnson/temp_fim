#!/usr/bin/env python3
from utils.audit_utils import get_last_modifier_advanced, check_audit_system
import os

print("🧪 Testing User Detection System")
print("=" * 40)

# Check system status
status = check_audit_system()
print(f"System Status: {status['message']}")

# Test with a file
test_file = "/tmp/test_user_detection.txt"
with open(test_file, "w") as f:
    f.write("test")

user = get_last_modifier_advanced(test_file)
print(f"Test file {test_file} -> User: {user}")

os.remove(test_file)
print("✅ Test completed")
