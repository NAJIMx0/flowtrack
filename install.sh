#!/bin/bash
# FlowTrack Installation Script

echo "========================================"
echo "FlowTrack Installation"
echo "========================================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

echo ""
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages

if [ $? -ne 0 ]; then
    echo "Warning: Some packages may have failed to install"
    echo "Trying with --user flag..."
    pip3 install -r requirements.txt --user
fi

echo ""
echo "Checking for nmap..."
which nmap

if [ $? -ne 0 ]; then
    echo "Warning: nmap is not installed"
    echo "Please install nmap for port scanning functionality:"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo "  Fedora/RHEL:   sudo dnf install nmap"
    echo "  macOS:         brew install nmap"
fi

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "To run FlowTrack:"
echo "  Linux:   sudo python3 main.py"
echo "  Windows: python main.py (as Administrator)"
echo ""
echo "Note: Packet sniffing requires root/admin privileges"
echo ""
