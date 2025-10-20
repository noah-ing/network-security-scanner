#!/bin/bash
# Simple nmap installer for Windows (Git Bash)

echo "======================================"
echo "    NMAP INSTALLER FOR WINDOWS"
echo "======================================"
echo ""

# Check if nmap is already installed
if command -v nmap &> /dev/null; then
    echo "✓ Nmap is already installed!"
    nmap --version
    echo ""
    echo "You can now run: python network_scanner.py"
    exit 0
fi

echo "Downloading nmap installer for Windows..."
echo ""

# Download nmap using curl (available in Git Bash)
curl -L -o nmap-setup.exe "https://nmap.org/dist/nmap-7.95-setup.exe"

if [ -f "nmap-setup.exe" ]; then
    echo ""
    echo "✓ Download complete!"
    echo ""
    echo "======================================"
    echo "     INSTALLATION INSTRUCTIONS:"
    echo "======================================"
    echo ""
    echo "1. The installer has been downloaded as: nmap-setup.exe"
    echo ""
    echo "2. Double-click 'nmap-setup.exe' in Windows Explorer to install"
    echo "   OR run: ./nmap-setup.exe"
    echo ""
    echo "3. During installation:"
    echo "   - Click 'Next' through the installer"
    echo "   - Accept default settings"
    echo "   - Make sure 'Add to PATH' is checked"
    echo ""
    echo "4. After installation, close and reopen Git Bash"
    echo ""
    echo "5. Verify installation by running: nmap --version"
    echo ""
    echo "6. Then run the scanner: python network_scanner.py"
    echo ""
    echo "======================================"
    
    # Try to run the installer
    echo ""
    read -p "Do you want to run the installer now? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Starting nmap installer..."
        ./nmap-setup.exe
    fi
else
    echo "ERROR: Failed to download nmap installer"
    echo ""
    echo "Please download manually from:"
    echo "https://nmap.org/download.html"
fi
