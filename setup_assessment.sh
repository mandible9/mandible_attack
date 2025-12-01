#!/bin/bash

# Vulnerability Assessment Framework Setup Script
# This script installs and configures the comprehensive vulnerability assessment framework

set -e  # Exit on any error

echo "=========================================="
echo "Vulnerability Assessment Framework Setup"
echo "=========================================="
echo "Purpose: Educational and defensive security research only"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root (for tool installation)
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. This is required for tool installation."
else
   print_warning "Not running as root. Some tools may fail to install."
   print_warning "Consider running with sudo: sudo ./setup_assessment.sh"
fi

# Update package lists
print_info "Updating package lists..."
sudo apt update || print_error "Failed to update package lists"

# Install Python dependencies
print_info "Installing Python dependencies..."
pip3 install -r requirements.txt || print_error "Failed to install Python dependencies"

# Install essential vulnerability assessment tools
print_info "Installing Network Scanning tools..."
sudo apt install -y nmap masscan rustscan unicornscan zmap || print_error "Failed to install network scanning tools"

print_info "Installing OS Vulnerability Scanners..."
sudo apt install -y lynis debsecan openscap-scanner || print_error "Failed to install OS vulnerability scanners"

print_info "Installing Web Application Scanners..."
sudo apt install -y nikto wapiti whatweb || print_error "Failed to install web application scanners"

print_info "Installing SSL/TLS Scanners..."
sudo apt install -y sslyze || print_error "Failed to install SSL/TLS scanners"

# Install testssl.sh separately
if ! command -v testssl.sh &> /dev/null; then
    print_info "Installing testssl.sh..."
    cd /tmp
    git clone https://github.com/drwetter/testssl.sh.git
    sudo cp testssl.sh/testssl.sh /usr/local/bin/
    sudo chmod +x /usr/local/bin/testssl.sh
    cd - > /dev/null
    rm -rf /tmp/testssl.sh
else
    print_status "testssl.sh already installed"
fi

print_info "Installing Configuration and Compliance tools..."
sudo apt install -y osquery || print_error "Failed to install configuration tools"

print_info "Installing Malware and Rootkit Detection tools..."
sudo apt install -y rkhunter chkrootkit aide clamav || print_error "Failed to install malware detection tools"

# Install Trivy
if ! command -v trivy &> /dev/null; then
    print_info "Installing Trivy..."
    sudo apt install -y wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt update
    sudo apt install -y trivy
else
    print_status "Trivy already installed"
fi

# Install Grype
if ! command -v grype &> /dev/null; then
    print_info "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
else
    print_status "Grype already installed"
fi

# Install Docker Bench Security
if ! command -v docker-bench-security &> /dev/null; then
    print_info "Installing Docker Bench Security..."
    sudo apt install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker
    git clone https://github.com/docker/docker-bench-security.git
    sudo cp docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security
    sudo chmod +x /usr/local/bin/docker-bench-security
    rm -rf docker-bench-security
else
    print_status "Docker Bench Security already installed"
fi

print_info "Installing Database Security tools..."
sudo apt install -y mysqltuner || print_error "Failed to install database security tools"

print_info "Installing Network Analysis tools..."
sudo apt install -y tcpdump tshark wireshark-common || print_error "Failed to install network analysis tools"

print_info "Installing OSINT and Reconnaissance tools..."
sudo apt install -y recon-ng theharvester || print_error "Failed to install OSINT tools"

print_info "Installing Password Analysis tools..."
sudo apt install -y cracklib-runtime john || print_error "Failed to install password analysis tools"

print_info "Installing Log Analysis tools..."
sudo apt install -y logwatch || print_error "Failed to install log analysis tools"

# Install Checkov
if ! command -v checkov &> /dev/null; then
    print_info "Installing Checkov..."
    pip3 install checkov || print_error "Failed to install Checkov"
else
    print_status "Checkov already installed"
fi

# Initialize ClamAV database
print_info "Initializing ClamAV database..."
sudo freshclam || print_warning "ClamAV database update failed (may be normal on first run)"

# Initialize RKHunter
print_info "Initializing RKHunter..."
sudo rkhunter --propupd || print_warning "RKHunter property update failed"

# Create assessment directories
print_info "Creating assessment directories..."
mkdir -p vulnerability_assessment/{scans,logs,reports,configs,findings}

# Set up configuration files
print_info "Setting up configuration files..."

# Create a sample configuration
cat > assessment_config.json << EOF
{
  "assessment_settings": {
    "default_timeout": 300,
    "max_concurrent_scans": 5,
    "output_directory": "vulnerability_assessment",
    "log_level": "INFO"
  },
  "tool_settings": {
    "nmap": {
      "default_scan_type": "-sV",
      "timing_template": "-T4",
      "default_ports": "1-1000"
    },
    "masscan": {
      "default_rate": "1000",
      "default_ports": "1-65535"
    },
    "lynis": {
      "scan_mode": "audit system"
    }
  },
  "reporting": {
    "include_raw_output": true,
    "generate_summary": true,
    "export_formats": ["json", "html"]
  }
}
EOF

# Create a sample targets file
cat > sample_targets.txt << EOF
# Sample targets file for vulnerability assessment
# Format: IP_ADDRESS|HOSTNAME|DESCRIPTION
# Remove this file and create your own with actual targets

192.168.1.1|gateway|Network Gateway Router
192.168.1.100|web-server|Internal Web Server
192.168.1.200|db-server|Database Server
example.com|external-site|Public Website
EOF

print_info "Creating systemd service files..."

# Create systemd service for Kali API server
cat > kali-assessment-server.service << EOF
[Unit]
Description=Kali Vulnerability Assessment API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/kali_server.py --ip 0.0.0.0 --port 5000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for MCP client
cat > kali-mcp-client.service << EOF
[Unit]
Description=Kali MCP Client for Vulnerability Assessment
After=network.target kali-assessment-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/mcp_server.py --server http://localhost:5000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Install systemd services (if running as root)
if [[ $EUID -eq 0 ]]; then
    print_info "Installing systemd services..."
    cp kali-assessment-server.service /etc/systemd/system/
    cp kali-mcp-client.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable kali-assessment-server.service
    systemctl enable kali-mcp-client.service
    print_status "Systemd services installed and enabled"
else
    print_warning "Skipping systemd service installation (requires root)"
fi

# Clean up temporary service files
rm -f kali-assessment-server.service kali-mcp-client.service

# Verify tool installation
print_info "Verifying tool installation..."

tools_to_check=(
    "nmap"
    "masscan"
    "lynis"
    "nikto"
    "rkhunter"
    "chkrootkit"
    "clamscan"
    "trivy"
    "grype"
    "osquery"
    "tcpdump"
    "tshark"
    "recon-ng"
    "theharvester"
    "john"
    "logwatch"
    "checkov"
)

missing_tools=()
installed_tools=0

for tool in "${tools_to_check[@]}"; do
    if command -v "$tool" &> /dev/null; then
        print_status "$tool is installed"
        ((installed_tools++))
    else
        print_warning "$tool is NOT installed"
        missing_tools+=("$tool")
    fi
done

print_info "Tool installation summary:"
print_status "Installed: $installed_tools/${#tools_to_check[@]} tools"

if [ ${#missing_tools[@]} -gt 0 ]; then
    print_warning "Missing tools: ${missing_tools[*]}"
    print_info "You may need to install these manually or check your package manager"
fi

# Create usage instructions
print_info "Creating usage instructions..."

cat > USAGE_INSTRUCTIONS.md << EOF
# Vulnerability Assessment Framework - Usage Instructions

## Quick Start

1. **Start the API Server**:
   \`\`\`bash
   sudo systemctl start kali-assessment-server
   # Or run manually:
   python3 kali_server.py --ip 0.0.0.0 --port 5000
   \`\`\`

2. **Start the MCP Client**:
   \`\`\`bash
   sudo systemctl start kali-mcp-client
   # Or run manually:
   python3 mcp_server.py --server http://localhost:5000
   \`\`\`

3. **Run Vulnerability Assessment**:
   \`\`\`bash
   # Assess a single target
   python3 vulnerability_assessment.py 192.168.1.100
   
   # Assess a domain
   python3 vulnerability_assessment.py example.com
   
   # Custom output directory
   python3 vulnerability_assessment.py target.com -o my_results
   \`\`\`

## Service Management

### Check Service Status
\`\`\`bash
sudo systemctl status kali-assessment-server
sudo systemctl status kali-mcp-client
\`\`\`

### Enable/Disable Services
\`\`\`bash
# Enable on boot
sudo systemctl enable kali-assessment-server
sudo systemctl enable kali-mcp-client

# Disable on boot
sudo systemctl disable kali-assessment-server
sudo systemctl disable kali-mcp-client
\`\`\`

### View Logs
\`\`\`bash
# System logs
sudo journalctl -u kali-assessment-server -f
sudo journalctl -u kali-mcp-client -f

# Assessment logs
tail -f vulnerability_assessment/logs/assessment_log_*.json
\`\`\`

## Configuration

Edit \`assessment_config.json\` to customize:
- Tool parameters
- Scan timeouts
- Output settings
- Reporting options

## Targets

Create a targets file for batch assessments:
\`\`\`bash
# Format: IP|HOSTNAME|DESCRIPTION
echo "192.168.1.100|web-server|Production Web Server" >> my_targets.txt
\`\`\`

## Results

Results are stored in:
- \`vulnerability_assessment/scans/\` - Individual tool outputs
- \`vulnerability_assessment/logs/\` - Execution logs
- \`vulnerability_assessment/reports/\` - Summary reports

## Troubleshooting

1. **Server Connection Issues**:
   \`\`\`bash
   curl http://localhost:5000/health
   \`\`\`

2. **Tool Not Found**:
   \`\`\`bash
   which TOOL_NAME
   sudo apt install TOOL_NAME
   \`\`\`

3. **Permission Issues**:
   \`\`\`bash
   sudo python3 vulnerability_assessment.py TARGET
   \`\`\`

## Important Reminders

- Only assess systems you own or have explicit permission to test
- This framework is for educational and defensive purposes only
- Follow all applicable laws and regulations
- Document all assessments properly
EOF

echo ""
echo "=========================================="
echo "Setup completed!"
echo "=========================================="
print_status "Tools installed: $installed_tools/${#tools_to_check[@]}"
print_status "Configuration files created"
print_status "Usage instructions created: USAGE_INSTRUCTIONS.md"
print_status "Assessment directories created"

if [ ${#missing_tools[@]} -gt 0 ]; then
    print_warning "Some tools failed to install. Check the output above."
    print_warning "You may need to install these manually."
fi

echo ""
print_info "Next steps:"
echo "1. Review USAGE_INSTRUCTIONS.md"
echo "2. Start the services (or run them manually)"
echo "3. Test with a target you own"
echo "4. Review the generated reports"
echo ""
print_warning "IMPORTANT: Only assess systems you own or have explicit permission to test!"
print_warning "This framework is for educational and defensive security purposes only!"
echo ""
echo "=========================================="
