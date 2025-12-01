#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def masscan_scan(target: str, ports: str = "1-65535", rate: str = "1000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan high-speed port scanner.
        
        Args:
            target: The IP address or hostname to scan
            ports: Port range to scan (default: 1-65535)
            rate: Scan rate in packets per second (default: 1000)
            additional_args: Additional Masscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/masscan", data)

    @mcp.tool()
    def rustscan_scan(target: str, ports: str = "-", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute RustScan fast port scanner.
        
        Args:
            target: The IP address or hostname to scan
            ports: Ports to scan (default: - for all)
            additional_args: Additional RustScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/rustscan", data)

    @mcp.tool()
    def unicornscan_scan(target: str, ports: str = "1-65535", mode: str = "U", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Unicornscan asynchronous scanner.
        
        Args:
            target: The IP address or hostname to scan
            ports: Port range to scan (default: 1-65535)
            mode: Scan mode (U for UDP, T for TCP)
            additional_args: Additional Unicornscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "mode": mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/unicornscan", data)

    @mcp.tool()
    def zmap_scan(target: str, port: str = "80", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ZMap internet-scale scanner.
        
        Args:
            target: The target network range
            port: Port to scan (default: 80)
            additional_args: Additional ZMap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "port": port,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/zmap", data)

    @mcp.tool()
    def lynis_audit(scan_mode: str = "audit system", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Lynis system security audit.
        
        Args:
            scan_mode: Scan mode (default: audit system)
            additional_args: Additional Lynis arguments
            
        Returns:
            Audit results
        """
        data = {
            "scan_mode": scan_mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/lynis", data)

    @mcp.tool()
    def debsecan_scan(additional_args: str = "") -> Dict[str, Any]:
        """
        Execute debsecan Debian vulnerability scanner.
        
        Args:
            additional_args: Additional debsecan arguments
            
        Returns:
            Scan results
        """
        data = {
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/debsecan", data)

    @mcp.tool()
    def wapiti_scan(url: str, scope: str = "domain", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wapiti web application vulnerability scanner.
        
        Args:
            url: The target URL
            scope: Scan scope (default: domain)
            additional_args: Additional Wapiti arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "scope": scope,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wapiti", data)

    @mcp.tool()
    def whatweb_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WhatWeb web technology identification.
        
        Args:
            target: The target URL or IP
            additional_args: Additional WhatWeb arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/whatweb", data)

    @mcp.tool()
    def sslyze_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SSLyze SSL/TLS configuration scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional SSLyze arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sslyze", data)

    @mcp.tool()
    def testssl_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute TestSSL.sh SSL/TLS configuration scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional TestSSL arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/testssl", data)

    @mcp.tool()
    def openscap_scan(profile: str = "xccdf_org.ssgproject.content_profile_standard", target: str = "/", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OpenSCAP security compliance scan.
        
        Args:
            profile: SCAP profile to use
            target: Target to scan (default: /)
            additional_args: Additional OpenSCAP arguments
            
        Returns:
            Scan results
        """
        data = {
            "profile": profile,
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/openscap", data)

    @mcp.tool()
    def osquery_query(query: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute osquery system information query.
        
        Args:
            query: SQL-like query to execute
            additional_args: Additional osquery arguments
            
        Returns:
            Query results
        """
        data = {
            "query": query,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/osquery", data)

    @mcp.tool()
    def rkhunter_scan(scan_mode: str = "--checkall", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute RKHunter rootkit detection scan.
        
        Args:
            scan_mode: Scan mode (default: --checkall)
            additional_args: Additional RKHunter arguments
            
        Returns:
            Scan results
        """
        data = {
            "scan_mode": scan_mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/rkhunter", data)

    @mcp.tool()
    def chkrootkit_scan(additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Chkrootkit rootkit detection scan.
        
        Args:
            additional_args: Additional Chkrootkit arguments
            
        Returns:
            Scan results
        """
        data = {
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/chkrootkit", data)

    @mcp.tool()
    def aide_scan(command: str = "--check", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute AIDE file integrity check.
        
        Args:
            command: AIDE command to execute (default: --check)
            additional_args: Additional AIDE arguments
            
        Returns:
            Scan results
        """
        data = {
            "command": command,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/aide", data)

    @mcp.tool()
    def clamav_scan(target: str = "/", scan_mode: str = "--infected", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ClamAV malware scan.
        
        Args:
            target: Target to scan (default: /)
            scan_mode: Scan mode (default: --infected)
            additional_args: Additional ClamAV arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_mode": scan_mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/clamav", data)

    @mcp.tool()
    def trivy_scan(target: str, scan_type: str = "fs", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Trivy vulnerability scanner.
        
        Args:
            target: Target to scan (file system, image, repo)
            scan_type: Scan type (fs, image, repo)
            additional_args: Additional Trivy arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/trivy", data)

    @mcp.tool()
    def grype_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Grype vulnerability scanner.
        
        Args:
            target: Target to scan
            additional_args: Additional Grype arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/grype", data)

    @mcp.tool()
    def docker_bench_scan(additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Docker Bench Security assessment.
        
        Args:
            additional_args: Additional Docker Bench arguments
            
        Returns:
            Assessment results
        """
        data = {
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/docker_bench", data)

    @mcp.tool()
    def mysqltuner_scan(host: str = "localhost", user: str = "root", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute MySQLTuner database security assessment.
        
        Args:
            host: MySQL host (default: localhost)
            user: MySQL user (default: root)
            additional_args: Additional MySQLTuner arguments
            
        Returns:
            Assessment results
        """
        data = {
            "host": host,
            "user": user,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/mysqltuner", data)

    @mcp.tool()
    def tcpdump_capture(interface: str = "eth0", capture_filter: str = "", packet_count: str = "100", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute tcpdump network packet capture.
        
        Args:
            interface: Network interface (default: eth0)
            capture_filter: BPF filter for packets
            packet_count: Number of packets to capture (default: 100)
            additional_args: Additional tcpdump arguments
            
        Returns:
            Capture results
        """
        data = {
            "interface": interface,
            "capture_filter": capture_filter,
            "packet_count": packet_count,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/tcpdump", data)

    @mcp.tool()
    def tshark_analyze(interface: str = "eth0", capture_filter: str = "", packet_count: str = "100", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute tshark network traffic analysis.
        
        Args:
            interface: Network interface (default: eth0)
            capture_filter: BPF filter for packets
            packet_count: Number of packets to capture (default: 100)
            additional_args: Additional tshark arguments
            
        Returns:
            Analysis results
        """
        data = {
            "interface": interface,
            "capture_filter": capture_filter,
            "packet_count": packet_count,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/tshark", data)

    @mcp.tool()
    def recon_ng_passive(workspace: str = "default", modules: list = [], additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Recon-ng passive reconnaissance.
        
        Args:
            workspace: Workspace name (default: default)
            modules: List of modules to run
            additional_args: Additional Recon-ng arguments
            
        Returns:
            Reconnaissance results
        """
        data = {
            "workspace": workspace,
            "modules": modules,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/recon_ng", data)

    @mcp.tool()
    def theharvester_osint(domain: str, sources: str = "baidu,google", limit: str = "500", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute theHarvester OSINT data gathering.
        
        Args:
            domain: Target domain
            sources: Data sources (default: baidu,google)
            limit: Result limit (default: 500)
            additional_args: Additional theHarvester arguments
            
        Returns:
            OSINT results
        """
        data = {
            "domain": domain,
            "sources": sources,
            "limit": limit,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/theharvester", data)

    @mcp.tool()
    def cracklib_check_password(password: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute cracklib-check password policy analysis.
        
        Args:
            password: Password to check
            additional_args: Additional cracklib-check arguments
            
        Returns:
            Password analysis results
        """
        data = {
            "password": password,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/cracklib_check", data)

    @mcp.tool()
    def john_hash_audit(hash_file: str, mode: str = "--test", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute John the Ripper hash policy audit (non-cracking).
        
        Args:
            hash_file: Path to hash file
            mode: Audit mode (default: --test)
            additional_args: Additional John arguments
            
        Returns:
            Audit results
        """
        data = {
            "hash_file": hash_file,
            "mode": mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john_audit", data)

    @mcp.tool()
    def metasploit_auxiliary(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute Metasploit auxiliary modules only (reconnaissance/enumeration).
        
        Args:
            module: Metasploit auxiliary module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit_auxiliary", data)

    @mcp.tool()
    def logwatch_analysis(service: str = "all", range: str = "yesterday", detail: str = "med", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Logwatch log analysis.
        
        Args:
            service: Service to analyze (default: all)
            range: Time range (default: yesterday)
            detail: Detail level (default: med)
            additional_args: Additional Logwatch arguments
            
        Returns:
            Log analysis results
        """
        data = {
            "service": service,
            "range": range,
            "detail": detail,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/logwatch", data)

    @mcp.tool()
    def checkov_scan(directory: str = ".", framework: str = "all", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Checkov Infrastructure as Code security scanning.
        
        Args:
            directory: Directory to scan (default: .)
            framework: Framework to scan (default: all)
            additional_args: Additional Checkov arguments
            
        Returns:
            IaC scan results
        """
        data = {
            "directory": directory,
            "framework": framework,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/checkov", data)

    @mcp.tool()
    def system_info_gather(info_type: str = "all", additional_args: str = "") -> Dict[str, Any]:
        """
        Gather comprehensive system information.
        
        Args:
            info_type: Type of information to gather (os, distro, kernel, hostname, uptime, memory, disk, processes, network, services, packages, users, groups, sudoers, cron, environment, or all)
            additional_args: Additional arguments
            
        Returns:
            System information
        """
        data = {
            "info_type": info_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/system_info", data)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
