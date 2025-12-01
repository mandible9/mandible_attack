#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/screenshot", methods=["POST"])
def screenshot():
    """Capture a screenshot for PoC documentation.

    Behaviour:
    - If a "url" is provided, this endpoint will open it in the default browser
      using xdg-open and wait a short time for rendering.
    - Then it calls `scrot` to capture the current desktop to a file under
      /tmp/mandible_screenshots.

    This is a simple helper; it assumes you are running a graphical session on Kali
    and that `scrot` is installed (sudo apt install scrot).
    """
    try:
        params = request.json or {}
        url = params.get("url", "")
        filename_prefix = params.get("name", "poc")

        screenshots_dir = "/tmp/mandible_screenshots"
        os.makedirs(screenshots_dir, exist_ok=True)

        # If URL is provided, try to open it so it is visible for the screenshot
        if url:
            try:
                # Non-blocking open; relies on user session
                subprocess.Popen(["xdg-open", url])
            except Exception as e:
                logger.warning(f"Could not open URL before screenshot: {e}")

        # Build screenshot filename
        safe_prefix = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in filename_prefix)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(screenshots_dir, f"{safe_prefix}_{timestamp}.png")

        # Small delay to allow browser/window to appear if URL was opened
        try:
            import time
            time.sleep(3)
        except Exception:
            pass

        # Use scrot to capture the whole screen
        scrot_cmd = ["scrot", outfile]
        result = execute_command(" ".join(scrot_cmd))

        if not result.get("success", False):
            return jsonify({
                "error": "Screenshot command failed",
                "details": result
            }), 500

        return jsonify({
            "success": True,
            "screenshot_path": outfile,
            "details": result
        })
    except Exception as e:
        logger.error(f"Error in screenshot endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute masscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", "1000")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Masscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"masscan {target} -p {ports} --rate {rate}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/rustscan", methods=["POST"])
def rustscan():
    """Execute rustscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "-")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("RustScan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"rustscan -a {target}"
        
        if ports != "-":
            command += f" -p {ports}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in rustscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/unicornscan", methods=["POST"])
def unicornscan():
    """Execute unicornscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        mode = params.get("mode", "U")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Unicornscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"unicornscan {target}:{ports} -m{mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in unicornscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/zmap", methods=["POST"])
def zmap():
    """Execute zmap with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "80")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("ZMap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"zmap -p {port} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in zmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/lynis", methods=["POST"])
def lynis():
    """Execute Lynis system audit."""
    try:
        params = request.json
        scan_mode = params.get("scan_mode", "audit system")
        additional_args = params.get("additional_args", "")
        
        command = f"lynis {scan_mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in lynis endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/debsecan", methods=["POST"])
def debsecan():
    """Execute debsecan vulnerability scanner."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")
        
        command = "debsecan"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in debsecan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wapiti", methods=["POST"])
def wapiti():
    """Execute Wapiti web application scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        scope = params.get("scope", "domain")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Wapiti called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wapiti -u {url} -s {scope}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wapiti endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Execute WhatWeb web technology identifier."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("WhatWeb called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"whatweb {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sslyze", methods=["POST"])
def sslyze():
    """Execute SSLyze SSL/TLS scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("SSLyze called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"sslyze --regular {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sslyze endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/testssl", methods=["POST"])
def testssl():
    """Execute TestSSL.sh SSL/TLS scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("TestSSL called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"testssl.sh {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in testssl endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/openscap", methods=["POST"])
def openscap():
    """Execute OpenSCAP security scan."""
    try:
        params = request.json
        profile = params.get("profile", "xccdf_org.ssgproject.content_profile_standard")
        target = params.get("target", "/")
        additional_args = params.get("additional_args", "")
        
        command = f"oscap xccdf eval --profile {profile} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in openscap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/osquery", methods=["POST"])
def osquery():
    """Execute osquery system information query."""
    try:
        params = request.json
        query = params.get("query", "")
        additional_args = params.get("additional_args", "")
        
        if not query:
            logger.warning("Osquery called without query parameter")
            return jsonify({
                "error": "Query parameter is required"
            }), 400
        
        command = f'osqueryi -A "{query}"'
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in osquery endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/rkhunter", methods=["POST"])
def rkhunter():
    """Execute RKHunter rootkit scanner."""
    try:
        params = request.json
        scan_mode = params.get("scan_mode", "--checkall")
        additional_args = params.get("additional_args", "")
        
        command = f"rkhunter {scan_mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in rkhunter endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/chkrootkit", methods=["POST"])
def chkrootkit():
    """Execute Chkrootkit rootkit scanner."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")
        
        command = "chkrootkit"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in chkrootkit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/aide", methods=["POST"])
def aide():
    """Execute AIDE integrity checker."""
    try:
        params = request.json
        command = params.get("command", "--check")
        additional_args = params.get("additional_args", "")
        
        aide_cmd = f"aide {command}"
        
        if additional_args:
            aide_cmd += f" {additional_args}"
        
        result = execute_command(aide_cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in aide endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/clamav", methods=["POST"])
def clamav():
    """Execute ClamAV malware scanner."""
    try:
        params = request.json
        target = params.get("target", "/")
        scan_mode = params.get("scan_mode", "--infected")
        additional_args = params.get("additional_args", "")
        
        command = f"clamscan -r {target} {scan_mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in clamav endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy vulnerability scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "fs")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Trivy called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"trivy {scan_type} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in trivy endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/grype", methods=["POST"])
def grype():
    """Execute Grype vulnerability scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Grype called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"grype {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in grype endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/docker_bench", methods=["POST"])
def docker_bench():
    """Execute Docker Bench Security."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")
        
        command = "docker-bench-security"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in docker_bench endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/mysqltuner", methods=["POST"])
def mysqltuner():
    """Execute MySQLTuner."""
    try:
        params = request.json
        host = params.get("host", "localhost")
        user = params.get("user", "root")
        additional_args = params.get("additional_args", "")
        
        command = f"mysqltuner.pl -host {host} -user {user}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in mysqltuner endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/tcpdump", methods=["POST"])
def tcpdump():
    """Execute tcpdump network capture."""
    try:
        params = request.json
        interface = params.get("interface", "eth0")
        capture_filter = params.get("capture_filter", "")
        packet_count = params.get("packet_count", "100")
        additional_args = params.get("additional_args", "")
        
        command = f"tcpdump -i {interface} -c {packet_count}"
        
        if capture_filter:
            command += f" {capture_filter}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in tcpdump endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/tshark", methods=["POST"])
def tshark():
    """Execute tshark network analysis."""
    try:
        params = request.json
        interface = params.get("interface", "eth0")
        capture_filter = params.get("capture_filter", "")
        packet_count = params.get("packet_count", "100")
        additional_args = params.get("additional_args", "")
        
        command = f"tshark -i {interface} -c {packet_count}"
        
        if capture_filter:
            command += f" {capture_filter}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in tshark endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/recon_ng", methods=["POST"])
def recon_ng():
    """Execute Recon-ng passive reconnaissance."""
    try:
        params = request.json
        workspace = params.get("workspace", "default")
        modules = params.get("modules", [])
        additional_args = params.get("additional_args", "")
        
        command = f"recon-ng -w {workspace}"
        
        if modules:
            for module in modules:
                command += f" -m {module}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in recon_ng endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/theharvester", methods=["POST"])
def theharvester():
    """Execute theHarvester OSINT tool."""
    try:
        params = request.json
        domain = params.get("domain", "")
        sources = params.get("sources", "baidu,google")
        limit = params.get("limit", "500")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("TheHarvester called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"theHarvester -d {domain} -b {sources} -l {limit}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in theharvester endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cracklib_check", methods=["POST"])
def cracklib_check():
    """Execute cracklib-check password policy analysis."""
    try:
        params = request.json
        password = params.get("password", "")
        additional_args = params.get("additional_args", "")
        
        if not password:
            logger.warning("Cracklib-check called without password parameter")
            return jsonify({
                "error": "Password parameter is required"
            }), 400
        
        command = f"echo {password} | cracklib-check"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cracklib_check endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john_audit", methods=["POST"])
def john_audit():
    """Execute John the Ripper hash policy audit (non-cracking)."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        mode = params.get("mode", "--test")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John audit called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john {mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john_audit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit_auxiliary", methods=["POST"])
def metasploit_auxiliary():
    """Execute Metasploit auxiliary modules only (reconnaissance/enumeration)."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit auxiliary called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Ensure it's an auxiliary module
        if not module.startswith("auxiliary/"):
            logger.warning(f"Non-auxiliary module blocked: {module}")
            return jsonify({
                "error": "Only auxiliary modules are allowed for vulnerability assessment"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "run\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_auxiliary.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit_auxiliary endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/logwatch", methods=["POST"])
def logwatch():
    """Execute Logwatch log analysis."""
    try:
        params = request.json
        service = params.get("service", "all")
        range = params.get("range", "yesterday")
        detail = params.get("detail", "med")
        additional_args = params.get("additional_args", "")
        
        command = f"logwatch --service {service} --range {range} --detail {detail}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in logwatch endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/checkov", methods=["POST"])
def checkov():
    """Execute Checkov IaC security scanning."""
    try:
        params = request.json
        directory = params.get("directory", ".")
        framework = params.get("framework", "all")
        additional_args = params.get("additional_args", "")
        
        command = f"checkov -d {directory} --framework {framework}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in checkov endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/system_info", methods=["POST"])
def system_info():
    """Gather comprehensive system information."""
    try:
        params = request.json
        info_type = params.get("info_type", "all")
        additional_args = params.get("additional_args", "")
        
        commands = {
            "os": "uname -a",
            "distro": "lsb_release -a",
            "kernel": "uname -r",
            "hostname": "hostname",
            "uptime": "uptime",
            "memory": "free -h",
            "disk": "df -h",
            "processes": "ps aux",
            "network": "ip addr show",
            "services": "systemctl list-units --type=service --state=running",
            "packages": "dpkg -l | head -20",
            "users": "cat /etc/passwd",
            "groups": "cat /etc/group",
            "sudoers": "sudo -l -U $(whoami)",
            "cron": "crontab -l",
            "environment": "env"
        }
        
        if info_type == "all":
            command = " && ".join([f"echo '=== {key.toUpperCase()} ===' && {cmd}" for key, cmd in commands.items()])
        elif info_type in commands:
            command = commands[info_type]
        else:
            logger.warning(f"Invalid system info type: {info_type}")
            return jsonify({
                "error": f"Invalid info_type. Must be one of: {', '.join(commands.keys())} or 'all'"
            }), 400
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in system_info endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto", "lynis", "rkhunter", "chkrootkit", "clamscan", "trivy", "osquery"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind the server to (default: 127.0.0.1 for localhost only)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
