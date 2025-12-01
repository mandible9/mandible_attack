# MCP Kali Vulnerability Assessment – Installation Guide

This guide explains how to install and run the **MCP-Kali-Server + Vulnerability Assessment Framework** from scratch.

The architecture has two main components:
- **Server side (Kali VM / Linux host)** – runs `kali_server.py` and all security tools
- **Client side (MCP client)** – runs `mcp_server.py` and exposes tools to your AI/MCP-compatible IDE

> **Use only on systems you own or are explicitly authorized to assess. This is for learning and defensive security only.**

---

## 1. Prerequisites

### 1.1. Kali / Linux VM
- A recent **Kali Linux** (or Debian-based) VM
- Internet access to install packages
- Python **3.10+** recommended
- Sudo/root access for tool installation

### 1.2. Clone This Repository
On your **Kali VM** (or Linux host where tools will run):

```bash
cd ~
# Clone your mandible_attack repo (adjust URL if needed)
git clone <your-repo-url> mandible_attack
cd mandible_attack
```

If you just copied the files manually, ensure all of these are present:
- `kali_server.py`
- `mcp_server.py`
- `requirements.txt`
- `vulnerability_assessment.py`
- `setup_assessment.sh`
- `VULNERABILITY_ASSESSMENT_README.md`
- `INSTALLATION_GUIDE.md` (this file)

---

## 2. Install Dependencies on the Server (Kali VM)

All tools and Python deps can be installed with the provided setup script.

### 2.1. Make the Setup Script Executable

```bash
cd ~/mandible_attack
chmod +x setup_assessment.sh
```

### 2.2. Run the Setup Script (as root or with sudo)

```bash
# Recommended
sudo ./setup_assessment.sh
```

What this script does (high level):
- Runs `apt update`
- Installs Python deps from `requirements.txt`:
  - `Flask`
  - `requests`
  - `mcp`
- Installs and configures a large set of security tools, including:
  - Network scanners: `nmap`, `masscan`, `rustscan`, `unicornscan`, `zmap`
  - OS/Compliance: `lynis`, `debsecan`, `openscap-scanner`, `osquery`
  - Web: `nikto`, `wapiti`, `whatweb`, `sslyze`, `testssl.sh`
  - Malware/Rootkit: `rkhunter`, `chkrootkit`, `aide`, `clamav`
  - Container: `trivy`, `grype`, `docker-bench-security`
  - DB: `mysqltuner`
  - Network analysis: `tcpdump`, `tshark`, `wireshark-common`
  - OSINT: `recon-ng`, `theharvester`
  - Password/auth: `cracklib-runtime`, `john`
  - Logs & IaC: `logwatch`, `checkov`
- Creates assessment directories under `vulnerability_assessment/`
- Creates config files: `assessment_config.json`, `sample_targets.txt`
- Optionally sets up **systemd services** for `kali_server.py` and `mcp_server.py` (if run as root)

If any tool fails to install, the script will print warnings; you can install missing tools manually later.

---

## 3. Running the Server Side (Kali API Server)

The **server side** is `kali_server.py`, which exposes REST API endpoints for all tools.

### 3.1. Start the Server Manually

From the repo directory on Kali:

```bash
cd ~/mandible_attack
python3 kali_server.py --ip 0.0.0.0 --port 5000
```

- `--ip 0.0.0.0` – listen on all interfaces (for remote MCP clients)
- `--port 5000` – default API port (you can change it if needed)

You should see log output like:

```text
INFO Starting Kali Linux Tools API Server on 0.0.0.0:5000
 * Running on http://0.0.0.0:5000
```

### 3.2. Verify the Server Health

From the Kali VM or any machine that can reach it:

```bash
curl http://<KALI_IP>:5000/health
```

Expected JSON (example):

```json
{
  "status": "healthy",
  "message": "Kali Linux Tools API Server is running",
  "tools_status": {
    "nmap": true,
    "gobuster": true,
    "dirb": true,
    "nikto": true,
    "lynis": true,
    ...
  },
  "all_essential_tools_available": true
}
```

If you used `setup_assessment.sh` as root, you can also manage the service via systemd:

```bash
sudo systemctl start kali-assessment-server
sudo systemctl status kali-assessment-server
```

---

## 4. Running the Client Side (MCP Client)

The **client side** (`mcp_server.py`) connects to the Kali API server and exposes tools to your MCP-compatible IDE / AI client.

You can run this:
- On the **same Kali VM**, or
- On another machine that can reach the Kali API server over the network.

### 4.1. Install Python Requirements on the Client Machine

If the client is not the same machine, copy the repo or at least `mcp_server.py` and `requirements.txt` to the client, then:

```bash
cd ~/mandible_attack
pip3 install -r requirements.txt
```

### 4.2. Start the MCP Server

On the client machine (or the same Kali VM if you prefer everything local):

```bash
cd ~/mandible_attack
python3 mcp_server.py --server http://<KALI_IP>:5000 --timeout 300
```

- `--server` – URL of the Kali API server
- `--timeout` – request timeout in seconds for long-running scans

You should see logs like:

```text
INFO Initialized Kali Tools Client connecting to http://<KALI_IP>:5000
INFO Successfully connected to Kali API server at http://<KALI_IP>:5000
INFO Server health status: healthy
INFO Starting Kali MCP server
```

If you installed the systemd service from the setup script and are running this **on Kali**:

```bash
sudo systemctl start kali-mcp-client
sudo systemctl status kali-mcp-client
```

---

## 5. Integrating with Your MCP-Compatible Client / IDE

The exact steps depend on your MCP-compatible client (Cursor, Windsurf, custom MCP runner, etc.), but the general idea is:

1. Configure a new MCP server named something like `kali-mcp` that points to the process started by `mcp_server.py`.
2. Most MCP runners will detect the tools exposed by `FastMCP` in `mcp_server.py` automatically.
3. Once connected, you will see tools like:
   - `nmap_scan`, `masscan_scan`, `rustscan_scan`, `zmap_scan`
   - `lynis_audit`, `debsecan_scan`, `openscap_scan`, `osquery_query`
   - `nikto_scan`, `wapiti_scan`, `whatweb_scan`, `sslyze_scan`, `testssl_scan`
   - `rkhunter_scan`, `chkrootkit_scan`, `aide_scan`, `clamav_scan`
   - `trivy_scan`, `grype_scan`, `docker_bench_scan`
   - `mysqltuner_scan`, `tcpdump_capture`, `tshark_analyze`
   - `theharvester_osint`, `recon_ng_passive`
   - `cracklib_check_password`, `john_hash_audit`
   - `metasploit_auxiliary`, `logwatch_analysis`, `checkov_scan`, `system_info_gather`

Consult your IDE’s MCP documentation for how to register a local MCP server executable.

---

## 6. Running the Full Vulnerability Assessment Script

Once both sides are running and tools are installed, you can execute the full assessment directly on the **Kali VM**:

```bash
cd ~/mandible_attack
python3 vulnerability_assessment.py <TARGET>
```

Examples:

```bash
# Internal IP
python3 vulnerability_assessment.py 192.168.1.100

# Domain name
python3 vulnerability_assessment.py example.com

# Custom output directory
python3 vulnerability_assessment.py 10.0.0.5 -o my_assessment_results
```

Outputs are stored under the chosen output directory (default `assessment_results/`):

- `scans/` – per-tool JSON outputs
- `logs/` – assessment logs
- `reports/` – consolidated JSON report(s)

---

## 7. Security & Safety Notes

- **Authorization is mandatory** – only scan assets you own or are explicitly authorized to assess.
- Tools are used in **non-exploit / assessment modes** only (reconnaissance, enumeration, configuration analysis).
- Many tools may require **root/sudo** to work properly (e.g., `tcpdump`, `rkhunter`).
- Be aware of **network impact** – avoid aggressive scans on production networks.

---

## 8. Quick Checklist

- [ ] Kali VM (or Linux host) ready
- [ ] Repo cloned to `~/mandible_attack`
- [ ] `sudo ./setup_assessment.sh` completed (or tools installed manually)
- [ ] `python3 kali_server.py --ip 0.0.0.0 --port 5000` running
- [ ] `python3 mcp_server.py --server http://<KALI_IP>:5000` running (on client or same host)
- [ ] MCP client/IDE configured to use `mcp_server.py`
- [ ] Vulnerability assessment script tested with a **lab / authorized** target

If you tell me your exact MCP client (e.g., Cursor, Windsurf, custom), I can add a short section to this guide with the exact configuration steps for that client.
