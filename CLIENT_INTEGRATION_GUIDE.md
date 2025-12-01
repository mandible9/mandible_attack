# Client Integration Guide (Claude, VS Code, and other MCP Clients)

This guide explains how to integrate the **Kali MCP Vulnerability Assessment Server** with:
- **Claude Desktop / Claude MCP clients**
- **VS Code / Visual Studio-like MCP integrations**
- Any other **MCP-compatible client** that can launch a local MCP server process

> Exact UI steps differ between clients, but the core idea is always:
> 1. Start `mcp_server.py`
> 2. Tell your MCP client how to launch/connect to it

---

## 1. Prerequisites (Recap)

Before integrating with any client, ensure:

1. **Kali API Server is running** (on Kali VM / Linux host):

   ```bash
   # On Kali / Linux
   cd ~/mandible_attack
   python3 kali_server.py --ip 0.0.0.0 --port 5000
   ```

   Or via systemd (if you installed services):

   ```bash
   sudo systemctl start kali-assessment-server
   sudo systemctl status kali-assessment-server
   ```

2. **MCP Server Script is available** on the machine where your MCP client runs (can be the same Kali VM or another machine with network access to Kali).

   Files needed on the MCP client machine:
   - `mcp_server.py`
   - `requirements.txt`

3. **Python deps installed on the client machine**:

   ```bash
   cd ~/mandible_attack
   pip3 install -r requirements.txt
   ```

4. You know the **Kali API URL**, e.g.:

   ```text
   http://<KALI_IP>:5000
   ```

---

## 2. Generic MCP Server Command

Most MCP-capable clients ask you for a **command** to run the MCP server. For this project, the command is:

```bash
python3 mcp_server.py --server http://<KALI_IP>:5000 --timeout 300
```

Examples:

- If the MCP client runs **on the same Kali VM**:

  ```bash
  python3 mcp_server.py --server http://127.0.0.1:5000 --timeout 300
  ```

- If the MCP client runs **on your Windows host** and Kali is at `192.168.56.10`:

  ```bash
  python3 mcp_server.py --server http://192.168.56.10:5000 --timeout 300
  ```

Make sure `mcp_server.py`'s working directory is the repo root (`mandible_attack`) so imports and logs work correctly.

---

## 3. Integrating with Claude (Desktop / MCP-enabled Clients)

> Note: The exact UI and config format may change over time. This section describes the **typical pattern** used by Claude-style MCP clients.

### 3.1. Define the MCP Server in Client Settings

Most Claude MCP clients let you register a custom MCP server via a JSON or TOML config file, or a UI form. The important fields are usually:

- **Name / ID**: `kali-mcp`
- **Command**: how to start the server
- **Working directory**: path to `mandible_attack`

Example conceptual config (pseudo-JSON):

```json
{
  "servers": {
    "kali-mcp": {
      "command": [
        "python3",
        "mcp_server.py",
        "--server",
        "http://<KALI_IP>:5000",
        "--timeout",
        "300"
      ],
      "cwd": "/path/to/mandible_attack"
    }
  }
}
```

Adjust paths and `<KALI_IP>` for your environment.

### 3.2. Start Claude / MCP Client

1. Restart or reload your Claude client so it picks up the new MCP server definition.
2. Open the **tools / MCP / servers** section inside the client.
3. You should see a server named **`kali-mcp`**.
4. Enable it for your workspace / project.

### 3.3. Verify Tools Are Available

Once enabled, the client should list MCP tools such as:

- `nmap_scan`
- `masscan_scan`
- `rustscan_scan`
- `zmap_scan`
- `lynis_audit`
- `debsecan_scan`
- `wapiti_scan`
- `nikto_scan`
- `whatweb_scan`
- `sslyze_scan`
- `testssl_scan`
- `rkhunter_scan`, `chkrootkit_scan`, `aide_scan`, `clamav_scan`
- `trivy_scan`, `grype_scan`, `docker_bench_scan`
- `mysqltuner_scan`
- `tcpdump_capture`, `tshark_analyze`
- `theharvester_osint`, `recon_ng_passive`
- `cracklib_check_password`, `john_hash_audit`
- `metasploit_auxiliary`
- `logwatch_analysis`, `checkov_scan`, `system_info_gather`

You can now instruct Claude to **use these tools** during a conversation, for example:

> "Use the `nmap_scan` tool against 192.168.1.100 to enumerate open ports, then summarize the findings."

The client will call the MCP tool, which talks to `kali_server.py` on the Kali VM.

---

## 4. Integrating with VS Code / Visual Studio-like Environments

Exact steps depend on the MCP extension you use (e.g., an Anthropic MCP extension or a generic MCP runner). The pattern is similar to Claude:

### 4.1. Install the MCP Extension / Plugin

1. Open **VS Code** (or similar IDE).
2. Install the extension that adds **Model Context Protocol (MCP)** support.
3. Locate its **configuration file** or **settings view** for MCP servers.

### 4.2. Add `kali-mcp` as a Custom Server

In the extension settings, add a new MCP server entry with:

- Name / ID: `kali-mcp`
- Command: `python3 mcp_server.py --server http://<KALI_IP>:5000 --timeout 300`
- Working directory: path where `mcp_server.py` lives (e.g. `C:\Users\Master\Desktop\mandible_attack` on Windows, `/home/user/mandible_attack` on Linux)

Example conceptual VS Code `settings.json` snippet (actual schema depends on extension):

```json
{
  "mcp.servers": {
    "kali-mcp": {
      "command": [
        "python3",
        "mcp_server.py",
        "--server",
        "http://192.168.56.10:5000",
        "--timeout",
        "300"
      ],
      "cwd": "C:/Users/Master/Desktop/mandible_attack"
    }
  }
}
```

Adapt keys/structure to your actual MCP extension docs.

### 4.3. Enable and Test in VS Code

1. Reload VS Code.
2. Open the **MCP / Tools** panel provided by the extension.
3. Ensure `kali-mcp` is listed and shows as **running/connected**.
4. In a chat panel, ask something like:

   > "Use `system_info_gather` to collect OS and kernel info from the Kali VM and summarize hardening recommendations."

The extension should:
- Call `kali-mcp` → `mcp_server.py`
- Which calls the Kali API → `kali_server.py`
- Which runs the actual tools on the Kali VM and returns results

---

## 5. Common Integration Pitfalls

### 5.1. Network Connectivity

- Ensure your **client machine** can reach the **Kali API server**:

  ```bash
  # From client machine
  curl http://<KALI_IP>:5000/health
  ```

- If this fails:
  - Check `kali_server.py` is running (`python3 kali_server.py ...`)
  - Ensure firewall/iptables rules allow port 5000
  - If using NAT/VM, ensure port forwarding is configured

### 5.2. Python Path / Working Directory

- The MCP client must run `mcp_server.py` in the **repo root** so imports work:

  - On Linux:
    - `cwd`: `/home/user/mandible_attack`
  - On Windows:
    - `cwd`: `C:/Users/Master/Desktop/mandible_attack`

- If you see `ImportError` for `KaliToolsClient` or similar, your `cwd` is probably wrong.

### 5.3. Tool Not Found on Kali

- If a tool fails (e.g. `trivy` not found), install it on Kali:

  ```bash
  which trivy
  sudo apt install trivy   # or use the instructions in setup_assessment.sh
  ```

- Re-run `curl http://<KALI_IP>:5000/health` to confirm.

---

## 6. Minimal End-to-End Smoke Test

1. **On Kali VM**:

   ```bash
   cd ~/mandible_attack
   python3 kali_server.py --ip 0.0.0.0 --port 5000
   ```

2. **On client machine** (same or different):

   ```bash
   cd ~/mandible_attack
   python3 mcp_server.py --server http://<KALI_IP>:5000 --timeout 300
   ```

3. **In Claude / VS Code**:
   - Ensure `kali-mcp` server is configured and enabled.
   - Ask the assistant:

     > "Call `server_health` from kali-mcp and tell me which tools are installed on the Kali VM."

4. You should see JSON-like output listing `tools_status` and `all_essential_tools_available`.

If you tell me the **exact MCP client** and its config format, I can extend this file with a ready-to-paste config block tailored to that client.
