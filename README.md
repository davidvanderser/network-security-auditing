# network-security-auditing
VirtualBox sandbox lab simulating credential interception over unencrypted transport layers and engineering PowerShell/Python scripts for real-time detection.


# Advanced Network Interception, TLS Decryption, and EDR Simulation Lab

An isolated, dual-node virtual laboratory environment designed to analyze cleartext data leakage, execute local network topology interception, construct an active HTTPS/TLS decryption pipeline, and engineer host-based detection capabilities against trust-store exploitation.

##  Architectural Overview
This laboratory is built inside a fully isolated virtual network infrastructure to guarantee zero packet leakage onto external production networks.

* **Network Fabric:** VirtualBox 7.x global NAT Network (`10.0.2.0/24`) with internal DHCP allocation.
* **Attacker Node:** Kali Linux 2026 rolling release (`10.0.2.15`).
* **Victim Node:** Windows 10 Pro environment (`10.0.2.3`).
* **Hardening Baseline:** Selective inbound ICMPv4 exceptions enabled on the Windows host firewall to validate cross-segment communication lanes.

---

##  Project Phases & Implementations

### Phase 1: Cleartext Credential Harvesting (FTP Auditing)
To prove the inherent flaw of legacy, unencrypted protocols, a local FTP Server was provisioned on the Windows host via Internet Information Services (IIS) without SSL requirements. 

Using **Wireshark** on Kali Linux, a passive capture filter was bound to the active interface. Traffic analysis verified that authentication details are passed over the wire in plain, readable text:

```text
[Wireshark TCP Stream Reassembly]
220 Microsoft FTP Service
USER labuser
331 Password required for labuser.
PASS Password123!
230 User logged in.
```

### Phase 2: Local Network MITM Interception (HTTP Phase)
Before jumping to proxy architectures, a local Man-in-the-Middle (MITM) attack was executed to intercept live web transactions over standard unencrypted **HTTP**.
1. Initialized **Bettercap** on the Kali node bound to the local interface (`sudo bettercap -iface eth0`).
2. Executed dynamic active network discovery (`net.probe on`) to map the sandbox topology and isolate the Windows 10 host target (`10.0.2.3`).
3. Formulated bidirectional route poisoning by setting the target variables and enabling full-duplex ARP spoofing (`set arp.spoof.targets 10.0.2.3`, `set arp.spoof.fullduplex true`, `arp.spoof on`).
4. **The Cryptographic Ceiling:** While unencrypted HTTP packets and credentials were successfully captured in plain text during web form submissions, navigating to encrypted **HTTPS** portals immediately blinded the sniffer. The underlying TLS layer reduced the captured payloads to completely unreadable, scrambled binary data blocks.

### Phase 3: Active HTTPS/TLS Decryption Pipeline
To overcome the limitations found in Phase 2 and gain visibility into encrypted streams, a corporate-grade proxy model was engineered:
1. Deployed an active interception web dashboard in Kali Linux via `mitmproxy` (`mitmweb`) listening on port `8080`.
2. Configured the Windows 10 manual network proxy routing directly into the Kali node.
3. Injected a custom Root Certificate Authority (`mitmproxy-ca-cert.p12`) into the Windows **Trusted Root Certification Authorities** machine store.
4. Filtered active traffic flows for HTTP `POST` methods to capture secure account creation payloads (e.g., `://pinterest.com`), successfully bypassing the TLS layer and exposing registration metrics in cleartext.

### Phase 4: Defensive Engineering & Host-Based EDR Scripting
To close the auditing loop, a forensic analysis was conducted on Windows to trace the markers left behind by certificate injection. A lightweight, simulated **Endpoint Detection and Response (EDR)** engine was written in PowerShell to monitor the system registry and instantly alert security teams of unauthorized root trust modifications.

---

## Included Scripts

### 1. Host-Based EDR Registry Watcher (`security_monitor.ps1`)
Run this on the Windows 10 victim node within an Administrator PowerShell window to detect unauthorized proxy certificate installations in real-time:

```powershell
Write-Host "[*] EDR Registry Monitor Active: Watching Trusted Roots... Press Ctrl+C to stop." -ForegroundColor Cyan
\$Path = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"

while (\$true) {
    Check = Get-ChildItem -Path Path -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty \$_.PsPath).FriendlyName -like "*mitmproxy*"
    }
    if (\$Check) {
        Write-Host "`n[!!!] REGISTRY SECURITY ALERT [!!!]" -ForegroundColor Red
        Write-Host "    Unauthorized Root Certificate Registry Injection!" -ForegroundColor Yellow
        Write-Host "    Target Key: $Path" -ForegroundColor White
        Write-Host "    Action Required: An active intercept tool has altered system trust stores.`n" -ForegroundColor LightRed
        break
    }
    Start-Sleep -Seconds 1
}
```

### 2. Network Passive Ping Monitor (`ping_monitor.py`)
Run this script on the Kali Linux node using `sudo python3 ping_monitor.py` to trace raw, decrypted ICMP transactions over the local wire using Scapy:

```python
from scapy.all import sniff, ICMP, IP

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet[ICMP].type == 8:
            print(f"[➔] PING REQUEST: {src_ip} is pinging {dst_ip}")
        elif packet[ICMP].type == 0:
            print(f"[✔] PING REPLY:   {dst_ip} responded to {src_ip}")

print("[*] Actively monitoring the NAT Network for ping traffic... Press Ctrl+C to stop.")
sniff(filter="icmp", store=0, prn=process_packet)
```

---

##  Lab Decommissioning & Cleanup
To restore the laboratory nodes to their pristine, untampered baseline:
1. **Proxy Teardown:** Disabled the Windows manual proxy server toggle.
2. **Certificate Eviction:** Opened `certmgr.msc` on Windows and permanently deleted `mitmproxy` from the Root Certificate directory.
3. **Session Purge:** Cleanly exited all socket-binding background terminals (`mitmweb`, `bettercap`) via standard execution interrupts (`Ctrl + C`).

---

##  Professional Competencies Gained
* Advanced Sandbox Environment Modeling (VirtualBox Expert Layouts).
* Cryptographic Key Management & Root Certificate Authority Mapping.
* Deep Packet Inspection & Traffic Reassembly (Wireshark).
* Proactive Endpoint Hardening & SIEM/EDR Automation (PowerShell & Python).
