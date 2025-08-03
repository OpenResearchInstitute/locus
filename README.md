# Opulent Voice Conference Server Test Plan & User Guide

## Overview

The Opulent Voice Conference Server enables multiple stations to communicate through a central relay. The server must run on a separate machine from the stations.

## Quick Start

### Requirements
- **3 machines minimum**: 1 for conference server, 2+ for stations
- **Network connectivity**: All machines on same network or with proper routing
- **Firewall**: Port 57372 (or custom port) open on server machine

### Basic Test Setup

**Machine A (Conference Server):**
```
python3 production_conference_server.py
```

**Machine B (Station 1):**
```
python3 interlocutor.py W1ABC -i <MACHINE_A_IP>
```

**Machine C (Station 2):**
```
python3 interlocutor.py VE3XYZ -i <MACHINE_A_IP>
```

## Expected Results

### Conference Server Output
```
📡 OPULENT VOICE CONFERENCE SERVER
📡 Listening on: 0.0.0.0:57372
🚀 Server ready for connections

🆕 NEW STATION: W1ABC at 192.168.1.100
🆕 NEW STATION: VE3XYZ at 192.168.1.101

📊 PERIODIC STATISTICS
📥 Frames received: 245
📤 Frames forwarded: 243
👥 Active stations: 2
```

### Station Terminals
When Station 1 types a message:
```
[W1ABC] Chat> hello everyone
[W1ABC] Chat> 
```

Station 2 should see:
```
📨 [W1ABC]: hello everyone
[VE3XYZ] Chat> 
```

## Detailed Test Procedures

### Test 1: Basic Connectivity
1. Start conference server on Machine A
2. Start Station 1 on Machine B
3. **Expected**: Server logs "NEW STATION: W1ABC"
4. Start Station 2 on Machine C  
5. **Expected**: Server logs "NEW STATION: VE3XYZ"

### Test 2: Chat Messages
1. Complete Test 1 first
2. Type message in Station 1 terminal: `hello from W1ABC`
3. **Expected**: Station 2 displays `📨 [W1ABC]: hello from W1ABC`
4. Type reply in Station 2: `VE3XYZ here, roger`
5. **Expected**: Station 1 displays `📨 [VE3XYZ]: VE3XYZ here, roger`

### Test 3: Voice Communication (PTT)
1. Complete Test 1 first
2. Press PTT button on Station 1
3. **Expected**: Station 1 shows `🎤 W1ABC: PTT was pressed`
4. **Expected**: Station 2 should receive and play audio
5. Release PTT on Station 1
6. **Expected**: Station 1 shows `🔇 W1ABC: PTT was released`

### Test 4: Multiple Stations and Simultaneous Transmissions
1. Add Station 3 on Machine D:
   ```
   python3 interlocutor.py K5XYZ -i <MACHINE_A_IP>
   ```
2. **Expected**: All stations can communicate with each other
3. **Expected**: Server shows 3 active stations in periodic stats
4. **Expected**: UI replay bubbles in Interlocutor message history have complete transmissions from the stations that sent them

## Configuration Options

### Conference Server Options
```
# Default port
python3 production_conference_server.py

# Custom port
python3 production_conference_server.py -p 8000

# Verbose logging
python3 production_conference_server.py -v
```

### Station Options
```
# Basic connection
python3 interlocutor.py W1ABC -i <SERVER_IP>

# Custom server port
python3 interlocutor.py W1ABC -i <SERVER_IP> -p 8000

# Custom listen port (usually not needed)
python3 interlocutor.py W1ABC -i <SERVER_IP> --listen-port 57373
```

## Troubleshooting

### ❌ "No stations connected"
- **Check**: Can stations ping the server machine?
- **Check**: Is firewall blocking port 57372?
- **Check**: Are stations using correct server IP?

### ❌ "Chat messages not received"
- **Check**: Do both stations show as connected on server?
- **Check**: Any error messages in station terminals?

### ❌ "Server shows same station twice"
- **Cause**: Station reconnected with new IP
- **Solution**: Normal (current) behavior, old entry will timeout

### ❌ "Packet storm / high frame rate"
- **Cause**: Server and station on same machine
- **Solution**: Move to separate machines (required)

## Advanced Configuration

### Service Installation (orindary Linux)
Create `/etc/systemd/system/opulent-voice-server.service`:
```ini
[Unit]
Description=Opulent Voice Conference Server
After=network.target

[Service]
Type=simple
User=opulentvoice
WorkingDirectory=/opt/opulent-voice
ExecStart=/usr/bin/python3 production_conference_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```
sudo systemctl enable opulent-voice-server
sudo systemctl start opulent-voice-server
sudo systemctl status opulent-voice-server
```

### Linode Deployment (Like at ORI)

#### 1. Create Linode Instance
```
# Recommended: Ubuntu 24.04 LTS, Shared CPU, 1GB RAM minimum
# Region: Choose closest to your stations for lowest latency
```

#### 2. Initial Server Setup
```
# Connect via SSH
ssh root@<LINODE_IP>

# Update system
apt update && apt upgrade -y

# Create service user
useradd -r -s /bin/false -m -d /opt/opulent-voice opulentvoice
```

#### 3. Install Opulent Voice
```
# Copy your files to the server (choose one method):

# Method A: Direct file copy (if files are on your local machine)
# scp production_conference_server.py radio_protocol.py root@<LINODE_IP>:/opt/opulent-voice/

# Method B: Clone from your repository (if you have one)
# git clone <YOUR_REPO_URL> .
# Note: this leaves the Python files in a subdirectory named after your repo (locus). Your files will probably need to be copied up a level.


# Method C: Create files directly on server
# nano production_conference_server.py
# nano radio_protocol.py
# (paste content from your local files)

# Set proper ownership
chown -R opulentvoice:opulentvoice /opt/opulent-voice

# Make server executable
chmod +x production_conference_server.py

# Test the server (optional)
sudo -u opulentvoice python3 production_conference_server.py --help
```

#### 4. Configure Firewall
```
# Enable UFW
ufw --force enable

# Allow SSH (IMPORTANT: Don't lock yourself out!)
ufw allow ssh

# Allow Opulent Voice port
ufw allow 57372/udp

# Optional: Allow custom port
# ufw allow 8000/udp

# Check status
ufw status
```

#### 5. Create Linode Service
Create `/etc/systemd/system/opulent-voice-server.service`:
```
[Unit]
Description=Opulent Voice Conference Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=opulentvoice
Group=opulentvoice
WorkingDirectory=/opt/opulent-voice
ExecStart=/usr/bin/python3 production_ready_server.py
Restart=always
RestartSec=10

# Security hardening for VPS
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/opulent-voice

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=opulent-voice

[Install]
WantedBy=multi-user.target
```

#### 6. Start Service
```
# Reload systemd
systemctl daemon-reload

# Enable and start service
systemctl enable opulent-voice-server
systemctl start opulent-voice-server

# Check status
systemctl status opulent-voice-server

# View logs
journalctl -u opulent-voice-server -f
```

#### 7. Monitor and Maintain
```
# Check service status
systemctl status opulent-voice-server

# View recent logs
journalctl -u opulent-voice-server --since "1 hour ago"

# Note: log view shown by journalctl may not show the very latest info. Instead, the log entries may be batched up and displayed in bursts.

# Restart if needed
systemctl restart opulent-voice-server

# Stop service
systemctl stop opulent-voice-server
```

#### 8. Optional: Domain Setup
```
# If you have a domain, create A record:
# conference.yourdomain.com -> <LINODE_IP>

# Test DNS resolution
nslookup conference.yourdomain.com

# Stations can then connect with:
# python3 interlocutor.py W1ABC -i <server-ip-address>
```

#### 9. Linode-Specific Monitoring
```
# Check network usage (Linode charges for excess bandwidth)
vnstat -i eth0

# Monitor system resources
htop

# Check disk usage
df -h

# View active connections
ss -tuln | grep 57372
```

#### 10. Backup Configuration
```
# Backup service file
cp /etc/systemd/system/opulent-voice-server.service ~/opulent-voice-backup.service

# Backup firewall rules
ufw --dry-run > ~/ufw-rules-backup.txt

# Create snapshot in Linode Manager for full system backup
```

### Custom Ports
If port 57372 is blocked or in use:
```
# Server
python3 production_conference_server.py -p 8000

# Stations  
python3 interlocutor.py W1ABC -i <SERVER> -p 8000
```

### Service Installation (Linux)
Create `/etc/systemd/system/opulent-voice-server.service`:
```
[Unit]
Description=Opulent Voice Conference Server
After=network.target

[Service]
Type=simple
User=opulentvoice
WorkingDirectory=/opt/opulent-voice
ExecStart=/usr/bin/python3 production_conference_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## Success Criteria

✅ **Server starts without errors**  
✅ **Stations connect and show proper callsigns**  
✅ **Chat messages delivered bidirectionally**  
✅ **Voice audio transmitted and received**  
✅ **Multiple stations can participate**  
✅ **Clean disconnection when stations exit**

## Common Command Reference
Commands all in one place. 

### Start Conference Server
```
python3 production_conference_server.py
```

### Connect Station (Standard)
```
python3 interlocutor.py <CALLSIGN> -i <SERVER_IP>
```

### Server Status Check
Look for these indicators:
- `🚀 Server ready for connections`
- `🆕 NEW STATION: <CALLSIGN>`
- `📊 Active stations: N`

### Shutdown
Server and station both shut down with `Ctrl+C`. 

## Security

### Built-in Protocol Security

The conference server includes automatic packet filtering that provides some basic security. Only Opulent Voice Protocol frames are accepted. There is a Header size validation. It drops headers smaller than 12 bytes. We have the very beginning of token validation. This server only forwards frames with valid prototype token (`0xBBAADD`). Station ID Validation is done. It rejects frames with invalid base-40 callsign encoding. Non-OVP traffic (HTTP, DNS, port scans) are automatically rejected. 

The server forwards entire Opulent Voice frames unchanged (header + payload). There is no content modification. Original station ID and message integrity is preserved. 

#### ✅ **Attack Resistance**
```
❌ HTTP requests → Dropped (wrong token)
❌ DNS queries → Dropped (invalid header)
❌ Port scans → Dropped (frame validation fails)
❌ Buffer overflows → Dropped (size validation)
✅ Valid OVP frames → Forwarded to other stations
```

### Security Monitoring

The server tracks security events:
```
# View server logs for security information
journalctl -u opulent-voice-server | grep "decode_errors"

# Check for unusual activity
📊 Decode errors: 15  # Number of rejected/invalid frames
```

### Network Security Recommendations

#### **Firewall Configuration** 
```
# Only allow OVP port (example for UFW)
ufw allow 57372/udp
ufw deny 57372/tcp  # Block TCP attempts

# Limit source IPs if possible (optional)
ufw allow from 192.168.1.0/24 to any port 57372
```

#### **Rate Limiting**
For high-security environments, consider OS-level rate limiting. 
```bash
# Limit connections per IP (example with iptables)
iptables -A INPUT -p udp --dport 57372 -m limit --limit 100/min -j ACCEPT
iptables -A INPUT -p udp --dport 57372 -j DROP
```

### Security Limitations & Considerations

#### **What the Server Does NOT Validate:**
Forwards encrypted/encoded payloads without inspection. No filtering of text messages or control commands. No validation of OPUS audio stream integrity. Relies on callsign encoding only. Token is fixed for this version. 

#### **Production Security Enhancements:**
For future satellite deployments, the roadmap includes A5 station authentication, cryptographic signatures, station validation. Monitoring (available now) includes logging of all station connections and disconnections. Alerts on high decode error rates. And, it monitors for unusual traffic patterns. 

Server preserves a list of original callsigns. Server doesn't restrict based on callsign validation beyond format checking

## Contact & Support

For issues with the conference server:
1. Check server logs for error messages
2. Verify network connectivity between machines
3. Ensure proper callsign encoding in base-40 format
4. Confirm `radio_protocol.py` is available on server machine

---

This is a production release of Locus in July 2025 for separate machine deployment only. 
