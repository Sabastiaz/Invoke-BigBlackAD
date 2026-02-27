# Invoke-BigBlackAD 🖤

> *"When your pentest hits a wall, there's only one man for the job."*

![PowerShell](https://img.shields.io/badge/PowerShell-3.0%2B-blue?style=for-the-badge&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)
![AD](https://img.shields.io/badge/Active%20Directory-Owned-red?style=for-the-badge)
![Summon](https://img.shields.io/badge/Big%20Black-Summoned-success?style=for-the-badge)

---

## 🧙 What is this?

`Invoke-BigBlackAD` is a **critical Active Directory pentesting tool** that should be deployed immediately when:

- BloodHound is confused 🐕
- SharpHound is crying 😭
- PowerView is shaking 😰
- You have no idea what you're doing 💀
- The Domain Admin is escaping 🏃

This tool solves **all** of the above by **summoning Big Black** — the legendary AD whisperer who will have you owning that domain in no time.

---

## ⚡ Quick Start 

**One-liner (IEX method):**
```powershell
IEX (iwr 'https://raw.githubusercontent.com/Sabastiaz/Invoke-BigBlackAD/main/Invoke-BigBlackAD.ps1' -UseBasicParsing)
```

**Clone and import locally:**
```powershell
git clone https://github.com/Sabastiaz/Invoke-BigBlackAD.git
Import-Module .\Invoke-BigBlackAD.ps1
Invoke-BigBlackAD                      # basic enumeration
Invoke-BigBlackAD -FullEnumeration     # full enumeration (shares, groups, ACLs, BloodHound, etc.)
```

---

## 🖥️ Expected Output

```
    ____  _         ____  _            _
 | __ )(_) __ _  | __ )| | __ _  ___| | __
 |  _ \| |/ _' | |  _ \| |/ _' |/ __| |/ /
 | |_) | | (_| | | |_) | | (_| | (__|   <
 |____/|_|\__, | |____/|_|\__,_|\___|_|\_\
           |___/
                    >> A D  W H I S P E R E R <<
[*] Initializing Advanced AD Enumeration Toolkit...
[*] Starting Big Black AD Enumeration...
[*] Target Domain: wowza.local
[*] Current User: Administrator
[*] Checking Active Directory Module...
[+] Active Directory Module loaded successfully
[*] Enumerating Domain Information...
[+] Domain: wowza.local
[+] Forest: wowza.local
[+] Domain Controllers: 1

Name                           Value
----                           -----
DomainMode                     Unknown
SchemaMaster
ForestName                     wowza.local
DomainControllers              dc01.wowza.local
ForestMode                     Unknown
DomainName                     wowza.local
PDC                            dc01.wowza.local

```

---

## 📋 Requirements

| Requirement | Version |
|---|---|
| PowerShell | 3.0+ |
| OS | Only Windows |
| Big Black | Available on Facebook |
| Desperation | Maximum |

---

## 🛠️ Features

🔹 1️⃣ Core AD Enumeration
✅ Domain Information
✅ User Enumeration
✅ AS-REP Roast Check
✅ Kerberoastable Accounts
✅ Group Enumeration
✅ Network Share Enumeration
✅ Delegation Check
✅ ACL Check

🔹 2️⃣ BloodHound Integration
✅ SharpHound Auto Detection
✅ Collection Mode
✅ Export Zip

🔹 3️⃣ AD Recycle Bin Inspector (Read-Only)
✅ Restore-DeletedADObject

🔹 4️⃣ Token & Privilege Analyzer (Full Host Context Module)
✅ whoami /priv
✅ whoami /all
✅ whoami /groups
✅ whoami /user
✅ Integrity Detection
Low / Medium / High / System

✅ Elevated Detection
✅ UAC Posture
✅ LSA Posture
✅ Export

🔹 5️⃣ Reporting
✅ Summary Report Generator

🔹 6️⃣ Modes

**Lab Mode** (`-Mode Lab`)
- Loads optional tools (PowerView if present)
- BloodHound full collection
- Opens Facebook profile at completion

**Audit Mode** (`-Mode Audit`, default)
- Conservative collection
- Lower noise
- DCOnly BloodHound collection

🔹 7️⃣ OPSEC Improvements

---

## 🤝 The Man, The Myth, The Legend

When your team is lost in the forest of Group Policy Objects and you can't find the path to Domain Admin, **Big Black** appears.

📬 **Contact Big Black directly:**
👉 [https://www.facebook.com/sabastian.fhantomhive](https://www.facebook.com/sabastian.fhantomhive)

Tell him: *"I need AD help. Chicken0248 sent me."*

---

## ⚠️ Disclaimer

This tool is an **inside joke** created for our pentesting team. It does not perform any actual Active Directory enumeration, exploitation, or reconnaissance. Any resemblance to a real security tool is purely for comedic effect.

Please do not use this on client engagements. Unless the client asks why you're opening Facebook mid-pentest. Then it's their fault.

---

## 📜 License

Do whatever you want with this. Big Black approves.

---

<p align="center">
  <i>Built with ❤️ and desperation by the team<br>
  Powered by Big Black's infinite AD wisdom</i>
</p>
