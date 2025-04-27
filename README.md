## Description

This PowerShell script gathers comprehensive system information and saves it to an HTML file. The script is designed to assist penetration testers and system administrators in quickly obtaining a detailed overview of a Windows system.

## Features

- **Operating System Information:** Host name, OS name, version, manufacturer, configuration, build type, registered owner, registered organization, product ID, original installation date, system boot time, Windows and system directories, boot device, system locale, input locale, time zone, and memory information.
    
- **Hardware and Domain Information:** System manufacturer, model, type, domain, domain membership, logon server, and primary domain controller.
    
- **Processor Information:** Name, number of cores, logical processors, and maximum clock speed.
    
- **BIOS Information:** BIOS version/date, manufacturer, and release date.
    
- **Paging File Information:** Path, current size, and allocated size.
    
- **Network Configuration:** Description of active adapters, DHCP status, physical address (MAC), IPv4 address, subnet mask, default gateway, DNS servers, and DHCP server.
    
- **Installed Hotfixes:** Hotfix ID, description, and installation date.
    
- **PowerShell Information:** Current admin privileges, version, edition, PowerShell v2 availability, execution policies, and loaded modules.
    
- **Environment Variables:** List of all environment variables and their values.
    
- **Local Defenses Check:** Firewall status, Windows Defender service status, and detailed Windows Defender status.
    
- **Connected Users and Additional Network Information:** Logged-in users, ARP table, and IPv4 routing table.
    
- **WMI Information:** Detailed information about the system, domain, users, local groups, system accounts, and running processes via WMI.
    
- **Net Command Equivalents (Active Directory & Local):** Domain password policy, domain groups, Domain Admins group members, domain controllers, domain computers, domain users, local groups, local Administrators group members, and local SMB shares.
    
- **Dsquery Equivalents (Active Directory):** Domain users and computers, objects in the Users container, users with non-required passwords, and the first 5 computer accounts.
    

## Requirements

- Windows PowerShell 2.0 or later
    
- Active Directory module (for domain-related information)
    
- Administrator privileges
    

## Usage

1. Save the script as a `.ps1` file (e.g., `ADInfo.ps1`).
    
2. Run PowerShell as an administrator.
    
3. Execute the script: `.\\ADInfo.ps1`
    
4. The script will generate an HTML file (`C:\\SystemInfo.html`) containing the gathered information.
    

## Output

The script generates an HTML file with the following sections:

1. General Information
    
2. Processor Information
    
3. Network Configuration
    
4. Connected Users and Additional Network Info
    
5. WMI Information
    
6. Net Command Equivalents (Active Directory & Local)
    
7. Dsquery Equivalents (Active Directory)
    
8. Installed Hotfixes
    
9. PowerShell Information and Security
    
10. Local Defenses Check
    
11. Environment Variables
    

Each section contains tables, lists, and preformatted text to present the information in a clear and organized manner. 

## Notes

- The script attempts to gather as much information as possible, but some sections may be empty if the system is not configured appropriately or if the script lacks the necessary privileges.
    
- The HTML file is saved to the C:\ root directory. You may need to run PowerShell as an administrator to write to this location.
    
- The script includes error handling to ensure that it runs even if some commands fail.
    
- The loaded PowerShell modules are included in the report to assist in the Post-Exploitation phase.
    
- Information about PowerShell execution policies is included to help identify potential vulnerabilities.
    
- Detailed Windows Defender information is included to help assess the system's security posture.
    
- WMI information is included to provide a comprehensive view of the system and its environment.
    
- Net command equivalents are included to provide a familiar way to access Active Directory and local information.
    
- Dsquery equivalents are included to facilitate the execution of common Active Directory queries.
