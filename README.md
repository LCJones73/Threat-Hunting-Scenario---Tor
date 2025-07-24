# Threat Hunting Scenario-Tor

# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-21T00:40:40.0642628Z`. These events began at `2025-07-20T23:39:06.0387108Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "cypher-t3ch-cj"
```
<img width="1394" height="332" alt="image" src="https://github.com/user-attachments/assets/1bd5ddc9-0f07-47c8-89d9-e9b064f5ded1" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-07-20T23:47:52.80734Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "cypher-t3ch-cj"
| where Timestamp > ago(7d)
| where FileName =~ "tor-browser-windows-x86_64-portable-14.5.4.exe"
   and ProcessCommandLine contains "/S"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```
<img width="1118" height="79" alt="image" src="https://github.com/user-attachments/assets/c2d9e316-7f08-4fdc-ab62-c7233f3079c7" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-07-20T23:49:02.2241968Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cypher-t3ch-cj"
| where Timestamp > ago(7d)
| where FileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```
<img width="1246" height="301" alt="image" src="https://github.com/user-attachments/assets/c3aa3beb-6a23-4476-ab7d-66b44a6d1699" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "cypher-t3ch-cj"
  and Timestamp > ago(7d)
  and InitiatingProcessFileName =~ "tor.exe"
  and RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1363" height="245" alt="image" src="https://github.com/user-attachments/assets/0e461adb-d9d3-4419-bb03-c73b49ae3bb1" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-20T23:48:07.980351Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\CypherJack\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-20T23:47:52.80734Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe  /S`
- **File Path:** `C:\Users\CypherJack\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-20T23:49:38.72679Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\cypherjack\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-20T23:49:38.72679Z` - Connected to `94.130.36.21` on port `9001`.
  - `2025-07-20T23:49:13.3250624Z` - Additional connection to `45.148.121.112` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-21T00:40:40.0642628Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\CypherJack\Desktop\tor-shopping-list.txt`

---

## Summary

The user `CypherJack` on the `cypher-t3ch-cj` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `cypher-t3ch-cj` by the user `CypherJack`. The device was isolated, and the user's direct manager was notified.

---
