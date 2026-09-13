# SPLUNK-SOC-Homelab

My SOC homelab built using Splunk Enterprise, Windows 11, Sysmon, and Splunk Universal Forwarder.

I built this to practice SIEM monitoring, detection engineering, Windows event analysis, investigation, incident response, and troubleshooting.

## Lab Setup

* Windows 11 VM

  * Sysmon
  * Splunk Universal Forwarder
* Ubuntu Server VM

  * Splunk Enterprise
* VMware Workstation Pro

### Setup

```text
Windows 11
    |
    | Windows Security Logs + Sysmon
    |
Splunk Universal Forwarder
    |
    v
Ubuntu Server
    |
Splunk Enterprise
```

---

# Incidents

## INC-001 - Windows Brute Force Detection

**Severity:** Medium
**Technique:** MITRE ATT&CK T1110 - Brute Force
**Detection:** >= 3 Failed logons for the same account within 5 minutes
**Data Source:** Windows Security Event Log

### SPL

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count by _time, Account_Name
| where count >= 3
| sort - _time
```

### Investigation

I generated multiple failed login attempts and used Splunk to identify the affected account and source.

Example:

```text
Account: rainexe
Host: DESKTOP-14IQ0FC
EventCode: 4625
```

### Response

* Check if the login attempts were legitimate
* Identify the source
* Check for a successful login afterward
* Reset credentials if compromise is suspected
* Investigate the source machine

### Screenshot

![INC-001](screenshots/inc-001-bruteforce.png)

---

## INC-002 - Suspicious PowerShell Activity

**Severity:** Medium
**Technique:** MITRE ATT&CK T1059.001 - PowerShell
**Detection:** PowerShell process execution detected on a Windows endpoint
**Data Source:** Sysmon Event ID 1 - Process Creation

### SPL

```spl
index=windows EventCode=4104
| search Message="*ExecutionPolicy Bypass*" OR Message="*EncodedCommand*" OR Message="*DownloadString*" OR Message="*Invoke-Expression*"
| table _time host Account_Name Message
| sort - _time
```

### Investigation

I used Sysmon Event ID 1 to identify PowerShell processes and reviewed the user, command line, parent process, and host.

### Response

* Review the PowerShell command line
* Identify the user
* Check the parent process
* Determine whether the activity was expected
* Review related events

### Screenshot

![INC-002](screenshots/inc-002-powershell.png)

---

## INC-003 - Suspicious Process Execution

**Severity:** Medium
**Technique:** MITRE ATT&CK T1218.005 - System Binary Proxy Execution: Mshta
**Detection:** Execution of potentially abused Windows binaries including PowerShell, CMD, MSHTA, Rundll32, Regsvr32, WScript, and CScript
**Data Source:** Sysmon Event ID 1 - Process Creation

### SPL

```spl
index=windows EventCode=1
| search Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*mshta.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe"
| search NOT ParentImage="*SplunkUniversalForwarder\\bin\\splunkd.exe"
| table _time host User Image CommandLine ParentImage
| sort - _time
```

### Investigation

I used Sysmon Event ID 1 to monitor process creation and reviewed the process, command line, parent process, user, and host.

I used `mshta.exe` to safely generate a test event.

The detection initially picked up legitimate Splunk Universal Forwarder activity. I investigated the event, identified `splunkd.exe` as the legitimate parent process, and added an exclusion to reduce false positives.

### Response

* Identify the process
* Review the command line
* Check the parent process
* Determine whether the execution was expected
* Check for related activity
* Isolate the endpoint if necessary

### Screenshot

![INC-003](screenshots/inc-003-process.png)

---

## INC-004 - User Account Created

**Severity:** Medium
**Technique:** MITRE ATT&CK T1136.001 - Create Account: Local Account
**Detection:** New local Windows user account created
**Data Source:** Windows Security Event Log - Event ID 4720

### SPL

```spl
index=windows EventCode=4720
| table _time host EventCode Message
| sort - _time
```

### Investigation

I created a temporary local account to generate a real Event ID 4720 event.

```text
Account Name: soc-test
Account Domain: DESKTOP-14IQ0FC
```

I checked the event to identify the newly created account and the available account information.

### Response

* Verify whether the account was authorized
* Identify who created it
* Disable or remove the account if unauthorized
* Review authentication activity
* Check for additional persistence

### Screenshot

![INC-004](screenshots/inc-004-account.png)

---

# Detection Coverage

| Incident | Detection                      | Status  |
| -------- | ------------------------------ | ------- |
| INC-001  | Windows Brute Force Detection  | Working |
| INC-002  | Suspicious PowerShell Activity | Working |
| INC-003  | Suspicious Process Execution   | Working |
| INC-004  | User Account Created           | Working |

---

# Debugging and Troubleshooting

A big part of building this lab was figuring out why telemetry and detections were not working as expected.

I treated each issue like a troubleshooting problem instead of changing multiple settings at once. I worked through the pipeline from the Windows endpoint to Splunk.

### My Debugging Process

**1. Confirm the event exists**

I first checked whether Windows or Sysmon was actually generating the event.

If the event did not exist on Windows, changing the Splunk query would not solve the problem.

**2. Check the forwarder**

If the event existed, I checked whether the Splunk Universal Forwarder was configured to collect it.

**3. Check permissions**

When Windows Event Logs were not being forwarded correctly, I checked the permissions of the `SplunkForwarder` service account and added it to the `Event Log Readers` group.

**4. Check the Splunk index**

I verified that events were reaching Splunk and being written to the expected `windows` index.

**5. Inspect the actual event fields**

Before writing or changing a detection, I inspected the events themselves and checked fields such as:

```text
EventCode
Image
CommandLine
ParentImage
User
host
Account_Name
src_ip
```

This allowed me to build detections around the telemetry actually available in the environment.

**6. Investigate false positives**

My suspicious process detection initially picked up legitimate activity from the Splunk Universal Forwarder.

Instead of simply ignoring the result, I investigated the event and identified `splunkd.exe` as the legitimate parent process.

I then added an exclusion to reduce false positives while keeping the detection active.

**7. Test the fix**

After making a configuration or detection change, I generated another event and checked Splunk again to confirm whether the issue was actually resolved.

### Problems I Worked Through

* Windows Event Logs not initially appearing in Splunk
* Splunk Universal Forwarder input configuration
* Windows Event Log permissions
* Splunk service account permissions
* Events appearing in unexpected indexes
* Checking monitored inputs and forwarding
* Splunk storage and dispatch disk space issues
* Missing Windows telemetry sources
* Detection false positives
* Validating detections with real test events

### Troubleshooting Approach

```text
Event Generated?
       |
       v
Forwarder Collecting It?
       |
       v
Correct Splunk Index?
       |
       v
Expected Fields Present?
       |
       v
SPL Query Working?
       |
       v
False Positives?
       |
       v
Tune Detection
       |
       v
Generate Test Event Again
```

The main thing I learned from this was that detection engineering is not just writing SPL.

When something does not work, I need to determine whether the problem is with event generation, permissions, collection, forwarding, indexing, fields, the query itself, or the detection logic.

That troubleshooting process is directly applicable to a SOC environment when dealing with missing telemetry, broken detections, false positives, or unexpected security events.

---

# Tools Used

* Splunk Enterprise
* Splunk Universal Forwarder
* Sysmon
* Windows 11
* Ubuntu Server
* VMware Workstation Pro

# Skills Practiced

* SPL
* SIEM monitoring
* Windows event analysis
* Sysmon
* Detection engineering
* Incident investigation
* MITRE ATT&CK
* Incident response
* Log analysis
* Troubleshooting
* False positive analysis
* Log collection and forwarding

---




# Notes

This is a personal homelab I built to practice SOC Analyst skills.

The detections are based on the Windows and Sysmon telemetry available in my lab. I used actual events and test activity to verify the detections instead of only writing theoretical SPL queries.

The debugging process was also part of the project. I had to troubleshoot the endpoint, log collection, permissions, forwarding, indexing, detection logic, and false positives before I could get the detections working.

This is still a work in progress. I’m going to keep building on top of this homelab and add more detections, tools, and telemetry over time until I can turn it into a more enterprise-level SOC environment.
