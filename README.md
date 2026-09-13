# SPLUNK-SOC-Homelab

My SOC homelab built using Splunk Enterprise, Windows 11, Sysmon, and Splunk Universal Forwarder.

I built this to practice SIEM monitoring, detection, investigation, and incident response in a virtual environment.

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

## INC-001 — Windows Brute Force Detection

### Goal

Detect repeated failed Windows login attempts.

### Event

`4625 — An account failed to log on`

### SPL

```spl
index=windows EventCode=4625
| stats count by Account_Name, src_ip
| sort - count
```

### Investigation

I generated multiple failed login attempts and used Splunk to group the events by account and source.

Example:

```text
Account: rainexe
Host: DESKTOP-14IQ0FC
EventCode: 4625
```

This makes it easier to identify repeated authentication failures against the same account.

### MITRE ATT&CK

`T1110 — Brute Force`

### Response

* Check if the login attempts were legitimate
* Identify the source of the attempts
* Check for a successful login afterward
* Reset the account credentials if compromise is suspected
* Investigate the source machine

### Screenshot

![INC-001](screenshots/inc-001-bruteforce.png)

---

## INC-002 — Suspicious PowerShell Activity

### Goal

Detect PowerShell activity that may require further investigation.

### Event

Sysmon process creation events.

### SPL

```spl
index=windows EventCode=1
| search Image="*powershell.exe"
| table _time host User Image CommandLine ParentImage
| sort - _time
```

### Investigation

I used Sysmon Event ID 1 to identify PowerShell processes running on the Windows machine.

I checked the user, process, command line, parent process, and host to determine what started PowerShell and what it was doing.

The detection is meant to flag PowerShell activity for investigation rather than automatically treating every PowerShell process as malicious.

### MITRE ATT&CK

`T1059.001 — Command and Scripting Interpreter: PowerShell`

### Response

* Review the PowerShell command line
* Identify the user who started the process
* Check the parent process
* Determine whether the activity was expected
* Review related events
* Investigate further if the activity is suspicious

### Screenshot

![INC-002](screenshots/inc-002-powershell.png)

---

## INC-003 — Suspicious Process Execution

### Goal

Detect potentially suspicious Windows process execution using Sysmon.

### Event

`1 — Process Create`

### SPL

```spl
index=windows EventCode=1
| search Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*mshta.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe"
| search NOT ParentImage="*SplunkUniversalForwarder\\bin\\splunkd.exe"
| table _time host User Image CommandLine ParentImage
| sort - _time
```

### Investigation

I used Sysmon Event ID 1 to monitor process creation.

The detection looks for Windows binaries that can be abused during an attack.

I also check the command line and parent process because the process itself is not enough to determine whether something is malicious.

I used `mshta.exe` to safely generate a test event.

### MITRE ATT&CK

`T1218.005 — System Binary Proxy Execution: Mshta`

### Response

* Identify the process
* Review the command line
* Check the parent process
* Identify the user
* Determine whether the execution was expected
* Check for related activity
* Isolate the endpoint if necessary

### Screenshot

![INC-003](screenshots/inc-003-process.png)

---

## INC-004 — User Account Created

### Goal

Detect newly created Windows user accounts.

### Event

`4720 — A user account was created`

### SPL

```spl
index=windows EventCode=4720
| table _time host EventCode Message
| sort - _time
```

### Investigation

I created a temporary local account to generate a real Windows Event ID 4720.

Test account:

```text
Account Name: soc-test
Account Domain: DESKTOP-14IQ0FC
```

Security ID:

```text
S-1-5-21-2992673872-3934415440-1281873822-1002
```

The detection is not tied to the test account. It looks for any Event ID 4720 so that it can detect newly created accounts in the environment.

In a real investigation, I would check who created the account and whether the account creation was authorized.

### MITRE ATT&CK

`T1136.001 — Create Account: Local Account`

### Response

* Verify whether the account was authorized
* Identify who created it
* Disable or remove the account if unauthorized
* Review authentication activity
* Check for additional persistence

### Screenshot

![INC-004](screenshots/inc-004-account.png)

---

## Detection Coverage

| Incident | Detection                      | Status  |
| -------- | ------------------------------ | ------- |
| INC-001  | Windows Brute Force Detection  | Working |
| INC-002  | Suspicious PowerShell Activity | Working |
| INC-003  | Suspicious Process Execution   | Working |
| INC-004  | User Account Created           | Working |

## Tools Used

* Splunk Enterprise
* Splunk Universal Forwarder
* Sysmon
* Windows 11
* Ubuntu Server
* VMware Workstation Pro

## Skills Practiced

* SPL
* SIEM monitoring
* Windows event analysis
* Sysmon
* Detection engineering
* Incident investigation
* MITRE ATT&CK
* Incident response
* Log analysis

## Notes

This is a personal homelab I built to practice SOC Analyst skills.

The detections are based on the Windows and Sysmon telemetry available in my lab. I used actual events and test activity to verify the detections instead of just writing theoretical SPL queries.
