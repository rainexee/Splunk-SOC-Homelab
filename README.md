# SPLUNK-SOC-Homelab

A SOC homelab I built to get more hands-on experience with **Splunk Enterprise, Windows logs, Sysmon, and detection engineering** while working toward a career in cybersecurity.

I wanted to build something practical instead of just studying the theory. This lab lets me work with Windows telemetry, write SPL detections, investigate events, troubleshoot log collection, and deal with false positives.

## Setup

* Windows 11 VM

  * Sysmon
  * Splunk Universal Forwarder
* Ubuntu Server VM

  * Splunk Enterprise
* VMware Workstation Pro

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

# Detections

## INC-001 - Windows Brute Force Detection

**Severity:** Medium
**MITRE ATT&CK:** T1110 - Brute Force
**Data Source:** Windows Security Event Log
**Detection:** 3+ failed logins for the same account within 5 minutes

### SPL

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count by _time, Account_Name
| where count >= 3
| sort - _time
```

### Investigation

I generated multiple failed login attempts on the Windows VM and used Splunk Enterprise to find the affected account.

```text
Account: rainexe
Host: DESKTOP-14IQ0FC
EventCode: 4625
```

I checked the account and host involved and looked at the timing of the failed attempts.

In a real environment, I'd also check whether the attempts were legitimate, look for a successful login afterward, and investigate the source if the activity looked suspicious.

### Screenshot

---

## INC-002 - Suspicious PowerShell Activity

**Severity:** Medium
**MITRE ATT&CK:** T1059.001 - PowerShell
**Data Source:** PowerShell Script Block Logging - Event ID 4104
**Detection:** Suspicious PowerShell script block activity

### SPL

```spl
index=windows EventCode=4104
| search Message="*ExecutionPolicy Bypass*" OR Message="*EncodedCommand*" OR Message="*DownloadString*" OR Message="*Invoke-Expression*"
| table _time host Account_Name Message
| sort - _time
```

### Investigation

I used PowerShell Script Block Logging in Splunk Enterprise to look for commands that would be worth investigating.

I focused on the actual contents of the script block instead of treating every PowerShell event as malicious.

I also checked the user and host involved to get more context around the activity.

### Response

For a real alert, I would:

* Review the PowerShell script block
* Identify the user
* Check what the command was trying to do
* Look for related PowerShell activity
* Determine whether the activity was expected
* Investigate further if it was suspicious

### Screenshot

---

## INC-003 - Suspicious Process Execution

**Severity:** Medium
**MITRE ATT&CK:** T1218.005 - System Binary Proxy Execution: Mshta
**Data Source:** Sysmon Event ID 1 - Process Creation
**Detection:** Potentially abused Windows binaries

### SPL

```spl
index=windows EventCode=1
| search Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*mshta.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe"
| search NOT ParentImage="*SplunkUniversalForwarder\\bin\\splunkd.exe"
| table _time host User Image CommandLine ParentImage
| sort - _time
```

### Investigation

I used Sysmon Event ID 1 and Splunk Enterprise to monitor process creation and look at things like the process name, command line, parent process, user, and host.

I used `mshta.exe` to safely generate a test event.

The first version of the detection also picked up legitimate Splunk Universal Forwarder activity. I looked into the event and found that `splunkd.exe` was the parent process.

I then added an exclusion for that known legitimate activity.

### Response

For a real alert, I would:

* Identify the process
* Review the command line
* Check the parent process
* Identify the user
* Determine whether the execution was expected
* Check for related activity
* Isolate the endpoint if necessary

### Screenshot

---

## INC-004 - User Account Created

**Severity:** Medium
**MITRE ATT&CK:** T1136.001 - Create Account: Local Account
**Data Source:** Windows Security Event Log - Event ID 4720
**Detection:** New local Windows user account created

### SPL

```spl
index=windows EventCode=4720
| table _time host EventCode Message
| sort - _time
```

### Investigation

I created a temporary local account to generate an actual Event ID 4720 event.

```text
Account Name: soc-test
Account Domain: DESKTOP-14IQ0FC
```

I then checked the event in Splunk Enterprise to see what information was available about the new account.

### Response

For a real alert, I would:

* Verify whether the account was authorized
* Identify who created it
* Disable or remove it if unauthorized
* Review authentication activity
* Check for additional persistence

### Screenshot

---

# Detection Coverage

| Incident | Detection                    | Status  |
| -------- | ---------------------------- | ------- |
| INC-001  | Windows Brute Force          | Working |
| INC-002  | Suspicious PowerShell        | Working |
| INC-003  | Suspicious Process Execution | Working |
| INC-004  | User Account Created         | Working |

# Debugging Sysmon and Log Collection

This ended up being one of the more useful parts of building the lab.

Sysmon itself was already installed, running, and generating events. The problem was getting those events through the **Splunk Universal Forwarder and into Splunk Enterprise** correctly.

Instead of changing everything at once, I worked through the pipeline one part at a time.

### 1. Check the Windows Endpoint

I started by checking Windows to make sure the events actually existed before troubleshooting Splunk Enterprise.

For Sysmon, I generated process activity and checked:

```text
Microsoft-Windows-Sysmon/Operational
```

I could see Event ID 1 being generated, so I knew Sysmon was working.

That meant the next thing to look at was the log collection.

### 2. Check Universal Forwarder Permissions

One of the problems I ran into was the Universal Forwarder not being able to properly read the Windows Event Logs.

The Forwarder runs as:

```text
NT SERVICE\SplunkForwarder
```

I checked the permissions and found that the service account needed access to the Windows Event Logs.

I added it to:

```text
Event Log Readers
```

and restarted the Universal Forwarder.

After that, I tested the logs again.

This showed me that an event can exist on the endpoint but still never make it to the SIEM if the process collecting it doesn't have the required permissions.

### 3. Check the Forwarder Configuration

After fixing the permissions, I checked what the Universal Forwarder was actually monitoring.

The Sysmon input was configured for:

```text
Microsoft-Windows-Sysmon/Operational
```

with the events being sent to the:

```text
windows
```

index in Splunk Enterprise.

I also checked the Windows Security Event Log inputs used for detections such as Event ID 4625 and 4720.

### 4. Check Splunk Enterprise

Once the Forwarder was configured, I checked Splunk Enterprise to see what was actually arriving.

I looked at:

* Index
* EventCode
* Host
* Sourcetype
* Available fields

For Sysmon, some of the fields I used were:

```text
EventCode
Image
CommandLine
ParentImage
User
host
```

For Windows Security events:

```text
EventCode
Account_Name
src_ip
host
Message
```

This helped me write the SPL around the data I actually had instead of assuming the fields would be there.

### 5. Work Backwards When Something Was Missing

When something wasn't showing up, I worked backwards:

```text
Windows
   |
   v
Sysmon / Event Log
   |
   v
Universal Forwarder
   |
   v
Splunk Enterprise
   |
   v
windows index
   |
   v
SPL Search
```

This made it easier to figure out where the problem actually was.

I also ran into a Splunk storage/dispatch issue during the setup, so I had to deal with the Splunk Enterprise side of the environment as well.

### 6. Deal With False Positives

Once Sysmon Event ID 1 was working in Splunk Enterprise, the process detection started picking up legitimate Splunk Universal Forwarder activity.

I investigated the events and found `splunkd.exe` as the parent process.

Instead of ignoring the events, I added an exclusion:

```spl
| search NOT ParentImage="*SplunkUniversalForwarder\\bin\\splunkd.exe"
```

That reduced the noise while keeping the detection active.

### 7. Test Changes

Whenever I changed something, I generated new activity on the Windows VM and checked Splunk Enterprise again.

I wanted to make sure the change actually worked instead of just assuming the configuration was correct.

## What I Took Away From It

The biggest thing I got from this was learning that detection engineering isn't just writing SPL.

If a detection isn't working, there can be a lot of places to check.

The event might not exist on Windows, the Forwarder might not be collecting it, permissions might be wrong, the event could be going into a different index, the fields might not be what I expected, or the query itself could be wrong.

Going through that process gave me a much better understanding of how endpoint telemetry actually gets from Windows into a SIEM.

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
* Windows Event Logs
* Sysmon
* Detection engineering
* Incident investigation
* MITRE ATT&CK
* Incident response
* Log analysis
* Troubleshooting
* False positive analysis
* Log collection and forwarding

# Notes

This is a personal homelab I built to get more practical cybersecurity experience.

The detections are based on Windows and Sysmon telemetry from my own lab. I used real events and controlled test activity to make sure the detections actually worked.

A big part of the project was troubleshooting the log pipeline and figuring out why events were or weren't making it into Splunk Enterprise.

This is still a work in progress. I'm going to keep building on top of this homelab and add more detections, tools, and telemetry over time until I can turn it into a more enterprise-level SOC environment.
---

♡ ~ rainexe
