# DetectSMB — Open Share Detection Approach

## What Was Asked
Detect open or overly permissive SMB shares in the environment
and identify any sensitive data exposed through them.

## My Approach (3 Stages)

### Stage 1 — KQL Advanced Hunting (Completed)

**What it does:** Queries MDE telemetry to detect suspicious SMB
*activity* — things that already happened.

**Why KQL first:** No agent or script needed. Runs against 30 days
of historical data immediately. Good for spotting past exposure
and tuning before building automated rules.

**Q1 — SMB Scanning / Share Enumeration Detection**
File: `shares/Q1_SMB_ScanningDetection.kql`
- Table: DeviceNetworkEvents (port 445)
- Logic: Flag any process that contacted >20 unique remote IPs
  over SMB in 24 hours. Threshold set to 20 after 30-day baseline
  showed max 18 for legitimate tools (svchost, lsass, MsMpEng).
- Finding: 1 result — a device contacting an unusual number of
  SMB endpoints. Pending mentor review to classify.

**Q4 — Guest / Anonymous Network Logon**
File: `shares/Q4_GuestAnonymousLogon.kql`
- Table: DeviceLogonEvents (LogonType == "Network" — SMB share access)
- Logic: Alert on any logon where AccountName is Guest or Anonymous over the network.
  No threshold — every occurrence is worth reviewing.
- Finding: Accounts are **active** and logging on (confirmed 2026-03-31).
  Treat each result as a High severity alert.

**Q2 — Sensitive File Access on Network Shares**
File: `shares/Q2_SensitiveFileAccess.kql`
- Table: DeviceFileEvents (UNC paths only — \\server\share\...)
- Logic: Flag access to files with sensitive names or extensions
  (.pem, .pfx, .p12, .ppk, KeePass*, password*, credentials*, etc.)
- Findings (30-day run):
  - ~9,300 false positives from Veeam backup writing SSL .pem
    certs → excluded by process name
  - **eHealth certificates on a share**: Multiple .p12 files
    (CM.p12, ACC-MYCARENET.p12, ehealthacc.p12) created by named
    users via explorer.exe. These are PKCS#12 bundles (cert + private
    key). Share used as informal cert store for ~8 years. Anyone with
    access can copy and use these to authenticate to healthcare systems.
  - **KeePass config on a share**: user 9091057 saving KeePass.config.xml
    to a network share. Config reveals the path to the .kdbx password
    database. Also: robocopy creating KeePass .lnk shortcuts (85 hits).

### Stage 2 — MDVM Network Share Assessment (Skipped)

MDVM Network Share Assessment requires the MDVM add-on license,
which is not available in this environment. Only basic MDVM
(bundled with MDE P2) is active. Confirmed 2026-03-31.

### Stage 3 — PowerShell via MDE Live Response (Planned)

**What it does:** Connects directly to file servers and enumerates
share *configuration* — what shares exist and who has permission.

**Why this complements KQL:** KQL shows access events (someone
accessed a file). PowerShell shows the ACL (anyone COULD access it).
Together: confirm whether the Q2 findings are accessible to
broad groups like Everyone or Authenticated Users.

**How it works:**
1. Run a KQL helper query to rank file servers by share activity
   and pick the top targets.
2. In MDE portal: Devices → [server] → Initiate Live Response Session
3. Upload and run `live-response/Get-ShareInventory.ps1`
4. Script runs `Get-SmbShare` + `Get-SmbShareAccess`, flags any share
   where Everyone / Authenticated Users / Domain Users has Allow access.
5. Download the CSV output. Cross-reference against Q2 findings.

**Script:** `live-response/Get-ShareInventory.ps1`

**KQL helper — find Live Response targets (ranked by share activity):**
```kql
DeviceFileEvents
| where FolderPath startswith "\\\\"
| extend UNCServer = extract(@"\\\\([^\\]+)\\", 1, FolderPath)
| where isnotempty(UNCServer)
| summarize ShareCount = dcount(FolderPath) by UNCServer
| sort by ShareCount desc
```

## Ongoing Detection (Next Step)

Convert queries into **Custom Detection Rules** in MDE:
- security.microsoft.com → Hunting → Custom detection rules → Create rule
- Set frequency: every 1 hour (Q2, Q4) or every 24 hours (Q1)
- Set alert title and severity (Q4 = High, Q2 = High, Q1 = Medium)
- Under Actions: Generate alert, optionally tag the device
- This turns one-time queries into continuous monitoring.

## Limitations Discovered

| Limitation | Impact |
|---|---|
| No Microsoft Sentinel | Cannot use SecurityEvent table or Windows Event Log queries |
| No SMB ActionTypes in DeviceEvents | Cannot detect share creation/deletion via KQL |
| No LanmanServer registry events | Cannot see share config changes in DeviceRegistryEvents |
| Guest/anonymous accounts active | NOT a limitation — Q4 detects these logons (High severity) |
| No MDVM add-on | Stage 2 not possible |

> **Note:** The above limitations are claimed based on investigation. Run the
> verification queries below in MDE Advanced Hunting to confirm before presenting
> to the mentor.

### Verification Queries

**1. No SMB ActionTypes in DeviceEvents:**
```kql
DeviceEvents
| where ActionType has_any ("smb", "Share", "share")
| summarize count() by ActionType
| order by count_ desc
```
Expected: 0 rows.

**2. No LanmanServer registry events:**
```kql
DeviceRegistryEvents
| where RegistryKey has "LanmanServer\\Shares"
| summarize count() by RegistryKey, ActionType
```
Expected: 0 rows.

**3. Guest/anonymous accounts disabled:**
```kql
DeviceLogonEvents
| where AccountName in~ ("Guest", "Anonymous")
| summarize count() by AccountName, DeviceName
```
Result: **Rows returned — accounts are active.** Q4 was created to detect these. ✓

**4. MDVM add-on unavailable:**
In MDE portal: Vulnerability Management → Assessments → Network shares.
Expected: Page does not exist or shows "not available".

## Files

| File | Purpose |
|---|---|
| `shares/Q1_SMB_ScanningDetection.kql` | Port 445 scanning detection |
| `shares/Q2_SensitiveFileAccess.kql` | Sensitive file access on UNC paths |
| `shares/Q4_GuestAnonymousLogon.kql` | Guest/anonymous network logon detection |
| `live-response/Get-ShareInventory.ps1` | Share ACL enumeration via Live Response |
