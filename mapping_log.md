# Compliance Mapping Log — NTRO PS 26155 (Phase 1: Cisco IOS-XE)

**Project:** AI-Driven Multi-Vendor Network Security Compliance Auditor (NTRO PS 26155)  
**Scope:** Cisco IOS-XE Rules (`COMMON-SSH-001` through `COMMON-MGMT-001`)  
**Target File:** `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/vendor_rule_mapping.json`  
**Validation Status:** `manually mapped, pending SME review`  

---

## 1. Summary of Mappings

| Common Rule ID | Vendor Rule ID | CIS Benchmark § | DISA STIG Vuln ID | CCI ID | Mapped NIST SP 800-53 rev5 Control | Rule Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **COMMON-SSH-001** | `CISCO-SSH-001` | §2.1.1.2 | `V-215845` | `CCI-003123` | `MA-4 (6)` | manually mapped, pending SME review |
| **COMMON-AAA-001** | `CISCO-AAA-001` | §1.1.1 | `V-215854` | `CCI-000370` | `CM-6 (1)` | manually mapped, pending SME review |
| **COMMON-NTP-001** | `CISCO-NTP-001` | §2.3.1.1 | `V-215843` | `CCI-001967` | `IA-3 (1)` | manually mapped, pending SME review |
| **COMMON-LOG-001** | `CISCO-LOG-001` | §2.2.4 | `V-220139` | `CCI-001851` | `AU-4 (1)` | manually mapped, pending SME review |
| **COMMON-SNMP-001** | `CISCO-SNMP-001` | §1.5.7 | `V-215841` | `CCI-001967` | `IA-3 (1)` | manually mapped, pending SME review |
| **COMMON-ACL-001** | `CISCO-ACL-001` | §1.2.5 | `V-215812` | `CCI-001368` | `AC-4` | manually mapped, pending SME review |
| **COMMON-INT-001** | `CISCO-INT-001` | *Unmapped* | `V-216646` | `CCI-001414` | `AC-4` | prototype |
| **COMMON-ROUTING-001** | `CISCO-ROUTING-001` | §3.3.3.1 | `V-216645` | `CCI-000803` | `IA-7` | manually mapped, pending SME review |
| **COMMON-STP-001** | `CISCO-STP-001` | *Unmapped* | `V-220656` | `CCI-002385` | `SC-5 a` | prototype |
| **COMMON-MGMT-001** | `CISCO-MGMT-001` | §1.2.5 | `V-216680` | `CCI-001414` | `AC-4` | manually mapped, pending SME review |

---

## 2. Detailed Per-Rule Evidence and Rationale

### 1. COMMON-SSH-001 (`CISCO-SSH-001`)
- **Check Focus:** SSH version, VTY access, approved authentication, management access restrictions
- **Configuration Evidence:** `ip ssh version 2`, `line vty`, `transport input ssh`, `login authentication`
- **CIS Benchmark:**
  - Control / Section: `2.1.1.2` (*Set version 2 for 'ip ssh version'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.1.1.2`
- **DISA STIG:**
  - Vuln ID: `V-215845` (Rule ID: `SV-215845r961557_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-003123`
  - NIST SP 800-53 rev5: `MA-4 (6)`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-003123`
- **Status:** `manually mapped, pending SME review`

---

### 2. COMMON-AAA-001 (`CISCO-AAA-001`)
- **Check Focus:** AAA enabled, authentication method, authorization, accounting
- **Configuration Evidence:** `aaa new-model`, `aaa authentication login`, `aaa authorization exec`, `aaa accounting`
- **CIS Benchmark:**
  - Control / Section: `1.1.1` (*Enable 'aaa new-model'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.1.1`
- **DISA STIG:**
  - Vuln ID: `V-215854` (Rule ID: `SV-215854r1156415_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-000370`
  - NIST SP 800-53 rev5: `CM-6 (1)`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-000370`
- **Status:** `manually mapped, pending SME review`

---

### 3. COMMON-NTP-001 (`CISCO-NTP-001`)
- **Check Focus:** Approved NTP server, NTP authentication, source interface
- **Configuration Evidence:** `ntp server`, `ntp authenticate`, `ntp trusted-key`, `ntp source`
- **CIS Benchmark:**
  - Control / Section: `2.3.1.1` (*Set 'ntp authenticate'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.3.1.1`
- **DISA STIG:**
  - Vuln ID: `V-215843` (Rule ID: `SV-215843r1050862_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001967`
  - NIST SP 800-53 rev5: `IA-3 (1)`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001967`
- **Status:** `manually mapped, pending SME review`

---

### 4. COMMON-LOG-001 (`CISCO-LOG-001`)
- **Check Focus:** Remote logging, severity, timestamps, local buffer
- **Configuration Evidence:** `logging host`, `logging trap`, `logging buffered`, `service timestamps log`
- **CIS Benchmark:**
  - Control / Section: `2.2.4` (*Set IP address for 'logging host'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.2.4`
- **DISA STIG:**
  - Vuln ID: `V-220139` (Rule ID: `SV-220139r1137890_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001851`
  - NIST SP 800-53 rev5: `AU-4 (1)`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001851`
- **Status:** `manually mapped, pending SME review`

---

### 5. COMMON-SNMP-001 (`CISCO-SNMP-001`)
- **Check Focus:** SNMP version, secure authentication, authorized monitoring hosts, weak community strings
- **Configuration Evidence:** `snmp-server group`, `snmp-server user`, `snmp-server host`, `snmp-server community`
- **CIS Benchmark:**
  - Control / Section: `1.5.7` (*Set 'snmp-server host' when using SNMP*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.5.7`
- **DISA STIG:**
  - Vuln ID: `V-215841` (Rule ID: `SV-215841r1107207_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001967`
  - NIST SP 800-53 rev5: `IA-3 (1)`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001967`
- **Status:** `manually mapped, pending SME review`

---

### 6. COMMON-ACL-001 (`CISCO-ACL-001`)
- **Check Focus:** Management ACL, source restriction, ACL application
- **Configuration Evidence:** `ip access-list`, `access-class`, `ip access-group`, `ipv6 access-class`
- **CIS Benchmark:**
  - Control / Section: `1.2.5` (*Set 'access-class' for 'line vty'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.2.5`
- **DISA STIG:**
  - Vuln ID: `V-215812` (Rule ID: `SV-215812r1137875_rule`)
  - Source Ref: `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml, Cisco IOS XE Router NDM STIG V3R7`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001368`
  - NIST SP 800-53 rev5: `AC-4`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001368`
- **Status:** `manually mapped, pending SME review`

---

### 7. COMMON-INT-001 (`CISCO-INT-001`)
- **Check Focus:** Unused interfaces, administrative shutdown, access/trunk classification
- **Configuration Evidence:** `interface`, `shutdown`, `description`, `switchport`
- **CIS Benchmark:**
  - Control / Section: *Unmapped* (CIS Cisco IOS XE 17.x Benchmark does not contain a dedicated standalone section for administratively shutting down unused interfaces).
- **DISA STIG:**
  - Vuln ID: `V-216646` (Rule ID: `SV-216646r1117237_rule`)
  - Title: *The Cisco router must be configured to have all inactive interfaces disabled.*
  - Source Ref: `U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml, Cisco IOS XE Router RTR STIG V3R5`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001414`
  - NIST SP 800-53 rev5: `AC-4`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001414`
- **Mapping Notes:** CIS benchmark Cisco IOS XE 17.x contains no dedicated section for disabling unused interfaces; mapped to DISA-STIG V-216646 and NIST SP 800-53 AC-4 via CCI-001414.
- **Status:** `prototype`

---

### 8. COMMON-ROUTING-001 (`CISCO-ROUTING-001`)
- **Check Focus:** Peer restrictions, routing authentication, approved neighbors
- **Configuration Evidence:** `router bgp`, `neighbor password`, `neighbor key`, `router ospf`, `area authentication`
- **CIS Benchmark:**
  - Control / Section: `3.3.3.1` (*Set 'neighbor password'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §3.3.3.1`
- **DISA STIG:**
  - Vuln ID: `V-216645` (Rule ID: `SV-216645r1007829_rule`)
  - Title: *The Cisco router must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.*
  - Source Ref: `U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml, Cisco IOS XE Router RTR STIG V3R5`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-000803`
  - NIST SP 800-53 rev5: `IA-7`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-000803`
- **Status:** `manually mapped, pending SME review`

---

### 9. COMMON-STP-001 (`CISCO-STP-001`)
- **Check Focus:** Edge-port protection, BPDU Guard, Root Guard, Loop Guard
- **Configuration Evidence:** `spanning-tree portfast`, `spanning-tree bpduguard enable`, `spanning-tree guard root`, `spanning-tree guard loop`
- **CIS Benchmark:**
  - Control / Section: *Unmapped* (STP is a Layer 2 Switch technology; CIS Cisco IOS XE 17.x Benchmark covers Layer 3 router profiles and omits STP edge protection).
- **DISA STIG:**
  - Vuln ID: `V-220656` (Rule ID: `SV-220656r856278_rule`)
  - Title: *The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.*
  - Source Ref: `U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml, Cisco IOS XE Switch L2S STIG V3R2`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-002385`
  - NIST SP 800-53 rev5: `SC-5 a`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-002385`
- **Mapping Notes:** STP (Spanning-Tree Protocol / BPDU Guard / Root Guard / Loop Guard) is a Layer 2 Switch feature covered in DISA STIG Switch L2S V-220656 (CCI-002385 / NIST SC-5 a); it is not present in the CIS Cisco IOS XE 17.x Router Benchmark.
- **Status:** `prototype`

---

### 10. COMMON-MGMT-001 (`CISCO-MGMT-001`)
- **Check Focus:** Management VRF, management service exposure, source restrictions
- **Configuration Evidence:** `vrf definition`, `vrf forwarding`, `ip http access-class`, `transport input ssh`, `access-class`
- **CIS Benchmark:**
  - Control / Section: `1.2.5` (*Set 'access-class' for 'line vty'*)
  - Source Ref: `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.2.5`
- **DISA STIG:**
  - Vuln ID: `V-216680` (Rule ID: `SV-216680r1117237_rule`)
  - Title: *The Cisco out-of-band management (OOBM) gateway router must be configured to have separate Interior Gateway Protocol (IGP) instances for the managed network and management network.*
  - Source Ref: `U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml, Cisco IOS XE Router RTR STIG V3R5`
- **CCI & NIST 800-53 rev5:**
  - CCI: `CCI-001414`
  - NIST SP 800-53 rev5: `AC-4`
  - Source Ref: `NIST SP 800-53 rev5, via CCI-001414`
- **Mapping Notes:** Management separation via VRF and access restrictions maps to DISA-STIG V-216680 (separate IGP/VRF for OOBM) and CIS §1.2.5 (VTY access restrictions).
- **Status:** `manually mapped, pending SME review`
