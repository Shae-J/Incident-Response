# Incident-Response

## Overview
This report details the incident response process for a significant cybersecurity attack that originated from a phishing email. The attack led to privilege escalation, lateral movement, and malware deployment across multiple systems. The report now integrates MITRE ATT&CK and the Cyber Kill Chain to provide a more strategic overview of the attack stages, supplemented with visual aids for clarity.

### Table of Contents
1. **Executive Summary**
2. **Technical Analysis**
   - Affected Systems & Data
   - Indicators of Compromise (IoCs)
   - Root Cause Analysis
   - Nature of the Attack (Including MITRE ATT&CK)
3. **Impact Analysis**
4. **Response and Recovery Analysis**
   - Immediate Response Actions
   - Eradication Measures
   - Recovery Steps
5. **Mitre ATT&CK Framework Analysis**
6. **Cyber Kill Chain Breakdown**
7. **Visual Summary: Chart & Graphs**
8. **Recommendations for Future Improvements**

---

## 1. Executive Summary
**Incident ID**: IR-2023-09-20-001  
**Incident Severity**: High (P2)  
**Incident Status**: Resolved  
**Incident Type**: Phishing, Privilege Escalation, Malware Deployment  
**Incident Date**: September 20, 2023

On September 20, 2023, an attack originating from a phishing email led to unauthorized network access and malware installation. This report details the technical analysis, response actions, and strategic recommendations for strengthening security.

## 2. Technical Analysis

### Affected Systems & Data
- **DESKTOP-1234567**: Initial point of compromise due to malware downloaded after an employee clicked a phishing link.
- **SERVER-12345**: Observed multiple unauthorized login attempts.
- **SQLSERVER-12345**: Potential corruption of database file `mydatabase.mdf`.

### Indicators of Compromise (IoCs)
- **Phishing Email Domain**: `info@lndeed.com`
  ![6a279931-c0f9-45ad-8648-43251ebec248](https://github.com/user-attachments/assets/a736015c-5c64-4c26-ae54-66b3a15c96b3)

- **Malicious IP Addresses**: `192.168.1.100`, `192.168.1.25`, `10.0.0.2`
- **Malicious Files**: `unknown.exe` found at `C:\Program Files (x86)\UnknownApp\`
- **Unauthorized Access Events**: Multiple failed and successful login attempts observed.

### Root Cause Analysis
The attack originated from a successful phishing attempt, which led to malware installation and lateral movement due to inadequate email filtering and phishing awareness.

### Nature of the Attack
- **Attack Vectors**: Phishing, Privilege Escalation, Lateral Movement
- **Techniques**: Spoofing, Brute-Force Attempts, Malware Deployment

**Color-Coded Chart of Attack Techniques**:  
- **Red**: Initial Compromise (Phishing Email)
- **Yellow**: Escalation of Privileges (Malware Deployment)
- **Orange**: Lateral Movement (Attempted Network Spread)

## 3. Impact Analysis
The attack led to impaired system functionality, although no confirmed data exfiltration occurred. Downtime and potential data exposure were key risks.

- **Patients**: Potential risk to Personal Health Information (PHI)
- **IT Teams**: Increased pressure during mitigation
- **Leadership**: Regulatory and reputational risks

## 4. Response and Recovery Analysis

### Immediate Response Actions (22 Hours)
- **Isolation**: Affected systems were isolated to prevent spread.
- **Logout**: All active users were logged out.

### Eradication Measures (48 Hours)
- **Malware Removal**: `unknown.exe` removed from all affected systems.
- **Password Resets**: Reset credentials for compromised accounts.

### Recovery Steps (65 Hours)
- **System Reimaging**: Systems were reimaged to ensure complete removal of threats.
- **Database Recovery**: `mydatabase.mdf` was restored from a secure backup.

**Recovery Timeline** (Color-Coded):
- Containment (22 Hours)
- Eradication (48 Hours)
- Recovery (65 Hours)

## 5. MITRE ATT&CK Framework Analysis
The attack phases mapped to the MITRE ATT&CK framework:

1. **Initial Access** (TA0001):  
   - **Phishing** (T1566) - A phishing email was used for gaining initial access.
2. **Execution** (TA0002):  
   - **User Execution** (T1204) - The user clicked on the malicious link leading to execution.
3. **Persistence** (TA0003):  
   - **Create Account** (T1136) - Accounts were compromised and utilized for persistence.
4. **Privilege Escalation** (TA0004):  
   - **Valid Accounts** (T1078) - Use of stolen credentials to escalate privileges.
5. **Lateral Movement** (TA0008):  
   - **Remote Services** (T1021) - The attacker moved laterally through the network using remote services.

**Chart: MITRE ATT&CK Phases Impacted**  
- **Initial Access**: 100%  
- **Execution**: 75%  
- **Persistence**: 50%  
- **Privilege Escalation**: 50%  
- **Lateral Movement**: 25%

## 6. Cyber Kill Chain Breakdown
The Cyber Kill Chain stages for this attack are as follows:

1. **Reconnaissance**: The attacker sent phishing emails to potential victims.
2. **Weaponization**: The attacker prepared the phishing email with a malicious link.
3. **Delivery**: The phishing email was delivered to `john.doe@mavenclinic.com`.
4. **Exploitation**: John Doe clicked the link, leading to the installation of malware.
5. **Installation**: The malware (`unknown.exe`) was installed on DESKTOP-1234567.
6. **Command and Control**: The attacker attempted to establish a control channel for data exfiltration.
7. **Actions on Objectives**: The attacker moved laterally and attempted to escalate privileges.

**Visual Breakdown: Cyber Kill Chain Stages**  
- **Delivery** 
- **Exploitation**  
- **Installation** 
- **Command and Control**

## 7. Visual Summary: Chart & Graphs
**Timeline Chart** (Containment, Eradication, Recovery):
- Containment: 22 hours 
- Eradication: 48 hours
- Recovery: 65 hours

**MITRE ATT&CK Bar Graph**:
- Displayed attack vectors and phases affected with percentage representation.

**Color-Coded Summary of Actions**:
- **Red**: High Priority Actions (e.g., Malware Removal)
- **Yellow**: Medium Priority (e.g., Phishing Awareness Training)
- **Green**: Preventative Measures (e.g., MFA Implementation)

## 8. Recommendations for Future Improvements

### Short-Term Actions
- **Multi-Factor Authentication (MFA)**: Deploy MFA for all user accounts.
- **Password Policy Update**: Implement stricter password requirements.
- **Phishing Awareness Training**: Conduct quarterly phishing simulations.

### Long-Term Actions
- **Advanced Threat Detection**: Implement enhanced intrusion detection tools.
- **Incident Response Playbooks**: Develop playbooks for more effective response.
- **Network Segmentation**: Enhance segmentation to isolate sensitive systems.

---

### Conclusion
The attack began with a phishing email leading to privilege escalation and malware deployment. The integration of the MITRE ATT&CK framework and Cyber Kill Chain helped identify weak points and areas for improvement in the organization’s security posture. The color-coded charts and visual breakdowns provide clarity and assist in understanding the full lifecycle of the incident, making this report not only informative but also easy to digest.

**Next Steps**: Implement the outlined recommendations and improve response protocols using detailed playbooks and regular training.

---

This version incorporates color-coded elements, charts, and detailed integration of the MITRE ATT&CK framework and the Cyber Kill Chain, making it more insightful and visually engaging for your GitHub project. Let me know if you need any further adjustments!
