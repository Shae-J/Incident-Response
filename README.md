# Incident-Response


## Overview
This lab demonstrates the complete process of responding to a cybersecurity incident that was triggered by a phishing attack. The attack resulted in privilege escalation, lateral movement across the network, and the installation of malware on several systems. The incident impacted both desktop and server infrastructure, involving sensitive systems and data. The report covers technical analysis, response actions, and recommendations for future improvements to enhance the organization's cybersecurity resilience.

## Incident Report Summary
- **Incident ID**: IR-2023-09-20-001
- **Incident Severity**: High (P2)
- **Incident Status**: Resolved
- **Incident Date**: September 20, 2023
- **Incident Type**: Phishing, Privilege Escalation, Malware Deployment

The attack originated from a phishing email that tricked an employee into clicking a malicious link. This allowed malware to be installed, leading to compromised credentials and escalation of privileges within the network. The incident required isolation, malware removal, and restoration actions to mitigate its impact.


## Documentation Details

### Technical Analysis (`documentation/technical_analysis.md`)
This document contains a technical breakdown of the incident, explaining how the attackers gained access to the internal network, the systems that were affected, and the indicators of compromise.

#### Affected Systems & Data:
- **DESKTOP-1234567**: Initial point of entry. Malware (unknown.exe) was installed after the employee clicked a phishing link.
- **SERVER-12345**: Observed multiple unauthorized access attempts. Possible data corruption was attempted on this system.
- **SQLSERVER-12345**: Experienced potential corruption of the database file (mydatabase.mdf), though no successful data exfiltration was detected.

#### Indicators of Compromise (IoCs):
- **Phishing Email Domain**: The email originated from a spoofed domain (`info@lndeed.com`) to trick the target into believing it was legitimate.
- **Malicious IPs Detected**:
  - **192.168.1.100**: Attempted privilege escalation and lateral movement within the network.
  - **192.168.1.25** and **10.0.0.2**: Involved in unauthorized internal network communications.
  - **111.64.203.113**: External phishing source IP.

#### Root Cause Analysis:
The attack was successful due to an employee being tricked by a phishing email into clicking a malicious link. The email bypassed existing security measures due to inadequate phishing detection. This led to malware installation and subsequent lateral movement within the network.

#### Nature of Attack:
- **Attack Type**: Phishing, Social Engineering, Privilege Escalation
- **Key Techniques**: Domain spoofing, credential compromise, brute-force login attempts, and malware deployment.

### Response and Recovery Analysis (`documentation/response_and_recovery.md`)
This document details the actions taken to respond to and recover from the incident.

#### Response Actions:
- **Immediate Response** (First 22 hours):
  - Isolated affected systems using VLAN segmentation.
  - Logged out all active users to prevent unauthorized access.
  - Informed staff about the ongoing phishing campaign and provided guidance on identifying and reporting suspicious emails.

- **Containment**:
  - **DESKTOP-1234567** and **SERVER-12345** were immediately isolated to prevent further spread.
  - Monitored network traffic for suspicious activities during containment.

#### Eradication Measures (Next 48 hours):
- **Malware Removal**:
  - Deleted all known instances of malware (`unknown.exe`) from affected systems.
  - Strengthened firewall rules to restrict traffic from malicious IPs.
- **Credential Reset**:
  - Passwords for compromised accounts (e.g., "JohnDoe" and "Admin") were reset.
  - Multi-Factor Authentication (MFA) was enforced on all restored accounts.

#### Recovery Steps (Following 65 hours):
- **System Reimaging**:
  - **DESKTOP-1234567** and **SERVER-12345** were reimaged to ensure complete removal of any residual threats.
- **Database Recovery**:
  - The affected SQL database (`mydatabase.mdf`) was restored from a secure backup, ensuring data integrity.
- **Monitoring**:
  - Continuous monitoring was activated to detect and respond to any lingering or renewed threat activity.

### Impact Analysis (`documentation/impact_analysis.md`)
This document explains how the attack impacted different stakeholders within the organization.

#### Stakeholder Impact:
- **Patients**:
  - **Data Privacy Concerns**: The breach raised concerns about the potential exposure of patients’ personal health information (PHI). Although no data exfiltration was confirmed, trust may have been affected.
  - **Service Disruptions**: Isolation of critical systems during the containment led to delays in accessing patient records, though redundant servers ensured minimal downtime.
  
- **IT and Security Teams**:
  - **Increased Workload**: The breach resulted in extended working hours and significant pressure on the IT and security teams to contain and remediate the incident.
  - **Post-Breach Adjustments**: Teams are now tasked with implementing improved security measures such as enhanced encryption, MFA, and continuous monitoring.

- **Healthcare Providers**:
  - **Operational Disruptions**: Interruptions in electronic health records (EHR) access impacted care delivery. The incident prompted internal discussions on the robustness of IT infrastructure.
  
- **Management and Leadership**:
  - **Decision-Making Challenges**: The leadership had to make rapid decisions regarding system isolation, communication with stakeholders, and managing the potential reputational fallout.

## Recommendations

### Mitigation Plan (`recommendations/mitigation_plan.md`)
This document provides an actionable plan to mitigate vulnerabilities that were identified during the incident.

#### Short-Term Mitigations:
- **MFA Deployment**: Immediately enforce multi-factor authentication for all critical accounts.
- **Password Policy Update**: Implement stricter password policies, including complexity and expiration requirements.
- **Network Segmentation**: Strengthen network segmentation to isolate sensitive systems and reduce the risk of lateral movement during an attack.

#### Long-Term Mitigations:
- **Phishing Awareness Training**: Conduct organization-wide phishing awareness training sessions with regular simulations.
- **Firewall Enhancements**: Update firewall rules to close unnecessary ports, such as SMB (445) and SSH (22).
- **Email Security Upgrade**: Invest in advanced email security solutions with anti-phishing and domain spoofing detection capabilities.

### Security Improvement Actions (`recommendations/security_improvement_actions.md`)
This document focuses on actions that can improve the organization's long-term security posture.

#### Training and Awareness:
- **Phishing Simulations**: Introduce quarterly phishing simulations to evaluate employee awareness and provide targeted training.
- **Incident Response Playbooks**: Develop and distribute incident response playbooks, ensuring all IT staff are familiar with response protocols.

#### Technological Enhancements:
- **Advanced Threat Detection**: Upgrade firewall and intrusion detection systems to provide enhanced protection against emerging threats.
- **Account Monitoring and Alerts**: Set up alerts for suspicious activities involving privileged accounts to detect and respond to unauthorized access attempts quickly.

#### Process Improvements:
- **Regular Backup Tests**: Implement regular tests of backup and restoration processes to ensure data recovery capabilities in the event of an attack.
- **Audit of Privileged Accounts**: Conduct an audit of privileged accounts and enforce strict monitoring to detect misuse or anomalous behavior.

---

This detailed structure provides an in-depth understanding of how a cybersecurity incident is analyzed, contained, eradicated, and mitigated. The lab documents and mitigation strategies provide a robust template for similar projects on GitHub, ensuring that incident response and recovery processes are well-documented and that vulnerabilities are addressed to prevent future incidents.
