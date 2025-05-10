# 🕹️ Metasploitable2

👉This report will be assessed according to its accuracy and comprehensiveness regarding every aspect of the test. Its goal is to confirm that the applicant possesses the technical know-how and understanding of penetration testing methodologies necessary to meet the requirements.


 # 📌Introduction:
  This report will be assessed for its accuracy and completeness across all aspects of the test. Its 
  The objective is to verify that the applicant has the technical expertise and comprehensive 
  An understanding of penetration testing methodologies is required to meet the specified criteria.

# 🎯Objective: 
  This assessment aims to perform an internal network penetration test on the 
  specified Personal network. The task requires a comprehensive and systematic approach 
  to achieve the desired outcomes. This test aims to simulate a real-world penetration test within the 
  provided testing environment. Additionally, it demonstrates the candidate’s approach from start to 
  finish, including the identification and exploitation of vulnerabilities, as well as the creation of a 
  detailed report.

 # 💊Requirements
  The tester is required to complete a comprehensive penetration testing report, which should 
  include the following sections:
  • Executive Summary and Recommendations: A non-technical overview summarizing key 
  findings and suggested actions.
  • Methodology and Vulnerability Analysis: A detailed explanation of the testing approach and 
  identified vulnerabilities.
  • Findings with Evidence: Each finding should include screenshots, step-by-step walkthroughs, 
  and sample code.
  • Additional Observations: Any other relevant information not covered in the previous 
  sections.

# 📌Project Scope
  This section defines the scope and boundaries of the project.
  Project Name: Metasploitable2

* Description: Metasploitable2 is a deliberately vulnerable virtual machine (VM) 
  designed for penetration testing, training, and security research. It is 
  widely utilized by cybersecurity professionals, students, and enthusiasts 
  to simulate real-world attack scenarios within a controlled environment.
  
  Scope: 192.168.219.132
  Credentials: NA
  Test Scope: Black Box Penetration Test

# 🛠️Summary
  Outlined is a Black Box Application Security assessment for the Metasploitable2.
  Finding ID Severity
  Service Enumeration via Open Ports:  Medium
  Credential Exposure Through Telnet Banner Disclosure: HIGH
  Exploiting FTP (Anonymous Access):  HIGH
  Samba smbd 3.x Remote Code Execution: HIGH
  Unveiling Usernames: SMTP Enumeration with Metasploit’s smtp_enum Module: HIGH


# 🎯 { Service Enumeration }
  * Testing Objective: Risk Rating
  * Service Enumeration: Low / Medium / High
  * Tools Used: Nmap
  * Vulnerability: Service Enumeration via Open Ports

  * Vulnerability Description:
    Service enumeration is a method used to identify the services running on specific ports of a target 
    system and determine their versions. This version information is crucial because it allows attackers 
    to search for known security vulnerabilities associated with the identified software versions. 
    During service enumeration on Metasploitable2, we observed that the application has many open 
    ports, each revealing the service name and its version. An attacker can use this information to 
    search for available exploits on the internet or in hacking payload databases. These exploits can 
    then be used to compromise the system.
  
  * Open Ports
    21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099, 1524, 2121,3306, 3632, 5900, 6000, 
    6667, 6697, 8009, 36979, 40940, 51217, 51247
  
  * Technical Impact:
    * Identification of Vulnerabilities: Attackers can map running services, detect outdated versions, and exploit 
      known CVEs (Common Vulnerabilities and Exposures).
    * Unauthorized Access: Weak or misconfigured services (e.g., open SSH, FTP, or RDP) can be exploited to 
      gain unauthorized access.
  
  * Privilege Escalation: Enumerated services may have misconfigured permissions or weak 
    authentication, allowing attackers to escalate privileges.
  
  * References: https://hackerone.com/reports/2210038
  
  # Step to Reproduce 
  * Let's begin first running the command in the terminal: nmap -sV 192.168.219.132
     
  ![service enumeration](https://github.com/user-attachments/assets/698edfcc-257a-48af-87b7-abdba489ce92)

# 🎯 { Exposure of Sensitive Information to an Unauthorized Actor}
* Testing Objective: Risk Rating
* Credential Exposure Through Telnet
* Banner Disclosure: Low / Medium / High
* Tools Used: Nmap, Kali Linux
    
* Vulnerability: Telnet banners may reveal sensitive information, such as usernames, system details, or even 
   credentials during the initial connection.

* Vulnerability Description:
  Telnet services configured with default or weak credentials pose a serious security risk. Attackers 
  can easily access systems using publicly known default usernames and passwords, leading to 
  unauthorized entry and potential system compromise.
  
* Open Ports: 23

* Technical Impact:
  * Unauthorized System Access – Full control over the target system.
  * Data Breach – Exposure of sensitive information.
  * Lateral Movement – Access to internal networks and additional systems.
  
* Mitigation Strategies
  * Disable Telnet and use SSH instead.
  * Change the Default Credentials immediately after setup.
  * Use Network Firewalls to block unauthorized Telnet access.
  * Monitor Logs & Traffic for suspicious login attempts.
  
* Step of Reproduce 
  * Let's begin First run the command in the terminal: telnet <target_ip>
  ![credential Exposure](https://github.com/user-attachments/assets/067b526a-3ec4-4a5d-9c98-2f472e94cf90)

  ![credential exposure1](https://github.com/user-attachments/assets/e67f343d-4f01-4d41-ad16-e89ec0fa1e15)

# 🎯 { Improper Restriction of Excessive Authentication Attempts}
* Testing Objective: Risk Rating
* Exploiting FTP (Anonymous Access) Low / Medium / High
* Tools Used: Nmap
* Vulnerability: vsftpd 2.3.4 - Backdoor Command Execution

* Vulnerability Description:
  vsFTPd (Very Secure FTP Daemon) version 2.3.4 contains a backdoor that allows an attacker to 
  gain a root shell by sending a specially crafted payload during the FTP login process. This 
  vulnerability was introduced by a malicious backdoor in the source code.
  
* Open Ports: 21
  
* Technical Impact:
  * Unauthenticated Remote Code Execution (RCE) – Attackers can execute arbitrary commands as root.
  * Full System Compromise – Since vsFTPd runs with elevated privileges, attackers gain full control.
  * Creation of Persistent Backdoors – Attackers can deploy malware, modify configurations, and escalate 
    attacks.
  
* Anonymous Login: Yes
  
* Step to reproduce


![anonymous](https://github.com/user-attachments/assets/d269e0ae-ccb9-407c-a5be-cfd630663e92)

![anonymous 1](https://github.com/user-attachments/assets/b3495b2e-30ec-4f3e-b663-2dcf75352850)

# 🎯 { Samba smbd 3.x Remote Code Execution }
* Testing Objective: Risk Rating
* Samba smbd 3.x Remote Code Execution Low / Medium / High
* Tools Used: Metasploit

* Vulnerability:
  Samba versions 3.0.0 to 3.0.25rc3 contain a remote code execution (RCE) vulnerability due to a 
  flaw in the handling of MS-RPC requests.
  
* Vulnerability Description:
  Samba versions 3.0.0 to 3.0.25rc3 contain a command injection vulnerability in the username 
  map script functionality. This allows remote attackers to execute arbitrary commands as root by 
  sending a specially crafted "username" parameter during authentication.
  
* Open Ports: 139
  
* Technical Impact:
  * Remote Code Execution (RCE) – Full system compromise.
  * Privilege Escalation – Attackers gain root access.
  * Lateral Movement – Attackers can pivot inside the network.
  * Data Exfiltration – Sensitive files and credentials can be stolen.
  
* Mitigation:
  * Upgrade Samba – Ensure you are running a patched version (3.0.25+).
  * Disable the "username map script" in the Samba configuration file (smb.conf).
  * Restrict SMB Ports (137, 138, 139, 445) using a firewall.
  * Implement Strong Authentication – Disable anonymous access.
  
* 🎉Step to Reproduce
![remote code](https://github.com/user-attachments/assets/cddb5961-e0f6-48dd-a74a-78c005642c8b)

![remotecode1](https://github.com/user-attachments/assets/163b1328-539e-40a8-b493-96f7a037a8f8)
![remotecode2](https://github.com/user-attachments/assets/7a6965ae-2707-4d37-81be-2cb7ff446e91)


# 🎯{ Exploiting SMTP enumeration }
* Testing Objective: Risk Rating
* SMTP Enumeration: Low / Medium / High
* Tools Used: Metasploit

* Vulnerability: Unveiling Usernames: SMTP Enumeration with Metasploit’s smtp_enum Module.
  
* Vulnerability Description:
  * Telnet services configured with default or weak credentials pose a serious security risk. Attackers 
    can easily access systems using publicly known default usernames and passwords, leading to 
    unauthorized entry and potential system compromise.
  
* Open Ports: 25
  
* Technical Impact:
  * User Enumeration – Attackers can identify valid usernames for brute-force attacks.
  * Phishing & Social Engineering – Leaked email addresses aid in targeted attacks.
  * Credential Stuffing – Discovered usernames may be used in password attacks.
  * Privilege Escalation – Attackers can map user roles and privilege levels.
  
* Mitigation Strategies:
  * Disable VRFY & EXPN Commands – Prevents direct user enumeration.
  * Enforce Authentication (SMTP AUTH) – Requires valid credentials for interaction.
  
* Step to reproduce

![smtp](https://github.com/user-attachments/assets/04eb3778-add9-4b80-bdaf-70ced5c9affa)
![smtp1](https://github.com/user-attachments/assets/614eec83-0b17-41fb-b7da-cda716addf09)
![smtp3](https://github.com/user-attachments/assets/cd603c51-645e-4ed0-a523-27a9b770f378)


# 🧁 CONCLUSION 
* This report highlights testing critical security flaws in Metasploitable2 that attackers can leverage to gain unauthorized access. 
  These assessments provided insights into real-world attack scenarios, allowing for an in-depth understanding of how adversaries can gain unauthorized access, 
  escalate privileges, and execute remote code.


