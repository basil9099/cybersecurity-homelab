## Windows Server with Active Directory (AD)

As part of my cybersecurity homelab, I've integrated a fully configured **Windows Server with Active Directory (AD)**. This server simulates a realistic enterprise environment, providing opportunities for practicing cybersecurity techniques, penetration testing, and Active Directory security management.

### Why a Windows Server with Active Directory?

- **Real-world Scenarios**: Simulate corporate environments involving Active Directory.
- **User Management**: Practice user account security, permissions, and access controls.
- **Penetration Testing**: Identify and exploit Active Directory vulnerabilities in a controlled environment.

### Simulated User Accounts

| Username        | First Name | Last Name | Description        | Office | Phone           | Email                      |
|-----------------|------------|-----------|--------------------|--------|-----------------|----------------------------|
| `alice.it`      | Alice      | Smith     | Helpdesk Analyst   | HQ-102 | +1 (555) 0102   | alice.it@homelab.local     |
| `bob.hr`        | Bob        | Johnson   | HR Assistant       | HQ-201 | +1 (555) 0103   | bob.hr@homelab.local       |
| `carol.finance` | Carol      | Bright    | Financial Analyst  | HQ-301 | +1 (555) 0104   | carol.finance@homelab.local|
| `david.bright`  | David      | Bright    | Finance Manager    | HQ-302 | +1 (555) 0105   | david.bright@homelab.local |

### Features & Configuration Highlights

- **Domain Setup**: Domain configured as `homelab.local`.
- **Group Policies**: Implemented to enforce password complexity and login restrictions.
- **Role-Based Access**: Defined roles and access controls for realistic user management scenarios.

### Usage Tips & Security Exercises

Practice cybersecurity exercises such as:

- **Privilege Escalation**: Test methods to escalate privileges securely.
- **Authentication Attacks**: Simulate brute-force and password-spraying attacks.
- **Log Analysis**: Learn to monitor and interpret Windows logs for suspicious activities.

### Next Steps

Future plans involve integrating:

- Endpoint Detection & Response (EDR) solutions.
- Security Information and Event Management (SIEM) solutions.
- Additional network security scenarios.

Use this environment to sharpen your cybersecurity skills, test security tools, and enhance your understanding of Windows and Active Directory security.
