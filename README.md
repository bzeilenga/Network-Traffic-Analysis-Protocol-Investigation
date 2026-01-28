# Network Traffic Analysis & Protocol Investigation
**Author:** Brian Zeilenga  
**Focus:** Network Security, Protocol Analysis, Cyber Defense  

---

## 1. Project Summary
This project involves a comprehensive analysis of live network traffic using **Wireshark** within an **Ubuntu** Linux environment. The primary objective was to perform deep packet inspection (DPI) to understand the mechanics of the TCP/IP stack and evaluate the security implications of unencrypted application-layer protocols. By documenting the lifecycle of network sessions, this project demonstrates technical proficiency in network monitoring, troubleshooting, and risk assessment.

## 2. Technical Scope & Environment
* **Platform:** Ubuntu Linux
* **Software:** Wireshark v4.x
* **Network Stack:** TCP/IP
* **Key Protocols:** ICMP, DNS, HTTP, TCP (Flags/Handshaking)

## 3. Methodology & Analysis

### 3.1. Connection Establishment (TCP Handshake)
To verify the integrity of the transport layer, I isolated the **TCP Three-Way Handshake**. This process is critical for establishing a reliable connection between the source and destination.

<div>
<img src="https://upload.wikimedia.org/wikipedia/commons/3/32/Tcp_normal_2.png" />
</div>

* **Filter Expression:** `tcp.flags.syn == 1`
* **Analysis:** Observed the sequence of **SYN**, **SYN-ACK**, and **ACK** packets. Validated that sequence and acknowledgment numbers were properly synchronized, ensuring a stable session establishment.

### 3.2. Network Diagnostics (ICMP)
Utilized Internet Control Message Protocol (ICMP) to analyze network reachability and path diagnostics.
* **Action:** Executed a standard echo request via terminal.
* **Observation:** Captured the Request/Reply cycle. Analyzed the **Time to Live (TTL)** and **RTT (Round Trip Time)** to baseline network performance and verify that no packet fragmentation occurred.

### 3.3. Protocol Vulnerability Assessment (HTTP)
A focused investigation was conducted on unencrypted HTTP traffic to simulate a security audit.
* **Filter Expression:** `http`
* **Finding:** By utilizing the **"Follow TCP Stream"** feature, I reconstructed the application-layer data. 
* **Security Risk:** The analysis confirmed that sensitive data transmitted via HTTP is sent in **cleartext**. This lack of encryption exposes the session to credential harvesting and data injection via Man-in-the-Middle (MitM) attacks.

## 4. Security Recommendations
Based on the findings of this analysis, the following security controls are recommended:
1.  **Encryption:** Deprecate unencrypted protocols (HTTP, FTP, Telnet) in favor of their secure counterparts (HTTPS/TLS, SSH).
2.  **Traffic Baselining:** Implement continuous network monitoring to detect anomalous traffic patterns or unauthorized protocol usage.
3.  **Harden Network Perimeter:** Utilize firewall rules to restrict ICMP traffic where not strictly necessary for diagnostics to reduce the network's reconnaissance surface.

---

## 5. Portfolio Evidence
| Milestone | Technical Evidence |
| :--- | :--- |
| **TCP Session Analysis** | <img width="976" height="73" alt="Screenshot 2026-01-28 131612" src="https://github.com/user-attachments/assets/489f25bf-30ec-4718-aa6c-4100435160c9" /> |
| **HTTP Stream Reconstruction** | <img width="1157" height="401" alt="Screenshot 2026-01-28 131410" src="https://github.com/user-attachments/assets/2bf52e8d-05a9-48c1-b2d6-7b223b025f14" /> |
| **ICMP Diagnostic Capture** | <img width="1790" height="395" alt="Screenshot 2026-01-28 131044" src="https://github.com/user-attachments/assets/88416569-b643-4903-9036-d70d89f4f727" /> <img width="632" height="166" alt="image" src="https://github.com/user-attachments/assets/17c33644-82d1-477f-863a-4e45082cb8ba" /> |

---

### Professional Alignment
This project aligns with the **NICE Framework** for the **Network Operations Specialist** and **Cyber Defense Analyst** roles. It mirrors the high-detail analytical requirements found in both clinical critical care and fire/rescue incident command, translated into a technical cybersecurity context.
