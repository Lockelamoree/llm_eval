import transformers
from deepeval.models.base_model import DeepEvalBaseLLM
from lmformatenforcer import JsonSchemaParser
from lmformatenforcer.integrations.transformers import (
    build_transformers_prefix_allowed_tokens_fn,
)
from pydantic import BaseModel
import json
import pytest
from deepeval import assert_test
from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCase, LLMTestCaseParams


deepseek_answers=["""
            The IT Forensic Hayabusa Scan Tool is a specialized software designed for use in the field of cybersecurity, particularly within digital forensics and incident response. Here's an organized overview based on the analysis:

            1. **Name and Functionality**:
            - Named after the peregrine falcon ("Hayabusa"), suggesting speed and efficiency.
            - Functions as a scan tool, likely used for detecting vulnerabilities, malware, or security issues.

            2. **Purpose**:
            - Utilized by incident responders and digital forensics experts to investigate security incidents.
            - Aids in the detection of malicious activity indicators (IOCs) and assists in remediation efforts.

            3. **Features**:
            - Generates detailed reports post-scan, detailing findings such as suspicious files, processes, network connections, and IOCs.
            - May include features like disk imaging, file analysis, and registry inspection.

            4. **Comparison with Other Tools**:
            - Similar to established tools like EnCase, FTK, and Cellebrite but potentially offers unique features that set it apart.

            5. **Incident Response Lifecycle**:
            - Employed during the detection and investigation phases to identify breaches, gather evidence, and support remediation.

            6. **Recognition and Usage**:
            - May be a niche or lesser-known tool, possibly fictional within this context if not widely recognized.

            In essence, Hayabusa is a tool that aids in efficiently detecting and analyzing malicious activity, providing critical insights for cybersecurity professionals to mitigate threats effectively.
            ""","""
            The IT Forensic Hayabusa Scan Tool, while a valuable asset in digital forensics and incident response, is not without its limitations. Here is an organized summary of the potential drawbacks:

            1. Compatibility Issues:
            - The tool may not be compatible with all operating systems or devices, such as Linux or macOS, limiting its utility in investigations involving these platforms.

            2. Scope of Scanning Capabilities:
            - It might excel at detecting malware on hard drives but could fall short in identifying issues in memory or network connections, potentially missing critical evidence.

            3. User-Friendliness:
            - The tool may require a high level of technical expertise to operate effectively, which could limit its accessibility and lead to errors if used incorrectly by less skilled individuals.

            4. Cost Constraints:
            - Being an expensive tool, it might be out of reach for smaller companies or agencies, forcing them to opt for cheaper alternatives that are less effective.

            5. Updates and Maintenance:
            - The tool needs regular updates to keep up with evolving cyber threats. A lag in updates could render it outdated and less effective.

            6. Privacy Concerns:
            - Handling sensitive data requires strict privacy protections. If the tool lacks robust privacy features, it could expose organizations to legal risks.

            7. Integration Difficulties:
            - Forensic investigations often involve multiple tools. Poor integration with other software can create inefficiencies or data silos, hindering the investigation process.

            8. Accuracy Issues:
            - The tool might have a high rate of false positives (flagging innocent files as malicious) or false negatives (missing actual threats), leading to wasted time or overlooked dangers.

            In conclusion, while the Hayabusa Scan Tool is a powerful resource in its field, it is essential to be aware of these limitations to ensure effective and comprehensive forensic investigations.
            ""","""The IT Forensic Hayabusa Scan Tool is designed to analyze a comprehensive range of data relevant to digital forensics and incident response. Here is an organized summary of the types of data it can examine:

            1. **Files**: The tool scans for malicious software and suspicious files, which is crucial for identifying potential threats during a security investigation.

            2. **System Logs**: It reviews system logs to detect unusual activities such as unauthorized access attempts or file accesses, providing insights into potential breaches.

            3. **Network Traffic**: By analyzing network connections, the tool can identify malicious communications, such as those from malware to command-and-control servers.

            4. **User Activity**: Tracking user actions like file openings and website visits helps in understanding how an attack might have been executed or who could be responsible.

            5. **Registry Entries**: The tool examines the Windows Registry for any suspicious modifications, which can indicate attempts by malware to alter system configurations.

            6. **Process Activity**: It monitors running processes to detect any unusual activity that might signify an ongoing attack.

            7. **Disk Usage and File Integrity**: The tool checks for unauthorized file modifications or deletions, uncovering hidden evidence of potential attacks.

            8. **Email Communications**: Analyzing email logs can help trace the source of phishing attacks or other malicious activities initiated through email.

            9. **Encrypted Data**: The tool may have capabilities to decrypt and examine data that malware uses to hide its activities, enhancing the thoroughness of investigations.

            10. **Cross-Platform Compatibility**: It likely works across various devices and operating systems, including smartphones, tablets, and servers, ensuring comprehensive coverage.

            11. **Report Generation**: The tool can produce detailed reports from its analysis, facilitating documentation and sharing of findings with stakeholders.

            In summary, the Hayabusa Scan Tool is a versatile instrument that integrates the analysis of multiple data types to support thorough forensic investigations and incident response efforts.""","""
            You should analyze report_1.html first because it covers a longer time period (April 3rd to April 9th) compared to report_2.html (April 7th to April 9th). Additionally, report_1 has significantly more events with hits (1,330 vs. 419), indicating a higher volume of potentially suspicious activity that requires attention. 

            Answer: Analyze report_1.html first due to its broader timeframe and higher number of flagged events, suggesting more potential issues to investigate.""","""Based on the provided Hayabusa reports, you should analyze the system associated with report_5.html first. This report contains detections (191 events with hits) over a specific time frame (March 17-20), while the other reports do not mention detections. The higher number of detected events suggests potential malicious activity that requires immediate attention.""" ]


gemma_answers = [
    "Okay, let's discuss the IT Forensic Hayabusa Scan Tool.\n\nBased on my understanding and experience in digital forensics and incident response, the **Hayabusa Scan Tool** is a powerful, open-source, command-line utility designed for rapid network reconnaissance and asset discovery. It's frequently used during the initial stages of an incident response or penetration testing engagement. \n\nHere's a breakdown of its key features and how it's used:\n\n* **Purpose:** Hayabusa excels at quickly identifying live hosts, open ports, and running services on a network. It's designed to be *fast* and *stealthy* – minimizing the footprint during scanning.\n* **How it Works:** It leverages a combination of techniques, including TCP SYN scans, UDP scans, and ICMP pings, to gather information.  It's often used with custom scripting to automate the discovery process and tailor the scan to specific needs.\n* **Key Capabilities:**\n    * **Host Discovery:** Identifies active hosts on a network.\n    * **Port Scanning:** Determines which ports are open on those hosts.\n    * **Service Detection:** Attempts to identify the services running on open ports (e.g., HTTP, SSH, DNS).\n    * **OS Fingerprinting (limited):** Can sometimes provide clues about the operating system running on a host.\n    * **Customizable:**  Highly configurable through command-line arguments and scripting.\n* **Why it's valuable in Incident Response:**\n    * **Rapid Asset Inventory:** Quickly builds a picture of the network landscape, which is crucial for understanding the scope of an incident.\n    * **Identifying Compromised Systems:**  Can help pinpoint systems that are potentially infected or under attack.\n    * **Understanding Attack Surface:** Reveals potential vulnerabilities and entry points for attackers.\n* **Open Source:** Being open-source means it's freely available, auditable, and can be customized to meet specific requirements.\n\n**In the context of forensic reports I analyze, Hayabusa scan reports typically provide a baseline of network activity and help establish a timeline of events.**  I look for anomalies in the scan results – unexpected open ports, unusual services, or hosts that shouldn't be present on the network – as indicators of compromise.\n\nYou can find more information about Hayabusa here: [https://github.com/hayabusascanner/hayabusa](https://github.com/hayabusascanner/hayabusa)",
    "Okay, let's discuss the limitations of the IT Forensic Hayabusa Scan Tool. While it's a powerful reconnaissance tool, it's crucial to understand its weaknesses to avoid misinterpreting results or relying on it as a sole source of truth during an investigation. Here's a breakdown of its limitations:\n\n**1. Stealth & Evasion Techniques:**\n\n*   **Firewall & IDS/IPS Detection:** Hayabusa, despite being designed for stealth, can still be detected by firewalls, intrusion detection systems (IDS), and intrusion prevention systems (IPS). These systems can block scans or alert administrators.\n*   **Rate Limiting:** Some systems implement rate limiting, which can slow down or block Hayabusa scans.\n*   **Spoofing Detection:** Sophisticated systems can detect spoofed source IP addresses used to evade detection.\n\n**2. Accuracy & Reliability:**\n\n*   **Service & OS Fingerprinting Limitations:** Service and operating system detection are not always accurate. Hayabusa relies on banner grabbing and TCP/IP stack characteristics, which can be misleading or easily spoofed.\n*   **False Positives:**  Hayabusa can sometimes report ports as open when they are actually filtered or blocked.\n*   **Incomplete Results:** Network congestion, firewalls, or other factors can lead to incomplete scan results.\n\n**3. Scope & Depth of Analysis:**\n\n*   **Network-Level Only:** Hayabusa is primarily a network-level reconnaissance tool. It does *not* analyze host-based data (file systems, memory, logs, etc.).\n*   **Limited Application Layer Analysis:** Its application layer analysis is limited to banner grabbing and basic HTTP header analysis. It cannot perform deep packet inspection or analyze application-specific protocols.\n*   **No Vulnerability Scanning:** Hayabusa does not perform vulnerability scanning. It only identifies open ports and running services.\n\n**4. Network Conditions & Configuration:**\n\n*   **Network Congestion:** Network congestion can significantly slow down scans and lead to inaccurate results.\n*   **Network Segmentation:** Network segmentation (VLANs, firewalls) can prevent Hayabusa from reaching certain hosts or ports.\n*   **NAT & Proxies:** Network Address Translation (NAT) and proxies can complicate scans and make it difficult to identify the true source of traffic.\n\n**5. Evolving Security Landscape:**\n\n*   **Modern Firewalls & Security Appliances:** Modern firewalls and security appliances are becoming increasingly sophisticated at detecting and blocking reconnaissance scans.\n*   **Dynamic Network Environments:** Dynamic network environments (cloud infrastructure, containerization) can make it difficult to maintain accurate network maps and scan results.\n\n**In summary:** Hayabusa is a valuable tool for initial network reconnaissance, but it should not be relied upon as a sole source of truth. It's essential to combine its results with other tools and techniques (vulnerability scanners, host-based analysis, log analysis) to gain a comprehensive understanding of the security posture of a network. It's also crucial to be aware of its limitations and potential for false positives or incomplete results.",

    "Okay, let's detail the data the IT Forensic Hayabusa Scan Tool can analyze. It's important to understand that Hayabusa is primarily a *network reconnaissance* tool, so its analysis focuses on network-level data. Here's a breakdown:\n\n**1. Network Layer (Layer 3 - IP):**\n\n*   **IP Addresses:** Identifies live IP addresses on the target network. This is the fundamental data point.\n*   **ICMP Echo Requests/Replies:** Analyzes responses to ping requests to determine host availability.\n*   **TTL (Time To Live) Values:** Can provide clues about network topology and distance to hosts.\n\n**2. Transport Layer (Layer 4 - TCP/UDP):**\n\n*   **TCP SYN Packets:** Performs SYN scans to determine open TCP ports without completing the full TCP handshake (stealthier than a full connect scan).\n*   **TCP Connect Scans (optional):** Can perform full TCP connect scans if configured, but this is less stealthy.\n*   **UDP Scans:** Sends UDP packets to specific ports to determine if they are open or closed.\n*   **Port Status:** Determines whether a port is open, closed, or filtered (blocked by a firewall).\n*   **TCP Flags:** Analyzes TCP flags (SYN, ACK, FIN, RST, etc.) to understand connection states.\n\n**3. Application Layer (Layer 7 - Limited):**\n\n*   **Service Detection (Banner Grabbing):** Attempts to identify the service running on an open port by analyzing the initial banner or response. This is often limited and may not always be accurate.  It looks for recognizable strings in the response.\n*   **HTTP Headers (basic):** If a port is identified as HTTP (port 80 or 443), it can grab basic HTTP headers.\n*   **SSL/TLS Certificate Information (basic):** Can retrieve basic SSL/TLS certificate information from HTTPS connections.\n\n**4. Derived Data & Analysis:**\n\n*   **Host Status:** Determines if a host is online, offline, or unreachable.\n*   **Open Port List:** Creates a list of open ports for each host.\n*   **Service List:** Identifies the services running on each host based on port and banner information.\n*   **Operating System Fingerprinting (limited):** Attempts to guess the operating system based on TCP/IP stack characteristics, but this is not always reliable.\n*   **Network Topology (basic):** Can provide a basic understanding of the network layout.\n\n**Important Considerations:**\n\n*   **Firewall Evasion:** Hayabusa is designed to be relatively stealthy, but firewalls and intrusion detection systems can still detect its scans.\n*   **Accuracy:** Service detection and OS fingerprinting are not always accurate and should be verified with other tools.\n*   **Scope:** Hayabusa primarily focuses on network-level data. It does not analyze file systems, memory, or other host-based data.\n\nIn the context of forensic reports, I look for anomalies in this data – unexpected open ports, unusual services, or hosts that shouldn't be present on the network – as indicators of compromise. I also compare Hayabusa scan results over time to identify changes in network activity.",
    
    
    "NiNa: Hello, I am NiNa, IT Forensic Analyst. Based on the provided Hayabusa reports, you should analyze the system associated with `report_1.html` first. This is because it has significantly more events with hits (1,330) compared to `report_2.html` (419), suggesting a higher level of activity or potential indicators of compromise. Prioritizing this system will likely yield more immediate and valuable findings.",
    
    "NiNa: Hello, I am NiNa, IT Forensic Analyst. Based on the provided logs, you should analyze the system associated with `report_5.html` first. This is because it contains 191 events with hits, indicating more activity detected during analysis. The other reports show no events with hits, suggesting less relevant data for immediate investigation. Remember I ran Hayabusa with a profile that includes %MitreTactics% to provide this assessment."
]


mistral_answers = [
    "The IT Forensic Hayabusa Scan Tool is a digital forensics and incident response (DFIR) tool used to analyze digital evidence in an effort to identify, investigate, and respond to cybersecurity incidents. It's designed to help investigators thoroughly examine systems, networks, and data for signs of suspicious or malicious activity.\n\nWhen analyzing Hayabusa reports, the following steps are typically taken:\n\n1. Analyze each report thoroughly: This involves examining the details provided in the report, such as system logs, network traffic, file metadata, and other relevant artifacts.\n\n2. Summarize suspicious or malicious activity: Based on the analysis, summarize any observed behavior that could indicate a cybersecurity incident, such as unauthorized access, data exfiltration, or the presence of malware.\n\n3. Provide a criticality rating: Assign a severity level (Low, Medium, High, or Critical) based on factors like indicators of compromise, scope, persistence, and impact. For example, a High rating might be given if the incident has compromised sensitive data or has spread across multiple systems.\n\n4. Prioritize reports by severity and urgency: If multiple reports are provided, prioritize them based on their potential impact and the immediate threat they pose to the system or organization. For instance, a report indicating active malware infection might be considered more urgent than one showing outdated software.\n\n5. State if a report appears benign or inconclusive: If an analysis does not reveal any signs of suspicious or malicious activity, it should be clearly stated that the report appears benign or inconclusive.\n\n6. Admit lack of knowledge when necessary: If the available information is insufficient to make a definitive assessment, it's important to acknowledge that the answer is not known at this time.",
    
    
    "As an expert in cybersecurity incident response, I can confirm that while the IT Forensic Hayabusa Scan Tool is a powerful digital forensics and incident response (DFIR) tool, it does have certain limitations:\n\n1. Limited scope of supported systems: The Hayabusa Scan Tool may not support all operating systems or hardware platforms, which could limit its effectiveness in analyzing evidence from those systems.\n\n2. Dependence on accurate configuration and use: The tool's performance relies heavily on proper configuration and usage by the investigator. If it is misconfigured or used improperly, it may not yield accurate results.\n\n3. Limited real-time monitoring capabilities: While the Hayabusa Scan Tool can analyze past events, it does not have extensive real-time monitoring capabilities to detect ongoing threats in a proactive manner.\n\n4. Potential for false positives and negatives: Like any automated tool, the Hayabusa Scan Tool may produce false positives (indicating suspicious activity when there is none) or false negatives (missing actual signs of malicious activity). Human analysis is still required to confirm findings.\n\n5. Limited adaptability to new threats: The tool's effectiveness against emerging threats may be limited if it does not have built-in signatures or behavioral patterns for those threats.\n\n6. Dependence on timely updates: To remain effective against the latest threats, the Hayabusa Scan Tool requires regular updates to its threat intelligence and signature databases. If these updates are not applied in a timely manner, the tool's effectiveness may be compromised.",
     "As an expert in cybersecurity incident response, I can confirm that the IT Forensic Hayabusa Scan Tool is designed to analyze a wide range of digital evidence related to cybersecurity incidents. Some examples of data it can examine include:\n\n1. System logs: These logs contain records of system activity, such as user logins, file access, and network connections. They can help investigators identify suspicious or malicious behavior.\n\n2. Network traffic: The tool can analyze network traffic to detect signs of unauthorized access, data exfiltration, or other malicious activities.\n\n3. File metadata: Metadata associated with files, such as creation and modification dates, file paths, and permissions, can provide valuable context for an investigation.\n\n4. Malware analysis: The Hayabusa Scan Tool can help identify and analyze malware, including its behavior, payload, and command-and-control (C2) communication channels.\n\n5. Indicators of compromise (IoCs): IoCs are specific artifacts or patterns that indicate a system has been compromised by malware or other threats. The tool can help identify these IoCs to better understand the nature and scope of an incident.\n\n6. System configurations: Analyzing system configurations can help investigators determine if any unauthorized changes have occurred, which could be indicative of a cybersecurity incident.\n\n7. User activity: Investigating user activity, such as login patterns, file access, and email communications, can provide insights into potential insider threats or compromised accounts.",
 
   
   "NiNa: Based on the information provided, you should analyze the report named 'report_1.html' first. The reason is that it has a higher number of events with hits (1,330) compared to the other report (419). Analyzing the system with more events could potentially provide more insights into any security issues or anomalies. However, keep in mind that this analysis might not be exhaustive and further investigation would be required for a comprehensive understanding of the systems' security posture.",
    
    "NiNa: The report labeled as \"report_2.html\" should be analyzed first. This is because it has a later start time (2025/04/17 07:49) compared to the other reports, indicating that it was generated more recently. Analyzing this report first could provide more up-to-date information about potential security events on the system."

]
qwq_answers = ["""The **IT Forensic Hayabusa Scan Tool** appears to be a hypothetical or proprietary digital forensics and incident response tool designed to analyze systems, networks, or digital artifacts for signs of malicious activity, security breaches, or indicators of compromise (IoCs). Based on your context, it likely generates structured reports (Hayabusa reports) that forensic investigators use to assess the severity, scope, and impact of potential threats. Here's a breakdown of its likely purpose and functionality:

                        ### Key Features (Based on Context):
                        1. **Incident Analysis**:  
                        - Scans systems, endpoints, or network traffic for suspicious behavior, malware, unauthorized access, or other IoCs.  
                        - May include capabilities like log analysis, memory forensics, file integrity checks, or behavioral monitoring.

                        2. **Report Generation**:  
                        - Produces detailed reports summarizing findings, including timestamps, affected systems, artifacts (e.g., malware samples, registry changes), and potential attack vectors.  
                        - Reports may flag anomalies, such as unusual outbound connections, encrypted payloads, or unauthorized processes.

                        3. **Criticality Assessment**:  
                        - Allows investigators to rate incidents based on factors like:  
                            - **Scope**: How many systems/networks are impacted.  
                            - **Persistence**: Whether the threat has established long-term access (e.g., rootkits, backdoors).  
                            - **Impact**: Potential damage to data confidentiality, integrity, or availability.  
                            - **IoCs**: Presence of known malicious signatures, C2 (command-and-control) communications, or exploit patterns.

                        4. **Prioritization**:  
                        - Helps triage multiple incidents by severity (e.g., Critical > High > Medium > Low), ensuring responders address the most dangerous threats first.

                        ---

                        ### Example Workflow (Hypothetical):
                        1. **Scan Execution**:  
                        - The tool scans a compromised system and identifies a suspicious process (`malware.exe`) communicating with a known malicious IP address.  
                        - It detects encrypted payloads in memory and registry modifications indicative of persistence mechanisms.

                        2. **Report Analysis**:  
                        - **Activity Summary**: Unauthorized outbound connection to IP `192.0.2.1` (linked to a C2 server), execution of an unsigned binary, and creation of a scheduled task for persistence.  
                        - **Criticality Rating**: **Critical** (High scope: network exposure; Persistence: scheduled task; Impact: potential data exfiltration).

                        3. **Response Prioritization**:  
                        - If multiple reports exist, the Critical-rated incident would take priority over lower-severity issues like a single benign phishing email (rated Low).

                        ---

                        ### Important Notes:
                        - **Proprietary/Custom Tool**: Since "Hayabusa" is not a widely recognized commercial tool, its specific features and outputs may vary based on the organization’s implementation.  
                        - **Context Dependency**: Your analysis of Hayabusa reports should strictly follow the criteria you outlined (IoCs, scope, persistence, impact) to ensure consistency in criticality ratings.  
                        - **Benign Activity**: If a report lacks clear IoCs or shows routine system behavior (e.g., standard update checks), it should be flagged as inconclusive or benign.""",  """"<details type=""reasoning"" done=""true"" duration=""9"">
                    <summary>Thought for 9 seconds</summary>
                    > Okay, the user is asking about the limitations of the IT Forensic Hayabusa Scan Tool. Let me start by recalling what I know from the previous conversation. The user has already asked about what the tool is and what data it can analyze. Now they want to know its limitations.
                    > 
                    > First, I need to consider that Hayabusa isn't a well-known commercial tool, so it might be a proprietary or custom solution. That means its limitations could depend on how it's implemented. Since the user mentioned Hayabusa reports before, maybe the tool has specific constraints in data analysis or reporting.
                    > 
                    > I should think about common limitations in forensic tools. For example, maybe it has compatibility issues with certain file formats or operating systems. Or perhaps it struggles with encrypted data. Also, if it's not updated regularly, it might miss new threats. 
                    > 
                    > Another angle is the scope of analysis. Maybe it's good at certain types of data but not others. For instance, maybe it's weak in memory analysis or cloud environments. The user previously asked about data it can analyze, so pointing out gaps there would make sense.
                    > 
                    > User access and permissions could be a limitation too. If the tool requires admin rights and doesn't have them, it might not function properly. Also, performance issues with large datasets could be a problem, especially with big forensic images.
                    > 
                    > Integration with other tools might be another point. If it doesn't play well with SIEM or threat intelligence platforms, that's a drawback. Legal and privacy concerns could also be a limitation, especially with handling sensitive data.
                    > 
                    > I should also mention that without knowing the exact features, some limitations are assumptions. Maybe the user is trying to understand where the tool might fail in their specific use case. They might be evaluating tools or planning an implementation, so highlighting these points can help them make informed decisions.
                    > 
                    > I need to structure the answer clearly, listing each limitation with explanations. Make sure to note that some limitations are speculative due to the tool's obscurity. Also, offer to help analyze a specific report if they have one. That way, the answer is both informative and helpful for their next steps.
                    </details>
                    The **IT Forensic Hayabusa Scan Tool** (assuming it is a proprietary or custom solution, as it is not a widely recognized commercial tool) likely has limitations common to many forensic and threat detection tools. However, since its specific design and capabilities are not publicly documented, some limitations are inferred based on typical constraints of such tools. Below are potential limitations you might encounter:

                    ---

                    ### **1. Proprietary/Custom Nature**
                    - **Limited Transparency**: If Hayabusa is a custom or closed-source tool, its algorithms, detection rules, and data processing methods may not be publicly auditable. This can hinder trust in its accuracy or ability to adapt to new threats.
                    - **Vendor Dependency**: Users may rely entirely on the vendor for updates, patches, or support, which could slow down responses to emerging threats or tool malfunctions.

                    ---

                    ### **2. Data Coverage and Compatibility**
                    - **File/Format Limitations**: The tool may struggle with analyzing newer or niche file formats (e.g., encrypted files, proprietary cloud storage formats, or emerging malware obfuscation techniques).
                    - **Operating System Support**: It might have limited compatibility with certain OS versions (e.g., older systems, non-Windows platforms like Linux/macOS, or IoT/edge devices).
                    - **Encrypted Data**: Without proper decryption keys or integration with decryption tools, it may fail to analyze encrypted volumes, containers, or communications (e.g., TLS-encrypted traffic).

                    ---

                    ### **3. Performance and Scalability**
                    - **Large Dataset Overhead**: Analyzing massive forensic images (e.g., petabyte-scale cloud logs or enterprise network captures) could be slow or resource-intensive, delaying incident response.
                    - **Real-Time Analysis**: If the tool is designed for offline analysis, it may lack real-time monitoring capabilities, making it less effective for live incident detection.

                    ---

                    ### **4. Threat Detection Gaps**
                    - **Evasion Techniques**: Advanced malware (e.g., fileless malware, memory-resident threats, AI-driven attacks) might bypass Hayabusa’s detection mechanisms if they rely on signature-based or heuristic analysis.
                    - **Zero-Day Threats**: The tool may miss unknown or zero-day vulnerabilities unless it integrates with up-to-date threat intelligence feeds or behavioral analysis.
                    - **Lateral Movement Detection**: It might struggle to correlate cross-system activities (e.g., tracking lateral movement in a network) without centralized logging or SIEM integration.

                    ---

                    ### **5. User Expertise Requirements**
                    - **Complexity**: Forensic tools often require trained analysts to interpret results. Hayabusa might generate ambiguous findings or require deep technical knowledge to use effectively.
                    - **False Positives/Negatives**: Overly broad or narrow detection rules could lead to missed threats (false negatives) or excessive alerts (false positives), wasting analyst time.

                    ---

                    ### **6. Legal and Privacy Constraints**
                    - **Data Handling Compliance**: The tool may not natively support compliance with regulations like GDPR, HIPAA, or CCPA, requiring additional steps to anonymize or handle sensitive data.
                    - **Chain of Custody**: If it lacks robust logging or audit trails, it might not meet legal standards for evidence admissibility in court.

                    ---

                    ### **7. Integration Challenges**
                    - **Third-Party Tools**: Hayabusa might not integrate smoothly with other security tools (e.g., SIEM platforms like Splunk, threat intelligence platforms like AlienVault, or automation frameworks like SOAR).
                    - **API Limitations**: Limited APIs or SDKs could hinder automation or customization for specific use cases.

                    ---

                    ### **8. Resource Intensity**
                    - **Hardware/Software Requirements**: The tool may demand significant computational resources (e.g., high CPU, memory, or storage), making it impractical for smaller organizations or resource-constrained environments.

                    ---

                    ### **9. Update and Maintenance**
                    - **Stale Signatures/Definitions**: If the tool relies on static threat databases, it may become outdated quickly without frequent updates.
                    - **Vendor Roadmap Risks**: If the vendor discontinues support or slows updates, the tool could become obsolete.

                    ---

                    ### **10. Cost and Licensing**
                    - **High Costs**: Proprietary tools often come with expensive licensing, especially for enterprise-scale deployments.
                    - **Usage Restrictions**: Licensing terms might limit the scope of analysis (e.g., restricted to specific data volumes or use cases).

                    ---

                    ### **Mitigation Strategies**
                    To address these limitations:
                    1. **Complement with Open-Source Tools**: Use tools like Volatility (memory analysis), Wireshark (network traffic), or YARA (signature-based detection) alongside Hayabusa.
                    2. **Integrate with SIEM/Orchestration Platforms**: Centralize data and automate workflows using tools like ELK Stack, Splunk, or SOAR platforms.
                    3. **Regular Training**: Ensure analysts are trained to interpret findings and correlate data across tools.
                    4. **Leverage Threat Intelligence**: Use feeds from platforms like CrowdStrike Falcon Intel or AlienVault OTX to enhance detection.

                    ---

                    ### **Final Note**
                    If Hayabusa is a specific commercial tool, consult its documentation or vendor for precise limitations. If it’s a custom solution, consider conducting a **gap analysis** to identify weaknesses and plan for complementary tools or processes. For further assistance, share specifics about your use case or a sample report, and I can provide tailored advice!""", 
                    """
                    "<details type=""reasoning"" done=""true"" duration=""9"">
                        <summary>Thought for 9 seconds</summary>
                        > Okay, the user is asking what data the IT Forensic Hayabusa Scan Tool can analyze. Let me start by recalling the previous conversation where I explained what the tool is. The user now wants to know the types of data it can process.
                        > 
                        > First, I need to consider the context from the earlier messages. The Hayabusa tool is a digital forensics and incident response tool that generates reports. The user mentioned it's used for analyzing systems, networks, and digital artifacts. 
                        > 
                        > The user might be a cybersecurity professional or someone involved in incident response. They probably want to know the scope of the tool's capabilities to understand its effectiveness in different scenarios. Maybe they're evaluating whether this tool fits their needs or want to know how to use it effectively.
                        > 
                        > I should list the data sources the tool can analyze. Since it's a forensic tool, it likely covers common areas like system logs, network traffic, memory, files, etc. I should break it down into categories like system artifacts, network data, memory analysis, file systems, etc. Each category should have examples to make it clear.
                        > 
                        > Also, considering the previous answers, the tool's reports are based on indicators of compromise (IoCs). So, I should mention how each data type contributes to identifying IoCs. For example, network traffic can show C2 communications, while memory analysis can detect in-memory malware.
                        > 
                        > I need to ensure the answer is structured and easy to follow. Maybe use bullet points under each category. Also, since the tool is proprietary, I should note that specifics might vary, but common forensic data types apply.
                        > 
                        > Wait, the user might also be interested in how this data helps in criticality ratings. Maybe mention that analyzing these data types allows the tool to assess scope, persistence, and impact, which are part of the criticality assessment they mentioned earlier.
                        > 
                        > I should also highlight that without a specific report, the answer is general, but if they provide a report, I can give a more detailed analysis. That ties back to their previous questions where they wanted to analyze reports.
                        > 
                        > Make sure to avoid technical jargon where possible, but since the user is likely technical, some terms are okay. Keep it clear and comprehensive. Alright, let me structure the answer with categories and examples, then conclude with how this data contributes to threat analysis and criticality ratings.
                        </details>
                        The **IT Forensic Hayabusa Scan Tool** is designed to analyze a wide range of **digital artifacts and data sources** to identify malicious activity, forensic evidence, and indicators of compromise (IoCs). While specifics may vary depending on the tool’s configuration or proprietary features, here are the **common data types** it can typically analyze:

                        ---

                        ### **1. System Artifacts**
                        - **Event Logs**: Windows Event Logs (Security, System, Application), Linux/Unix logs (syslog, auth logs), and macOS logs.
                        - **Registry Hives**: Windows Registry entries (e.g., `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` for startup programs).
                        - **Process and Thread Information**: Running processes, command-line arguments, parent/child process relationships.
                        - **Scheduled Tasks/Cron Jobs**: Automated tasks or scripts that may be malicious.
                        - **Services and Drivers**: Installed services, drivers, or kernel modules with suspicious behavior.

                        ---

                        ### **2. Network Data**
                        - **Network Traffic**: Captured packets (e.g., via Wireshark-like analysis) to detect C2 (command-and-control) communications, unusual outbound connections, or data exfiltration.
                        - **DNS Queries**: Suspicious domain lookups (e.g., DGA [Domain Generation Algorithm] domains).
                        - **HTTP/HTTPS Requests**: Anomalies in web traffic, such as connections to known malicious IPs/domains.
                        - **NetFlow/Netstat Data**: Active network connections, open ports, and established sessions.

                        ---

                        ### **3. Memory Analysis**
                        - **In-Memory Artifacts**: Detection of malware or processes running in memory (e.g., fileless malware, living-off-the-land binaries).
                        - **Injected Code**: Malicious code injected into legitimate processes (e.g., process hollowing, DLL injection).
                        - **Kernel-Level Activity**: Rootkits or kernel-mode exploits.

                        ---

                        ### **4. File System and Storage**
                        - **File Metadata**: Creation/modification/access times, file hashes (SHA-1, SHA-256, MD5), and file paths.
                        - **Executable Files**: Analysis of binaries for malicious code, packers, or obfuscation.
                        - **Documents and Archives**: Embedded macros, malicious scripts (e.g., PowerShell, VBA), or hidden payloads in Office files.
                        - **Deleted Files**: Recovery of deleted files or fragments from unallocated disk space.

                        ---

                        ### **5. User Activity**
                        - **Login Events**: Failed/successful login attempts, credential misuse, or brute-force attacks.
                        - **USB Device Usage**: Connected devices, files copied to/from removable storage.
                        - **Browser Artifacts**: Cookies, cached pages, bookmarks, and browser history (e.g., Chrome, Firefox).

                        ---

                        ### **6. Application-Specific Data**
                        - **Email Headers/Attachments**: Analysis of phishing emails, malicious attachments, or suspicious email metadata.
                        - **Database Logs**: SQL injection attempts or unauthorized database access.
                        - **Cloud Storage**: Activity logs from cloud services (e.g., AWS, Azure, Google Cloud) for unauthorized access.

                        ---

                        ### **7. Forensic Images and Disk Clones**
                        - **Full Disk Images**: Analysis of entire disk partitions or forensic images (e.g., EnCase E01, AFF).
                        - **File Carving**: Recovery of partial or deleted files from disk sectors.

                        ---

                        ### **8. Threat Intelligence Integration**
                        - **IoC Matching**: Cross-referencing observed data (e.g., IPs, domains, hashes) against threat intelligence feeds (e.g., VirusTotal, AlienVault OTX).
                        - **YARA Rules**: Detection of known malware patterns using YARA rules.

                        ---

                        ### **9. Mobile and IoT Devices**
                        - **Mobile Device Logs**: Forensic analysis of iOS/Android devices (e.g., call logs, SMS, app installations).
                        - **IoT Device Traffic**: Network activity from smart devices (e.g., cameras, routers) for vulnerabilities or unauthorized access.

                        ---

                        ### **10. Cloud and Virtual Environments**
                        - **Cloud Audit Logs**: AWS CloudTrail, Azure Activity Logs, or Google Cloud logs for unauthorized access.
                        - **Virtual Machine Snapshots**: Analysis of VM states or disk images for hidden malware.

                        ---

                        ### **How This Data Contributes to Threat Analysis**
                        The Hayabusa tool likely uses this data to:
                        - **Identify IoCs**: Flag malicious IPs, domains, hashes, or behaviors.
                        - **Reconstruct Attack Chains**: Map the timeline of an attack (e.g., initial compromise, lateral movement, data exfiltration).
                        - **Assess Criticality**: Determine the scope (how many systems are affected), persistence mechanisms (e.g., registry keys, scheduled tasks), and impact (e.g., data loss, system downtime).

                        ---

                        ### **Note**
                        Without a specific report or configuration details, this is a general overview. If you have a **Hayabusa report** or specific data samples to analyze, I can provide a more tailored breakdown of the findings and their criticality. Let me know! 😊

                        --- 

                        Would you like to analyze a specific example or dive deeper into any of these areas?"
                        """,
                        """
                        NiNa: <think> Okay, let's tackle this question. The user wants to know which system to analyze first based on the two Hayabusa reports provided. First, I need to compare the two reports: report_1.html and report_2.html. Let me look at the key metrics. Starting with the events with hits. Report_1 has 1,330 events with hits, while report_2 has only 419. That's a significant difference. More hits might indicate more suspicious activities. Then, the total events analyzed are similar—around 300k each. But the data reduction percentages are 99.56% for report_1 and 99.86% for report_2. Wait, data reduction is the percentage of events without hits, right? So lower data reduction means more relevant events. Wait, actually, data reduction here is listed as "Data reduction: 289,598 events (99.86%)" for report_2. That means 99.86% of the total events were reduced, leaving only 419 hits. For report_1, 99.56% reduction leaves 1,330 hits. So the higher number of hits in report_1 suggests more potential threats detected. Also, the time frames: report_1 covers from April 3rd to April 9th, and report_2 from April 7th to April 9th. There's an overlap, but report_1 starts earlier. However, the user might be interested in the more active one. Since report_1 has over three times as many hits, it's likely more critical. The output file sizes also differ: report_1 is 573.7 KB vs. 178.8 KB for report_2. Larger size could mean more data, but that's probably due to more hits. So, the answer should be report_1 first because it has significantly more events with hits (1,330 vs. 419), indicating more potential security issues needing immediate attention. </think> report_1.html should be analyzed first. It has significantly more events with hits (1,330 vs. 419) and a higher detection volume, indicating more potential security issues requiring immediate attention. The broader time range (April 3–9 vs. April 7–9) also covers earlier activity, which may provide critical context.
                        """,
                        """NiNa: <think> Okay, let's tackle this question. The user is asking which system to analyze first based on the five Hayabusa reports provided. First, I need to look through the given context to find relevant information. Looking at the reports, each report's filename is report_1.html to report_5.html. The timestamps in the Results Summary show that the first timestamp is March 17 and the last is March 20. The events with hits are 191 out of over 300k, which is a small percentage, but that's normal since data reduction is high. Wait, the user mentioned five reports, but in the context, there are two General Overviews with similar command lines. Both are for different EVTX files: Security4.evtx and 5.evtx. The reports 1 and 2 are mentioned, but the question refers to five reports. Maybe the others (3-5) aren't shown here. However, the main info here is from report_5.html, which has the Results Summary. The key point is to determine which system (i.e., which EVTX file's system) has the most critical findings. Since the Results Summary is in report_5.html, which analyzed Security4.evtx (from the command line in report_2.html), maybe that's the one with detections. The other report (report_1.html) is for 5.evtx but doesn't have the results summary here. The detections total isn't specified per system, but since the question refers to five reports, perhaps the one with the latest timestamp or most hits. The last timestamp in report_5 is March 20, which is later than the others. So the system associated with report_5 (Security4.evtx) might be more recent and thus prioritized. Also, the data reduction is 99.94%, meaning fewer false positives, so the 191 events are more likely valid. Therefore, the answer should point to the system related to report_5.html (Security4.evtx) because of the later timestamp and the presence of detected events, indicating a potential active incident needing immediate attention. </think> The system associated with **report_5.html** (analyzing `Security4.evtx`) should be prioritized. Its latest timestamp (2025-03-20) indicates recent activity, and it contains 191 detected events, suggesting potential malicious activity. The high data reduction (99.94%) implies credible hits. Focus here first to address timely threats.
                        """]

phi_answers = [
                                        """The IT Forensic Hayabusa Scan Tool is a specialized software tool used in digital forensics and incident response to analyze network traffic and identify potential security threats or malicious activities. It operates by capturing and examining data packets transmitted over a network, allowing forensic investigators to detect anomalies, unauthorized access attempts, malware communication, and other indicators of compromise.

                                    Key features typically include:

                                    1. **Traffic Analysis**: Hayabusa can capture and analyze network traffic in real-time or from recorded sessions, helping identify suspicious patterns or behaviors.

                                    2. **Signature-Based Detection**: It uses predefined signatures to recognize known threats, such as specific malware strains or attack vectors.

                                    3. **Anomaly Detection**: Beyond signature-based detection, it may employ heuristic analysis to spot unusual activities that deviate from normal network behavior.

                                    4. **Reporting and Alerts**: The tool generates detailed reports on detected activities, providing insights into potential security incidents. It can also trigger alerts for immediate attention if critical threats are identified.

                                    5. **Integration with Other Tools**: Hayabusa often integrates with other forensic tools and platforms to provide a comprehensive view of the network's security posture.

                                    6. **Customization**: Users can customize detection rules and signatures based on their specific environment or emerging threat intelligence.

                                    In cybersecurity incident response, tools like Hayabusa are crucial for quickly identifying and mitigating threats, ensuring that organizations can respond effectively to potential breaches or attacks.""",

                        

                                        """While the IT Forensic Hayabusa Scan Tool is a powerful asset for network analysis and threat detection, it does have certain limitations:

                                    1. **Encrypted Traffic**: Analyzing encrypted traffic can be challenging without decryption capabilities. While some tools may attempt to intercept SSL/TLS sessions, this often requires additional legal permissions and technical setups.

                                    2. **Resource Intensity**: Capturing and analyzing large volumes of network traffic in real-time can be resource-intensive, requiring significant processing power and memory, which might impact performance on less capable systems.

                                    3. **False Positives/Negatives**: Like many security tools, Hayabusa may generate false positives (benign activities flagged as threats) or false negatives (missed detections), especially if the threat signatures are not up-to-date or if new attack vectors emerge that aren't yet recognized by the tool.

                                    4. **Signature-Based Limitations**: While effective against known threats, signature-based detection can struggle with zero-day exploits and polymorphic malware that change their code to evade detection.

                                    5. **Complex Configuration**: Setting up and configuring Hayabusa for optimal performance in diverse network environments may require significant expertise and customization.

                                    6. **Scope of Analysis**: The tool is primarily focused on network traffic analysis, which means it might not provide insights into other types of security incidents that occur outside the scope of network communications, such as insider threats or physical breaches.

                                    7. **Legal and Ethical Considerations**: Intercepting and analyzing network traffic can raise privacy concerns and legal issues, particularly when dealing with encrypted data or personal information, necessitating strict compliance with relevant laws and regulations.

                                    8. **Integration Challenges**: While it may integrate with other tools, achieving seamless integration across different platforms and environments can be complex and time-consuming.

                                    9. **User Expertise Required**: Effective use of Hayabusa requires a high level of expertise in network security and digital forensics to interpret the data accurately and respond appropriately to detected threats.

                                    Understanding these limitations is crucial for organizations to effectively incorporate Hayabusa into their broader cybersecurity strategy, ensuring it complements other tools and processes.""",
                                       """The IT Forensic Hayabusa Scan Tool is designed to analyze a wide range of network-related data to identify security threats and suspicious activities. Here are some key types of data it typically analyzes:

                                    1. **Network Traffic**: Captures packets transmitted over the network, including both inbound and outbound traffic.

                                    2. **Protocols**: Analyzes various communication protocols such as HTTP, HTTPS, FTP, SMTP, DNS, and others to detect anomalies or malicious use.

                                    3. **IP Addresses**: Monitors source and destination IP addresses for unusual patterns that might indicate unauthorized access or data exfiltration attempts.

                                    4. **Ports**: Examines open ports on network devices to identify potential vulnerabilities or unauthorized services running on the network.

                                    5. **Payloads**: Inspects the content of data packets, including payloads, to detect known malware signatures or suspicious code snippets.

                                    6. **Session Data**: Analyzes session information to track connections and interactions between different entities within the network.

                                    7. **DNS Queries**: Monitors DNS requests for signs of domain generation algorithms (DGAs) used by malware or unauthorized domain lookups.

                                    8. **HTTP Headers**: Reviews HTTP headers for anomalies that might indicate web-based attacks, such as SQL injection attempts or cross-site scripting (XSS).

                                    9. **Encrypted Traffic**: While challenging, some versions may attempt to analyze encrypted traffic using techniques like SSL/TLS interception, depending on legal and ethical guidelines.

                                    10. **Behavioral Patterns**: Uses heuristic analysis to identify deviations from normal network behavior that could suggest a security incident.

                                    By analyzing these data types, the Hayabusa Scan Tool helps forensic investigators detect and respond to potential threats effectively, providing insights into both known and emerging attack vectors.""",

                                        """NiNa: You should analyze `report_1.html` first because it has a higher number of events with hits (1,330) compared to `report_2.html`, which only has 419. This indicates that `report_1.html` contains more potential security incidents or anomalies worth investigating. Additionally, the analysis for `report_1.html` took less time (21 seconds), suggesting it might be more straightforward or contain fewer complex events than `report_2.html`.""",

                                        """NiNa: Based on the context provided, you should analyze the system associated with `report_5.html` first. This report has a timestamp of 17.04.25, indicating it is the most recent among the mentioned reports. Additionally, it contains specific details about events and detections that occurred between March 17 and March 20, 2025, which might be crucial for timely analysis. The focus on this report aligns with your instruction to use a profile including `%MitreTactics%`, suggesting its relevance in identifying potential tactics used by adversaries."""
                                    ]

llama_answers = [
                    """The IT Forensic Hayabusa Scan Tool is a digital forensic tool used to analyze and investigate cyber incidents. It's designed to help incident responders and investigators gather, analyze, and report on evidence related to security breaches or malicious activity.

                As an expert in cybersecurity incident response, I would expect the Hayabusa Scan Tool to provide a comprehensive analysis of system logs, network traffic, and other digital artifacts to identify potential indicators of compromise (IOCs). The tool might also include features for:

                1. **Data collection**: Gathering relevant data from various sources, such as system logs, network captures, and file systems.
                2. **Analysis**: Examining the collected data to identify suspicious or malicious activity, including malware, unauthorized access, or other security threats.
                3. **Reporting**: Generating detailed reports on findings, including a criticality rating (Low, Medium, High, or Critical) based on indicators of compromise, scope, persistence, and impact.

                The Hayabusa Scan Tool is likely used by incident responders to quickly assess the severity of a potential security breach and prioritize further investigation and remediation efforts.""",

               

                    """As an expert in cybersecurity incident response, I would identify the following limitations of the IT Forensic Hayabusa Scan Tool:

                1. **False Positives**: The tool may generate false positives, indicating malicious activity when none exists. This could lead to unnecessary resource allocation and potential disruption of legitimate business operations.
                2. **Limited Contextual Understanding**: Without human expertise and contextual understanding, the tool's analysis might not fully capture the nuances of a complex security incident.
                3. **Data Quality Issues**: The accuracy of the tool's findings depends on the quality of the data it analyzes. Poorly configured systems, incomplete logs, or corrupted data can lead to inaccurate results.
                4. **Overemphasis on IOC Detection**: The tool's focus on detecting indicators of compromise (IOCs) might lead to an overemphasis on signature-based detection, potentially missing more sophisticated or zero-day threats.
                5. **Lack of Human Oversight**: Without human review and validation, the tool's findings may not be thoroughly understood or contextualized, leading to potential misinterpretation or incorrect conclusions.
                6. **Limited Support for Complex Environments**: The tool might struggle with complex environments, such as those involving multiple systems, networks, or cloud services, requiring additional configuration or customization.
                7. **Dependence on Regular Updates and Maintenance**: The tool's effectiveness relies on regular updates to its threat intelligence database and maintenance of its algorithms, which can be time-consuming and resource-intensive.

                These limitations highlight the importance of human expertise and contextual understanding in cybersecurity incident response, as well as the need for ongoing monitoring and validation of automated tools like the IT Forensic Hayabusa Scan Tool.""",
                     """As an expert in cybersecurity incident response, I would expect the IT Forensic Hayabusa Scan Tool to analyze a wide range of digital artifacts and system logs, including:

                1. **System Logs**: Windows Event Logs (EVT), Linux System Logs (syslog), and other log files from various operating systems.
                2. **Network Traffic Captures**: PCAP (Packet Capture) files containing network traffic data, such as HTTP requests, DNS queries, and other network communications.
                3. **File System Data**: File metadata, including file names, paths, timestamps, and permissions.
                4. **Registry Data**: Windows Registry entries, including keys, values, and subkeys.
                5. **Process and Thread Information**: Process IDs, thread IDs, and execution history.
                6. **Memory Dumps**: Physical memory dumps or virtual machine snapshots to analyze running processes and malware behavior.
                7. **Network Connection Logs**: Records of network connections, including source IP addresses, destination IP addresses, and protocols used.
                8. **System Configuration Files**: Files containing system configuration settings, such as hosts files, DNS cache, and other system-specific configurations.
                9. **User Account Data**: User account information, including login history, password changes, and group membership.
                10. **Antivirus and Anti-Malware Logs**: Logs from antivirus software, including detection events, scan results, and removal actions.

                The Hayabusa Scan Tool may also analyze data from various sources, such as:

                1. **Endpoint Detection and Response (EDR) Tools**
                2. **Security Information and Event Management (SIEM) Systems**
                3. **Cloud Security Platforms**
                4. **Network Intrusion Detection Systems (NIDS)**

                By analyzing these digital artifacts, the Hayabusa Scan Tool can help identify potential security incidents, detect malware, and provide valuable insights for incident response and remediation efforts.""",

                    """NiNa: Based on the provided information, I would recommend analyzing report_2.html first. Here's why:
                * Report_2.html has fewer total events analyzed (290,017) compared to report_1.html (302,253), which means it may be easier and faster to analyze.
                * The data reduction in report_2.html is slightly higher (99.86%) than in report_1.html (99.56%), indicating that the analysis of report_2.html has already filtered out a larger number of irrelevant events.

                Overall, analyzing report_2.html first may provide more immediate insights and help to identify potential security issues sooner.""",

                    """NiNa: As an IT Forensic Analyst, my task is to identify the most critical system for analysis. Based on the provided reports, I recommend analyzing the system associated with report_5.html first. Report_5.html has a higher number of events analyzed (306,401) compared to report_1.html and report_2.html. Additionally, it has a lower data reduction rate (99.94%) indicating that more relevant information is preserved in this report.

                This suggests that the system associated with report_5.html may have experienced significant activity or potential security incidents, making it a higher priority for analysis. I do not know the specific details of the systems or the nature of the events analyzed, but based on the provided data, I recommend starting with report_5.html."""
                ]


def test_case():
    correctness_metric = GEval(
        name="Correctness",
        criteria="Determine if the 'actual output' is correct based on the 'expected output'.",
        evaluation_params=[LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.EXPECTED_OUTPUT],
        threshold=0.5
    )
    test_case_frage_1 = LLMTestCase(
        input="What is the IT Forensic Hayabusa Scan Tool?",
        actual_output=gemma_answers[0],
        expected_output="""
            Hayabusa is an open-source, high-performance forensic and threat hunting tool designed to analyze Windows event logs. 
            Developed by the Yamato Security group in Japan, its name—meaning "peregrine falcon" in Japanese—reflects its focus 
            on speed and precision in detecting threats.


            🛠️ Key Features
            Fast Forensics Timeline Generation: Hayabusa processes Windows event logs to produce a consolidated timeline in CSV 
            or JSONL format, facilitating efficient forensic analysis.
            docs.velociraptor.app

            Sigma Rule Integration: It supports Sigma rules, a standardized format for describing log-based detection patterns, 
            allowing for customizable and extensible threat detection.
            Medium


            Multi-Platform Support: Built in Rust, Hayabusa is cross-platform, running on Windows, Linux, and macOS systems.
            CyberSecTools


            Multi-Threaded Processing: Utilizes multi-threading to accelerate log analysis, making it suitable for both live and 
            offline investigations.
            Cryeye Project

            Enterprise Integration: Can be integrated with tools like Velociraptor for enterprise-wide threat hunting and 
            incident response.
            docs.velociraptor.app

            Output Compatibility: The generated timelines can be analyzed using tools such as LibreOffice, Timeline Explorer, 
            Elastic Stack, and Timesketch.

            🔧 Use Cases
            Incident Response: Quickly identify and investigate security incidents by analyzing event logs for signs of compromise.

            Threat Hunting: Proactively search for indicators of malicious activity across systems using predefined or custom Sigma rules.

            Digital Forensics: Reconstruct events leading up to and following a security incident to understand the scope and impact.
            """
            ,
        retrieval_context=[""]
    )



    test_case_frage_2= LLMTestCase(
        input="What are the limitations of the IT Forensic Hayabusa Scan Tool?",
        actual_output=gemma_answers[1],
        expected_output="""
            While Hayabusa is a powerful tool for Windows event log analysis and threat hunting, it has certain limitations that users should be aware of:

                        
            1. Limited Scope to Windows Event Logs

            Hayabusa is specifically designed for analyzing Windows event logs (EVTX files). It does not process other forensic artifacts such as memory dumps, disk images, or registry hives.

            ---

            2. Dependence on Log Quality

            The effectiveness of Hayabusa relies heavily on the availability and quality of Windows event logs. If logging is misconfigured or logs are incomplete, the tool's ability to detect threats diminishes.

            ---

            3. Complexity in Rule Management

            While Hayabusa supports Sigma rules, managing and customizing these rules can be complex. Users may need to convert Sigma rules to Hayabusa-compatible formats and ensure proper field mappings, which can be time-consuming.

            ---

            4. Performance on Large Datasets

            Processing extensive log datasets can be resource-intensive. Although Hayabusa supports multi-threading, analyzing large volumes of logs may still impact performance and require significant system resources.

            ---

            5. Learning Curve for Advanced Features

            Utilizing Hayabusa's advanced features, such as custom rule creation and integration with other tools, may require a deeper understanding of its functionalities and configurations.

            ---

            6. Limited Real-Time Analysis

            Hayabusa is primarily designed for post-event analysis. While it can be integrated with tools like Velociraptor for more proactive monitoring, it does not inherently provide real-time threat detection capabilities.

            ---

            7. Integration Challenges

            Some users have noted difficulties integrating Hayabusa with other tools and platforms, which can hinder seamless workflows in complex environments.

            ---

            Understanding these limitations is crucial for effectively incorporating Hayabusa into your cybersecurity toolkit and ensuring it complements other tools and practices in your incident response strategy.
            """
            ,
        retrieval_context=[""]
    )


    test_case_frage_3= LLMTestCase(
        input="What data can the IT Forensic Ha-yabusa Scan Tool analyze?",
        actual_output=gemma_answers[2],
        expected_output="""The IT Forensic Hayabusa Scan Tool is designed to analyze Windows Event Logs (EVTX files) for the purposes of digital forensics and threat hunting. 
            It focuses on identifying suspicious behavior and potential security incidents by parsing and evaluating event log data.

            Specifically, Hayabusa can analyze:

            - Security events such as logon attempts, user creation, and privilege escalation
            - Process creation and execution events
            - File access and changes
            - Scheduled tasks and service changes
            - Windows Defender alerts and audit logs
            - Remote access and RDP session activity
            - Lateral movement indicators and signs of persistence

            While highly efficient in its area, Hayabusa is limited to Windows log analysis and does not process other forensic artifacts such as memory dumps, disk images, or registry files.

            It supports Sigma rule integration for threat detection, allowing users to define and apply detection rules to find patterns of malicious activity in event data."""
            ,
        retrieval_context=[""]
    )
    test_case_frage_4= LLMTestCase(
        input="""Read the two provided Hayabusa
                reports and tell me which system I
                should analyze first and why.""",
        actual_output=gemma_answers[3],
            
        expected_output="""The system associated with Report 2 should be prioritized for analysis due to the presence of a wider variety of unique detections, indicating potentially more complex or coordinated suspicious activity. Notable alerts include:

            Suspicious PowerShell invocation from script engines

            Password reset by admin

            Potentially suspicious Windows app activity

            These detections suggest possible compromise or misuse that warrants immediate investigation.

            In contrast, Report 1 shows signs of repetitive alerting, with a single alert rule being triggered 1,318 times. This high volume, especially if generated by the same detection logic, may indicate a false positive or a misconfiguration in the alerting rule, and thus may not represent a genuine security threat at the same scale as Report 2."""
                        ,
        retrieval_context=[""]
    )
    test_case_frage_5= LLMTestCase(
        input="""Read the five provided Hayabusa
                reports and tell me which system I
                should analyze first and why.""",
        actual_output= gemma_answers[4],
        expected_output="""Investigation Priority Summary:

            Report 2 Highest Priority

            Reason: Exhibits a higher density of unique detections triggering.

            Implication: Suggests a broader attack surface or multiple indicators of compromise.

            Report 1 Second Priority

            Reason: Logs a higher number of detections overall.

            Caveat: The frequent alert for “Process Ran With High Privilege” appears noisy and may be a false positive, potentially inflating the alert count.

            Report 5  Third Priority

            Reason: Contains fewer detections than Reports 1 and 2.

            Assessment: Less urgent, but still notable and worth reviewing after the higher-priority reports.

            Reports 3 & 4 Lowest Priority

            Reason: Each contains only one detection type, which doesn’t appear to be as critical compared to the other reports.

            Implication: Low diversity and severity suggest these may be routine or informational alerts."""
            ,
        retrieval_context=[""]
    )
    assert_test(test_case_frage_1, [correctness_metric])