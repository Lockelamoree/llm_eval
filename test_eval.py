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


def test_case():
    correctness_metric = GEval(
        name="Correctness",
        criteria="Determine if the 'actual output' is correct based on the 'expected output'.",
        evaluation_params=[LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.EXPECTED_OUTPUT],
        threshold=0.5
    )
    test_case_frage_1 = LLMTestCase(
        input="What is the IT Forensic Hayabusa Scan Tool?",
        actual_output=deepseek_answers[0],
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
        input="What is the IT Forensic Hayabusa Scan Tool?",
        actual_output=deepseek_answers[1],
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
        actual_output=deepseek_answers[2],
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
        actual_output=deepseek_answers[3],
            
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
        actual_output= deepseek_answers[4],
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