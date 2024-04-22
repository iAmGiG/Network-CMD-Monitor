# Network CMD Monitor

## Mission Statement

"To be a tool to help IT administrators monitor critical network ports on client machines that are already designed to accept remote CMDs (such as SSH ports or similar). Using an effective method of prioritizing and identifying malicious behavior via regular expressions, this tool aims to provide a lightweight monitoring solution that can be deployed quickly without much overhead."

## Introduction

This project is designed as a logging and alert prioritization tool rather than an interceptor. It is intended for IT administrators who need to ensure the security of network ports that accept remote commands. The tool leverages regular expressions to detect potentially malicious activity and prioritize alerts.

## Goals

The primary goal of this project is to provide a simple yet effective monitoring system for remote command execution, which includes:

- Detection of potentially malicious commands transmitted over network connections.
- Logging of all such activities with appropriate time stamps and metadata.
- Prioritization of logs based on the potential threat level, using a simple tiered system.
- Offering an educational tool to understand network security basics and the practical application of regex in cybersecurity.

## Prerequisites

What things you need to install the software and how to install them:

```bash
python3 -m pip install -r requirements.txt
```

## Common Commands Definitions

- **system_call**: Refers to basic system-related commands like ls, pwd, netstat which often appear in benign contexts but can be part of reconnaissance in a malicious context.
- **security_injection**: Includes attempts to inject or execute commands that could alter system states or configurations. This includes SQL injections like 'OR 1=1 -- and command injections like ; rm -rf /.
- **sql_injection**: Specifically targets the injection of SQL code into data fields to manipulate database queries.
- **xss_injection**: Concerns the insertion of scripts typically in web applications that could lead to cross-site scripting (XSS) attacks.
- **rfi_inclusion**: Detection of Remote File Inclusion (RFI) which involves including remote files through web requests.
- **path_traversal**: Identifies attempts to access directories and files outside of the web server's root directory.
- **port_scanning**: Looks for patterns that suggest scanning of network ports which can be preliminary steps in a network attack.
- **brute_force**: Attempts to detect repeated trial-and-error attempts to guess passwords or other credentials.

## Testing Procedure

### Setup

1. **Initialize the Server**: Configure a test server to accept CMDs as plaintext. This server will also host the listener and logger components.
2. **Deploy the Listener**: Start the listener thread upon server startup to ensure it captures all incoming traffic.

### Test Cases

1. **Normal CMDs**: Send benign command-line instructions to verify that the system logs them correctly without raising unnecessary alerts.
2. **Malicious Patterns**: Introduce commands that match known malicious patterns to test the detection capabilities and alert prioritization.
3. **High Volume**: Simulate a high volume of CMDs to test the system's performance and its ability to scale when faced with potential DDoS attacks or other high-load scenarios.

### Logging and Alerts

- **Logs**: Check logs for accurate time stamps and descriptions of both normal and suspect activities.
- **Alerts**: Review alert outputs to ensure that the prioritization corresponds to the potential threat levels.

## Future Enhancements

- **Dynamic Threshold Adjustment**: Consider implementing a more dynamic system for alert prioritization based on adaptive thresholds or machine learning.
- **Broader Pattern Database**: Expand the regex library to cover a wider range of malicious activities, possibly integrating community-contributed patterns.
- **Integration with external repositories** for enhanced pattern recognition.
- **Development of a more robust client-server** architecture to handle real-time data monitoring and logging.
