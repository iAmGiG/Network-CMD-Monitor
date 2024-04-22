# Network CMD Monitor

## Mission Statement
"To be a tool to help IT administrators monitor critical network ports on client machines that are already designed to accept remote CMDs (such as SSH ports or similar). Using an effective method of prioritizing and identifying malicious behavior via regular expressions, this tool aims to provide a lightweight monitoring solution that can be deployed quickly without much overhead."

## Introduction
This project is designed as a logging and alert prioritization tool rather than an interceptor. It is intended for IT administrators who need to ensure the security of network ports that accept remote commands. The tool leverages regular expressions to detect potentially malicious activity and prioritize alerts.

## Project Components
### Server
A simple server set up to receive CMDs as plaintext via specified network ports. This server acts as the primary receiver and first point of contact for incoming network commands.

### Listener
Integrated within the server, the listener operates on a separate thread. Its primary function is to observe all incoming messages, analyze them using a series of pattern checkers, and log the results.

### Logger
Logs every transaction, noting down the time and a brief description of the activity. If a potentially harmful pattern is detected, it raises the concern level in the log based on predefined criteria.

### Alert Prioritizer
Utilizes a tiered system to elevate the priority level of alerts. This system is initially based on the quantity of matches within a connection to simplify implementation. Future versions may include more complex algorithms for threat assessment.

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

### Evaluation Criteria
- **Accuracy**: Measure the accuracy of the pattern detection system in identifying malicious commands.
- **Performance**: Evaluate the performance impact on the host machine, ensuring minimal overhead.
- **Scalability**: Assess how well the tool scales with increased network traffic and attack complexity.

## Future Enhancements
- **Dynamic Threshold Adjustment**: Consider implementing a more dynamic system for alert prioritization based on adaptive thresholds or machine learning.
- **Broader Pattern Database**: Expand the regex library to cover a wider range of malicious activities, possibly integrating community-contributed patterns.
