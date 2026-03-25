# Malware Beaconing

This scenario shows periodic outbound connections made by malware to a command-and-control server. The traffic is captured to analyze beaconing behavior.

## Steps
1. Simulate beaconing with a script that makes scheduled HTTP requests to an external server.
2. Capture the traffic with Wireshark.
3. Observe the regular intervals of outbound connections.
