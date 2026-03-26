# Brute Force

This scenario simulates an SSH brute force attack. Multiple login attempts are generated to a target host, which should be visible in the packet capture.

## Steps
1. Use a tool such as Hydra to perform the attack: `hydra -l user -P passwords.txt ssh://<target>`.
2. Capture the traffic with Wireshark.
3. Identify repeated failed SSH login attempts in the capture.
