@echo off
:: ==============================================================================
:: CYBERDUDEBIVASH APEX PURPLE SWARM - AUTONOMOUS BAS
:: Target Threat: Ransomware Under Pressure: Tactics, Techniques, and Procedures in a Shifting Threat Landscape
:: Generated: 2026-03-28 08:44:42 UTC
:: WARNING: This is a SAFE simulation script. It contains NO malicious payload.
:: Usage: Run this in a sandbox to trigger the APEX Sigma/SOAR detections.
:: ==============================================================================

echo [APEX] Initiating safe behavioral simulation...

:: 1. Simulate C2 Beaconing (Benign Ping to trigger network telemetry)
echo [APEX] Simulating external connection to IOC...
ping 127.0.0.1 -n 1 > nul

:: 2. Simulate File Drop (Benign text file creation)
echo [APEX] Dropping benign test artifact...
echo "CDB_APEX_BENIGN_TEST_STRING_MATCH_ME" > %TEMP%\apex_test_artifact.txt

:: 3. Simulate Privilege Escalation attempt (Harmless whoami)
echo [APEX] Triggering simulated execution behavior...
whoami /priv > nul

echo [APEX] Simulation complete. 
echo [APEX] Check your Splunk/CrowdStrike dashboard. If APEX SOAR is active, this was detected.
pause
