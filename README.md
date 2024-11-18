# Nano Monitor

<img src="./images/Sample.png" style="border-radius: 15px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); width: 50%;">

Nano Monitor is a simple and lightweight network monitoring tool built with Python.

## Features

- Ping Monitoring
- HTTP Monitoring
- SNMP Monitoring
- Traffic Monitoring
- Anomaly Detection
- Threshold Detection
- Failure Detection
- Webhook Notifications
- Logging Monitoring Data

## Installation

1. Click on "Releases" on the right-hand side of the screen.

<img src="./images/Releases.png" style="border-radius: 15px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); width: 50%;">

2. Download the "nano_monitor.py"

<img src="./images/nano_monitor.png" style="border-radius: 15px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); width: 50%;">

3. Place `nano_monitor.py` in any directory.

    ### To use the Anomaly Alerts feature:
    Install the machine learning library `scikit-learn`:
    ```
    pip install scikit-learn
    ```

    ### To use the SNMP Monitoring or Traffic Monitoring features:
    Install Net-SNMP.

    For Ubuntu or other Debian-based systems:
    ```
    sudo apt install snmp
    ```
    For CentOS or other RedHat-based systems:
    ```
    sudo yum install net-snmp net-snmp-utils
    ```
    For Windows:<br>
    [https://sourceforge.net/projects/net-snmp/](https://sourceforge.net/projects/net-snmp/)

## Start-up

1. Navigate to the directory where `nano_monitor.py` is located via CLI.

2. Run `nano_monitor.py` with Python:

   On Linux:
   ```
   python3 nano_monitor.py
   ```

   On Windows:
   ```
   python nano_monitor.py
   ```

3. If the following prompt appears, the startup is successful:

   `Enter the host or URL to monitor:`

## Usage Example

- Simple Ping monitoring  
`192.168.1.1`

- Simple HTTP monitoring (GET request)  
`https://example.com`

- SNMP monitoring of a specific OID  
`192.168.1.1 --snmp public 1.3.6.1.4.1.2021.11.11.0`

- Traffic monitoring on ifIndex.1  
`192.168.1.1 --snmp public traffic.1`

- Traffic monitoring using ifName (e.g., Gi0/1)  
`192.168.1.1 --snmp public traffic.Gi0/1`

- Ping monitoring with anomaly detection (256 data points, 0.01 contamination)  
`192.168.1.1 --anomaly`

- Ping monitoring with threshold detection  
`192.168.1.1 --thresh >=300`

- Traffic monitoring with threshold detection  
`192.168.1.1 --snmp public traffic.Gi0/1 --thresh in>=1gbps out>=500mbps`

- Ping monitoring with failure and webhook notifications (15-minute suppression interval)  
`192.168.1.1 --fail --webhook https://example.com/webhook 15`

- Ping monitoring with logging (default filename)  
`192.168.1.1 --log`

## Details of Each Option

Enter any of the following commands to view the help:

`-h`, `--help`, `?`
