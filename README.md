# Security-Onion-SOC-Workshop
<br>

  ![Image 2](https://i.imgur.com/mObZonw.png)
<br><br>

## Objective

The objective of this project is to set up a virtual network environment for analyzing malware traffic using Security Onion, a Windows VM for Open Source Intelligence (OSINT), and various tools like Wireshark, AbuseIPDB, and VirusTotal. This setup aims to provide a realistic SOC (Security Operations Center) experience for malware analysis and network security monitoring. <br><br>

## Components

- **VirtualBox**: Used for creating and managing virtual machines.
- **Security Onion VM**: A powerful Linux distro for intrusion detection, network security monitoring, and log management.
- **Windows VM**: Utilized for conducting OSINT and other security-related tasks.
- **Zeek (formerly Bro)**: An integral part of Security Onion, Zeek is a powerful network analysis framework focused on security monitoring.
- **Wireshark**: Network protocol analyzer for network troubleshooting and analysis.
- **AbuseIPDB**: Online database for reporting and checking IP addresses involved in malicious activities.
- **VirusTotal**: A service for analyzing suspicious files and URLs for malware.
- **NAT Network**: Configured in VirtualBox for network simulation.
- **Malware Traffic Analysis PCAP File**: Used for practical experience in analyzing malicious network traffic.

<details>
  <summary><h2><b>Section 1: Setting Up the Virtual Environment</b></h2></summary>
  This section will guide us through the setup of our virtual environment using VirtualBox. We'll configure a NAT network and install two virtual machines – one for Security Onion and another for a Windows environment to facilitate OSINT and to access the Security Onion web interface. <br><br>

  - **Step 1: Download Security Onion ISO File**:  
    Begin by downloading the Security Onion ISO file from the official Security Onion GitHub page. This ISO file will be used to install Security Onion on our virtual machine.
    
  ![Image 2](https://i.imgur.com/uookvCd.png)
    <br><br>
    
  - **Step 2: Create a New Virtual Machine in VirtualBox for Security Onion**:  
    Next, we'll set up a new virtual machine in VirtualBox specifically for Security Onion.
    - Allocate the following resources:
      - Base Memory: Approximately 8 GB
      - Processors: 3 cores
      - Hard Disk Storage: 200 GB
    
  ![Image 2](https://i.imgur.com/KQ3TE5g.png)
    <br><br>
    
  ![Image 2](https://i.imgur.com/JZIiCYe.png)
    <br><br>
    
  ![Image 2](https://i.imgur.com/FYk1M4y.png)
    <br><br>
       
  - **Step 3: Create a New Windows VM**:  
    We also need a Windows virtual machine for OSINT activities and to access the Security Onion web interface.
    - Allocate the following resources:
      - Base Memory: Approximately 8 GB
      - Processors: 3 cores
      - Hard Disk Storage: 50 GB
    <br><br>

  - **Step 4: Create a NAT Network in VirtualBox**:  
    To allow both VMs to communicate with each other and the internet, we’ll create a NAT Network in VirtualBox.
    - Navigate to 'File' > 'Tools'
    - Click on 'Network Manager'
    - Click on NAT Networks and configure with the following settings:
      - Name: NatNetwork
      - IPv4 Prefix: 10.2.22.0/24

  ![Image 2](https://i.imgur.com/EseCdCy.png)
    <br><br>
    
  ![Image 2](https://i.imgur.com/oqxJmkH.png)
    <br><br>

  - **Step 5: Configure Network Settings for Both VMs**:  
    Finally, assign both VMs to our newly created NAT Network.
    - For each VM, go to 'Settings' > 'Network'
    - Under 'Attached to:', select 'NAT Network'
    - Choose 'NatNetwork' from the dropdown menu
<br>

  ![Image 2](https://i.imgur.com/c89c24P.png)
<br><br>

  Great! We've successfully created our virtual network environment and set up the virtual machines necessary for this workshop. This foundational step is critical for our subsequent activities in network security monitoring and analysis with Security Onion.

</details>

<details>
  <summary><h2><b>Section 2: Security Onion Initial Setup</b></h2></summary>
  Lets setup up and configure our Security Onion (NSM) Network Security Monitoring solution<br><br>

  - **Step 1: Boot up Security Onion VM**:  
    - Set our Administrator username: streetrack
    - Set password: *********
      
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>

  - **Step 2: Set and choose the following configurations**:  
      
  ![Image 2](https://i.imgur.com/TKUtGex.png)
<br><br>
  ![Image 2](https://i.imgur.com/ZTWYOSZ.png)
<br><br>
  ![Image 2](https://i.imgur.com/cnPWynd.png)
<br><br>
  ![Image 2](https://i.imgur.com/IM6XvNY.png)
<br><br>
  ![Image 2](https://i.imgur.com/3k3ZteC.png)
<br><br>
  ![Image 2](https://i.imgur.com/cMBPrI3.png)
<br><br>
  ![Image 2](https://i.imgur.com/qhZ5MSs.png)
<br><br>
  ![Image 2](https://i.imgur.com/hdhMJpb.png)
<br><br>
  ![Image 2](https://i.imgur.com/ykd87qv.png)
<br><br>
  ![Image 2](https://i.imgur.com/3lWnzWx.png)
<br><br>
  ![Image 2](https://i.imgur.com/cYwjsis.png)
<br><br>
  ![Image 2](https://i.imgur.com/gpxr3Ev.png)
<br><br>
  ![Image 2](https://i.imgur.com/FEbvbPy.png)
<br><br>
  ![Image 2](https://i.imgur.com/MIuG3Md.png)
<br><br>
  ![Image 2](https://i.imgur.com/F59aOvX.png)
<br><br>
  ![Image 2](https://i.imgur.com/KOWgLZu.png)
<br><br>
  ![Image 2](https://i.imgur.com/vljPmFG.png)
<br><br>
  ![Image 2](https://i.imgur.com/7zsfomx.png)
<br><br>
  ![Image 2](https://i.imgur.com/RENFe9F.png)
<br><br>
  ![Image 2](https://i.imgur.com/0A7CbRk.png)
<br><br>
  ![Image 2](https://i.imgur.com/aJMIVel.png)
<br><br>
  
  Awesome! We've completed the set up of our Security Onion Server!<br>
  In order to access the web interface of Security Onion, we'll use the following:<br>
    - Website: https://10.2.22.20<br>
    - Username: streetrack@homelab.com<br>
    - Password: ***********

</details>

<details>
  <summary><h2><b>Section 3: Logging into Security Onion</b></h2></summary>
  In this section, we will go over the steps to log into our SIEM, Security Onion. This process is crucial for accessing the powerful suite of tools that Security Onion provides for network security monitoring and analysis. <br><br>

  - **Step 1: Confirm Security Onion Services**:
    - Within our Security Onion VM, it’s important to first ensure that all necessary services are operational. Run the following command to see if the services are up and running. This step confirms that the system is ready for use.<br><br>
      - ```bash
        sudo so-status
        ```
<br>
 
  ![Image 2](https://i.imgur.com/nYKCBlT.png)
<br><br>

  - **Step 2: Start The Windows VM and Navigate to Security Onion**:  
    - Once we've confirmed that the services in the Security Onion VM are active, proceed to the Windows VM. This VM will be used to access the Security Onion web interface.
    - Start by minimizing the Security Onion VM.
    - Boot up the Windows VM.
    - Open a web browser on the Windows VM and navigate to the Security Onion's IP address (in this case, 10.2.22.20).
    - Click on 'Advanced' if prompted by the browser, and then 'Proceed to 10.2.22.20' to bypass any security warnings. These warnings are typical when accessing local network services.
    <br><br>
  
  ![Image 2](https://i.imgur.com/ko1ARJD.png)
<br><br>

  - **Step 3: Log In to Security Onion**:  
    - Upon reaching the Security Onion login page, enter the credentials we have previously set up. It’s crucial to remember these credentials as they provide access to our SOC's central monitoring system.
      - Username: streetrack@homelab.com
      - Password: **********
    - Successfully logging in will grant us access to the dashboard and various tools provided by Security Onion, marking the beginning of our security monitoring activities.
    <br><br>
  
  ![Image 2](https://i.imgur.com/BkDzo42.png)
<br><br>
  
  ![Image 2](https://i.imgur.com/SIPNXLH.png)
<br><br>

  Congratulations! We have successfully logged into Security Onion. This is a significant step in starting our journey into network security monitoring and analysis. The Security Onion interface is where we will spend most of our time analyzing network traffic, investigating alerts, and honing our cybersecurity skills. 

</details>

<details>
  <summary><h2><b>Section 4: Downloading and Importing Malicious PCAP File</b></h2></summary>
  In this section, we will focus on acquiring and importing a malicious pcap file into Security Onion. This is a crucial step for practicing network traffic analysis and threat hunting. <br><br>

  - **Step 1: SSH into Security Onion from Windows VM**:  
    - Start by opening a PowerShell window in the Windows VM.
    - Use SSH to connect to the Security Onion VM with our username and password<br><br>
      - ```bash
        ssh streetrack@10.2.22.20
        ```
        
  ![Image 2](https://i.imgur.com/4QauvKf.png)
<br><br>

  - **Step 2: Create a Temporary Folder in Security Onion**:  
    - Once logged in, we'll run 'ls' to take note of where we're at
    - Create a temporary directory(temp) where the pcap file will be downloaded.
    - Navigate into our temp directory<br><br>
      - ```bash
        ls
        ```
      - ```bash
        mkdir temp
        ```
      - ```bash
        cd temp
        ```
        
    ![Image 2](https://i.imgur.com/7BdYAmv.png)
<br><br>

  - **Step 3: Navigate to Malware-Traffic-Analysis.net on Windows VM**:  
    - On the Windows VM, open a web browser and go to [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).
    - Under Traffic Analysis Exercises, click on 'Click Here' for Training exercises to analyze pcap files of network traffic
    - We'll then choose '2022-01-07 Traffic analysis exercise - Spoonwatch'<br>
    - Right-click on the the pcap link and choose 'Copy Link Address'
    
    ![Image 2](https://i.imgur.com/bAA7QG3.png)
<br><br>

    ![Image 2](https://i.imgur.com/ZBBzY5o.png)
<br><br>

    ![Image 2](https://i.imgur.com/cODFyaz.png)
<br><br>
    
  - **Step 4: Download the PCAP File Using Wget in PowerShell**:
    - Switch back to the PowerShell SSH session connected to Security Onion.
    - Use the `wget` command and paste the copied link address to download the file<br><br>
      - ```bash
        wget https://www.malware-traffic-analysis.net/2022/01/07/2022-01-07-traffic-analysis-exercise.pcap.zip
        ```
    ![Image 2](https://i.imgur.com/BSsooKQ.png)
<br><br>
    
  - **Step 5: Unzip the PCAP File**:
    - The zipped pcap file requires a password to unzip. The password is: infected
    - Use the following command to unzip the pcap file:<br><br>
      - ```bash
        unzip 2022-01-07-traffic-analysis-exercise.pcap.zip
        ```
    ![Image 2](https://i.imgur.com/ME0M40y.png)
<br><br>

  - **Step 6: Import the PCAP into Security Onion**:  
    - Now, we'll import the pcap file into Security Onion for analysis.
    - The following command will import the pcap:<br><br>
      - ```bash
        sudo so-import-pcap 2022-01-07-traffic-analysis-exercise.pcap
        ```
    ![Image 2](https://i.imgur.com/C0BuQrR.png)
<br><br

  Lets GO! We've successfully downloaded and imported the malicious pcap file into Security Onion. With the file now being analyzed by Suricata and Zeek, we can dive into network traffic analysis and threat hunting, gaining hands-on experience in identifying and investigating cybersecurity threats.

</details>

<details>
  <summary><h2><b>Section 5: Creating a Case from Alerts</b></h2></summary>
  After importing the pcap file into Security Onion, it's time to analyze the alerts generated and escalate them into a case. This section will guide us through adjusting the date and time filters to locate the relevant events, escalating an alert, and assigning the case for further investigation. <br><br>

  - **Step 1: Adjust Date and Time Filters**:  
    - Navigate to the Dashboards or Alerts page in Security Onion.
    - Adjust the date and time filters to match the time frame of the pcap data to ensure all relevant events are visible
    - We'll use the whole month of January 2022
      
    ![Image 2](https://i.imgur.com/063F51n.png)
<br><br>

  - **Step 2: Review and Escalate Alerts**:  
    - As we review the alerts that correspond to the events in the pcap file, we can see the following:
      - Count (number of times the alert has been flagged)
      - Rule.Name (the alert rule that has been triggered)
      - Event.Module (the module that flagged the alert, in this case, Siricata)
      - Severity (how much impact the alert has)<br><br>
    - We'll choose the first one which has the highest count and severity level for further investigation and escalate it to a new case.
      - Locate the blue icon on the left of the alert
      - Click and Escalate to a new case
    
    ![Image 3](https://i.imgur.com/lwiBWwt.png)
<br><br>
    ![Image 3](https://i.imgur.com/LiYonOG.png)
<br><br>

  - **Step 3: Assign and Update Case Status**:  
    - Once the case has been created, we'll assign it to our account
      - Click on the binoculars icon
      - Choose Assignee<br><br>
    - Update the case status to 'In Progress' to reflect that an investigation is underway.
    
    ![Image 2](https://i.imgur.com/Vu1E5zI.png)
<br><br>
    ![Image 3](https://i.imgur.com/jtOip0E.png)
<br><br>

  Great! We've now created and assigned a case based on the alerts triggered by the pcap analysis. This is a critical step in the incident response process where we begin to dive deeper into the data, examining the details of the traffic and understanding the context of the alerts. Next up, THE HUNT!

</details>







## __Conclusion__

This project successfully demonstrates the creation of a virtual SOC environment using Security Onion, Wireshark, and various OSINT tools. The hands-on experience gained in analyzing malware traffic and employing OSINT techniques provides valuable insights into the world of network security and threat intelligence.

</details>




