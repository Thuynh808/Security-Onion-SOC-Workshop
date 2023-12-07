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
  This crucial phase follows the pcap import into Security Onion, where we analyze generated alerts to identify potential threats. The goal is to escalate noteworthy alerts into cases for a detailed investigation. This section walks through fine-tuning the date and time settings to isolate the events within our pcap timeframe and how to create cases for our investigation. <br><br>

  - **Step 1: Adjust Date and Time Filters**:  
    - On the Security Onion Dashboard or Alerts page, locate the time filter usually found at the top right corner.
    - We'll set the filter to encompass the entire month of January 2022, ensuring that all events from our pcap are included in the view. This step is critical as it frames our analysis within the correct scope.
      
    ![Image 2](https://i.imgur.com/063F51n.png)
<br><br>

  - **Step 2: Review and Escalate Alerts**:  
    - Here we'll examine the list of alerts, paying special attention to the following attributes:
      - **Count**: The frequency of the alert occurrence.
      - **Rule Name**: Which rule was triggered to raise the alert.
      - **Event Module**: The module (such as Suricata) that detected the alert.
      - **Severity**: The potential impact of the alert, indicating urgency.<br><br>
    - For this exercise, we’ll focus on the most prominent alert, indicated by the highest count and severity. To escalate, click the blue icon to the left of the alert and select 'Escalate to new case'
    
    ![Image 3](https://i.imgur.com/lwiBWwt.png)
<br><br>
    ![Image 3](https://i.imgur.com/LiYonOG.png)
<br><br>

  - **Step 3: Assign and Update Case Status**:  
    - With the case created, it's time to take ownership. Click on the binoculars icon to open the case, then select our username from the 'Assignee' dropdown
    - Set the case status to 'In Progress'. This label signals that we have begun investigating the case, a proactive step in the incident response workflow
    
    ![Image 2](https://i.imgur.com/Vu1E5zI.png)
<br><br>
    ![Image 3](https://i.imgur.com/jtOip0E.png)
<br><br>

  Excellent! We have successfully identified a critical alert and initiated a case for it. Documenting and assigning the case is pivotal, as it formalizes our response to the incident. Next, we'll embark on "THE HUNT," where we'll analyze the case details, searching for the tell-tale signs of a cybersecurity threat and piecing together the narrative of the attack.

</details>

<details>
  <summary><h2><b>Section 6: The HUNT</b></h2></summary>

  <details>
  <summary><h3><b>Subsection 6.1: Initiating The Hunt</b></h3></summary>
  
  - **Starting The Hunt**:
    - To initiate the hunt, we navigate to the 'Cases' section within Security Onion to review the incidents.
    - We'll select the 'MALWARE Oski Stealer HTTP POST Pattern' alert and choose the 'Hunt' option. This action allows us to explore further details about the triggered rule and the events associated with it, setting the stage for a deeper investigation.
    
    ![Image 3](https://i.imgur.com/QtEUyBG.png)
<br><br>
  
  - **Observing IP Addresses**:
    - Upon reviewing the detailed events, we take note of the IP addresses associated with the alert. In this case, the local IP `192.168.1.216` has made an HTTP POST request to the external IP `2.56.57.108`. This signifies outbound communication from our network to a potential external threat actor, which requires further examination.
   
    ![Image 3](https://i.imgur.com/jh879C6.png)
<br><br>

  - **IP Reputation Check with AbuseIPDB**:
    - A crucial step in threat hunting is to assess the reputation of the external IP addresses involved. A visit to AbuseIPDB reveals past reports of malicious activities associated with `2.56.57.108`<br><br>
    - We can see that the IP has been listed for various categories of abuse including SMTP brute-force attempts and email spam. This information suggests a pattern of negative behavior associated with the IP.
  
    ![Image 3](https://i.imgur.com/Gpzi8tS.png)
<br><br>

  - **VirusTotal Search**:
    - Next, we'll query VirusTotal for any records related to `2.56.57.108`. This check can show if the IP has been flagged for malicious activities, linking it to known malware campaigns or other suspicious actions.
    
    ![Image 3](https://i.imgur.com/84FM12R.png)
<br><br>

  - **VirusTotal Detection Details**:
    - The details from VirusTotal offer a deeper look at what specific threats the IP has been associated with. This section often lists detections by various security vendors, confirming the IP's involvement in malicious activities.<br><br>
    - The external IP `2.56.57.108` checked on VirusTotal is marked as malicious by multiple security vendors. This underlines the threat it poses, confirming suspicions from our Security Onion alerts.

    ![Image 3](https://i.imgur.com/i3nQqWa.png)
<br><br>

  - **VirusTotal Details Analysis**:
    - When we click on the Details section of the report we can see other information associated with the IP<br><br>
    - Now scroll down and we notice that the IP `2.56.57.108` has been reported in the MalwareBazaar Database along with other threat intelligence feeds
  
    ![Image 3](https://i.imgur.com/xZQX678.png)
<br><br>

    ![Image 3](https://i.imgur.com/mV6SHn9.png)
<br><br>
  
  In this section, we looked into the suspicious IP `2.56.57.108` from our alert. Tools like AbuseIPDB told us this IP was used for brute-force attacks and email spam. VirusTotal also showed us this IP is a known source of malware.  This information sets a foundation for deeper analysis, as we now have evidence linking this IP to potential security threats.
  
  </details>

  <details>
  <summary><h3><b>Subsection 6.2: Deep Dive into Event Correlation</b></h3></summary>

  - **Event Correlation**:
    - We start by correlating the suspicious IP with other events captured in our logs to identify related activities.
    - This step is crucial for establishing a timeline and understanding the scope of the potential threat.
    - If we scroll to the right of the HTTP POST pattern alert, we'll see the `Network Community ID`
    - This ID will gather data from both Zeek and Siricata and put together a timeline of events that were triggered and are associated with this alert
    - We can click on the Network Community ID and choose Only to see all alerts with this particular ID

    ![Image 4](https://i.imgur.com/0b6OqK8.png)
<br><br>

    ![Image 4](https://i.imgur.com/FfrMqtF.png)
<br><br>

  - **Analyzing Communication Patterns**:
    - Next, we analyze the communication patterns between the internal and the suspicious external IP to see if there is any irregularity in the connections
    - Patterns could indicate command and control (C2) communication, data exfiltration, or other malicious activities.
    - We notice that after our local host made the POST request, there's another alert `EXE or DLL Windows file download HTTP`which indicate a download of a possible executable file
    - After that, a `Dotted Quad host MZ response` alert was triggered. This supports the previous alert because the MZ file header is associated with .EXE files

    ![Image 5](https://i.imgur.com/IC7aXzE.png)
<br><br>

  - **Analyzing Alert Details**:<br>
    - Now if we click and expand on the file download alert, we can gather more information including `timestamp`, `source.ip`, `destination.ip`, and `destination.port`, providing context for when and how the communication occurred.<br><br>
    - The event is categorized under `network`, with the `event.dataset` of `suricata.alert`, indicating that this transaction was flagged by our IDS/IPS, Suricata, highlighting the need for closer inspection of the data payload.

    ![Image 5](https://i.imgur.com/2BNYu69.png)
<br><br>

  - **Payload Analysis**:<br>
    - Scrolling down, we can see that in the network data, the file has a `content-type` of an `image/jpeg` but the file header starts with `MZ` which is associated with executables in the Windows enviroment. This is a red flag because adversaries tend to disguise malicious files to pass as harmless ones. This information adds to our case as we investigate further.
  
    ![Image 7](https://i.imgur.com/Hi5UbKH.png)
<br><br>

  - **Suspicious File Transfer**:
    - Scroll down further and we can detect an alert for a zipped file named 'Chrome_Default.txt' being sent from the local IP to the external IP<br><br>
    - The use of compressed files like ZIP is often a strategy used by attackers to evade detection and facilitate the unauthorized transfer of data, known as data exfiltration<br><br>
    - Given the previous suspicious activities associated with the external IP, this transfer raises concerns that sensitive data may be compromised or stolen

    ![Image 6](https://i.imgur.com/zCxWq18.png)
<br><br>

  In Subsection 6.2, our investigation revealed a pattern of unusual network behavior, including the download of files that looked suspicious and an alert for a zipped file being sent to an external IP. This kind of activity often points to cyber threats like malware attacks or data theft. A file that seemed to be an image but was actually an executable file stood out as a red flag. The evidence suggested that our network might be at risk, emphasizing the importance of prompt action to check for any damage or data loss.

  </details>

    
</details>








## __Conclusion__

This project successfully demonstrates the creation of a virtual SOC environment using Security Onion, Wireshark, and various OSINT tools. The hands-on experience gained in analyzing malware traffic and employing OSINT techniques provides valuable insights into the world of network security and threat intelligence.

</details>




