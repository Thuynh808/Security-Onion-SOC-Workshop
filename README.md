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



## __Conclusion__

This project successfully demonstrates the creation of a virtual SOC environment using Security Onion, Wireshark, and various OSINT tools. The hands-on experience gained in analyzing malware traffic and employing OSINT techniques provides valuable insights into the world of network security and threat intelligence.

</details>




