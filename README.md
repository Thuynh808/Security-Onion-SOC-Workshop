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
  This section covers the setup of the virtual environment using VirtualBox, including the configuration of a NAT network and the installation of virtual machines.<br><br>

  - **Step 1: Download Security Onion ISO File**:  
    Go to Security Onion's GitHub page and download the ISO file.

  ![Image 2](https://i.imgur.com/uookvCd.png)
<br><br>
    
  - **Step 2: Create a New Virtual Machine in VirtualBox**:  
    Here we will create a new virtual machine in VirtualBox for the Security Onion.<br>

    - Base Memory: About 8 gb<br>
    - Processors: 3 cores
    - Hard Disk storage: 200 gb

  ![Image 2](https://i.imgur.com/KQ3TE5g.png)
<br><br>

    

  ![Image 2](https://i.imgur.com/JZIiCYe.png)
<br><br>

    

  ![Image 2](https://i.imgur.com/FYk1M4y.png)
<br><br>
       
  - **Step 3: Create a New Windows VM**:  
    Set up a Windows virtual machine for accessing Security Onion, OSINT, and other security tasks.<br>

    - Base Memory: About 8 gb<br>
    - Processors: 3 cores<br>
    - Hard Disk storage: 50 gb<br><br>

  - **Step 4: Create a NAT Network in VirtualBox**:  
    Here we will create a NAT Network in VirtualBox for our Security Onion and Windows VM<br>
    - Go to File > Tools > And choose Network Manager

  ![Image 2](https://i.imgur.com/EseCdCy.png)
<br><br>

  -  
    - Click on NAT Networks and set the Name and IP subnet: 
    - Name: NatNetwork
    - IPv4 Prefix: 10.2.22.0/24

  ![Image 2](https://i.imgur.com/oqxJmkH.png)
<br><br>

  - **Step 5: Configure Network Settings for Both VMs**:  
    - Go to each vm and click on Settings > Network > Set the following: <br>
    - Attached to: NAT Network
    - Name: NatNetwork

  ![Image 2](https://i.imgur.com/c89c24P.png)
<br><br>

  Excellent! We've just finished creating our Network and And Virtual Machines for this lab. Next is setting up the Security Onion operating system.
    

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
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  ![Image 2](https://i.imgur.com/lCRnaTj.png)
<br><br>
  


</details>


<details>
  <summary><h2><b>Section 2: Network Monitoring and Analysis</b></h2></summary>
  In this section, we dive into the use of Security Onion and Wireshark for monitoring and analyzing network traffic.<br><br>

  - **Step 1: Configuring Security Onion**:  
    Initial configuration and setup of Security Onion for capturing and analyzing network traffic.

  - **Step 2: Analyzing Traffic with Wireshark**:  
    Using Wireshark to inspect the PCAP file and understand the nature of the malware traffic.<br><br>

</details>

<details>
  <summary><h2><b>Section 3: Utilizing OSINT and Online Tools</b></h2></summary>
  This section focuses on leveraging the Windows VM for OSINT and using online tools like AbuseIPDB and VirusTotal for deepening the analysis.<br><br>

  - **Step 1: OSINT Techniques**:  
    Employing OSINT methods on the Windows VM to gather additional information about the malware and its origins.

  - **Step 2: Using AbuseIPDB and VirusTotal**:  
    Utilizing AbuseIPDB to check for reported malicious activities of IPs and VirusTotal for analyzing suspicious files and URLs.<br><br>

</details>

## __Conclusion__

This project successfully demonstrates the creation of a virtual SOC environment using Security Onion, Wireshark, and various OSINT tools. The hands-on experience gained in analyzing malware traffic and employing OSINT techniques provides valuable insights into the world of network security and threat intelligence.

</details>

<details>
  <summary><h2><b>Section 1: Pre-Installation Checks</b></h2></summary>
  Before beginning the installation process, we need to perform some preliminary checks to ensure a smooth setup.<br><br>

  - **Step 1: Validate Domain Controller (DC) Settings**:  
    Ensure that the Windows Server 2019 Domain Controller is up and running.
    Validate that DHCP and DNS services are functional on the DC.

  - **Step 2: Confirm Network Interface Card (NIC) Settings**:  
    On `UbuntuServer00`, set the NIC to "Internal Network".
    Make sure it aligns with the DC's internal network settings.<br><br>

  ![Image 2](https://i.imgur.com/4gJND4G.png)
<br><br>

</details>

<details>
  <summary><h2><b>Section 2: Installing UbuntuServer00</b></h2></summary>
  In this section, we will go through the installation process for Ubuntu Server and prepare it for integration with the Active Directory environment.<br><br>
  
  - **Step 1: Begin Installations**:  
    Boot up the `UbuntuServer00` VM from the ISO images and start the installation process.<br><br>

  ![Image 2](https://i.imgur.com/7QGI7d9.png)
<br><br>

  - **Step 2: Network Connections**:  
    During the installation, reach the "Network Connections" section.
    Ensure that we are provided an IP within the range of the DC, which is between `10.2.22.100-200`.
    In this example, we were allocated the IP `10.2.22.104`.<br><br>

  ![Image 2](https://i.imgur.com/2woJCXg.png)
<br><br>
  
  - **Step 3: Profile Setup**:  
    Here we will setup our profile:
      - Your name: Thong Huynh
      - Your server's name: ubuntuserver00
      - Pick a username: thuynh808
      - Password: ************<br><br>

  ![Image 2](https://i.imgur.com/xZXu4zn.png)
<br><br>

  - **Step 3: SSH Setup**:  
    Proceed to the SSH setup and select "Install OpenSSH server".<br><br>

  ![Image 2](https://i.imgur.com/PqhsFd1.png)
<br><br>

  - **Step 4: Complete Installation and Login**:  
    Once the installation is completed, select "Reboot Now".
    After the system reboots, press Enter, and the login prompt will appear.<br><br>

  ![Image 2](https://i.imgur.com/PSbLdjt.png)
<br><br>

  Awesome! We've successfully installed UbuntuServer00!

</details>


