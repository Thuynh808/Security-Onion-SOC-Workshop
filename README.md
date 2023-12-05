# Security-Onion-SOC-Workshop


  ![Image 2](https://i.imgur.com/mObZonw.png)
<br><br>

## Objective

The goal of this project is to integrate an Ubuntu Server (`UbuntuServer00`) into an existing Active Directory environment (`Streetrack.com`). This will enable centralized management of user credentials, enhanced security, and a seamless user experience. <br><br>

## Components

- **VirtualBox**: For creating and running virtual machines
- **Windows Server 2019 (DC)**: Serves as the Domain Controller for the `Streetrack.com` domain
- **Ubuntu Server 20.04.3**: To be integrated into the Active Directory environment
- **SSH**: Secure Shell for remote management of Ubuntu Server
- **PAM**: Pluggable Authentication Module for Unix/Linux authentication
- **SSSD**: System Security Services Daemon for AD integration
- **Kerberos**: For secure authentication between Ubuntu Server and AD
- **Net-tools**: Network utilities for network troubleshooting and configuration

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

<details>
  <summary><h2><b>Section 3: Initial Server Updates and Installing net-tools</b></h2></summary>
  After installing Ubuntu Server, we'll ensure that it's up to date and install additional network tools for troubleshooting and configuration.<br><br>

  - **Step 1: Log in to the Ubuntu Server**:  
    Use the username and password created during the installation to log in.<br><br>

  ![Image 2](https://i.imgur.com/9o0oH2z.png)
<br><br>
  
  - **Step 2: Update the System**:  
    Run the following command to update the package list and install the latest versions.
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

  - **Step 3: Install net-tools**:  
    Run the following command to install net-tools, which provide network troubleshooting and configuration utilities.
    ```bash
    sudo apt install net-tools
    ```

</details>

<details>
  <summary><h2><b>Section 4: Accessing UbuntuServer00 via SSH from Domain Controller</b></h2></summary>
  Now that our server is updated and equipped with necessary tools, let's establish a secure SSH connection to it from the Domain Controller. 
 <br><br>

  - **Step 1: Confirm Server IP Address**:   
    Run `ifconfig` on `UbuntuServer00` to display the network details and confirm its IP address.<br><br>
    ```bash
    ifconfig
    ```
    
  ![Image 2](https://i.imgur.com/5zVVujx.png)
<br><br>
  
  - **Step 2: SSH from Domain Controller**:   
    Open the Command Prompt on the Domain Controller.
    Use the `ssh` command to initiate a connection to `UbuntuServer00`.
    ```bash
    ssh thuynh808@10.2.22.104
    ```
    
  - **Step 3: Accept Host Key and Complete Connection**: <br>
    Upon connecting for the first time, we'll be prompted to accept the host key. Verify the fingerprint, type (`yes`) and press Enter.
    
  - **Step 4: Enter Password**: <br>
    After accepting the host key,  we'll input the password we created for `UbuntuServer00`. <br>

  ![Image 2](https://i.imgur.com/QC9nIrz.png)
<br><br>
  
  Great! we were able to successfully SSH from the `DC` into our `Ubuntuserver00`

</details>

<details>
  <summary><h2><b>Section 5: Setting Date, Time, and Time Zone</b></h2></summary>
  To ensure accurate time synchronization within the domain, we'll set the date, time, and time zone for the `Ubuntuserver00` <br><br>

  - **Step 1: Switch to Root User**: <br>
    Switch to the root user to have the necessary permissions for changing the date, time, and time zone. <br>
    ```bash
    sudo su -
    ```
    <br>
    
  - **Step 2: Set Date and Time Manually**: <br>
    Set the date and time manually using the `date` command. Replace `YYYY-MM-DD` with the matching date and `HH:MM:SS` with the same time in 24-hour format as our `DC` Domain Controller. <br>
    ```bash
    date -s "YYYY-MM-DD HH:MM:SS"
    ```
    
  ![Image 2](https://i.imgur.com/wjqIdjr.png)
<br><br>
    
  - **Step 3: Set Time Zone to US/Hawaii**: <br>
    Change the system's time zone to "US/Hawaii" using the `timedatectl` command. <br><br>
    ```bash
    timedatectl set-timezone US/Hawaii
    ```

  ![Image 2](https://i.imgur.com/hUOUyhh.png)
<br><br>
    
  - **Step 4: Verify Domain Time Sync**: <br>
    Verify if the time on our Ubuntu server is synced with the domain controller's time <br><br>
    ```bash
    date
    ```

  ![Image 2](https://i.imgur.com/yixlaxk.png)
<br><br>

  So far so good! We've confirmed that both the `DC` and `Ubuntuserver00` are time synced. Matching the time between them is crucial for smooth and secure communication, accurate event recording, and reliable authentication within the network.
  
</details>

<details>
  <summary><h2><b>Section 6: Installing Packages for Active Directory Integration</b></h2></summary>
  <br>

  In this section, we'll be installing the required packages that are essential for integrating UbuntuServer00 into the Active Directory domain.

  - **Step 1: Install Packages**:  
    Open a terminal on `UbuntuServer00`.

    Run the following command to install the necessary packages for Active Directory integration:
    ```bash
    sudo apt install sssd-ad sssd-tools realmd packagekit krb5-user adcli
    ```
  <br>
    
  - **Step 2 : Kerberos Default Realm**: <br>
    Set Kerberos Authentication Default Realm: `STREETRACK.COM`

  ![Image 2](https://i.imgur.com/4MaKeNT.png)
<br><br>

  Setting the Kerberos version 5 realm defines a secure space where users and systems can authenticate and access resources within our network. Kerberos will be authenticating our Active Directory users. It will use a system of encrypted tickets to verify users. 

</details>

<details>
  <summary><h2><b>Section 7: Active Directory Integration Process</b></h2></summary>
  <br>

  In this section, we'll discover the Active Directory domain and join it using the packages we installed earlier. Joining the domain will enable access to domain resources. We will also configure package files for proper authentication. 

  - **Step 1: Discover the Domain**: <br>
    Run the command to discover the Active Directory domain: <br><br>
    ```bash
    sudo realm discover STREETRACK.COM
    ```
    This command will provide information about the Active Directory realm, such as its domain controllers and supported authentication mechanisms.
    
  ![Image 2](https://i.imgur.com/ozoacBJ.png)
<br><br>

  - **Step 2: Join the Domain**:  <br>
    Run the following command to join the Ubuntu Server to the Active Directory domain: <br><br>
    ```bash
    sudo realm join -v STREETRACK.COM
    ```
    We'll then input our domain Administrator password
        
  ![Image 2](https://i.imgur.com/P9C7poE.png)
<br><br>

  - **Step 3: Verify the Joining**:  <br>
    After successful domain joining, we can verify it using the following command: <br><br>
    ```bash
    sudo realm list
    ```
    This should display the details of the joined domain, including its name, domain controller, and configured realm.
    We can also check our DC's Active Directory Users and Computers and verify `UBUNTUSERVER00` under Computers.

  ![Image 2](https://i.imgur.com/dGsl7DW.png)
<br><br>

  ![Image 2](https://i.imgur.com/rmzK7lB.png)
<br><br>

  - **Step 4: Update PAM Configuration**:  <br>
    Run the following command to update the Pluggable Authentication Module (PAM) configuration: <br><br>
    ```bash
    sudo nano /etc/pam.d/common-session
    ```
    We're going to add an entry: <br><br>
    ```bash
    session optional    pam_mkhomedir.so
    ```
    This configuration will auto create a home directory for a user's first time log in.
            
  ![Image 2](https://i.imgur.com/uF75hfi.png) 
<br><br>
    Save and Exit with: <br>
    ```
    Ctrl + O , Enter , Ctrl + X
    ```
<br><br>

  - **Step 5: Update krb5.conf**: <br>
    Run the following command to update the krb5.conf file: <br><br>
    ```bash
    sudo nano /etc/krb5.conf
    ```
    Here we'll add 4 entries:
      - udp_preference_limit = 0
      - rdns = False
      - dns_lookup_kdc = True
      - dns_lookup_realms = True
        
  ![Image 2](https://i.imgur.com/5UatQaW.png) 
<br><br>
    Save and Exit with: <br>
    ```
    Ctrl + O , Enter , Ctrl + X
    ```
<br><br>

  - **Step 6: Update SSSD Service**: <br>
    The following command will let us update the System Security Servicess Daemon (SSSD): <br><br>
    ```bash
    sudo nano /etc/sssd/sssd.conf
    ```
    Here we'll add 2 entries and make sure everything else is there also:
      - krb5_keytab = /etc/krb5.keytab
      - ldap_keytab_init_creds = True
        
  ![Image 2](https://i.imgur.com/wXxUeWw.png) 
<br><br>
    Save and Exit with: <br>
    ```
    Ctrl + O , Enter , Ctrl + X
    ```
<br><br>
  - **Step 7: Restart SSSD Service**: <br>
    After updating the configuration, restart the System Security Services Daemon (SSSD) for changes to take effect and check its status to make sure its configured properly: <br><br>
    ```bash 
    sudo systemctl restart sssd
    ```
    ```bash
    sudo systemctl status sssd
    ```
 <br><br>
  ![Image 2](https://i.imgur.com/9gH2Vi0.png) 
<br><br>
  ![Image 2](https://i.imgur.com/83bzxUW.png) 
<br><br>

  We can see that we've joined the realm with entries to the KEYTAB and SSSD is restarted and enabled. 

</details>

<details>
  <summary><h2><b>Section 8: Verifying Active Directory Authentication</b></h2></summary>
  <br>

  To ensure that Active Directory authentication is working properly, we will perform the following steps:

  - **Step 1: Logging in with Domain Admin Account:**
    Log in to the Ubuntu Server (`UbuntuServer00`).
    We'll use our Active Directory domain admin credentials to log in: <br><br>
    ```bash
    sudo login thuynh@streetrack.com
    ```
    ![Image 2](https://i.imgur.com/cjIehEF.png) 
<br><br>
    Great! We're in! Now let's confirm that we were issued a kerberos ticket for authentication:
    
    ```bash
    klist
    ```
    ![Image 2](https://i.imgur.com/v3WfENe.png) 
<br><br>

    Looks like our ticket has been issued for us!

  - **Step 2: Adding Domain Admin to sudoers List:**
    To allow our domain admin to execute administrative commands, we'll add the domain admin to the `sudoers` list using the `visudo` command.
    ```bash
    sudo visudo
    ```
    
    ```plaintext
    thuynh ALL=(ALL:ALL) ALL
    ```
    ![Image 2](https://i.imgur.com/8pbfgra.png) 
<br><br>

    Save and exit the editor.
   
    Here we've confirmed that (`thuynh@Streetrack.com`) has sudo priveleges. <br><br>
    
    ![Image 2](https://i.imgur.com/w01L2k0.png) 
<br><br>

  - **Step 3: Log Out and Log In with Regular AD User:** <br><br>
    Log out from the current session with the domain admin account.
    ```bash
    exit
    ```
    Log in again using a different Active Directory user account to verify that general AD users can also authenticate and access the server.
    ```bash
    su - pcoulson@streetrack.com
    ```
    ![Image 2](https://i.imgur.com/VW2yr4A.png) 
<br><br>

    Excellent! We did it! We now have integrated an `ubuntuserver00` with our `Streetrack.com` domain!!

</details>

## __Conclusion__
  
  In conclusion, our successful integration of Ubuntu Server into the Active Directory domain showcases our prowess in bridging diverse systems. Thanks to Kerberos and Active Directory LDAP authentication is seamless, enhancing security and user interaction. This success reflects our preparedness for intricate IT landscapes, propelling us forward on our journey.


</details>

