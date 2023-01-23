from email.policy import default
#from typing_extensions import ParamSpecKwargs
from netmiko import Netmiko
import paramiko
from getpass import getpass
import datetime
import pexpect
import pexpect.popen_spawn
import wexpect
import os
import csv
import time
import re
from pathlib import Path
import sys

"""

Set the following Windows environment variables prior to running:

upsStandardPassword
upsNewPassword
upsSNMPv3auth
upsSNMPv3priv
radiusSecret


You can set the desired values in your OS's environment variables to keep them out of the script.

Alternatively, you can comment out the section where the variables are set by getting the OS environment variables and instead use the section below it to
prompt for each of the values.


Once this script is run against all the UPSes (and assuming it was successful) the value for upsStandardPassword should be changed to match the value
of upsNewPassword. The next time the password is rotated, upsNewPassword should be updated before this script is run.

For example, if the current standard password is "12345" then the value of upsStandardPassword should be set to "12345"
If the password is being rotated to "ABCDEF" then the value of upsNewPassword should be set to "ABCDEF"
Once the script is run, the value of upsStandardPassword should be set to "ABCDEF" making both variables the same value. Then the next time the password
is to be rotated, upsNewPassword is set to the new password and this script is run.

This script is intended to be run against APC Smart-UPS units with a Network Management Card 2 installed that have either been factory reset or are brand new. 
These commands may work against other models of APC UPS or even PDUs, but this script specifically was not written for them. If you want to do the same things 
in this script to a different APC platform, you should copy this script to a new script and make the necessary modifications for the target platform. Since 
this script is only being tested against the Smart-UPS platform with an NMC2 module installed, I cannot guarantee its functionality on any other platform. 

USE AT YOUR OWN RISK

"""

def firstLoginAttempt(ups, upsIP, username, defaultPassword, standardPassword, newPassword, passwordStatus, prompt="apc>"):
    """
    Define variables
    """
    usingCurrentStdPW = False
    firstLogin = False
    usingNewStdPW = False
    usingDefaultPW = False

    print(ups + " Checking if this is the first login...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Checking if this is the first login...\n")
    with wexpect.spawn(f"ssh -o StrictHostKeyChecking=no {username}@{upsIP}", timeout=10, encoding="utf-8") as ssh:
    #   ssh.logfile = sys.stdout        # Uncomment this for debugging
        ssh.expect("password")
        ssh.sendline(defaultPassword)
        firstLogin = ssh.expect(['The current password policy requires you to change your password', 'denied', prompt, wexpect.TIMEOUT])
        if firstLogin == 0:
            firstLogin = True
            print(ups + ", First Time Login, setting password\n")
            ssh.sendline(defaultPassword)
            ssh.expect("Enter new password:")
            ssh.sendline(newPassword)
            time.sleep(0.5)
            ssh.sendline(newPassword)
            ssh.expect(prompt)
            file.write(ups + ", First Time Login, setting password\n")
            usingNewStdPW = True
        elif firstLogin == 1:
            firstLogin = False
            ssh.sendline(standardPassword)
            stdMatch = ssh.expect([prompt, 'denied'])
            if stdMatch == 0:
                usingCurrentStdPW = True
                print(ups + " is using the current standard password\n")
                file.write(ups + " is using the current standard password\n")
            else:
                ssh.sendline(newPassword)
                newMatch = ssh.expect([prompt, "denied"])
                if newMatch == 0:
                    usingNewStdPW = True
                    print(ups + " is using the new standard password\n")
                    file.write(ups + " is using the new standard password\n")
                else:
                    print("ERROR: " + ups + " is using an unknown password\n")
                    file.write(ups + " is using an unknown password\n")
        elif firstLogin == 2:
            usingDefaultPW = True
            print(ups + " is using the default password\n")
            file.write(ups + " is using the default password\n")
        else:
            #print(ssh.read())      # Uncomment this for debugging
            print("ERROR: " + ups + " connection timed out\n")
            file.write("ERROR: " + ups + " connection timed out\n")
        file.close()
        ssh.close()

        passwordStatus['firstTime'] = firstLogin
        passwordStatus['currentStdPW'] = usingCurrentStdPW
        passwordStatus['newStdPW'] = usingNewStdPW
        passwordStatus['defaultPW'] = usingDefaultPW
        return passwordStatus

def standardizePassword(ups, upsIP, username, currentPassword, newPassword, prompt="apc>"):
    print(ups + " Standardizing password...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Standardizing password...\n")
    
    with wexpect.spawn(f"ssh {username}@{upsIP}", timeout=10, encoding="utf-8") as ssh:
    #   ssh.logfile = sys.stdout        # Uncomment this for debugging
        ssh.expect("password:")
        ssh.sendline(currentPassword)
        ssh.expect(prompt)
        ssh.sendline("user -n apc -cp " + currentPassword + " -pw " + newPassword + "\r") # Have to add carriage return due to terminal width limitation
        ssh.expect("Success")
        usingNewStdPW = True
        print(ups + " Standardized password\n")
        file.write(ups + " Standardized password\n")
        file.close()
        ssh.close()
        return usingNewStdPW

def deleteUsername(ups, upsIP, username, password):
        print(ups + ", Deleting \"device\" user...\n")
        myDevice = {
			'host': upsIP,
			'username': username,
			'password': password,
			'device_type': 'cisco_ios',
			}
        net_connect = Netmiko(**myDevice)
        userNameList = net_connect.send_command('user -l')
        for line in userNameList.splitlines():
            if line [0:6] == "device":
                net_connect.send_command("user -del device")
                print(ups + ", Deleted device user\n")
                file = open("ups_log.txt", "a")
                file.write(ups + ", Deleted device user\n")
                file.close()
                net_connect.disconnect()
                time.sleep(2.5)     # Sometimes deleting this user after changing the superuser password causes a reboot, so we wait
                return(True)
                

def configureRadius(ups, upsIP, username, password, radiusSecret):
    print(ups + ", Configuring RADIUS...\n")
    radiusCommands = ["radius -a radiusLocal ", 
    "radius -p1 X.X.X.X ", 
    "radius -o1 1812 ", 
    "radius -s1 " + radiusSecret + " ", 
    "radius -t1 30 ", 
    "radius -p2 X.X.X.X ", 
    "radius -o2 1812 ", 
    "radius -s2 " + radiusSecret + " ", 
    "radius -t2 30 "]

    myDevice = {
			'host': upsIP,
			'username': username,
			'password': password,
			'device_type': 'cisco_ios',
			}
    net_connect = Netmiko(**myDevice)
    radiusConfig = net_connect.send_command('radius')
    for line in radiusConfig.splitlines():
        if "0.0.0.0" in line:
            for command in radiusCommands:
            #   print(command)      # Uncomment this for debugging
                net_connect.write_channel(command + "\r")
                time.sleep(0.5)
            print("\n" + ups + ", Configured RADIUS\n")
            file = open("ups_log.txt", "a")
            file.write("\n" + ups + ", Configured RADIUS\n")
            file.close()
            net_connect.disconnect()
            return(True)

def checkRadius(ups, upsIP, username, password):
    print(ups + " Checking RADIUS with " + username + "...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Checking RADIUS with " + username + "...\n")
    prompt = "apc>"
    with wexpect.spawn(f"ssh -o StrictHostKeyChecking=no {username}@{upsIP}", timeout=10, encoding="utf-8") as ssh:
    #   ssh.logfile = sys.stdout        # Uncomment this for debugging
        ssh.expect("password")
        ssh.sendline(password)
        stdMatch = ssh.expect([prompt, 'denied'])
        if stdMatch == 0:
            print(ups + " RADIUS check successful\n")
            file.write(ups + " RADIUS check successful\n")
            file.close()
            ssh.close()
            return(True)
        else:
            print("ERROR: " + ups + " RADIUS check unsuccessful\n")
            file.write("ERROR: " + ups + " RADIUS check unsuccessful\n")
            file.close()
            ssh.close()
            return(False)
        

def configureNetworkSettings(ups, upsIP, username, password, sysName, sysDomain):
    print(ups + " Configuring remaining network settings - NTP and hostname...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Configuring remaining network settings - NTP and hostname...\n")
    networkCommands = ['tcpip -d ' + sysDomain, 'tcpip -h ' + sysName, 'ntp -e enable', 'ntp -p ntp1.' + sysDomain, 'ntp -s ntp2' + sysDomain, 'ntp -u']
    myDevice = {
			'host': upsIP,
			'username': username,
			'password': password,
			'device_type': 'cisco_ios',
			}
    net_connect = Netmiko(**myDevice)
    for command in networkCommands:
    #   print(command)      # Uncomment this for debugging
        net_connect.write_channel(command + "\r")
        time.sleep(0.5)
    print("\n" + ups + " Configured network settings\n")
    file.write("\n" + ups + " Configured network settings\n")
    file.close()
    net_connect.disconnect()

def configureSystemSettings(ups, upsIP, username, password, sysName, sysLocation, emailDomain):
    print(ups + " Configuring system settings...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Configuring system settings...\n")
    systemCommands = ['system -s enable', 
    'system -n ' + sysName, 
    'system -c example@' + emailDomain, 
    'system -l "' + sysLocation + '"',
    'prompt -s long']
    myDevice = {'host': upsIP, 'username': username, 'password': password, 'device_type': 'cisco_ios',}
    net_connect = Netmiko(**myDevice)
    for command in systemCommands:
    #   print(command)      # Uncomment this for debugging
        net_connect.write_channel(command + "\r\r")
        time.sleep(0.5)
    print("\n" + ups + " Configured system settings\n")
    file.write("\n" + ups + " Configured system settings\n")
    file.close()
    net_connect.disconnect()

def configureEmailSettings(ups, upsIP, username, password, sysName, emailDomain):
    print(ups + " Configuring email settings...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Configuring email settings...\n")
    emailCommands = ['smtp -f ' + sysName + '@' + emailDomain, 
    'smtp -s smtp.example.com', 'smtp -p 25', 
    'email -g1 enable', 
    'email -t1 apc-alerts@' + emailDomain, 
    'email -o1 long', 
    'email -l1 enUs', 
    'email -r1 local']
    myDevice = {'host': upsIP, 'username': username, 'password': password, 'device_type': 'cisco_ios',}
    net_connect = Netmiko(**myDevice)
    for command in emailCommands:
    #   print(command)      # Uncomment this for debugging
        net_connect.write_channel(command + "\r")
        time.sleep(0.5)
    print("\n" + ups + " Configured email settings\n")
    file.write("\n" + ups + " Configured email settings\n")
    file.close()
    net_connect.disconnect()

def configureSNMPSettings(ups, upsIP, username, password, upsSNMPv3user, upsSNMPv3auth, upsSNMPv3priv):
    print(ups + " Configuring SNMP settings...\n")
    file = open("ups_log.txt", "a")
    file.write(ups + " Configuring SNMP settings...\n")
    snmpCommands = ['snmpv3 -S enable', 
    'snmpv3 -u1 ' + upsSNMPv3user, 
    'snmpv3 -a1 ' + upsSNMPv3auth, 
    'snmpv3 -c1 ' + upsSNMPv3priv, 
    'snmpv3 -ap1 md5', # Change as necessary
    'snmpv3 -pp1 des', # Change as necessary
    'snmpv3 -ac1 enable', 
    'snmpv3 -au1 ' + upsSNMPv3user, 
    'snmpv3 -n1 X.X.X.X', # Add IP of SNMP monitoring host
    'snmpv3 -ac2 enable', 
    'snmpv3 -au2 ' + upsSNMPv3user, 
    'snmpv3 -n2 X.X.X.X'] # Add IP of SNMP monitoring host
    myDevice = {'host': upsIP, 'username': username, 'password': password, 'device_type': 'cisco_ios',}
    net_connect = Netmiko(**myDevice)
    for command in snmpCommands:
    #   print(command)        # Uncomment this for debugging
        net_connect.write_channel(command + "\r\r")
        time.sleep(0.5)
    print("\n" + ups + " Configured SNMP settings\n")
    file.write("\n" + ups + " Configured SNMP settings\n")
    file.close()
    net_connect.disconnect()
    # Disconnecting triggers the necessary reboot to apply settings but not immediately, wait in function before exiting
    time.sleep(7)

username = "apc"
# If necessary, a RADIUS service account that can be used to perform the necessary configurations once RADIUS is enabled
serviceUsername = "exampleServiceAccount"
defaultPassword = "apc" # Default NMC account password
upsSNMPv3user = "exampleUser"
emailDomain = "example.com"
sysDomain = "example.local" # This would be your AD domain probably, it may be the same as emailDomain. If so, uncomment next line and comment this one
# sysDomain = emailDomain

# Get passwords from environment variables. Comment out this section to prompt the user for passwords instead
standardPassword = os.environ.get('upsStandardPassword')
newPassword = os.environ.get('upsNewPassword')
upsSNMPv3auth = os.environ.get('upsSNMPv3auth')
upsSNMPv3priv = os.environ.get('upsSNMPv3priv')
radiusSecret = os.environ.get('radiusSecret')

"""
# Alternatively, prompt user to input passwords. Uncomment this section to use this method

print("Provide current standard password for UPS local account:")
standardPassword = getpass()
print("Provide new standard password for UPS local account:")
newPassword = getpass()
print('Provide auth password for SNMP account ' + upsSNMPv3user + ':')
upsSNMPv3auth = getpass()
print('Provide priv password for SNMP account ' + upsSNMPv3user + ':')
upsSNMPv3priv = getpass()
print("Provide RADIUS secret key:")
radiusSecret = getpass()
"""

print("Provide password for account " + serviceUsername + ":")
servicePassword = getpass()
usingDefaultPW = False
usingCurrentStdPW = False 
usingNewStdPW = False

passwordStatus = dict()
passwordStatus['firstTime'] = False
passwordStatus['currentStdPW'] = False
passwordStatus['newStdPW'] = False
passwordStatus['defaultPW'] = False
                

def main ():

    with open('ups_list_rerun.csv') as csvfile:
        upslist = csv.reader(csvfile, delimiter=',', quotechar='|')
        next(upslist)

        for row in upslist:
            upsIP = row[0]
            sysName = row[1]
            sysLocation = row[2]

            ups = sysName + ' (' + upsIP + ')'

            try:
                myDevice = {
                    'host': upsIP,
                 	'username': serviceUsername,
                 	'password': servicePassword,
                 	'device_type': 'cisco_ios',
                }
                print(ups)
                print("Logging in now...")
                
                firstLoginAttempt(ups, upsIP, username, defaultPassword, standardPassword, newPassword, passwordStatus)
                """
                Check for which password a given UPS was already using, add to log file and print to console
                """
                if passwordStatus["defaultPW"] == passwordStatus['currentStdPW'] == passwordStatus['newStdPW'] == False:
                    print(ups + ' is using an unknown password\n')
                    file = open("ups_log.txt", "a")
                    file.write(ups + ' is using an unknown password\n')
                    file.close()
                    raise Exception(ups + ' is using an unknown password')
                elif passwordStatus['newStdPW'] != True:
                    if passwordStatus["currentStdPW"] == True:
                        currentPassword = standardPassword
                        print(ups + ' is using the current standard password\n')
                        file = open("ups_log.txt", "a")
                        file.write(ups + ' is using the current standard password\n')
                        file.close()
                    elif passwordStatus["defaultPW"] == True:
                        currentPassword = defaultPassword
                        print(ups + ' is using the default password\n')
                        file = open("ups_log.txt", "a")
                        file.write(ups + ' is using the default password\n')
                        file.close()
                    usingNewStdPW = standardizePassword(ups, upsIP, username, currentPassword, newPassword)
                    if usingNewStdPW == True:
                        currentPassword = newPassword
                        print(ups + ' is now using the new standard password\n')
                        file = open("ups_log.txt", "a")
                        file.write(ups + ' is now using the new standard password\n')
                        file.close()
                    else:
                        print('Could not set password for ' + ups + '\n')
                        file = open("ups_log.txt", "a")
                        file.write('Could not set password for ' + ups + '\n')
                        file.close()
                else:
                    currentPassword = newPassword
                    print(ups + ' is already using the new standard password\n')
                    file = open("ups_log.txt", "a")
                    file.write(ups + ' is already using the new standard password\n')
                    file.close()

                userExisted = deleteUsername(ups, upsIP, username, currentPassword)
                if userExisted != True:
                    file = open("ups_log.txt", "a")
                    file.write(ups + ", device User does not exist\n")
                    file.close()
                """
                Sometimes the NMC reboots after standardizing the password and then deleting the "device" user. Add a wait period
                to allow for the device to finish rebooting.
                """
                print("Sometimes the NMC reboots after standardizing the password and then deleting the \"device\" user. Waiting for reboot...\n")
                time.sleep(25)
                radiusSet = configureRadius(ups, upsIP, username, currentPassword, radiusSecret)
                if radiusSet == True:
                    # try logging in with service account, if access denied RADIUS is not set, or set incorrectly
                    if checkRadius(ups, upsIP, serviceUsername, servicePassword) == False:
                        print("ERROR: Verify RADIUS configuration for " + ups + "\n")
                        file = open("ups_log.txt", "a")
                        file.write("ERROR: Verify RADIUS configuration for " + ups + "\n")
                        file.close()

                configureNetworkSettings(ups, upsIP, serviceUsername, servicePassword, sysName, sysDomain)
                configureSystemSettings(ups, upsIP, serviceUsername, servicePassword, sysName, sysLocation, emailDomain)
                configureEmailSettings(ups, upsIP, serviceUsername, servicePassword, sysName, emailDomain)
                configureSNMPSettings(ups, upsIP, serviceUsername, servicePassword, upsSNMPv3user, upsSNMPv3auth, upsSNMPv3priv)
                print("Exiting after SNMP changes triggers reboot, waiting for reboot to finish...\n")
                time.sleep(30)
                print("Attempting to log in with service account " + serviceUsername + "...\n")
                net_connect = Netmiko(**myDevice)
                if serviceUsername + '@apc>' in net_connect.find_prompt():
                    print("Log in successful\n")
                    print("Completed configuration for " + ups + " successfully!\n")
                else:
                    print("ERROR: Log in unsuccessful\n")
                    print("Completed configuration for " + ups + ", check management connectivity\n")
                net_connect.disconnect()
                
            except:
                print("Login failed on: ", ups)
                file = open("ups_log.txt", "a")
                file.write(ups + ", Could not login\n")
                file.close()
                continue

main()