#!/usr/bin/env python
import os
import requests
import json
import sys
import logging
from logging import handlers
import boto,boto.ec2
from sys import exit


class AWSInventory:
    appliances = [];
    applianceList = 'appliances.txt';
    windowsHosts = [];
    linuxHosts = [];
    applianceHosts = [];

    def __init__(self): 
        self.region = 'us-east-1'
        #appliances is a list private IPs of appliances loaded from the file.
        self.appliances = []
        self.applianceList = 'appliances.txt'
        self.windowsHosts = [];
        self.linuxHosts = [];
        self.applianceHosts = [];
        self.ec2conn = None;
        
    def set_aws_region(self, region):
        self.region = region
        
    def aws_ec2_inventory(self):
        # This function connects to EC2 in the defined region and pulls all EC2 instances
        # with the exception of terminated instances. Each instance is then categorized as an
        # appliance, windows hosts, or linux host. Appliances are identified via listing in a
        # provided appliances exception list. Instances with a platform value of Windows are
        # marked as Windows hosts, all hosts not in the appliances list or having Windows as
        # the platform are marked as Linux hosts

        self.windowsHosts = []
        self.linuxHosts = []
        self.applianceHosts = []
        self.ec2conn = None;
        
        try:
            appliances = [line.rstrip() for line in open(self.applianceList)]
        except Exception as e:
            #logger.error("Error while attempting to read appliances host list. Error is: {0}".format(e))
            print ("Error while attempting to read appliances host list. Error is: {0}".format(e))
            print "Error reading appliances host exclusion list. See /var/log/messages for more detail"
            sys.exit()

        try:
            self.ec2conn = boto.ec2.connect_to_region(self.region)
        except Exception as e:
            #logger.error("Error while connecting to Ec2 to download inventory. Error is: {0}".format(e))
            print ("Error while connecting to Ec2 to download inventory. Error is: {0}".format(e))
            print "Error connecting to EC2 to download inventory. See /var/log/messags for more detail"
            sys.exit()

        reservations = self.ec2conn.get_all_reservations(filters={'instance-state-name': ['pending','running','shutting-down','stopping','stopped']})
        for reservation in reservations:
            for instance in reservation.instances:
                platform = instance.platform
                privateIP = instance.private_ip_address
                if privateIP in appliances:
                    self.applianceHosts.append(privateIP)
                else:
                    if platform == "windows":
                        self.windowsHosts.append(privateIP)
                    else:
                        self.linuxHosts.append(privateIP)

        return True;
        
    def get_appliance_hosts(self):
        return self.applianceHosts
    
    def get_linux_hosts(self):
        return self.linuxHosts
    
    def get_windows_hsots(self):
        return self.windowsHosts
    
    
    