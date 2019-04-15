""" Cisco ASA

"""

import base64
import re
from netmiko import ConnectHandler

class ciscoASA():

    def __init__(self,device_ip,user,passwd):
        device = {
            'device_type': 'cisco_asa',
            'ip': device_ip,
            'username': user,
            'password': passwd,
            'secret': passwd
        }
        self.net_connect = ConnectHandler(**device)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.net_connect:
            self.net_connect.disconnect()

    def showRoute(self):
        return self.net_connect.send_command("show route").split('\n')

    def getRoute(self,ip):
        """ Get Route for an IP """
        return self.net_connect.send_command("show route {}".format(ip)).split('\n')

    def setContext(self,context):
        return self.net_connect.send_command("changeto context {}".format(context))

    def getContexts(self):
        self.net_connect.send_command("changeto system")
        return self.net_connect.send_command("sh run | i ^context").split('\n')

    def getCryptoPeer(self):
        """ Runs 'show run crypto | i address|peer' """
        return self.net_connect.send_command("show run crypto | i address|peer").split('\n')
    
    def getTunnelGroup(self,ip):
        """ Runs 'show run tunnel-group <ip>' """
        return self.net_connect.send_command("show run tunnel-group {}".format(ip)).split('\n')
    
    def getGroupPolicy(self,gp):
        """ Runs 'show run group-policy <group-policy>' """
        return self.net_connect.send_command("show run group-policy {}".format(gp)).split('\n')
    
    def getACL(self,acl):
        """ Runs 'show access-list <access-list>' """
        return self.net_connect.send_command("show access-list {}".format(acl)).split('\n')
    
    def getACLcfg(self,acl):
        """ Runs 'show run access-list <access-list>' """
        return self.net_connect.send_command("show run access-list {}".format(acl)).split('\n')

    def get_network_objects(self):
        """ Runs 'show run object network in-line' """
        return self.net_connect.send_command("show run object network in-line").split('\n')

    def getObjectCfg(self,obj):
        """ Runs 'show run object id <object>' """
        return self.net_connect.send_command("show run object id {}".format(obj)).split('\n')

    def getObjectGrpCfg(self,objgrp):
        """ Runs 'show run object-group id <objgrp>' """
        return self.net_connect.send_command("show run object-group id {}".format(objgrp)).split('\n')

    def getObject(self,ip):
        """ Get object name if exists from IP """
        try:
            obj_regex = 'object\snetwork\s(\S*)'
            object = self.net_connect.send_command("show run object in-line | i {}$".format(ip))
            if object == '':
                obj_msg = "No object for {}".format(ip)
                my_obj = "h-<hostname>_{}".format(ip)
            else:
                obj_pat = re.search(obj_regex,object,re.VERBOSE)
                obj_msg = object
                my_obj = obj_pat.group(1)
        except Exception as e:
            print("getObject Error: {}".format(e))
        return obj_msg,my_obj

    def getACLname(self,fwint):
        """ Takes Firewall Interface name as input and outputs ACL name attached """
        try:
            acl = self.net_connect.send_command("sh run access-group | i {}".format(fwint)).split('\n')
            acl_regex = 'access-group\s(.*)\sin\sinterface.*'
            for entry in acl:
                acl_pat = re.search(acl_regex,entry,re.VERBOSE)
                if acl_pat:
                    return acl_pat.group(1)
        except Exception as e:
            print("getACLname Error: {}".format(e))

    def packetTracer(self,**socket):
        """ Run packet tracer """
        cmd=("packet-tracer input {} {} {} 55000 {} {}".format(
                    socket['interface'],
                    socket['protocol'],
                    socket['source_ip'],
                    socket['dest_ip'],
                    socket['dest_port'],
                ))
        print("Command: {}".format(cmd))
        return self.net_connect.send_command(cmd).split('\n')

    def ptACL(self,data):
        """ Take list returned from packetTracer and parse out ACL """
        self.append=0
        self.acl=[]
        for line in data:
            if re.search('^Type:\sACCESS-LIST$',line,re.VERBOSE):
                self.append=1
            if re.search('^Phase.*',line,re.VERBOSE):
                self.append=0
            if self.append==1:
                self.acl.append(line)
        return self.acl

