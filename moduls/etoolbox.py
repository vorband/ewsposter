#!/usr/bin/env python

from moduls.elog import logme
import ConfigParser
import re
import time
import sys
import os
import ipaddress
from requests import get
import socket

def countme(Section,Item,Count,ECFG):

    z = ConfigParser.RawConfigParser()
    z.read(ECFG["homedir"] + os.sep + "ews.idx")

    if z.has_section(Section) is not True:
        z.add_section(Section)

    if z.has_option(Section,Item) is not True:
        z.set(Section,Item,0)

    if Count >= 0:
        z.set(Section,Item,Count)
    elif Count == -2:
        z.set(Section,Item,str(int(z.get(Section,Item)) + 1))
    elif Count == -3:
        z.set(Section,Item,0)

    with open(ECFG["homedir"] + os.sep + "ews.idx", 'wb') as countfile:
        z.write(countfile)
        countfile.close

    if Count == -1:
        return z.get(Section,Item)

    return


def calcminmax(MODUL,imin,imax,ECFG):

    if (imax - imin) > int(ECFG["sendlimit"]):
        logme(MODUL,"Need to send : " + str(imax -imin) + " limit is : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)
        imax = imin + int(ECFG["sendlimit"])

    return imin,imax


def timestamp():
    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    return time.strftime('%Y%m%dT%H%M%ST', localtime) + milliseconds


def ip4or6(ip):

    if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip):
        return "4"
    else:
        return "6"


def readcfg(MODULE,ITEMS,FILE):

    RC = {}

    config = ConfigParser.ConfigParser()
    config.read(FILE)

    for items in ITEMS:
        if config.has_option(MODULE,items) is True and len(config.get(MODULE,items)) > 0:
            RC[items] = config.get(MODULE,items)
        else:
            print(" => [ERROR] Config parameter [%s] '%s=' didn't find or empty in %s config file. Abort !"%(MODULE,items, FILE))
            sys.exit()

    if "ip" in RC:
        RC["ipv"] = ip4or6(RC["ip"])

    return RC


def readonecfg(MODULE,item,FILE):

    config = ConfigParser.ConfigParser()
    config.read(FILE)

    if config.has_option(MODULE,item) is True and len(config.get(MODULE,item)) > 0:
        return config.get(MODULE,item)
    elif config.has_option(MODULE,item) is True and len(config.get(MODULE,item)) == 0:
        return "NULL"
    elif config.has_option(MODULE,item) is False:
        return "FALSE"
    else:
        return "UNKNOW"

def checkForPublicIP(ip):
    return ipaddress.ip_address(ip).is_global

def getOwnExternalIP(storedip):
    # try MY_EXTIP from env
    try:
        if os.environ.get('MY_EXTIP') is not None:
            if ipaddress.ip_address(unicode(os.environ.get('MY_EXTIP'))).is_global:
                return os.environ.get('MY_EXTIP')
    except:
        # try the IP from ews.cfg
        try:
            if ipaddress.ip_address(unicode(storedip)).is_global:
                return storedip
            # try to resolve IP from external service
            else:
                try:
                    extip = get('https://api.ipify.org', timeout=5).text
                    if ipaddress.ip_address(unicode(extip)).is_global:
                        return extip
                    return storedip
                except:
                    print " => [ERROR] Could not determine a valid public IP"
                    return storedip
        except ValueError:
            try:
                extip = get('https://api.ipify.org', timeout=5).text
                if ipaddress.ip_address(unicode(extip)).is_global:
                    return extip
                else:
                    print " => [ERROR] Could not determine a valid public IP"
                    return "0.0.0.0"
            except:
                print " => [ERROR] Could not determine a valid public IP"
                return "0.0.0.0"
    print " => [ERROR] Could not determine a valid public IP"
    return "0.0.0.0"

def getHostname():
    if os.environ.get('MY_HOSTNAME') is not None:
        return  os.environ.get('MY_HOSTNAME')
    else:
        return "SomeRandomHoneypot"

def getOwnInternalIP():
    # try MY_INTIP from env
    try:
        if os.environ.get('MY_INTIP') is not None:
            if ipaddress.ip_address(unicode(os.environ.get('MY_INTIP'))).is_private:
                return os.environ.get('MY_INTIP')
            else:
                print " => [ERROR] Could not determine a valid private IP"
                return "0.0.0.0"
    except:
        print " => [ERROR] Could not determine a valid private IP"
        return "0.0.0.0"
    print " => [ERROR] Could not determine a valid private IP"
    return "0.0.0.0"

def resolveHost(host):
    """ resolve an IP, either from IP or hostname """
    try:
        return ipaddress.IPv4Address(host)
    except:

        if ipaddress.IPv4Address(socket.gethostbyname(host)):
            return socket.gethostbyname(host)
        else:
            return False


if __name__ == "__main__":
    pass
