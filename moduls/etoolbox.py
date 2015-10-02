#!/usr/bin/env python

from moduls.elog import logme
import ConfigParser
import re
import time
import sys
import os

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


if __name__ == "__main__":
    pass
