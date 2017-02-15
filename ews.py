#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import os
import time
import ConfigParser
import hashlib
from linecache import getline, clearcache
from datetime import datetime
from lxml import etree

from moduls.exml import ewsauth, ewsalert
from moduls.einit import locksocket, ecfg, daycounterreset
from moduls.elog import logme
from moduls.etoolbox import ip4or6, readcfg, readonecfg, timestamp, calcminmax, countme

import sqlite3
import MySQLdb.cursors
import requests
import random
import base64
import urllib
import hpfeeds
import fnmatch
import json

name = "EWS Poster"
version = "v1.8.4b"


def ewswebservice(ems):

    MODUL = "ewswebservice"

    headers = { 'User-Agent'     : name + " " + version,
                'Content-type'   : 'text/xml',
                'SOAPAction'     : '',
                'charset'        : 'UTF-8',
                'Connection'     : 'close'
              }

    host = random.choice([ ECFG["rhost_first"] , ECFG["rhost_second"] ])

    if ECFG["proxy"] != "NULL" and ECFG["proxy"] != "FALSE":
       proxydic = { "https" : ECFG["proxy"] }
    else:
       proxydic = {}

    try:
        if not "https" in proxydic:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       timeout=60,
                                       verify= not ECFG["a.ignorecert"]
                                      )
        else:
            webservice = requests.post(host,
                                       data=ems,
                                       headers=headers,
                                       allow_redirects=True,
                                       proxies=proxydic,
                                       timeout=60,
                                       verify= not ECFG["a.ignorecert"]
                                      )


        webservice.raise_for_status()

        xmlresult = re.search('<StatusCode>(.*)</StatusCode>', webservice.text).groups()[0]

        if xmlresult != "OK":
            logme(MODUL,"XML Result != ok ( %s) (%s)" % (xmlresult,webservice.text) ,("LOG","VERBOSE"),ECFG)
            return False

        if ECFG["a.verbose"] is True:
            logme(MODUL,"---- Webservice Report ----" ,("VERBOSE"),ECFG)
            logme(MODUL,"HOST          : %s" % (host) ,("VERBOSE"),ECFG)
            logme(MODUL,"XML Result    : %s" % (xmlresult) ,("VERBOSE"),ECFG)
            logme(MODUL,"Statuscode    : %s" % (webservice.status_code) ,("VERBOSE"),ECFG)
            logme(MODUL,"Header        : %s" % (webservice.headers) ,("VERBOSE"),ECFG)
            logme(MODUL,"Body          : %s" % (webservice.text) ,("VERBOSE"),ECFG)
            logme(MODUL,"",("VERBOSE"),ECFG)

        return True

    except requests.exceptions.Timeout, e:
        logme(MODUL,"Timeout to remote host %s (%s)" % (host , str(e)) ,("LOG","VERBOSE"),ECFG)
        return False

    except requests.exceptions.ConnectionError, e:
        logme(MODUL,"Remote host %s didn't answers ! (%s)" % (host , str(e)) ,("LOG","VERBOSE"),ECFG)
        return False

    except requests.exceptions.HTTPError, e:
        logme(MODUL,"HTTP Errorcode != 200 (%s)" % (str(e)) ,("LOG","VERBOSE"),ECFG)
        return False


def viewcounter(MODUL,x,y):

    if y  == 100:
        x += 100
        # Inform every 100 send records
        logme(MODUL,str(x) +" EWS alert records sent ...",("P2"),ECFG)
        y = 1
    else:
        y += 1

    return x,y


def sender():

    MODUL = "sender"

    def clean_dir(DIR,MODUL):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            if not ".ews" in files:
                os.remove(DIR + os.sep + files)
                logme(MODUL, "Cleaning spooler dir: %s delete file: %s" % (DIR, files),("LOG"),ECFG)
        return()

    def check_job(DIR,MODUL):
        FILEIN = filelist(DIR)

        if len(FILEIN) < 1:
            logme(MODUL, "Sender : No Jobs to send in %s" % (DIR),("P1"),ECFG)
            return False
        else:
            logme(MODUL, "Sender : There are %s jobs to send in %s" %(str(len(FILEIN)),DIR),("P1"),ECFG)
            return True

    def send_job(DIR,MODUL):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            with open(DIR +  os.sep + files,'r') as alert:
                EWSALERT = alert.read()
                alert.close()

            if ewswebservice(EWSALERT) is True:
                os.remove(DIR + os.sep + files)
            else:
                fpart = files.split('.')

                if len(fpart) == 2:
                    newname = fpart[0] + ".1." + fpart[1]
                else:
                    newname = fpart[0] + "." + str(int(fpart[1]) + 1) + "." + fpart[2]

                os.rename(DIR + os.sep + files, DIR + os.sep + newname)
        return

    def del_job(DIR,MODUL):
        FILEIN = filelist(DIR)

        for files in FILEIN:
            fpart = files.split('.')
            if len(fpart) == 3 and int(fpart[1]) > 4:
                logme(MODUL, "Cleaning spooler dir: %s delete file: %s reached max transmit counter !" % (DIR, files),("LOG"),ECFG)
                os.remove(DIR + os.sep + files)

    def filelist(DIR):

        if os.path.isdir(DIR) is not True:
            logme(MODUL,"Error missing dir " + DIR + " Abort !",("P1","EXIT"),ECFG)
        else:
            return os.listdir(DIR)

    clean_dir(ECFG["spooldir"],MODUL)
    del_job(ECFG["spooldir"],MODUL)

    if check_job(ECFG["spooldir"],MODUL) is False:
        return

    send_job(ECFG["spooldir"],MODUL)

    return


def buildews(esm,DATA,REQUEST,ADATA):

    ewsalert(esm,DATA,REQUEST,ADATA)

    if int(esm.xpath('count(//Alert)')) >= 100:
        sendews(esm)
        esm = ewsauth(ECFG["username"],ECFG["token"])

    return esm


def sendews(esm):

    if ECFG["a.ewsonly"] is True:
        writeews(etree.tostring(esm, pretty_print=True))
        return

    if ECFG["a.debug"] is True:
        writeews(etree.tostring(esm, pretty_print=True))

    if ECFG["ews"] is True and ewswebservice(etree.tostring(esm)) is not True:
        writeews(etree.tostring(esm, pretty_print=True))

    if ECFG["hpfeed"] is True:
        hpfeedsend(esm)

    return


def writeews(EWSALERT):
    with open(ECFG["spooldir"] + os.sep + timestamp() + ".ews",'w') as f:
        f.write(EWSALERT)
        f.close()

    return True


def malware(DIR,FILE,KILL):
    if not os.path.isdir(DIR):
        return 1,DIR + " NOT EXISTS!"

    if os.path.isfile(DIR + os.sep + FILE) is True:
        if os.path.getsize(DIR + os.sep + FILE) <= 5 * 1024 * 1024:
            malwarefile = base64.encodestring(open(DIR + os.sep + FILE).read())
            if KILL is True:
                os.remove(DIR + os.sep + FILE)
            return 0,malwarefile
        else:
            return 1,"FILE " + DIR + os.sep + FILE + " is bigger than 5 MB!"
    else:
        return 1, "FILE " + DIR + os.sep + FILE + " NOT EXISTS!"


def hpfeedsend(esm):

    try:
        hpc = hpfeeds.new(ECFG["host"],int(ECFG["port"]),ECFG["ident"],ECFG["secret"])
        logme("hpfeedsend","Connect to (%s)" % format(hpc.brokername) ,("P3","VERBOSE"),ECFG)
    except hpfeeds.FeedException, e:
        logme("hpfeedsend","HPFeeds Error (%s)" % format(e) ,("LOG","VERBOSE"),ECFG)
        return False

    hpc.publish(ECFG["channels"],etree.tostring(esm, pretty_print=True))

    emsg = hpc.wait()

    if emsg: 
        logme("hpfeedsend","HPFeeds Error (%s)" % format(emsg) ,("LOG","VERBOSE"),ECFG)
        return False

    return True


def buildjson(jesm,DATA,REQUEST,ADATA):

    if DATA["sport"] == "":
       DATA["sport"] = "0"

    jesm += '{"timestamp":"%s","event_type":"alert","src_ip":"%s","src_port":%s,"dest_ip":"%s","dest_port":%s,"honeypot":{"name":"%s","nodeid":"%s"}}' %\
             (
                 ("%sT%s.000000" % (DATA["timestamp"][0:10],DATA["timestamp"][11:19])),
                 DATA["sadr"],
                 DATA["sport"],
                 DATA["tadr"],
                 DATA["tport"],
                 REQUEST["description"],
                 DATA["aid"]
             )

    jesm += "\n"

    return jesm


def writejson(jesm):
    if len(jesm) > 0 and ECFG["json"] is True:
        with open(ECFG["jsondir"],'a+') as f:
            f.write(jesm)
            f.close()


def verbosemode(MODUL,DATA,REQUEST,ADATA):
    logme(MODUL,"---- " + MODUL + " ----" ,("VERBOSE"),ECFG)
    logme(MODUL,"Nodeid          : %s" % DATA["aid"],("VERBOSE"),ECFG)
    logme(MODUL,"Timestamp       : %s" % DATA["timestamp"],("VERBOSE"),ECFG)
    logme(MODUL,"" ,("VERBOSE"),ECFG)
    logme(MODUL,"Source IP       : %s" % DATA["sadr"],("VERBOSE"),ECFG)
    logme(MODUL,"Source IPv      : %s" % DATA["sipv"],("VERBOSE"),ECFG)
    logme(MODUL,"Source Port     : %s" % DATA["sport"],("VERBOSE"),ECFG)
    logme(MODUL,"Source Protocol : %s" % DATA["sprot"],("VERBOSE"),ECFG)
    logme(MODUL,"Target IP       : %s" % DATA["tadr"],("VERBOSE"),ECFG)
    logme(MODUL,"Target IPv      : %s" % DATA["tipv"],("VERBOSE"),ECFG)
    logme(MODUL,"Target Port     : %s" % DATA["tport"],("VERBOSE"),ECFG)
    logme(MODUL,"Target Protocol : %s" % DATA["tprot"],("VERBOSE"),ECFG)

    for key,value in ADATA.items():
        logme(MODUL,"%s       : %s" %(key,value) ,("VERBOSE"),ECFG)

    logme(MODUL,"" ,("VERBOSE"),ECFG)

    return

def glastopfv3():

    MODUL  = "GLASTOPFV3"
    logme(MODUL,"Starting Glastopf V3.x Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("glastopfv3","nodeid","sqlitedb","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
       HONEYPOT["ip"] = ECFG["ip"]

    # Malwaredir exist ? Issue in Glastopf ! RFI Directory first create when the first RFI was downloaded

    #if os.path.isdir(HONEYPOT["malwaredir"]) == False:
    #    logme(MODUL,"[ERROR] Missing Malware Dir " + HONEYPOT["malwaredir"] + ". Abort !",("P3","LOG"),ECFG)
    #    return

    # is sqlitedb exist ?

    if os.path.isfile(HONEYPOT["sqlitedb"]) is False:
        logme(MODUL,"[INFO] Missing sqlitedb file " + HONEYPOT["sqlitedb"] + ". Skip !",("P3","LOG"),ECFG)
        return

    # open database

    con = sqlite3.connect(HONEYPOT["sqlitedb"],30)
    con.row_factory = sqlite3.Row
    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from events")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Glastopf Database. Skip !",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from events where id > ? and id <= ?;",(imin,imax))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter empty requests and nagios checks

        if  row["request_url"] == os.sep or row["request_url"] == "/index.do?hash=DEADBEEF&activate=1":
            countme(MODUL,'sqliteid',row["id"],ECFG)
            continue

        # Prepair and collect Alert Data

        DATA = {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : row["time"],
                    "sadr"      : re.sub(":.*$","",row["source"]),
                    "sipv"      : "ipv" + ip4or6(re.sub(":.*$","",row["source"])),
                    "sprot"     : "tcp",
                    "sport"     : "",
                    "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                    "tadr"      : HONEYPOT["ip"],
                    "tprot"     : "tcp",
                    "tport"     : "80",
                  }

        REQUEST = {
                    "description" : "WebHoneypot : Glastopf v3.1",
                    "url"         : urllib.quote(row["request_url"].encode('ascii', 'ignore'))
                  }

        if "request_raw" in  row.keys() and len(row["request_raw"]) > 0:
            REQUEST["raw"] = base64.encodestring(row["request_raw"].encode('ascii', 'ignore'))

        if "filename" in  row.keys() and row["filename"] != None:
           error,malwarefile = malware(HONEYPOT["malwaredir"],row["filename"],ECFG["del_malware_after_send"])
           if error == 0:
                REQUEST["binary"] = malwarefile
           else:
                logme(MODUL,"Mission Malwarefile %s" % row["filename"] ,("P1","LOG"),ECFG)

        # Collect additional Data

        ADATA = {
                 "sqliteid"    : row ["id"],
                }

        if "request_method" in  row.keys():
           ADATA["httpmethod"] = row["request_method"]

        if "request_raw" in  row.keys():
            m = re.search( r'Host: (\b.+\b)', row["request_raw"] , re.M)
            if m:
                ADATA["host"] = str(m.group(1))

        if "request_header" in  row.keys():
            if 'Host' in json.loads(row["request_header"]):
                ADATA["host"] = str(json.loads(row["request_header"])["Host"])

        if "request_body" in  row.keys():
            if len(row["request_body"]) > 0:
                ADATA["requestbody"] = row["request_body"]

        esm = buildews(esm,DATA,REQUEST,ADATA)
        if "request_body" in  row.keys():
            if len(row["request_body"]) > 0:
                ADATA["requestbody"] = row["request_body"]

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'sqliteid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return

def glastopfv2():

    MODUL  = "GLASTOPFV2"
    logme(MODUL,"Starting Glastopf V2 Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("glastopfv2","nodeid","mysqlhost","mysqldb","mysqluser","mysqlpw","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
       HONEYPOT["ip"] = ECFG["ip"]

    # open database

    try:
        con = MySQLdb.connect(host=HONEYPOT["mysqlhost"], user=HONEYPOT["mysqluser"], passwd=HONEYPOT["mysqlpw"],
                              db=HONEYPOT["mysqldb"], cursorclass=MySQLdb.cursors.DictCursor)
    except MySQLdb.Error,e:
        logme(MODUL,"[ERROR] %s" %(str(e)),("P3","LOG"),ECFG)
        return 

    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from log")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Glastopf Database. Skip!",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from log where id > %s and id <= %s;",(imin,imax))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter nagios checks

        if row["req"] == "/index.do?hash=DEADBEEF&activate=1":
            countme(MODUL,'mysqlid',row["id"],ECFG)
            continue

        # Prepair and collect Alert Data

        DATA = {
                 "aid"       : HONEYPOT["nodeid"],
                 "timestamp" : str(row["attime"]),
                 "sadr"      : row["ip"],
                 "sipv"      : "ipv" + ip4or6(row["ip"]),
                 "sprot"     : "tcp",
                 "sport"     : "",
                 "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                 "tadr"      : HONEYPOT["ip"],
                 "tprot"     : "tcp",
                 "tport"     : "80",
                }

        REQUEST = {
                    "description"  : "Webhoneypot : Glastopf v2.x",
                    "url"          : urllib.quote(row["req"])
                  }

        if row["filename"] != None:
           error,malwarefile = malware(HONEYPOT["malwaredir"],row["filename"],ECFG["del_malware_after_send"])
           if error == 0:
                REQUEST["binary"] = malwarefile
           else:
                logme(MODUL,"Mission Malwarefile %s" % row["filename"] ,("P1","LOG"),ECFG)

        # Collect additional Data

        ADATA = {
                 "mysqlid"   : str(row ["id"]),
                 "host"      : row["host"],
                }

        if row["victim"] != "None":
            ADATA["victim"] = row["victim"]

        # Rest

        esm = buildews(esm,DATA,REQUEST, ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'mysqlid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)


    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return


def kippo():

    MODUL  = "KIPPO"
    logme(MODUL,"Starting Kippo Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("kippo","nodeid","mysqlhost","mysqldb","mysqluser","mysqlpw")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    HONEYPOT["ip"] = readonecfg(MODUL,"ip", ECFG["cfgfile"])

    if HONEYPOT["ip"].lower() == "false" or HONEYPOT["ip"].lower() == "null":
       HONEYPOT["ip"] = ECFG["ip"]

    # open database

    try:
        con = MySQLdb.connect(host=HONEYPOT["mysqlhost"], user=HONEYPOT["mysqluser"], passwd=HONEYPOT["mysqlpw"],
                              db=HONEYPOT["mysqldb"], cursorclass=MySQLdb.cursors.DictCursor)

    except MySQLdb.Error,e:
        logme(MODUL,"[ERROR] %s" %(str(e)),("P3","LOG"),ECFG)

    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(id) from auth")

    maxid = c.fetchone()["max(id)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Kippo Database. Skip!",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT auth.id, auth.username, auth.password, auth.success, auth.timestamp, auth.session, sessions.starttime, sessions.endtime, sessions.ip, sensors.ip as kippoip, clients.version from auth, sessions, sensors, clients WHERE (sessions.id=auth.session) AND (sessions.sensor = sensors.id) AND (sessions.client = clients.id) AND auth.id > %s and auth.id <= %s ORDER BY auth.id;" % (imin,imax))

    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # Prepair and collect Alert Data

        DATA =    {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : str(row["timestamp"]),
                    "sadr"      : str(row["ip"]),
                    "sipv"      : "ipv" + ip4or6(str(row["ip"])),
                    "sprot"     : "tcp",
                    "sport"     : "",
                    "tipv"      : "ipv" + ip4or6(HONEYPOT["ip"]),
                    "tadr"      : HONEYPOT["ip"],
                    "tprot"     : "tcp",
                    "tport"     : "22",
                  }

        REQUEST = {
                    "description" : "SSH Honeypot Kippo",
                  }

        # Collect additional Data

        if str(row["success"]) == "0":
            login = "Fail"
        else: 
            login = "Success"

        ADATA = {
                 "sqliteid"    : str(row["id"]),
                 "starttime"   : str(row["starttime"]),
                 "endtime"     : str(row["endtime"]),
                 "version"     : str(row["version"]),
                 "login"       : login,
                 "username"    : str(row["username"]),
                 "password"    : str(row["password"])
                }

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'mysqlid',row["id"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return


def dionaea():

    MODUL  = "DIONAEA"
    logme(MODUL,"Starting Dionaea Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("dionaea","nodeid","sqlitedb","malwaredir")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # Malwaredir exist ?

    if os.path.isdir(HONEYPOT["malwaredir"]) is False:
        logme(MODUL,"[ERROR] Missing Malware Dir " + HONEYPOT["malwaredir"] + ". Abort !",("P3","LOG"),ECFG)

     # is sqlitedb exist ?

    if os.path.isfile(HONEYPOT["sqlitedb"]) is False:
        logme(MODUL,"[ERROR] Missing sqlitedb file " + HONEYPOT["sqlitedb"] + ". Abort !",("P3","LOG"),ECFG)
        return

    # open database

    con = sqlite3.connect(HONEYPOT["sqlitedb"],30)
    con.row_factory = sqlite3.Row
    c = con.cursor()

    # calculate send limit

    c.execute("SELECT max(connection) from connections;")

    maxid = c.fetchone()["max(connection)"]

    if maxid is None:
        logme(MODUL,"[INFO] No entry's in Dionaea Database. Skip !",("P2","LOG"),ECFG)
        return

    imin, imax = calcminmax(MODUL,int(countme(MODUL,'sqliteid',-1,ECFG)),int(maxid),ECFG)

    # read alerts from database

    c.execute("SELECT * from connections where connection > ? and connection <= ?;",(imin,imax,))
    rows = c.fetchall()

    # counter inits

    x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    for row in rows:

        x,y = viewcounter(MODUL,x,y)

        # filter empty remote_host

        if row["remote_host"] == "": 
            countme(MODUL,'sqliteid',row["connection"],ECFG)
            continue

        # Prepair and collect Alert Data

        DATA =   {
                    "aid"       : HONEYPOT["nodeid"],
                    "timestamp" : datetime.fromtimestamp(int(row["connection_timestamp"])).strftime('%Y-%m-%d %H:%M:%S'),
                    "sadr"      : str(row["remote_host"]),
                    "sipv"      : "ipv" + ip4or6(str(row["remote_host"])),
                    "sprot"     : str(row["connection_type"]),
                    "sport"     : str(row["remote_port"]),
                    "tipv"      : "ipv" + ip4or6(str(row["local_host"])),
                    "tadr"      : str(row["local_host"]),
                    "tprot"     : str(row["connection_type"]),
                    "tport"     : str(row["local_port"]),
                  }

        REQUEST = {
                    "description" : "Network Honeyport Dionaea v0.1.0",
                  }

        # Check for malware bin's

        c.execute("SELECT download_md5_hash from downloads where connection = ?;",(str(row["connection"]),))
        check = c.fetchone()

        if check is not None:
           error,malwarefile = malware(HONEYPOT["malwaredir"],check[0],ECFG["del_malware_after_send"])
           if error == 0:
               REQUEST["binary"] = malwarefile
           else:
               logme(MODUL,"Mission Malwarefile %s" % check[0] ,("P1","LOG"),ECFG)

        # Collect additional Data

        ADATA = {
                 "sqliteid"    : str(row["connection"]),
                }

        # generate template and send

        esm = buildews(esm,DATA,REQUEST,ADATA)
        jesm = buildjson(jesm,DATA,REQUEST,ADATA)

        countme(MODUL,'sqliteid',row["connection"],ECFG)
        countme(MODUL,'daycounter', -2,ECFG)

        if ECFG["a.verbose"] is True:
            verbosemode(MODUL,DATA,REQUEST,ADATA)

    con.close()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-1),("P2"),ECFG)
    return


def honeytrap():

    MODUL  = "HONEYTRAP"
    logme(MODUL,"Starting Honeytrap Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("honeytrap","nodeid","attackerfile","payloaddir","newversion")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # Attacking file exists ?

    if os.path.isfile(HONEYPOT["attackerfile"]) is False:
        logme(MODUL,"[ERROR] Missing Attacker File " + HONEYPOT["attackerfile"] + ". Abort !",("P3","LOG"),ECFG)

    # Payloaddir exist ?

    if os.path.isdir(HONEYPOT["payloaddir"]) is False:
        logme(MODUL,"[ERROR] Missing Payload Dir " + HONEYPOT["payloaddir"] + ". Abort !",("P3","LOG"),ECFG)

    # New Version are use ?

    if HONEYPOT["newversion"].lower() == "true" and not os.path.isdir(HONEYPOT["payloaddir"]):
        logme(MODUL,"[ERROR] Missing Payload Directory " + HONEYPOT["payloaddir"] + ". Abort !",("P3","LOG"),ECFG)

    # Calc MD5sum for Payloadfiles

    if HONEYPOT["newversion"].lower() == "true":
       logme(MODUL,"Calculate MD5sum for Payload Files",("P2"),ECFG)

       for i in os.listdir(HONEYPOT["payloaddir"]):
           if not "_md5_" in i:
            filein = HONEYPOT["payloaddir"] + os.sep + i
            os.rename(filein,filein + "_md5_" +  hashlib.md5(open(filein, 'rb').read()).hexdigest())

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["attackerfile"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            if HONEYPOT["newversion"].lower() == "false":
                date , time , _ , source, dest, _ = line.split(" ",5)
                protocol = "" ; md5 = ""
            else:
                date , time , _ , protocol, source, dest, md5, _ = line.split(" ",7)

            #  Prepair and collect Alert Data

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s" % (date[0:4], date[4:6], date[6:8], time[0:8]),
                        "sadr"      : re.sub(":.*$","",source),
                        "sipv"      : "ipv" + ip4or6(re.sub(":.*$","",source)),
                        "sprot"     : protocol,
                        "sport"     : re.sub("^.*:","",source),
                        "tipv"      : "ipv" + ip4or6(re.sub(":.*$","",dest)),
                        "tadr"      : re.sub(":.*$","",dest),
                        "tprot"     : protocol,
                        "tport"     : re.sub("^.*:","",dest),
                      }


            REQUEST = {
                        "description" : "NetworkHoneypot Honeytrap v1.1"
                      }

            # Search for Payload

            if HONEYPOT["newversion"].lower() == "true":
                sfile = "from_port_%s-%s_*_%s-%s-%s_md5_%s" % (re.sub("^.*:","",dest),protocol,date[0:4], date[4:6], date[6:8],md5)

                for mfile in os.listdir(HONEYPOT["payloaddir"]):
                   if fnmatch.fnmatch(mfile, sfile):
                       error , payloadfile = malware(HONEYPOT["payloaddir"],mfile,False)
                       if error == 0:
                           REQUEST["raw"] = payloadfile
                       else:
                           logme(MODUL,"Mission Malwarefile %s" % row["filename"] ,("P1","LOG"),ECFG)


            # Collect additional Data

            ADATA = {
                    }

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

def rdpdetect():

    MODUL  = "RDPDETECT"
    logme(MODUL,"Starting RDPDetect Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("rdpdetect","nodeid","iptableslog","targetip")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # iptables file exists ?

    if os.path.isfile(HONEYPOT["iptableslog"]) is False:
        logme(MODUL,"[ERROR] Missing Iptables LogFile " + HONEYPOT["iptableslog"] + ". Abort !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["iptableslog"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            if HONEYPOT["targetip"] == re.search('SRC=(.*?) ', line).groups()[0]:
                continue

            # Prepair and collect Alert Data

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s:%s:%s" % (line[0:4], line[4:6], line[6:8], line[9:11], line[12:14], line[15:17]),
                        "sadr"      : re.search('SRC=(.*?) ', line).groups()[0],
                        "sipv"      : "ipv" + ip4or6(re.search('SRC=(.*?) ', line).groups()[0]),
                        "sprot"     : re.search('PROTO=(.*?) ', line).groups()[0].lower(),
                        "sport"     : re.search('SPT=(.*?) ', line).groups()[0],
                        "tipv"      : "ipv" + ip4or6(ECFG["ip"]),
                        "tadr"      : ECFG["ip"],
                        "tprot"     : re.search('PROTO=(.*?) ', line).groups()[0].lower(),
                        "tport"     : re.search('DPT=(.*?) ', line).groups()[0],
                      }

            REQUEST = {
                        "description" : "RDPDetect"
                      }


            # Collect additional Data

            ADATA =   {
                      }

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

def emobility():

    MODUL  = "EMOBILITY"
    logme(MODUL,"Starting eMobility Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("eMobility","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:

        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            # Prepair and collect Alert Data

            line = re.sub(r'  ',r' ',re.sub(r'[\[\]\-\>]',r'',line))

            srcipandport, dstipandport, url, dateandtime =  line.split("|",3)

            DATA =    {
                        "aid"       : HONEYPOT["nodeid"],
                        "timestamp" : "%s-%s-%s %s" % (dateandtime[0:4], dateandtime[4:6], dateandtime[6:8], dateandtime[9:17]),
                        "sadr"      : "%s.%s.%s.%s" % (srcipandport.split(".")[0], srcipandport.split(".")[1], srcipandport.split(".")[2], srcipandport.split(".")[3]),
                        "sipv"      : "ipv4",
                        "sprot"     : "tcp",
                        "sport"     : srcipandport.split(".")[4],
                        "tipv"      : "ipv4",
                        "tadr"      : "%s.%s.%s.%s" % (dstipandport.split(".")[0], dstipandport.split(".")[1], dstipandport.split(".")[2], dstipandport.split(".")[3]),
                        "tprot"     : "tcp",
                        "tport"     : dstipandport.split(".")[4],
                      }

            REQUEST = {
                        "description" : "eMobility Honeypot",
                        "url"         : urllib.quote(url.encode('ascii', 'ignore'))
                      }


            # Collect additional Data

            ADATA =   {
                      }

            # generate template and send

            esm = buildews(esm,DATA,REQUEST,ADATA)
            jesm = buildjson(jesm,DATA,REQUEST,ADATA)

            countme(MODUL,'fileline',-2,ECFG)
            countme(MODUL,'daycounter', -2,ECFG)

            if ECFG["a.verbose"] is True:
                verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return


def conpot():
    MODUL  = "CONPOT"
    logme(MODUL,"Starting Conpot Modul.",("P1"),ECFG)

    # collect honeypot config dic

    ITEMS  = ("conpot","nodeid","logfile")
    HONEYPOT = readcfg(MODUL,ITEMS,ECFG["cfgfile"])

    # logfile file exists ?

    if os.path.isfile(HONEYPOT["logfile"]) is False:
        logme(MODUL,"[ERROR] Missing LogFile " + HONEYPOT["logfile"] + ". Skip !",("P3","LOG"),ECFG)

    # count limit

    imin = int(countme(MODUL,'fileline',-1,ECFG))

    if int(ECFG["sendlimit"]) > 0:
        logme(MODUL,"Send Limit is set to : " + str(ECFG["sendlimit"]) + ". Adapting to limit!",("P1"),ECFG)

    I = 0 ; x = 0 ; y = 1

    esm = ewsauth(ECFG["username"],ECFG["token"])
    jesm = ""

    while True:
    
        x,y = viewcounter(MODUL,x,y)

        I += 1

        if int(ECFG["sendlimit"]) > 0 and I > int(ECFG["sendlimit"]):
            break

        line = getline(HONEYPOT["logfile"],(imin + I)).rstrip()

        if len(line) == 0:
            break
        else:
            # parse json
            try:
                content = json.loads(line)
            except ValueError, e:
                logme(MODUL,"Invalid json entry found in conpot log file, skipping to next line...",("P1"),ECFG)
                pass # invalid json
            else:
                DATA =    {
                            "aid"       : HONEYPOT["nodeid"],
                            "timestamp" : "%s-%s-%s %s" % (content['timestamp'][0:4], content['timestamp'][5:7], content['timestamp'][8:10], content['timestamp'][11:19]]),
                            "sadr"      : content['src_ip'],
                            "sipv"      : "ipv4",
                            "sprot"     : "tcp",
                            "sport"     : "%d" % content['src_port'],
                            "tipv"      : "ipv4",
                            "tadr"      : content['dst_ip'],
                            "tprot"     : "tcp",
                            "tport"     : "undefined",
                        }

                REQUEST = {
                            "description" : "Conpot Honeypot",
                        }


                # Collect additional Data

                ADATA =   {
                            "conpot_event_type"    :   content['event_type'],
                            "conpot_data_type"     :   content['data_type'],
                            "conpot_sensor_id"     :   content['sensorid'],
                            "conpot_request"       :   content['request'],
                            "conpot_id"            :   content['id'],
                            "conpot_response"      :   content['response']
                        }

                # generate template and send

                esm = buildews(esm,DATA,REQUEST,ADATA)
                jesm = buildjson(jesm,DATA,REQUEST,ADATA)

                countme(MODUL,'fileline',-2,ECFG)
                countme(MODUL,'daycounter', -2,ECFG)

                if ECFG["a.verbose"] is True:
                    verbosemode(MODUL,DATA,REQUEST,ADATA)

    # Cleaning linecache
    clearcache()

    if int(esm.xpath('count(//Alert)')) > 0:
        sendews(esm)

    writejson(jesm)

    if y  > 1:
        logme(MODUL,"%s EWS alert records send ..." % (x+y-2),("P2"),ECFG)
    return

###############################################################################
 
if __name__ == "__main__":

    MODUL = "MAIN"

    global ECFG
    ECFG = ecfg(name,version)

    lock = locksocket(name)

    if lock is True:
        logme(MODUL,"Create lock socket successfull.",("P1"),ECFG)
    else:
        logme(MODUL,"Another Instance is running !",("P1"),ECFG)
        logme(MODUL,"EWSrun finish.",("P1","EXIT"),ECFG)

    while True:

        if ECFG["a.daycounter"] is True:
            daycounterreset(lock,ECFG)

        if ECFG["a.ewsonly"] is False:
            sender()


        for i in ("glastopfv3", "glastopfv2", "kippo", "dionaea", "honeytrap", "rdpdetect", "emobility", "conpot"):

            if ECFG["a.modul"]:
                if ECFG["a.modul"] == i:
                    if readonecfg(i.upper(),i,ECFG["cfgfile"]).lower() == "true":
                        eval(i+'()')
                        break
                else:
                    continue

            if readonecfg(i.upper(),i,ECFG["cfgfile"]).lower() == "true":
               eval(i+'()')

        if int(ECFG["a.loop"]) == 0:
            logme(MODUL,"EWSrun finish.",("P1"),ECFG)
            break
        else:
            logme(MODUL,"Sleeping for %s seconds ...." % ECFG["a.loop"] ,("P1"),ECFG)
            time.sleep(int(ECFG["a.loop"]))

