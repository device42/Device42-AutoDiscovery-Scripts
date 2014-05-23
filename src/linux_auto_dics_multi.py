"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

#########################################################################################################################################################
# v1.1.0 of python script that uses paramiko to run remote commands using ssh and
# gets system info on *nix based systems, parses it and uploads to device42 appliance using APIs
# tested on Redhat, Fedora and Ubuntu installations. Cent OS 5.x OS detection issue discussed below.
# paramiko has a LGPL license that is included with the repository. ipcalc has a BSD LICENSE mentioned on top of the ipcalc.py file.
# OS detection doesn't work correctly for CentOS 5.x, These show as redhat 5.x. Set GET_OS_DETAILS to False for CentOS 5.x based systems.
# LINES 32-51 to match your environment and requirements. If used in conjuction with other auto-discovery methods, you can configure which info to ignore
# Network slash notations added in v1.1.0
#########################################################################################################################################################


import sys
import re
import paramiko
import math
import urllib2, urllib
from base64 import b64encode
import simplejson as json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

D42_API_URL = 'https://D42_IP_or_FQDN'           #make sure to NOT to end in /
D42_USERNAME = 'D42USER'
D42_PASSWORD = 'D42PASS'
USE_IP_RANGE = True
IP_RANGE = ['192.168.11.10', '192.168.11.202']  #Start and End IP. There is no validation in the script. Please make sure these are in same subnet. Valid if USE_IP_RANGE = True
NETWORKS = ['10.10.0.0/23', '10.11.8.0/23',]   #End with , if a single network. always use / notation for the network. Only valid if USE_IP_RANGE = False
LINUX_USER = 'USER'
LINUX_PASSWORD = 'PASS'            #Change USE_KEY_FILE to False if using password. password for linux servers. not required if using key file.
USE_KEY_FILE = False                #change this to true, if not using password.
KEY_FILE = '/path/.ssh/id_rsa.pub' #key file name (with full path if not in same directory as the script)
PORT = 22                          #ssh port to use
TIMEOUT = 5                        #timeout in seconds for the ssh session
GET_SERIAL_INFO = True
GET_HARDWARE_INFO = True
GET_OS_DETAILS = True
GET_CPU_INFO = True
GET_MEMORY_INFO = True
ignoreDomain = True
uploadipv6 = True
DEBUG = False

def to_ascii(s):
    try: return s.encode('ascii','ignore')
    except: return None

def closest_memory_assumption(v):
    if v < 512: v = 128 * math.ceil(v / 128.0)
    elif v < 1024: v = 256 * math.ceil(v / 256.0)
    elif v < 4096: v = 512 * math.ceil(v / 512.0)
    elif v < 8192: v = 1024 * math.ceil(v / 1024.0)
    else: v = 2048 * math.ceil(v / 2048.0)
    return int(v)

def enumerate_ips():
    iplist = []
    start = list(map(int, IP_RANGE[0].split(".")))
    end = list(map(int, IP_RANGE[1].split(".")))
    temp = start
    iplist.append(IP_RANGE[0])
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ipadd=(".".join(map(str, temp)))
        iplist.append(ipadd)
    return iplist

def post(params, what):
    if what == 'device': THE_URL = D42_API_URL + '/api/device/'
    elif what == 'ip': THE_URL = D42_API_URL + '/api/ip/'
    elif what == 'mac': THE_URL = D42_API_URL + '/api/1.0/macs/'
    data= urllib.urlencode(params)
    headers = {
            'Authorization' : 'Basic '+ b64encode(D42_USERNAME + ':' + D42_PASSWORD),
            'Content-Type' : 'application/x-www-form-urlencoded'
        }
    req = urllib2.Request(THE_URL, data, headers)
    if DEBUG: print '---REQUEST---',req.get_full_url()
    if DEBUG: print req.headers
    if DEBUG: print req.data
    try:
        r = urllib2.urlopen(req)
        if r.getcode() == 200:
            obj = r.read()
            msg = json.loads(obj)
            return True, msg
        else:
            return False, r.getcode()
    except urllib2.HTTPError, e:
        error_response = e.read()
        if DEBUG: print e.code, error_response
        return False, error_response
    except Exception,e:
        return False, str(e)

def grab_and_post_inventory_data(machine_name):
    try:
        if not USE_KEY_FILE: ssh.connect(str(machine_name), port=PORT, username=LINUX_USER, password=LINUX_PASSWORD, timeout=TIMEOUT)
        else: ssh.connect(str(machine_name), port=PORT, username=LINUX_USER, key_filename=KEY_FILE, timeout=TIMEOUT)
    except paramiko.AuthenticationException:
        print str(machine_name) + ': authentication failed'
        return None
    except Exception as err:
        print str(machine_name) + ': ' + str(err)
        return  None
    devargs = {}

    stdin, stdout, stderr = ssh.exec_command("/bin/hostname")
    if not stderr.readlines():
        if ignoreDomain: device_name = to_ascii(stdout.readlines()[0].rstrip()).split('.')[0]
        else: device_name = to_ascii(stdout.readlines()[0].rstrip())
        devargs.update({'name': device_name})

    stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -s system-uuid")
    if not stderr.readlines():
        uuid = stdout.readlines()[0].rstrip()
        if uuid and uuid != '': devargs.update({'uuid': uuid})

    if GET_SERIAL_INFO:
        stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -s system-serial-number")
        if not stderr.readlines():
            serial_no = stdout.readlines()[0].rstrip()
            if serial_no and serial_no != '': devargs.update({'serial_no': serial_no})

    stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -s system-manufacturer")
    if not stderr.readlines():
        manufacturer = stdout.readlines()[0].rstrip()
        if manufacturer and manufacturer != '':
            for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
                if mftr == to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip():
                    manufacturer = 'virtual'
                    devargs.update({ 'type' : 'virtual', })
                    break
            if manufacturer != 'virtual' and GET_HARDWARE_INFO:
                devargs.update({'manufacturer': to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip()})
                stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -s system-product-name")
                if not stderr.readlines():
                    hardware = stdout.readlines()[0].rstrip()
                    if hardware and hardware != '': devargs.update({'hardware': hardware})

    if GET_OS_DETAILS:
        stdin, stdout, stderr = ssh.exec_command("/usr/bin/python -m platform")
        if not stderr.readlines():
            release = stdout.readlines()[0].rstrip()
            if release and release != '':
                    devargs.update({
                    'os': release.split('-with-')[1].split('-')[0],
                    'osver': release.split('-with-')[1].split('-')[1],
                    })

    if GET_MEMORY_INFO:
        stdin, stdout, stderr = ssh.exec_command("grep MemTotal /proc/meminfo")
        if not stderr.readlines():
            memory_raw = stdout.readlines()[0].replace(' ', '').replace('MemTotal:','').replace('kB','')
            if memory_raw and memory_raw != '':
                memory = closest_memory_assumption(int(memory_raw)/1024)
                devargs.update({'memory': memory})

    if GET_CPU_INFO:
        cpucount = 0
        cpuspeed = ''
        corecount = 0

        stdin, stdout, stderr = ssh.exec_command("cat /proc/cpuinfo | grep processor | wc -l")
        if not stderr.readlines():
            cpucount = int(stdout.readlines()[0].strip())


        stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -s processor-frequency")
        if not stderr.readlines():
            cpuspeedinfo = stdout.readlines()
            for item in cpuspeedinfo:
                if 'MHz' in item:
                    cpuspeed = item.split(' ')[0]
                    break
            if cpuspeed != '': devargs.update({'cpupower': cpuspeed,})

        stdin, stdout, stderr = ssh.exec_command("sudo dmidecode -t processor")
        if not stderr.readlines():
            coreinfo = stdout.readlines()
            for item in coreinfo:
                if 'Core Count' in item:
                    corecount = int(item.replace('Core Count: ', '').strip())
                    break
            if corecount == 0:
                corecount = 1
            if cpucount > 0:
                cpucount /= corecount
                devargs.update({'cpucount': cpucount})
                devargs.update({'cpucore': corecount})

    ADDED, msg = post(devargs, 'device')

    if ADDED:
        print machine_name + ': ' + msg['msg'][0]
        device_name_in_d42 = msg['msg'][2]
        stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig -a") #TODO add just macs without IPs
        if not stderr.readlines():
            ipinfo = stdout.readlines()

            # ======= MAC  only=========#
            for rec in ipinfo:
                if 'hwaddr' in rec.lower():
                    mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', rec, re.I).group()
                    print 'MAC: %s' % mac
                    print rec.split("\n")[0].split()[0]
                    mac_address = {
                    'macaddress' : mac, 
                    'port_name': rec.split("\n")[0].split()[0],
                    'device' : device_name_in_d42,
                    'override': 'smart'
                     }
                    ADDED, msg_mac = post(mac_address, 'mac')
                    if ADDED:
                        print mac + ': ' + str(msg_mac)
                    else:
                        print mac + ': failed with message = ' + str(msg_mac)
                    print '\n\n'
            # =======  / MAC only =========#

            for i, item in enumerate(ipinfo):
                if 'Ethernet' in item:
                    if 'inet addr' in ipinfo[i+1]:
                        ipv4_address = ipinfo[i+1].split()[1].replace('addr:', '')
                        ip = {
                        'ipaddress': ipv4_address,
                        'tag': item.split("\n")[0].split()[0],
                        'macaddress' : item.split("\n")[0].split()[4],
                        'device' : device_name_in_d42,
                         }
                        ADDED, msg_ip = post(ip, 'ip')
                        if ADDED:
                            print ipv4_address + ': ' + str(msg_ip)
                        else:
                            print ipv4_address + ': failed with message = ' + str(msg_ip)
                    if uploadipv6 and ('inet6 addr' in ipinfo[i+1] or 'inet6 addr' in ipinfo[i+2]):
                        if 'inet6 addr' in ipinfo[i+1]: ipv6_address = ipinfo[i+1].split()[2].split('/')[0]
                        else: ipv6_address = ipinfo[i+2].split()[2].split('/')[0]
                        ip = {
                        'ipaddress': ipv6_address,
                        'tag': item.split("\n")[0].split()[0],
                        'macaddress' : item.split("\n")[0].split()[4],
                        'device' : device_name_in_d42,
                         }
                        ADDED, msg_ip = post(ip, 'ip')
                        if ADDED:
                            print ipv6_address + ' : ' + str(msg_ip)
                        else:
                            print ipv6_address + ': failed with message = ' + str(msg_ip)
    else:
        print machine_name + ': failed with message: ' + str(msg)
    ssh.close()
    return devargs

if USE_IP_RANGE:
    iplist = enumerate_ips()
    for ip in iplist:
        grab_and_post_inventory_data(ip)
else:
    try: import ipcalc
    except:
        print 'Unable to import ipcalc.'
        print 'Please run: pip install git+git://github.com/tehmaze/ipcalc.git@master'
        print 'or drop ipcalc.py in the same path as this script'
        print 'or make sure it is installed and in the system path.'
        print 'https://github.com/tehmaze/ipcalc/blob/master/ipcalc.py'
        sys.exit(0)
    for network in NETWORKS:
        for ip in ipcalc.Network(network):
            grab_and_post_inventory_data(ip)

