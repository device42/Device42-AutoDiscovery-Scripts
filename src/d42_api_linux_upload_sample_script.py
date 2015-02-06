#!/usr/bin/env python

"""
NOTE:
This script is obsolete.  
Please use "nix_bsd_mac_inventory (https://github.com/device42/nix_bsd_mac_inventory)" script instead.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

################################################################
# v1.1.0 of linux script that
# gets system info on a *nix based system, parses it and
# uploads to device42 appliance using APIs
# tested on Redhat, Fedora and Ubuntu installations
# OS Detection doesn't work correctly on CentOS 5.x.
# Set GET_OS_DETAILS = False, if you want to ignore OS details
###############################################################

import urllib
import urllib2
import traceback
from base64 import b64encode
import subprocess
import math
import simplejson as json

##### Change Following 11 lines to match your environment #####
D42_API_URL = 'https://your-d42-IP-or-FQDN-here'  #make sure to not end in /
D42_USERNAME = 'your-d42-username-here'
D42_PASSWORD = 'your-d42-password-here'
GET_SERIAL_INFO = True
GET_HARDWARE_INFO = True
GET_OS_DETAILS = True
GET_CPU_INFO = True
GET_MEMORY_INFO = True
uploadipv6 = True
ignoreDomain = True  #If you want to strip the domain name part from the hostname.
DEBUG = False        #True if you want to print detailed debug log

def to_ascii(s):  # ignore non-ascii chars
    try: return s.encode('ascii','ignore')
    except: return None
 
def post(params, what):
    if what == 'device': THE_URL = D42_API_URL + '/api/device/'
    elif what == 'ip': THE_URL = D42_API_URL + '/api/ip/'
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

def linux():
    device_name = subprocess.Popen(['/bin/hostname'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    if ignoreDomain: device_name = to_ascii(device_name).rstrip().split('.')[0]
    else: device_name = to_ascii(device_name).rstrip()
    device = {'name': device_name,}
    uuid = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-uuid'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    if uuid and uuid != '': device.update({'uuid': to_ascii(uuid).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").rstrip()})

    if GET_OS_DETAILS:
        release = subprocess.Popen(['/usr/bin/python', '-m' 'platform'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        device.update({'os': release.split('-with-')[1].split('-')[0],  'osver': release.split('-with-')[1].split('-')[1]})

    if GET_SERIAL_INFO:
        serial_no = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-serial-number'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        if serial_no and serial_no != '': device.update({'serial_no': to_ascii(serial_no).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip()})

    manufacturer = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-manufacturer'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
        if mftr == to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip():
            manufacturer = 'virtual'
            device.update({ 'type' : 'virtual', })
            break    
    if manufacturer != 'virtual' and GET_HARDWARE_INFO:
        hardware = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-product-name'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        if hardware and hardware != '':
            device.update({
                'manufacturer': to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip(),
                'hardware': to_ascii(hardware).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip(),
                })

    if GET_MEMORY_INFO:
        memory_total = subprocess.Popen(['grep', 'MemTotal', '/proc/meminfo'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].replace(' ', '').replace('MemTotal:','').replace('kB','')
        memory = closest_memory_assumption(int(memory_total)/1024)
        device.update({'memory': memory})

    if GET_CPU_INFO:
        cpucount = 0
        cpuspeed = ''
        corecount = 0

        cpucountinfo = subprocess.Popen(['cat', '/proc/cpuinfo'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        for item in cpucountinfo.split('\n'):
            if 'processor' in item:
                cpucount += 1

        cpuinfo = subprocess.Popen(['sudo', 'dmidecode', '-s', 'processor-frequency'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        for item in cpuinfo.split('\n'):
            if 'MHz' in item:
                cpuspeed = item.split(' ')[0]
                break

        coreinfo = subprocess.Popen(['sudo', 'dmidecode', '-t', 'processor'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        for item in coreinfo.split('\n'):
            if 'Core Count' in item:
                corecount = int(item.replace('Core Count: ', '').strip())
                break
        if corecount == 0: corecount = 1

        if cpucount != 0:
            cpucount /= corecount
            device.update({
                'cpucount': cpucount,
                'cpucore': corecount,
                })
            if cpuspeed != '':
                device.update({'cpupower': cpuspeed,})

    ADDED, msg = post(device, 'device')
    if ADDED:
        print 'Device done: ' + str(msg)
        device_name_in_d42 = msg['msg'][2]
    
        ipinfo = subprocess.Popen(['/sbin/ifconfig', '-a'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        ipinfo_lines = ipinfo.split('\n')
    
        for i, item in enumerate(ipinfo_lines):
            if 'Ethernet' in item:
                if 'inet addr' in ipinfo_lines[i+1]:
                    ipv4_address = ipinfo_lines[i+1].split()[1].replace('addr:', '')
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
                if uploadipv6 and ('inet6 addr' in ipinfo_lines[i+1] or 'inet6 addr' in ipinfo_lines[i+2]):
                    if 'inet6 addr' in ipinfo_lines[i+1]: ipv6_address = ipinfo_lines[i+1].split()[2].split('/')[0]
                    else: ipv6_address = ipinfo_lines[i+2].split()[2].split('/')[0]
                    ip = {
                    'ipaddress': ipv6_address,
                    'tag': item.split("\n")[0].split()[0],
                    'macaddress' : item.split("\n")[0].split()[4],
                    'device' : device_name_in_d42,
                     }
                    ADDED, msg_ip = post(ip, 'ip')
                    if ADDED:
                        print ipv4_address + ': ' + str(msg_ip)
                    else:
                        print ipv4_address + ': failed with message = ' + str(msg_ip)
    else:
        print 'Failed with message: ' + str(msg)

def closest_memory_assumption(v):
    if v < 512: v = 128 * math.ceil(v / 128.0)
    elif v < 1024: v = 256 * math.ceil(v / 256.0)
    elif v < 4096: v = 512 * math.ceil(v / 512.0)
    elif v < 8192: v = 1024 * math.ceil(v / 1024.0)
    else: v = 2048 * math.ceil(v / 2048.0)
    return int(v)


def main():
    try:
        linux()
    except:
        traceback.print_exc()

if __name__ == "__main__":
    main()    
