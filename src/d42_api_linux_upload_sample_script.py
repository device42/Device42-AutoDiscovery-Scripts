"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

##############################################
# v1.0.4 of linux script that
# gets system info on a *nix based system, parses it and
# uploads to device42 appliance using APIs
# tested on Redhat, Fedora and Ubuntu installations
##############################################
import sys
import urllib
import urllib2
import traceback
import base64
import re
import subprocess
import math

##### Change Following 5 lines to match your environment #####
d42url = 'https://your-d42-url-here'
urluser = 'your-d42-username-here'
urlpass = 'your-d42-password-here'
uploadipv6 = True
ignoreDomain = True  #If you want to strip the domain name part from the hostname.


def to_ascii(s):
    # ignore non-ascii chars
    try: return s.encode('ascii','ignore')
    except: return None
 
def post(url, params):
    """http post with basic-auth params is dict like object"""
    result = ''
    try:
        data= urllib.urlencode(params) # convert to ascii chars
        headers = {
            'Authorization' : 'Basic '+ base64.b64encode(urluser + ':' + urlpass),
            'Content-Type' : 'application/x-www-form-urlencoded'
        }

        req = urllib2.Request(url, data, headers)

        print '---REQUEST---',req.get_full_url()
        print req.headers
        print req.data
        reponse = urllib2.urlopen(req)

        print '---RESPONSE---'
        print reponse.getcode()
        print reponse.info()
        result =  str(reponse.read())
    except urllib2.HTTPError as err:
        print '---RESPONSE---'
        print err.getcode()
        print err.info()
        result = str(err.read())
    except urllib2.URLError as err:
        print '---RESPONSE---'
        result = str(err)
    return result


def linux():
    if d42url[:-1] == '/':
        API_IP_URL = d42url + 'api/ip/'
        API_DEVICE_URL = d42url + 'api/device/'
    else:
        API_IP_URL = d42url + '/api/ip/'
        API_DEVICE_URL = d42url + '/api/device/'
    result = ''
    device_name = subprocess.Popen(['/bin/hostname'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    release = subprocess.Popen(['/usr/bin/python', '-m' 'platform'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    if ignoreDomain: device_name = to_ascii(device_name).rstrip().split('.')[0]
    else: device_name = to_ascii(device_name).rstrip()
    device = {
    'name': device_name,
    'os': release.split('-with-')[1].split('-')[0],
    'osver': release.split('-with-')[1].split('-')[1],
    #'osverno': release.split('-with-')[0],
    }
    manufacturer = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-manufacturer'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    hardware = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-product-name'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    serial_no = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-serial-number'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    uuid = subprocess.Popen(['sudo', '/usr/sbin/dmidecode', '-s', 'system-uuid'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
        if mftr == to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip():
            manufacturer = 'virtual'
            device.update({ 'manufacturer' : 'vmware', })
            break    
    if manufacturer != 'virtual':
        device.update({
            'manufacturer': to_ascii(manufacturer).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip(),
            'hardware': to_ascii(hardware).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip(),
            'serial_no': to_ascii(serial_no).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").strip(),
            })
    device.update({'uuid': to_ascii(uuid).replace("# SMBIOS implementations newer than version 2.6 are not\n# fully supported by this version of dmidecode.\n", "").rstrip()})
    memory_total = subprocess.Popen(['grep', 'MemTotal', '/proc/meminfo'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].replace(' ', '').replace('MemTotal:','').replace('kB','')
    memory = closest_memory_assumption(int(memory_total)/1024)
    cpucount = 0
    cpuspeed = ''
    cpuinfo = subprocess.Popen(['dmidecode', '-s', 'processor-frequency'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    for item in cpuinfo.split('\n'):
        if 'MHz' in item:
            cpuspeed = item.split(' ')[0]
            cpucount += 1
    corecount = 0
    coreinfo = subprocess.Popen(['dmidecode', '-t', 'processor'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    for item in coreinfo.split('\n'):
        if 'Core Count' in item:
            #corecount += 1
            corecount = item.replace('Core Count: ', '').strip()
    if corecount == 0: corecount = 1
    device.update({
        'cpucount': cpucount,
        'cpucore': corecount,
        'memory': memory,
        })
    if cpuspeed != '': 
        device.update({'cpupower': cpuspeed,})    
    result += post(API_DEVICE_URL, device)
    
    ipinfo = subprocess.Popen(['/sbin/ifconfig', '-a'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    ipinfo_lines = ipinfo.split('\n')
    
    for i, item in enumerate(ipinfo_lines):
        #print item
        if 'Ethernet' in item:
            if 'inet addr' in ipinfo_lines[i+1]:
                ipv4_address = ipinfo_lines[i+1].split()[1].replace('addr:', '')
                ip = {
                'ipaddress': ipv4_address,
                'tag': item.split("\n")[0].split()[0],
                'macaddress' : item.split("\n")[0].split()[4],
                'device' : device_name,
                 }
                result += post(API_IP_URL, ip)
            
            if uploadipv6 and ('inet6 addr' in ipinfo_lines[i+1] or 'inet6 addr' in ipinfo_lines[i+2]):
                if 'inet6 addr' in ipinfo_lines[i+1]: ipv6_address = ipinfo_lines[i+1].split()[2].split('/')[0]      
                else: ipv6_address = ipinfo_lines[i+2].split()[2].split('/')[0]      
                ip = {
                'ipaddress': ipv6_address,
                'tag': item.split("\n")[0].split()[0],
                'macaddress' : item.split("\n")[0].split()[4],
                'device' : device_name,
                 }
                result += post(API_IP_URL, ip)                

    print result    
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