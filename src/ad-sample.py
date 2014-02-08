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
# queries active directory for each computer
# adds device and ip to device42 appliance via REST APIs
#
#   Requires:
#       powershell
#       ironpython
#       .net 4
#
#   to run:
#       ipy.exe ad-sample.py
#   v2.2, Updated: 02-08-2014
##############################################

import types
import os.path
import urllib
import urllib2
import traceback
import base64
import System
import clr
import math
clr.AddReference("System.DirectoryServices")
clr.AddReference('System.Management.Automation')

from System.Management.Automation import RunspaceInvoke
# +---------------------------------------------------------------------------

# create a runspace to run shell commands from
RUNSPACE = RunspaceInvoke()

BASE_URL='https://your-url-here'        #make sure to NOT to end in /

API_DEVICE_URL=BASE_URL+'/api/device/'
API_IP_URL    =BASE_URL+'/api/ip/'

USER    ='put-your-user-name-here'
PASSWORD='put-your-password-here'

DRY_RUN = False # donot post just print the request that will be send
DEBUG = True

def post(url, params):
    """http post with basic-auth params is dict like object"""
    try:
        data= urllib.urlencode(params) # convert to ascii chars
        headers = {
            'Authorization' : 'Basic '+ base64.b64encode(USER + ':' + PASSWORD),
            'Content-Type'  : 'application/x-www-form-urlencoded'
        }

        if DRY_RUN:
            print url, headers, data
        else:
            req = urllib2.Request(url, data, headers)

            if DEBUG: print '---REQUEST---',req.get_full_url()
            if DEBUG: print req.headers
            if DEBUG: print req.data

            reponse = urllib2.urlopen(req)

            if DEBUG: print '---RESPONSE---'
            if DEBUG: print reponse.getcode()
            if DEBUG: print reponse.info()
            if DEBUG: print reponse.read()
    except urllib2.HTTPError as err:
        print '---RESPONSE---'
        if DEBUG: print err.getcode()
        if DEBUG: print err.info()
        if DEBUG: print err.read()
    except urllib2.URLError as err:
        print '---RESPONSE---'
        print err

def get_computers():
    """Enumerates ALL computer objects in AD"""
    searcher = System.DirectoryServices.DirectorySearcher()
    searcher.SearchRoot = System.DirectoryServices.DirectoryEntry()
    searcher.Filter = "(objectCategory=computer)"
    searcher.PropertiesToLoad.Add("name")
    return sorted([a for item in searcher.FindAll() for a in item.Properties['name']])

def get_servers():
    """Enumerates ALL Servers objects in AD"""
    searcher = System.DirectoryServices.DirectorySearcher()
    searcher.SearchRoot = System.DirectoryServices.DirectoryEntry()
    searcher.Filter = "(&(objectCategory=computer)(OperatingSystem=Windows*Server*))"
    searcher.PropertiesToLoad.Add("name")
    return sorted([a for item in searcher.FindAll() for a in item.Properties['name']])

def get_fromfile():
    """Enumerates Computer Names in a text file Create a text file and enter
    the names of each computer. One computer name per line. Supply the path
    to the text file when prompted.
    """
    while True:
        filename = raw_input('Enter the path for the text file: ')
        if filename:
            if not os.path.exists(filename):
                print "file not exists or insufficient permissions '%s'" % filename
            elif not os.path.isfile(filename):
                print "not a file, may be a dir '%s'" % filename
            else:
                f = open(filename)
                try: computers = [line.strip() for line in f]
                finally: f.close()
                return sorted(computers)

def get_frommanualentry():
    """'SingleEntry' - Enumerates Computer from user input"""
    while True:
        c = raw_input('Enter Computer Name or IP: ')
        if c: return [c]

def wmi(query):
    """create list of dict from result of wmi query"""
    return [dict([(prop.Name, prop.Value) for prop in psobj.Properties])
        for psobj in RUNSPACE.Invoke(query)]

def wmi_1(query):
    a = wmi(query)
    if a: return a[0]
    else: return {}

def to_ascii(s):
    """remove non-ascii characters"""
    if type(s) == types.StringType:
        return s.encode('ascii','ignore')
    else:
        return str(s)
        
def closest_memory_assumption(v):
    if v < 512: v = 128 * math.ceil(v / 128.0)
    elif v < 1024: v = 256 * math.ceil(v / 256.0)
    elif v < 4096: v = 512 * math.ceil(v / 512.0)
    elif v < 8192: v = 1024 * math.ceil(v / 1024.0)
    else: v = 2048 * math.ceil(v / 2048.0)
    return int(v)
        
def main():
    banner="""\

+----------------------------------------------------+
| Domain Admin rights are required to enumerate information |
+----------------------------------------------------+
    """
    print banner

    menu="""\
Which computer resources would you like to run auto-discovery on?
    [1] All Domain Computers
    [2] All Domain Servers
    [3] Computer names from a File
    [4] Choose a Computer manually
    """
    while True:
        resp = raw_input(menu)
        if   resp == '1': computers = get_computers(); break
        elif resp == '2': computers = get_servers(); break
        elif resp == '3': computers = get_fromfile(); break
        elif resp == '4': computers = get_frommanualentry(); break

    if not computers:
        print "ERROR: No computer found"
    else:
        for c in computers:
            try:
                computer_system = wmi_1("Get-WmiObject Win32_ComputerSystem -Comp %s" % c)
                operating_system = wmi_1("Get-WmiObject Win32_OperatingSystem -Comp %s" % c)
                bios = wmi_1("Get-WmiObject Win32_BIOS -Comp %s" % c)
                mem = closest_memory_assumption(int(computer_system.get('TotalPhysicalMemory')) / 1047552)
                dev_name = to_ascii(computer_system.get('Name')).lower()
                device = {
                    'name'          : dev_name,
                    'memory'        : mem,
                }
                if 'Caption' in operating_system:
                    device.update({'os' : to_ascii(operating_system.get('Caption'))})
                    if 'CSDVersion' in operating_system: device.update({'osver' : to_ascii(operating_system.get('CSDVersion'))})
                    if 'Manufacturer' in operating_system: device.update({'osmanufacturer': to_ascii(operating_system.get('Manufacturer'))})
                    if 'SerialNumber' in operating_system: device.update({'osserial' : to_ascii(operating_system.get('SerialNumber'))})
                    if 'Version' in operating_system: device.update({'osverno' : to_ascii(operating_system.get('Version'))})
                manufacturer = ''
                for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
                    if mftr == to_ascii(computer_system.get('Manufacturer')).strip():
                        manufacturer = 'virtual'
                        device.update({ 'manufacturer' : 'vmware', })
                        break
                if manufacturer != 'virtual':
                    device.update({
                        'manufacturer': to_ascii(computer_system.get('Manufacturer')).strip(),
                        'hardware': to_ascii(computer_system.get('Model')).strip(),
                        'serial_no': to_ascii(bios.get('SerialNumber')).strip(),
                        })
                cpucount = 0
                for cpu in wmi("Get-WmiObject Win32_Processor -Comp %s" % c):
                    cpucount += 1
                    cpuspeed = cpu.get('MaxClockSpeed')
                    cpucores = cpu.get('NumberOfCores')
                if cpucount > 0:

                    device.update({
                        'cpucount': cpucount,
                        'cpupower': cpuspeed,
                        'cpucore':  cpucores,
                        })


                post(API_DEVICE_URL, device)

                for ntwk in wmi("Get-WmiObject Win32_NetworkAdapterConfiguration -Comp %s | where{$_.IPEnabled -eq \"True\"}" % c):
                    for ipaddr in ntwk.get('IPAddress'):
                        ip = {
                            'ipaddress'  : ipaddr,
                            'macaddress' : ntwk.get('MACAddress'),
                            'tag'        : ntwk.get('Description'),
                            'device'     : dev_name,
                        }
                        try: post(API_IP_URL, ip)
                        except: print 'Exception occured trying to upload info for IP: %s' % ipaddr
            except Exception, err:
                print 'failed for machine', c, str(err)
if __name__=="__main__":
    main()