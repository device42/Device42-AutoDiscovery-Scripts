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
# queries active directorty for each computer
# adds device and ip to device42 appliances
#
#   Requires:
#       powershell
#       ironpython
#       .net 4
#
#   to run:
#       ipy.exe ad-sample.py
#
##############################################

import types
import os.path
import urllib
import urllib2
import traceback
import base64
import System
import clr

clr.AddReference("System.DirectoryServices")
clr.AddReference('System.Management.Automation')

from System.Management.Automation import RunspaceInvoke
# +---------------------------------------------------------------------------

# create a runspace to run shell commands from
RUNSPACE = RunspaceInvoke()

DOMAIN_ROLE = {
        0:"Stand Alone Workstation",
        1:"Member Workstation",
        2:"Stand Alone Server",
        3:"Member Server",
        4:"Back-up Domain Controller",
        5:"Primary Domain Controller",
    }

DRIVE_TYPE = {
        2:"Floppy",
        3:"Fixed Disk",
        5:"Removable Media",
    }

BASE_URL='http://your-url-here'

API_DEVICE_URL=BASE_URL+'/api/device/'
API_IP_URL    =BASE_URL+'/api/ip/'

USER    ='put-your-user-name-here'
PASSWORD='put-your-password-here'

DRY_RUN = False # donot post just print the request that will be send

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

            print '---REQUEST---',req.get_full_url()
            print req.headers
            print req.data

            reponse = urllib2.urlopen(req)

            print '---RESPONSE---'
            print reponse.getcode()
            print reponse.info()
            print reponse.read()
    except urllib2.HTTPError as err:
        print '---RESPONSE---'
        print err.getcode()
        print err.info()
        print err.read()
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

def main():
    banner="""\

+----------------------------------------------------+
| Admin rights are required to enumerate information |
+----------------------------------------------------+
    """
    print banner

    menu="""\
Which computer resources would you like in the report?
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
            computer_system = wmi_1("Get-WmiObject Win32_ComputerSystem -Comp %s" % c)
            operating_system = wmi_1("Get-WmiObject Win32_OperatingSystem -Comp %s" % c)
            bios = wmi_1("Get-WmiObject Win32_BIOS -Comp %s" % c)
            device = {
                'name'          : to_ascii(computer_system.get('Name')),
                'manufacturer'  : to_ascii(computer_system.get('Manufacturer')),
                'hardware'      : to_ascii(computer_system.get('Model')),
                'memory'        : to_ascii(computer_system.get('TotalPhysicalMemory')),
                'serial_no'     : to_ascii(bios.get('SerialNumber')),
                'os'            : to_ascii(operating_system.get('Caption')),
                'osver'         : to_ascii(operating_system.get('CSDVersion')),
                'osmanufacturer': to_ascii(operating_system.get('Manufacturer')),
                'osserial'      : to_ascii(operating_system.get('SerialNumber')),
                'osverno'       : to_ascii(operating_system.get('Version')),
            }
            post(API_DEVICE_URL, device)

            for ntwk in wmi("Get-WmiObject Win32_NetworkAdapterConfiguration -Comp %s | where{$_.IPEnabled -eq \"True\"}" % c):
                for ipaddr in ntwk.get('IPAddress'):
                    ip = {
                        'ipaddress'  : ipaddr,
                        'macaddress' : ntwk.get('MACAddress'),
                        'device'     : c,
                    }
                    post(API_IP_URL, ip)

if __name__=="__main__":
    main()