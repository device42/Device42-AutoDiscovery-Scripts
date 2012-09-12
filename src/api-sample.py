"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
##################################################
# a sample script to show how to use
#   /api/ip/add-or-update
#   /api/device/add-or-update
#
# requires ironPython (http://ironpython.codeplex.com/) and
# powershell (http://support.microsoft.com/kb/968929)
##################################################

import clr

clr.AddReference('System.Management.Automation')

from System.Management.Automation import (
    PSMethod, RunspaceInvoke
)
RUNSPACE = RunspaceInvoke()

import urllib
import urllib2
import traceback
import base64
import math
BASE_URL='http://your-url-here'

API_DEVICE_URL=BASE_URL+'/api/device/'
API_IP_URL    =BASE_URL+'/api/ip/'

USER    ='put-your-user-name-here'
PASSWORD='put-your-password-here'

def post(url, params):
    """
    http post with basic-auth
    params is dict like object
    """
    try:
        data= urllib.urlencode(params) # convert to ascii chars
        headers = {
            'Authorization' : 'Basic '+ base64.b64encode(USER + ':' + PASSWORD),
            'Content-Type'  : 'application/x-www-form-urlencoded'
        }

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

def to_ascii(s):
    # ignore non-ascii chars
    return s.encode('ascii','ignore')

def wmi(query):
    return [dict([(prop.Name, prop.Value) for prop in psobj.Properties]) for psobj in RUNSPACE.Invoke(query)]
def closest_memory_assumption(v):
    return int(256 * math.ceil(v / 256.0))


def add_or_update_device():
    computer_system  = wmi('Get-WmiObject Win32_ComputerSystem -Namespace "root\CIMV2"')[0] # take first
    bios             = wmi('Get-WmiObject Win32_BIOS -Namespace "root\CIMV2"')[0]
    operating_system = wmi('Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2"')[0]
    mem = closest_memory_assumption(int(computer_system.get('TotalPhysicalMemory')) / 1047552)
    dev_name = to_ascii(computer_system.get('Name')).lower()
    device = {
        'name'          : dev_name,
        'memory'        : mem,
        'os'            : to_ascii(operating_system.get('Caption')),
        'osver'         : operating_system.get('CSDVersion'),
        'osmanufacturer': to_ascii(operating_system.get('Manufacturer')),
        'osserial'      : operating_system.get('SerialNumber'),
        'osverno'       : operating_system.get('Version'),
    }
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
    for cpu in wmi('Get-WmiObject Win32_Processor  -Namespace "root\CIMV2"'):
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


    network_adapter_configuration = wmi('Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}')

    for ntwk in network_adapter_configuration:
        for ipaddr in ntwk.get('IPAddress'):
            ip = {
                'ipaddress'  : ipaddr,
                'macaddress' : ntwk.get('MACAddress'),
                'tag'        : ntwk.get('Description'),
                'device'     : dev_name,
            }
            post(API_IP_URL, ip)

def main():
    try:
        add_or_update_device()
    except:
        traceback.print_exc()

if __name__ == "__main__":
    main()
