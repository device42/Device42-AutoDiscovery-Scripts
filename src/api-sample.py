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

clr.AddReference('System.Management') # Added for DateTime Conversion
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
import ssl
import functools
BASE_URL = 'https://d42applianceaddress'

API_DEVICE_URL = BASE_URL + '/api/1.0/devices/'
API_IP_URL = BASE_URL + '/api/1.0/ips/'
API_CUSTOMFIELD_URL = BASE_URL+'/api/1.0/device/custom_field/'

USER = 'd42username'
PASSWORD = 'd42password'


old_init = ssl.SSLSocket.__init__
@functools.wraps(old_init)
def init_with_tls1(self, *args, **kwargs):
    kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
    old_init(self, *args, **kwargs)
ssl.SSLSocket.__init__ = init_with_tls1


def api_call(url, method, params=None):
    """
    http with basic-auth
    method is string of http method
    params is dict like object
    """
    try:
        data = urllib.urlencode(dict([k, str(v).encode('utf-8')] for k, v in params.items()))  # convert to ascii chars
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(USER + ':' + PASSWORD),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if params:
            req = urllib2.Request(url=url, data=data, headers=headers)
        else:
            req = urllib2.Request(url=url, headers=headers)
        if method == 'PUT' :
            req.get_method = lambda: method

        print '---REQUEST---', req.get_full_url()
        print req.headers
        print req.data

        # turn off https check
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reponse = urllib2.urlopen(req, context=ctx)

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
    return s.encode('ascii', 'ignore')


def wmi(query):
    return [dict([(prop.Name, prop.Value) for prop in psobj.Properties]) for psobj in RUNSPACE.Invoke(query)]


def closest_memory_assumption(v):
    return int(256 * math.ceil(v / 256.0))


def add_or_update_device():
    computer_system = wmi('Get-WmiObject Win32_ComputerSystem -Namespace "root\CIMV2"')[0]  # take first
    bios = wmi('Get-WmiObject Win32_BIOS -Namespace "root\CIMV2"')[0]
    operating_system = wmi('Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2"')[0]
    mem = closest_memory_assumption(int(computer_system.get('TotalPhysicalMemory')) / 1047552)
    dev_name = to_ascii(computer_system.get('Name')).lower()
    device = {
        'name': dev_name,
        'memory': mem,
        'os': to_ascii(operating_system.get('Caption')),
        'osver': operating_system.get('CSDVersion'),
        'osmanufacturer': to_ascii(operating_system.get('Manufacturer')),
        'osserial': operating_system.get('SerialNumber'),
        'osverno': operating_system.get('Version'),
    }
    manufacturer = ''
    for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
        if mftr == to_ascii(computer_system.get('Manufacturer')).strip():
            manufacturer = 'virtual'
            device.update({'manufacturer': 'vmware', })
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
    api_call(API_DEVICE_URL, 'POST', device)

    network_adapter_configuration = wmi('Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}')
    for ntwk in network_adapter_configuration:
        for ipaddr in ntwk.get('IPAddress'):
            ip = {
                'ipaddress' : ipaddr,
                'macaddress': ntwk.get('MACAddress'),
                'tag': ntwk.get('Description'),
                'device': dev_name,
            }
            api_call(API_IP_URL, 'POST', ip)

    # Update Custom Field using PUT method
    domname = to_ascii(computer_system.get('Domain')).lower()
    dom = {
        'name': dev_name, 
        'key': 'Domain', 
        'value': domname
    }
    api_call(API_CUSTOMFIELD_URL, 'PUT', dom)

def main():
    try:
        add_or_update_device()
    except:
        traceback.print_exc()

if __name__ == "__main__":
    main()
