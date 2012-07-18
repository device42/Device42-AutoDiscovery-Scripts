"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

################################################################
# The script goes through the yaml fact files created by facter
# and populates device42 database with following info:
#device name, manufacturer, hardware model, serial #, os info, memory, cpucount and cpucores info
# IP address, interface name and mac address.
# Script tested with python 2.4
################################################################


import types
import os.path
import urllib
import urllib2
import traceback
import base64
import sys
import glob
#Device42 URL and credentials
BASE_URL='https://your-device42-url'  #Please make sure there is no / in the end

API_DEVICE_URL=BASE_URL+'/api/device/'   
API_IP_URL =BASE_URL+'/api/ip/'          

USER ='your-user-name'
PASSWORD='your-password-here'
DRY_RUN = False

# puppet config dir
puppetdir="/var/opt/lib/pe-puppet/yaml/node/"  #Change to reflect node directory with yaml fact files.


def post(url, params):
    """http post with basic-auth params is dict like object"""
    try:
        data= urllib.urlencode(params) # convert to ascii chars
        headers = {
            'Authorization' : 'Basic '+ base64.b64encode(USER + ':' + PASSWORD),
            'Content-Type' : 'application/x-www-form-urlencoded'
        }

        if DRY_RUN:
            print url, headers, data
        else:
            req = urllib2.Request(url, data, headers)
            print '---REQUEST---',req.get_full_url()
            print req.headers
            print req.data

            response = urllib2.urlopen(req)
            print '---RESPONSE---'
            print response.read()

    except Exception, Err:
        print '-----EXCEPTION OCCURED-----'
        print str(Err)
def to_ascii(s):
    """remove non-ascii characters"""
    if type(s) == types.StringType:
        return s.encode('ascii','ignore')
    else:
        return str(s)        
def roundPow2(roundVal):
    base2val = 1
    while roundVal >= base2val:
        base2val*=2
    
    # dont round up if there the same, just give the same vars
    if roundVal == base2val/2:
        return base2val/2 # Round down and round up.
    
    
    smallRound = base2val/2
    largeRound = base2val
    
    # closest to the base 2 value
    diffLower = abs(roundVal - smallRound)
    diffHigher = abs(roundVal - largeRound)
    if diffLower < diffHigher:
        mediumRound = smallRound
    else:
        mediumRound = largeRound

    return mediumRound       
for infile in glob.glob( os.path.join(puppetdir, '*yaml') ):       
    d = {}
           
    f = open(infile)
    print "---Going through fact file: %s" % infile
    for line in f:
        if "--" not in line:

            line = line.strip().replace('"','')
            try:
                key, val = line.split(':',1)
                d[key] = val.strip()
            except: pass

    f.close()       
    device_name = to_ascii(d['clientcert'])  #using clientcert as the nodename here, you can change it to your liking.
    device = {
        'name' : device_name,
        'os' : to_ascii(d.get('operatingsystem', None)),
        'osverno' :to_ascii(d['operatingsystemrelease']),
    }
    manufacturer = ''
    for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
        if mftr == to_ascii(d['manufacturer']):
            manufacturer = 'virtual'
            device.update({ 'manufacturer' : 'vmware', })
            break    
    if manufacturer != 'virtual':
        device.update({
            'manufacturer' :  to_ascii(d['manufacturer']),
            'hardware' : to_ascii(d['productname']),
            'serial_no' : to_ascii(d['serialnumber']),  
            })  
    if d['memorysize'].split(' ')[1] == 'MB':
        memory = roundPow2(int(float(d['memorysize'].split(' ')[0])))
    else: memory = roundPow2(int(float(d['memorysize'].split(' ')[0])*1024))
    cpucount = int(d['physicalprocessorcount'])
    if cpucount == 0: cpucount = 1
    cpucore = int(d['processorcount'])
    
    device.update({
        'memory': memory,
        'cpucount': cpucount,
        'cpucore': cpucore,        
        })
    
    post(API_DEVICE_URL, device)
    interfaces =  d['interfaces'].split(',')
    for interface in interfaces:
        if not 'loopback' in interface.lower():
            ipkey = 'ipaddress'+'_'+interface.replace(' ','').lower()
            mackey  = 'macaddress'+'_'+interface.replace(' ','').lower()
            try: macaddress = d[mackey]
            except: macaddress = d.get('macaddress')
            ip = {
                'ipaddress' : d.get(ipkey, None),
                'macaddress' : macaddress,
                'device' : device_name,
                'tag': interface.replace('_', ' ')
                }
            if ip.get('ipaddress') is not None and ip.get('ipaddress') != '127.0.0.1': post(API_IP_URL, ip)

