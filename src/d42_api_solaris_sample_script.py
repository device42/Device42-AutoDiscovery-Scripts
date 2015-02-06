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

##############################################
# v1.0.0P1 Beta of solaris script that
# gets system info from a solaris system, parses it and
# uploads to device42 appliance using APIs
# tested on Solaris Sparc 10(sparc and x86)
##############################################
import types
import subprocess
import re
import urllib2
import urllib
import base64

##### Change Following 4 lines to match your environment #####
d42url = 'https://your-d42-url-here'
urluser = 'your-d42-username-here'
urlpass = 'your-d42-password-here'
ignoreDomain = True  #If you want to strip the domain name part from the hostname.

def post(url, params):
    result = ''
    try:
        data= urllib.urlencode(params)
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
        print reponse
        result =  str(reponse.read())
    except Exception, Err:
        print '-----EXCEPTION OCCURED-----'
        print str(Err)
    return result

def to_ascii(s):
    """remove non-ascii characters"""
    if type(s) == types.StringType:
        return s.encode('ascii','ignore')
    else:
        return str(s)   
def cpu():
    cpu_info = {}
    cpu= subprocess.Popen(['psrinfo', '-v'], stdout=subprocess.PIPE)
    i = cpu.stdout.readlines()[2]
    info = re.findall("The (.+) processor operates at (.+) MHz", i)
    cpu_info['cpupower'] = info[0][1]
    cpu= subprocess.Popen(['psrinfo', '-p'], stdout=subprocess.PIPE)
    cpus = cpu.stdout.readlines()
    cpu_info['cpucount'] = cpus[0][0]
    cpu = subprocess.Popen(['kstat', 'cpu_info'], stdout=subprocess.PIPE)
    cores = 0
    for x in cpu.stdout.readlines():
        if "core_id" in x:
            cores +=1
    cpu_info["Cores"] = str(cores)
    try:
        cpu_info["cpucore"] = str(cores/int(cpus[0][0]))
    except:
        cpu_info["Cores per CPU"] = "N/A"
    return cpu_info
    
def memory():
    memory_info = {}
    mem = subprocess.Popen(['prtconf'], stdout = subprocess.PIPE)
    for x in mem.stdout.readlines():
        if "Memory" in x:
            break
    m = re.findall("Memory size: (.+)", x)[0].split(" ")
    memory_info['memory'] = m[0]
    return memory_info

def ip():
    ip_info = []
    i = subprocess.Popen(['ifconfig', '-a'], stdout=subprocess.PIPE)
    out = i.stdout.readlines()
    devices = []
    num = 0
    for x in out:
        if ":" in x and "ether" not in x:
            devices.append([x])
            if len(devices)!=1:
                num +=1
        else:
            devices[num].append(x)
    for x in devices:
        device_specs = {}
        switch = {'inet':'ipaddress', 'ether':'macaddress'}
        device_name = x[0].split(" ")[0].strip(":")
        dev_info = "".join(x)
        specs = []
        specs.append(re.compile("(inet .+)", re.DOTALL).findall(dev_info))
        #----Extra information not passed to the post function, can be added in future by
        #----referencing it as "list[number].split()[1]" ([0] is its name)
        specs.append(re.compile("(netmask .+)", re.DOTALL).findall(dev_info))
        specs.append(re.compile("(broadcast .+)", re.DOTALL).findall(dev_info))
        specs.append(re.compile("(groupname .+)", re.DOTALL).findall(dev_info))
        #----
        specs.append(re.compile("(ether .+)", re.DOTALL).findall(dev_info))
        for spec in specs:
            if spec != []:
                if spec[0].split()[0].strip() == "inet" or spec[0].split()[0].strip() == "ether":
                    device_specs[switch[spec[0].split()[0].strip()]] = spec[0].split()[1].strip()
        device_specs.update({'tag':device_name})
        ip_info.append(device_specs)
    return ip_info

def sys():
    sys_info = {}
    info = subprocess.Popen(["uname", "-i"], stdout = subprocess.PIPE)
    i = info.stdout.readline()
    prtdiag = subprocess.Popen(["/usr/platform/"+i.strip()+"/sbin/prtdiag"], stdout = subprocess.PIPE)
    prtdiagout = prtdiag.stdout.readline()
    uname = subprocess.Popen(['uname', '-a'], stdout = subprocess.PIPE)
    u = uname.stdout.readline()
    sys_info['os'] = u.split()[0] + " " + u.split()[2]
    sys_info['osver'] = u.split()[3]
    showrev = subprocess.Popen(['showrev', '-p'], stdout = subprocess.PIPE)
    p = showrev.stdout.readlines()
    patch = p[len(p)-1].split()[1]
    sys_info['osverno'] = patch    
    sys = re.findall("System Configuration: (.+)", prtdiagout)[0]
    manufacturer = " ".join(sys.split()[0:2])
    for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen', 'innotek']:
        if mftr.lower() == to_ascii(manufacturer).lower():
            manufacturer = 'virtual'
            sys_info['manufacturer'] = 'vmware'
            break    
    if manufacturer != 'virtual':
        sys_info['manufacturer'] = manufacturer
        sys_info['hardware'] = " ".join(sys.split(" ")[len(sys.split(" "))-3:])    
        try:
            smbios = subprocess.Popen(['smbios'], stdout = subprocess.PIPE)
            smbiosout = smbios.stdout.readlines()
            for line in smbiosout:
                if "Serial Number:" in line:
                    sys_info['serial_no'] = line.strip("Serial Number: ").strip()
        except:
            pass
    return sys_info

if d42url[:-1] == '/':
        API_IP_URL = d42url + 'api/ip/'
        API_DEVICE_URL = d42url + 'api/device/'
else:
        API_IP_URL = d42url + '/api/ip/'
        API_DEVICE_URL = d42url + '/api/device/'
name = subprocess.Popen(['hostname'], stdout = subprocess.PIPE)
name = name.stdout.readlines()[0].strip("\n")
if ignoreDomain: name = to_ascii(name).strip().split('.')[0]
else: name = to_ascii(name).strip()
device = {'name':name}
device.update(cpu())
device.update(sys())
device.update(memory())
post(API_DEVICE_URL, device)
i = {}
for i in ip():
    i['device'] = name
    if 'macaddress' in i: i['macaddress'] = ":".join([j.zfill(2) for j in i['macaddress'].split(":")]).lower()
    if i.get('ipaddress') is not None and i.get('ipaddress') != '127.0.0.1' and i.get('ipaddress') != '0.0.0.0': post(API_IP_URL, i)

