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
# and finds the running services and adds as application components to Device42 via REST APIs
# works best with Device42 v5.6.0 and above (to automatically add the service accounts as components)
#   Requires:
#       powershell
#       ironpython
#       .net 4
#
#   to run:
#       ipy.exe ad-sample.py
#   v1.0, Created: 02-08-2014
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

D42_URL='https://your-url-here'                        #make sure to NOT to end in /
D42_USER    ='put-your-user-name-here'
D42_PASSWORD='put-your-password-here'

PATH_NAME_STRINGS_TO_IGNORE = ['system32', 'vmware', ]     #Any service running under a path containing this string will be ignored.
ADD_SERVICE_ACCOUNT_AS_DEPENDENCY = True                   #Change to False if you don't want to record dependency on service account
SERVICE_ACCOUNT_PREFIX = 'ServiceAccount_'                 #Prefix to add to service accounts to see the impact - change to '' if no prefix is required
IGNORE_ALL_SERVICES_RUNNING_AS_LOCALSYSTEM = False         #If you just want to get services running under service accounts - set this to True

DRY_RUN = False                                            #Set to True to NOT post to D42 and just print the parameters that will be sent
DEBUG = False

def post(params):
    """http post with basic-auth params is dict like object"""
    try:
        data= urllib.urlencode(params) # convert to ascii chars
        headers = {
            'Authorization' : 'Basic '+ base64.b64encode(D42_USER + ':' + D42_PASSWORD),
            'Content-Type'  : 'application/x-www-form-urlencoded'
        }

        if DRY_RUN:
            print params
        else:
            req = urllib2.Request(D42_URL, data, headers)

            if DEBUG: print '---REQUEST---',req.get_full_url()
            if DEBUG: print req.headers
            if DEBUG: print req.data

            reponse = urllib2.urlopen(req)

            if DEBUG: print '---RESPONSE---'
            if DEBUG: print reponse.getcode()
            if DEBUG: print reponse.info()
            print reponse.read()
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

def to_ascii(s):
    """remove non-ascii characters"""
    if type(s) == types.StringType:
        return s.encode('ascii','ignore')
    else:
        return str(s)

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
                services = wmi("Get-WmiObject win32_service -Comp %s" % c)
                for service in services:
                    #eprint service
                    s = 0
                    if service.get('State') == 'Running':
                        if IGNORE_ALL_SERVICES_RUNNING_AS_LOCALSYSTEM and service.get('StartName').lower() == 'localsystem':
                            continue
                        else:
                            for partial_path_name in PATH_NAME_STRINGS_TO_IGNORE:
                                if partial_path_name in service.get('PathName').lower():
                                    s = 1
                                    break
                            if s == 0:
                                args = {'name': service.get('Name')+' ('+service.get('SystemName')+' )',  'device':service.get('SystemName') }
                                if ADD_SERVICE_ACCOUNT_AS_DEPENDENCY and service.get('StartName').lower() != 'localsystem' :
                                    args.update({'depends_on': SERVICE_ACCOUNT_PREFIX + service.get('StartName')})
                                try: post(args)
                                except Exception, err: print 'Post to D42 failed with error', str(err)
            except Exception, err:
                print 'failed for machine', c, str(err)

if __name__=="__main__":
    main()