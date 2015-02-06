**NOTE:**
**The following scripts are obsolete. Please use [`nix_bsd_mac_inventory`]( https://github.com/device42/nix_bsd_mac_inventory )  script instead.**  
* d42\_api\_linux\_upload\_sample\_script.py  
* d42\_api\_solaris\_sample\_script.py  
* linux\_auto\_dics\_multi.py  


[Device42](http://www.device42.com/) is a comprehensive data center inventory management and IP Address management software that integrates centralized password management, impact charts and applications mappings with IT asset management.

This project contains sample scripts to show how to use Device42 developer APIs and populate device42 appliance with your network inventory information.


## Scripts Provided
-----------------------------
   * **api-sample.py** : Runs against a single windows system and uploads info to device42 appliance
   * **ad-sample.py**  : Can run against Active directory computers, servers or a given list and upload discovered systems' info to device42 appliance.
   * **d42_api_linux_upload_sample_script.py** : Runs on a single *nix based system and uploads info to device42 appliance.
   * **sample-script-facter-facts-to-d42.py** : Runs on puppet master and uploads nodes info from facter fact files to device42 appliance.
   * **d42_api_solaris_sample_script.py**: Runs on an individual solaris system and uploads info to device42 appliance.
   * **linux_auto_dics_multi.py**: Run on a *nix system with paramiko to get inventory using ssh from an IP range and upload to d42 appliance.
   * **winservice.py**  : Can run against Active directory computers, servers or a given list and upload discovered services as application components to device42 appliance.

### Requirement
-----------------------------
   * python 2.7.x
   * ad-sample, api-sample and winservice scripts require Poweshell 1.0 or Powershell 2.0, .Net 4 and IronPython 2.7.x.
   * linux_auto_disc_multi requires installation of paramiko library. Install: sudo pip install paramiko (or Ubuntu/Debian: sudo apt-get install python-paramiko)

### Usage
-----------------------------

   * Follow the instructions in individual scripts. Instructions have been added as comments in the scripts provided.

### Further Documentation
----------------------------
   * For api-sample.py: [Windows Single machine auto-discovery script][1]
   * For ad-sample.py: [Device42 windows AD based auto-disc script doc][2]
   * For linux_auto_disc_multi.py: [Python auto-discovery script to get system inventory info for linux machines on the network][3]


[1]: http://docs.device42.com/auto-discovery/auto-discover-windows-machinesingle-apis/
[2]: http://docs.device42.com/auto-discovery/auto-populate-windows-machines-ad-apis/
[3]: http://blog.device42.com/2013/08/python-auto-discovery-script-to-get-system-inventory-info-for-linux-machines-on-the-network/

