[Device42](http://www.device42.com/) is a comprehensive data center inventory management and IP Address management software that integrates centralized password management, impact charts and applications mappings with IT asset management.

This project contains sample scripts to show how to use Device42 developer APIs and populate device42 appliance with your network inventory information.


## Scripts Provided
-----------------------------
   * api-sample.py : Runs against a single windows system and uploads info to device42 appliance
   * ad-sample.py  : Can run against Active directory computers, servers or a given list and upload discovered systems' info to device42 appliance.
   * d42_api_linux_upload_sample_script.py : Runs on a single *nix based system and uploads info to device42 appliance.
   * sample-script-facter-facts-to-d42 : Runs on puppet master and uploads nodes info from facter fact files to device42 appliance.
   * d42_api_solaris_sample_script.py: Runs on an individual solaris system and uploads info to device42 appliance.
   * linux_auto_dics_multi.py: Run on a *nix system with paramiko to get inventory using ssh from an IP range and upload to d42 appliance.

### Requirement
-----------------------------
   * python 2.7.x
   * ad-sample and api-sample scripts require Poweshell 1.0 or Powershell 2.0.
   * linux_auto_disc_multi requires installation of paramiko library. Install: sudo pip install paramiko (or Ubuntu/Debian: sudo apt-get install python-paramiko)

### Usage
-----------------------------

Follow the instructions in individual scripts. Instructions have been added as comments in the scripts provided.


### Further Documentation
----------------------------

    * For api-sample.py: http://docs.device42.com/auto-discovery/auto-discover-windows-machinesingle-apis/
    * For ad-sample.py: http://docs.device42.com/auto-discovery/auto-populate-windows-machines-ad-apis/



