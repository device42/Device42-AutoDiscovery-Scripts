[Device42](http://www.device42.com/) is a comprehensive data center inventory management and IP Address management software that integrates centralized password management, impact charts and applications mappings with IT asset management.

This project contains sample scripts to show how to use Device42 developer APIs and populate device42 appliance with your network inventory information.


## Scripts Provided
-----------------------------
   * api-sample.py : Runs against a single windows system and uploads info to device42 appliance
   * ad-sample.py  : Can run against Active directory computers, servers or a given list and upload discovered systems' info to device42 appliance.
   * d42_api_linux_upload_sample_script.py : Runs on a single *nix based system and uploads info to device42 appliance.
   * sample-script-facter-facts-to-d42 : Runs on puppet master and uploads nodes info from facter fact files to device42 appliance.