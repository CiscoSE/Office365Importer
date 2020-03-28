# Stealthwatch: Office 365 Importer

[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/CiscoSE/Office365Importer)

## Summary

This is a script to import Microsoft Office 365 address space into Tags (Host Groups) within Stealthwatch Enterprise.

This allows for more granular tuning and identification of network flows within Stealthwatch Enterprise.

You can find more information on Stealthwatch's APIs on [Cisco DevNet](https://developer.cisco.com/docs/stealthwatch/).

## Requirements

1. Python 3.x
2. Stealthwatch 7.0 or higher
    - Updates files and documentation can be found in the Network Visibility and Segementation product category on [software.cisco.com](https://software.cisco.com/download/home/286307082)
3. Stealthwatch user credentials with the "Master Admin" role assigned.
    - User roles are configured in the Stealthwatch web interface.  Simply navigate to *Global Settings -> User Management*.

## Configuration File

The ***config.json*** file contains the following variables:

- O365_VERSION_URL: The URL containing the current version of the Microsoft Office 365 address data. (String)
- O365_ENDPOINTS_URL: The URL containing the Microsoft Office 365 address data. (String)
- GUID: A unique UUID for the script to identify itself to Microsoft. (String) **This will get generated on the first run.**
- SW_ADDRESS: The IP or FQDN of the Stealthwatch SMC. (String)
- SW_USERNAME: The Username to be used to authenticate to Stealthwatch. (String)
- SW_PASSWORD: The Password to be used to authenticate to Stealthwatch. (String)
- SW_TENANT_ID: The Stealthwatch Tenant (Domain) ID to be used. (Integer)
- SW_PARENT_TAG: The parent Tag (Host Group) ID where each Office 365 service will be imported. (Integer)

## How To Run

1. Prior to running the script for the first time, copy the ***config.example.json*** to ***config.json***.
    * ```cp config.example.json config.json```
    * **OPTIONAL:** You can manually enter configuration data in the ***config.json*** file if desired. By default, the script will assume it needs to create a parent Tag (Host Group) called "Microsoft Office 365" in the **Outside** host group. If you wish to use a different Tag (Host Group), create it in Stealthwatch, then add the ID number to ***config.json***.
2. Install the required packages from the ***requirements.txt*** file.
    * ```pip install -r requirements.txt```
    * You'll probably want to set up a virtual environment: [Python 'venv' Tutorial](https://docs.python.org/3/tutorial/venv.html)
    * Activate the Python virtual environment, if you created one.
3. Run the script with ```python office_365_importer.py```

> If you didn't manually enter configuration data, you'll get prompted for the Stealthwatch IP/FQDN, Username, and Password. The script will store these credentials in the ***config.json*** file for future use. **This means you probably want to make the ***config.json*** file read-only. You probably will also want to create unique credentials for scripting/API purposes.**

The script will automatically try to determine your Stealthwatch Tenant ID, and store that in the ***config.json*** file as well.

## Docker Container

This script is Docker friendly, and can be deployed as a container.

To build the container, run the script once to populate the ***config.json*** file, or manually populate the configuration variables.

Once the ***config.json*** file is populated, run the following command to build the container:

- ```docker build -t office-365-importer .```

You can then run the container as a daemon with the following command:

- ```docker run -d --name office-365-importer office-365-importer```
