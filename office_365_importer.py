#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# office_365_importer.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 10/20/2019
#
############################################################

import argparse
import getpass
import json
import os
import shutil
import time
import uuid

import requests

from stealthwatch_client import StealthwatchClient

# Config Paramters
CONFIG_FILE = "config.json"
CONFIG_DATA = {}

# Set a wait interval (in seconds) - Microsoft recommends an minimum of 1 hour
INTERVAL = 3600


####################
#    FUNCTIONS     #
####################


def load_config(retry=False):
    """Load configuration data from file."""

    print("Loading configuration data...")

    # If we have a stored config file, then use it, otherwise terminate
    if os.path.isfile(CONFIG_FILE):

        # Open the CONFIG_FILE and load it
        with open(CONFIG_FILE, "r") as config_file:
            CONFIG_DATA = json.loads(config_file.read())

        print("Configuration data loaded successfully.")

        return CONFIG_DATA

    else:
        # Check to see if this is the initial load_config attempt
        if not retry:

            # Print that we couldn't find the config file, and attempt to copy the example
            print("The configuration file was not found. Copying 'config.example.json' file to '{}', and retrying...".format(CONFIG_FILE))
            shutil.copyfile('config.example.json', CONFIG_FILE)

            # Try to reload the config
            return load_config(retry=True)
        else:

            # Exit gracefully if we cannot load the config
            print("Unable to automatically create config file. Please copy 'config.example.json' to '{}' manually.".format(CONFIG_FILE))
            exit()


def save_config():
    """Save configuration data to file."""

    with open(CONFIG_FILE, "w") as output_file:
        json.dump(CONFIG_DATA, output_file, indent=4)


def get_current_version():
    """Retrieve the latest version number of the Office 365 address feed."""

    # Build the URL to request
    url = CONFIG_DATA["O365_VERSION_URL"] + "?clientrequestid=" + CONFIG_DATA["GUID"]

    try:
        # Fetch the version info from Microsoft
        response = requests.get(url)

        # Check to make sure the GET was successful
        if response.status_code == 200:

            return response.json()["latest"]

    except Exception as err:
        print("Error fetching version info from Microsoft: " + str(err))
        exit(1)


def get_new_addresses():
    """Retrieve the latest IP address from Microsoft and return a dictionary of IPs by service."""

    print("Fetching address ranges from Microsoft...")

    # Build the URL to request
    url = CONFIG_DATA["O365_ENDPOINTS_URL"] + "?clientrequestid=" + CONFIG_DATA["GUID"]

    try:
        # Get the latest address feed from Microsoft
        response = requests.get(url)

        # If the request was successful
        if response.status_code >= 200 or response.status_code < 300:

            # A placeholder list for IPs
            ip_dict = {}

            services = response.json()

            # Iterate through each service
            for service in services:

                # If this service object contains IP addresses
                if "ips" in service.keys():

                    # If it"s a new service, then initialize a list
                    if service["serviceAreaDisplayName"] not in ip_dict.keys():
                        ip_dict[service["serviceAreaDisplayName"]] = []

                    # For each IP range in the service, append it to the list
                    for ip_range in service["ips"]:
                        ip_dict[service["serviceAreaDisplayName"]].append(ip_range)

            return ip_dict

        else:
            print("Failed to get data from Microsoft. Terminating.")
            exit()

    except Exception as err:
        print("Unable to get the Office 365 address feed - Error: {}".format(err))
        exit()


def main():
    """This is a function to run the main logic of the Office 365 Importer."""

    # Get the latest version of the feed from Microsoft
    current_version = get_current_version()

    # If the latest version is higher than our last imported version, then import the new stuff
    if current_version > CONFIG_DATA["LAST_VERSION_IMPORTED"]:

        # Get the latest IP list from Microsoft
        ip_dict = get_new_addresses()

        # Instantiate a new StealthwatchClient
        stealthwatch = StealthwatchClient(validate_certs=False)

        # Login to Stealtwatch
        stealthwatch.login(CONFIG_DATA["SW_ADDRESS"], CONFIG_DATA["SW_USERNAME"], CONFIG_DATA["SW_PASSWORD"])

        # If a Domain ID wasn't specified, then get one
        if not CONFIG_DATA["SW_TENANT_ID"]:

            # Get Tenants from REST API, and save it
            CONFIG_DATA["SW_TENANT_ID"] = stealthwatch.get_tenants()
            save_config()

        else:

            # Set the Tenant ID
            stealthwatch.set_tenant_id(CONFIG_DATA["SW_TENANT_ID"])

        # If a parent Tag isn't specified, then create one
        if not CONFIG_DATA["SW_PARENT_TAG"]:

            # Create the Tag
            response = stealthwatch.create_tag(0, "Microsoft Office 365")

            # Save the parent Tag/Host Group ID
            CONFIG_DATA["SW_PARENT_TAG"] = response["data"][0]["id"]
            save_config()

        print("Uploading data to Stealthwatch...")

        # Iterate through each of the Office 365 services
        for service_name, ip_list in ip_dict.items():

            # If the host group was already created for the service, update that, otherwise create one
            if service_name in CONFIG_DATA.keys():

                # Update the Tag (Host Group) with the latest data
                stealthwatch.update_tag(CONFIG_DATA["SW_PARENT_TAG"], CONFIG_DATA[service_name], service_name, ip_list)
            else:
                # Create a new Tag (Host Group) for the Office 365 service
                response = stealthwatch.create_tag(CONFIG_DATA["SW_PARENT_TAG"], service_name, ip_list)

                # Save the new Tag/Host Group ID
                CONFIG_DATA[service_name] = response["data"][0]["id"]
                save_config()

        # Update the latest imported version
        CONFIG_DATA["LAST_VERSION_IMPORTED"] = current_version
        save_config()

        print("Office 365 addresses successfully imported.")

    else:
        print("Last imported data is up-to-date.")
        return


####################
# !!! DO WORK !!!  #
####################


if __name__ == "__main__":

    # Set up an argument parser
    parser = argparse.ArgumentParser(description="A script to import Office 365 addresses into Stealthwatch")
    parser.add_argument("-d", "--daemon", help="Run the script as a daemon", action="store_true")
    args = parser.parse_args()

    # Load configuration data from file
    CONFIG_DATA = load_config()

    # If there's no GUID, then make one
    if not CONFIG_DATA["GUID"]:

        # Generate the GUID and save it
        CONFIG_DATA["GUID"] = str(uuid.uuid4())
        save_config()

    # If not hard coded, get the SMC Address, Username and Password
    if not CONFIG_DATA["SW_ADDRESS"]:
        CONFIG_DATA["SW_ADDRESS"] = input("Stealthwatch IP/FQDN Address: ")
        save_config()
    if not CONFIG_DATA["SW_USERNAME"]:
        CONFIG_DATA["SW_USERNAME"] = input("Stealthwatch Username: ")
        save_config()
    if not CONFIG_DATA["SW_PASSWORD"]:
        CONFIG_DATA["SW_PASSWORD"] = getpass.getpass("Stealthwatch Password: ")
        save_config()

    if args.daemon:
        while True:
            main()
            print("Waiting {} seconds...".format(INTERVAL))
            time.sleep(INTERVAL)
    else:
        main()
