######## Imports #########
import logging
import ipaddress
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database
from bs4 import BeautifulSoup

######## Description #############
route_name = "maxpatrol_vm"  # [a-zA-Z0-9_]

tools_description = [  # array with tools information (to join same tools process algorith, like Nmap and masscan)
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/7t0YYfTQ/7mwaiv8d2jf4dvukreevy74rrge04cqy.jpg",  # upload icon to IMG-BB etc
        "Official name": "MaxPatrol VM",
        "Short name": "maxpatrol_vm",  # [a-zA-Z0-9_]
        "Description": "Next-generation vulnerability management system. The solution allows you to build a full-fledged vulnerability management process and control it during both routine operation and urgent scanning.",
        # can use HTML inside.
        "URL": "https://global.ptsecurity.com/products/maxpatrol-vm",
        "Plugin author": "@drakylar"  # Change as you want :)
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    # Example multiple file upload field
    # must not be "access_token"
    xml_files = MultipleFileField(label='xml_files',  # same as variable name
                                  description="XML-report",  # short description
                                  default=None,
                                  validators=[],
                                  # Validate argument - https://wtforms.readthedocs.io/en/2.3.x/validators/
                                  _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"})

    ports_description = StringField(label='ports_description',
                                    validators=[],
                                    description="Ports description",
                                    default="Added from MaxPatrol VM scan",
                                    _meta={"display_row": 1, "display_column": 2, "file_extensions": ""})

    hosts_description = StringField(label='hosts_description',
                                    description="Hosts description",
                                    validators=[],
                                    default="Added from MaxPatrol VM scan",
                                    _meta={"display_row": 2, "display_column": 1, "file_extensions": ""})
    hostnames_description = StringField(label='hostnames_description',
                                        validators=[],
                                        default="Added from MaxPatrol VM scan",
                                        description="Hostnames description",
                                        _meta={"display_row": 2, "display_column": 2, "file_extensions": ""})


def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # fields variables
    xml_files = input_dict["xml_files"]
    ports_description = input_dict["ports_description"]
    hosts_description = input_dict["hosts_description"]
    hostnames_description = input_dict["hostnames_description"]

    for bin_file_data in xml_files:
        try:
            # scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            scan_result = BeautifulSoup(bin_file_data.decode('utf-8'), "lxml")
            for asset_obj in scan_result.find("root").findAll("assets"):
                # Windows hosts
                if asset_obj.find("_x0040_windowshost"):
                    # windows
                    issue_hostname = asset_obj.find('_x0040_windowshost').text.split(" (")[0].strip()
                    issue_ip = asset_obj.find('_x0040_windowshost').text.split(" (")[1].strip(" )(")
                    issue_os = asset_obj.find('windowshost.osname').text + " " + asset_obj.find(
                        'windowshost.osversion').text
                    issue_service_name = ""
                    issue_tech_info = ""
                    issue_cve = asset_obj.find('windowshost._x0040_nodevulners.cves').text
                    issue_cvss = float(asset_obj.find('windowshost._x0040_nodevulners.score').text.replace(",", "."))
                    issue_name = asset_obj.find('windowshost._x0040_nodevulners').text
                    issue_description = asset_obj.find('windowshost._x0040_nodevulners.description').text
                    issue_fix = asset_obj.find('windowshost._x0040_nodevulners.howtofix').text
                elif asset_obj.find("_x0040_unixhost"):
                    # linux
                    issue_hostname = asset_obj.find('_x0040_unixhost').text.split(" (")[0].strip()
                    issue_ip = asset_obj.find('_x0040_unixhost').text.split(" (")[1].strip(" )(")
                    issue_os = asset_obj.find('unixhost.osname').text + " " + asset_obj.find(
                        'unixhost.osversion').text
                    issue_service_name = asset_obj.find('unixhost.packages.name').text + " " + asset_obj.find(
                        'unixhost.packages.version').text
                    issue_tech_info = ""
                    issue_cve = asset_obj.find('unixhost.packages._x0040_nodevulners.cves').text
                    issue_cvss = float(
                        asset_obj.find('unixhost.packages._x0040_nodevulners.score').text.replace(",", "."))
                    issue_name = "{} ({})".format(asset_obj.find('unixhost.packages._x0040_nodevulners').text,
                                                  asset_obj.find('unixhost.packages.name').text)
                    issue_description = asset_obj.find('unixhost.packages._x0040_nodevulners.description').text
                    issue_fix = asset_obj.find('unixhost.packages._x0040_nodevulners.howtofix').text
                elif asset_obj.find("softwarename"):
                    # soft
                    issue_hostname = asset_obj.find('_x0040_host').text.split(" (")[0].strip()
                    issue_ip = asset_obj.find('_x0040_host').text.split(" (")[1].strip(" )(")
                    issue_os = asset_obj.find('host.osname').text
                    issue_service_name = asset_obj.find('softwarename').text + " " + asset_obj.find(
                        'softwareversion').text
                    issue_tech_info = asset_obj.find('host.softs._x0040_vulners.vulnerableentity.path').text
                    issue_cve = asset_obj.find('host.softs._x0040_vulners.cves').text
                    issue_cvss = float(
                        asset_obj.find('host.softs._x0040_vulners.score').text.replace(",", "."))
                    issue_name = "{} ({})".format(asset_obj.find('vulners').text, asset_obj.find('softwarename').text)
                    issue_description = asset_obj.find('host.softs._x0040_vulners.description').text
                    issue_fix = asset_obj.find('host.softs._x0040_vulners.howtofix').text
                else:
                    return "Provided XML has a non windows/linux/software asset!"

                ipaddress.ip_address(issue_ip)
                if issue_cvss > 10 or issue_cvss < 0:
                    return "CVSS is not in range (0..10)"

                # creating host
                current_host = db.select_project_host_by_ip(current_project['id'], issue_ip)
                if current_host:
                    current_host_id = current_host[0]['id']
                else:
                    current_host_id = db.insert_host(current_project['id'], issue_ip, current_user['id'],
                                                     comment=hosts_description,
                                                     os=issue_os)
                current_port_id = db.select_host_port(current_host_id, 0, True)[0]['id']
                issue_hostname = issue_hostname.strip(" \r\n\t")
                current_hostname_id = None
                if issue_hostname:
                    current_hostname_id = db.select_ip_hostname(current_host_id, issue_hostname)
                    if not current_hostname_id:
                        current_hostname_id = db.insert_hostname(
                            current_host_id,
                            issue_hostname,
                            hostnames_description,
                            current_user['id']
                        )
                    else:
                        current_hostname_id = current_hostname_id[0]['id']

                issue_services = {current_port_id: ["0"]}
                if current_hostname_id:
                    issue_services = {current_port_id: [current_hostname_id]}

                issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_description, issue_service_name,
                                                            issue_cvss, current_user['id'], issue_services,
                                                            "Need to recheck", current_project['id'], issue_cve, 0,
                                                            "custom",
                                                            issue_fix, "", issue_tech_info)


        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing XML report!"
    return ""
