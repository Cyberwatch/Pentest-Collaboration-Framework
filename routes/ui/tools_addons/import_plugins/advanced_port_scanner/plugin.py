######## Imports #########
import ipaddress
import logging

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "advanced_port_scanner"

tools_description = [
    {
        "Icon file": "advanced_ip_scanner.png",
        "Icon URL": "https://i.ibb.co/bWFJ6Qk/advanced-ip-scanner.png",
        "Official name": "Advanced IP Scanner",
        "Short name": "advanced_ip_scanner",
        "Description": "Reliable and free network scanner to analyze LAN. The program shows all network devices, gives you access to shared folders, provides remote control of computers (via RDP and Radmin), and can even remotely switch computers off. It is easy to use and runs as a portable edition. It should be the first choice for every network admin.",
        "URL": "https://www.advanced-ip-scanner.com/",
        "Plugin author": "@drakylar"
    }, {
        "Icon file": "advanced_port_scanner.png",
        "Icon URL": "https://i.ibb.co/M8PW8KM/advanced-port-scanner.png",
        "Official name": "Advanced Port Scanner",
        "Short name": "advanced_port_scanner",
        "Description": "A Free network scanner allowing you to quickly find open ports on network computers and retrieve versions of programs running on the detected ports.The program has a user-friendly interface and rich functionality.",
        "URL": "https://www.advanced-port-scanner.com/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    files = MultipleFileField(
        label='files',
        description='.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from Advanced Port Scanner',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ignore_ports = StringField(
        label='ignore_ports',
        description='Ignore ports',
        default='554,7070',
        validators=[],
        _meta={"display_row": 2, "display_column": 1}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from Advanced Port Scanner',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )
    add_no_open = BooleanField(label='add_no_open',
                               description="Add hosts without open ports",
                               default=False,
                               validators=[],
                               _meta={"display_row": 3, "display_column": 2})


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)
    # xml files
    for bin_file_data in input_dict['files']:
        try:
            file_data = bin_file_data.decode("charmap")
            scan_result = BeautifulSoup(file_data, "lxml")
            hosts_list = scan_result.findAll("row")
            for host_obj in hosts_list:
                host_ip = host_obj.attrs["ip"]
                ipaddress.ip_address(host_ip)  # check that ip is correct
                hostnames_list = []
                hostnames_list.append(host_obj.attrs["name"].lower() if "name" in host_obj.attrs else "")
                hostnames_list.append(host_obj.attrs["alias"].lower() if "alias" in host_obj.attrs else "")

                host_netbios = host_obj.attrs["netbiosname"] if "netbiosname" in host_obj.attrs else ""

                if "netbiosgroup" in host_obj.attrs and host_obj.attrs["netbiosname"] and host_netbios:
                    host_netbios += "." + host_obj.attrs["netbiosgroup"]

                hostnames_list.append(host_netbios.lower())

                hostnames_list = list(set(hostnames_list))

                host_os = host_obj.attrs["os_version"] if "os_version" in host_obj.attrs else ""
                host_status = host_obj.attrs["status"]  # alive/unknown
                host_manufacture = host_obj.attrs["manufacturer"] if "manufacturer" in host_obj.attrs else ""
                host_users = host_obj.attrs["user"] if "user" in host_obj.attrs else ""
                host_mac = host_obj.attrs["mac"] if "mac" in host_obj.attrs and \
                                                    host_obj.attrs["mac"] != "00:00:00:00:00:00" else ""
                host_description_full = ""
                if host_manufacture:
                    host_description_full = host_manufacture
                if host_users:
                    host_description_full += "\n" + "Users: " + host_users
                if host_mac:
                    host_description_full += "\n" + "MAC: " + host_mac
                host_description_full = host_description_full.strip(" \t\r\n")

                if not host_description_full:
                    host_description_full = input_dict['hosts_description']

                host_http_8080_description = host_http_80_description = ""
                if host_obj.attrs["has_http"] == "1":
                    http_description = host_obj.attrs["http_title"] if "http_title" in host_obj.attrs else ""
                    if "http_title_full" in host_obj.attrs and host_obj.attrs["http_title_full"]:
                        http_description = host_obj.attrs["http_title_full"]
                    if host_obj.attrs["is_http8080"] == "1":
                        host_http_8080_description = http_description
                    else:
                        host_http_80_description = http_description

                host_ftp_21_description = host_obj.attrs["ftp_version"] if "ftp_version" in host_obj.attrs else ""
                host_https_443_description = host_obj.attrs[
                    "https_version"] if "https_version" in host_obj.attrs else ""
                if "https_version_full" in host_obj.attrs and host_obj.attrs["https_version_full"]:
                    host_https_443_description = host_obj.attrs["https_version_full"]
                host_rdp_3389_description = host_obj.attrs["rdp_version"] if "rdp_version" in host_obj.attrs else ""

                host_printers = []

                for printer_obj in host_obj.findAll('printer'):
                    host_printers.append("- {}:/".format(printer_obj.attrs["name"].strip("/")))
                host_printers = list(set(host_printers))

                host_shares = []
                for share_obj in host_obj.findAll('share'):
                    host_shares.append("- {}:/".format(share_obj.attrs["name"].strip("/")))

                host_ports = {}  # num -> {"service":"...","description":"..."}
                for port_obj in host_obj.findAll('service'):
                    port_num = int(port_obj.attrs["port"])
                    port_service = "unknown"
                    port_description = port_obj.attrs["version"]
                    if port_num in [80, 8080, 8888]:
                        port_service = "http"
                    if port_num == 445:
                        port_service = "smb"
                    if port_num in [443, 4443, 8443]:
                        port_service = "https"
                    if port_num == 3389:
                        port_service = "rdp"
                    if port_num == 135:
                        port_service = "rpc"
                    if port_num == 139:
                        port_service = "netbios-ssn"
                    if port_num == 515:
                        port_service = "printer"
                    if port_num == 80 and host_http_80_description:
                        port_description = host_http_80_description
                    if port_num == 443 and host_https_443_description:
                        port_description = host_https_443_description
                    if port_num == 8080 and host_http_8080_description:
                        port_description = host_http_8080_description
                    if port_num == 21 and host_ftp_21_description:
                        port_description = host_ftp_21_description
                    if port_num == 3389 and host_rdp_3389_description:
                        port_description = host_rdp_3389_description
                    if port_num == 445 and host_shares:
                        port_description += "\n\nShares:" + "\n".join(host_shares)
                    if port_num == 445 and host_printers:
                        port_description += "\n\nPrinters:" + "\n".join(host_printers)

                    port_description = port_description.strip(' \t\r\n')

                    if 0 < port_num < 65536:
                        host_ports[port_num] = {
                            "service": port_service,
                            "description": port_description
                        }

                if host_obj.attrs["has_http"] == "1" and \
                        host_obj.attrs["is_http8080"] == "0" and \
                        80 not in host_ports:
                    host_ports[80] = {
                        "service": "http",
                        "description": host_http_80_description
                    }

                if host_obj.attrs["has_http"] == "1" and \
                        host_obj.attrs["is_http8080"] == "1" and \
                        8080 not in host_ports:
                    host_ports[80] = {
                        "service": "http",
                        "description": host_http_8080_description
                    }

                if host_obj.attrs["has_https"] == "1" and 443 not in host_ports:
                    host_ports[443] = {
                        "service": "https",
                        "description": host_https_443_description
                    }

                if host_obj.attrs["has_ftp"] == "1" and 21 not in host_ports:
                    host_ports[21] = {
                        "service": "ftp",
                        "description": host_ftp_21_description
                    }

                if host_obj.attrs["has_rdp"] == "1" and 3389 not in host_ports:
                    host_ports[3389] = {
                        "service": "rdp",
                        "description": host_rdp_3389_description
                    }

                if (host_shares or host_printers) and 445 not in host_ports:
                    description = ""
                    if host_shares:
                        description = "Shares:" + "\n".join(host_shares)
                    if host_printers:
                        description += "\n\nPrinters:" + "\n".join(host_printers)
                    description = description.strip(' \r\t\n')
                    host_ports[445] = {
                        "service": "smb",
                        "description": description
                    }

                if input_dict['add_no_open'] or len(host_ports):

                    # add host
                    host_id = db.select_project_host_by_ip(current_project['id'], host_ip)
                    if not host_id:
                        host_id = db.insert_host(current_project['id'], host_ip, current_user['id'],
                                                 host_description_full, os=host_os)
                    else:
                        host_id = host_id[0]['id']
                        db.update_host_description(host_id, host_description_full)
                        db.update_host_os(host_id, host_os)

                    # add hostnames
                    for hostname in hostnames_list:
                        if hostname:
                            hostname_id = db.select_ip_hostname(host_id, hostname)
                            if not hostname_id:
                                hostname_id = db.insert_hostname(host_id, hostname.lower(),
                                                                 input_dict['hostnames_description'],
                                                                 current_user['id'])

                    # add ports
                    for port_num in host_ports:
                        port_id = db.select_host_port(host_id, port_num, True)
                        if port_id:
                            port_id = port_id[0]['id']
                            db.update_port_proto_description(port_id, host_ports[port_num]['service'],
                                                             host_ports[port_num]['description'])
                        else:
                            port_id = db.insert_host_port(host_id, port_num, True, host_ports[port_num]['service'],
                                                          host_ports[port_num]['description'],
                                                          current_user['id'], current_project['id'])
        except Exception as e:
            logging.error("Exception during file parsing: {}".format(e))
            return 'One of files is corrupted!'

    return ""
