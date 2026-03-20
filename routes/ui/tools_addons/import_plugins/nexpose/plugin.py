######## Imports #########
import ipaddress
import logging

from flask_wtf import FlaskForm
from bs4 import BeautifulSoup
from wtforms import *
from system.db import Database

# For demonstration
import json

######## Description #############
route_name = "nexpose"  # [a-zA-Z0-9_]

tools_description = [  # array with tools information (to join same tools process algorith, like Nmap and masscan)
    {
        "Icon file": "icon.jpg",
        "Icon URL": "https://i.ibb.co/0nB426p/image.png",  # upload icon to IMG-BB etc
        "Official name": "Nexpose",
        "Short name": "nexpose",  # [a-zA-Z0-9_]
        "Description": "Vulnerability scanner which aims to support the entire vulnerability management lifecycle, including discovery, detection, verification, risk classification, impact analysis, reporting and mitigation.",
        "URL": "https://www.rapid7.com/products/nexpose/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(label='xml_files',  # same as variable name
                                  description="XML-report",  # short description
                                  default=None,
                                  validators=[],
                                  # Validate argument - https://wtforms.readthedocs.io/en/2.3.x/validators/
                                  _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"})


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # fields variables
    xml_files = input_dict["xml_files"]  # [b"1234", b"5678"]

    for bin_file_data in input_dict['xml_files']:
        try:
            # scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            scan_result = BeautifulSoup(bin_file_data.decode('utf-8'), "lxml")
            hosts_list = scan_result.find("nexposereport").find("nodes").findAll("node")
            vuln_db = scan_result.find("nexposereport").find("vulnerabilitydefinitions")
            for host_obj in hosts_list:
                ip = host_obj.attrs["address"]
                ipaddress.ip_address(ip)
                mac_address = ("MAC: " + str(host_obj.attrs["hardware-address"])) \
                    if "hardware-address" in host_obj.attrs and host_obj.attrs["hardware-address"] else ""

                hostnames_arr = []
                if host_obj.find("names"):
                    hostnames_arr = [str(x.get_text()).lower() for x in host_obj.find("names").findAll("name")]

                fingerprints = ""
                if host_obj.find("fingerprints"):
                    fingerprints = host_obj.find("fingerprints").findAll("os")

                host_os = ""

                if len(fingerprints) > 0:
                    host_os = "family=" + str(fingerprints[0].attrs["family"]).strip() if "family" in fingerprints[0].attrs else ""
                    host_os += " vendor=" + str(fingerprints[0].attrs["vendor"]).strip() if "vendor" in fingerprints[0].attrs else ""
                    host_os += " product=" + str(fingerprints[0].attrs["product"]).strip() if "product" in fingerprints[0].attrs else ""
                    host_os += " version=" + str(fingerprints[0].attrs["version"]).strip() if "version" in fingerprints[0].attrs else ""
                    host_os += " arch=" + str(fingerprints[0].attrs["arch"]).strip() if "arch" in fingerprints[0].attrs else ""
                    if "device-class" in fingerprints[0].attrs and fingerprints[0].attrs["device-class"]:
                        host_os = "device_class= " + fingerprints[0].attrs["device-class"].strip() + " " + host_os
                    host_os = host_os.strip("\r\n \t")

                # add host
                current_host = db.select_project_host_by_ip(current_project['id'], ip)
                if current_host:
                    current_host_id = current_host[0]['id']
                    if host_os:
                        db.update_host_os(current_host_id, host_os)
                    if mac_address:
                        db.update_host_description(current_host_id, mac_address)
                else:
                    current_host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                     comment=mac_address,
                                                     os=host_os)
                # add hostnames
                if hostnames_arr:
                    for hostname in hostnames_arr:
                        hostname_id = db.select_ip_hostname(current_host_id, hostname)
                        if hostname_id:
                            hostname_id = hostname_id[0]['id']
                        else:
                            hostname_id = db.insert_hostname(current_host_id,
                                                             hostname, "Nexpose scan",
                                                             current_user['id'])
                # add ports
                ports_list = []
                if host_obj.find("endpoints"):
                    ports_list = host_obj.find("endpoints").findAll("endpoint")

                for port_obj in ports_list:
                    if port_obj.attrs["status"] != "closed":
                        port_num = int(port_obj.attrs["port"])
                        if not (0 < port_num < 65536):
                            raise Exception("port is not in range 1..65535")
                        is_tcp = port_obj.attrs["protocol"] == "tcp"
                        services_list = port_obj.find("services").findAll("service")
                        port_service = "unknown"
                        port_description = ""
                        if len(services_list) > 0:
                            service_obj = services_list[0]
                            port_service = str(service_obj.attrs["name"]).replace("<", "").replace(">", "")
                            # config get
                            config_obj = port_obj.find("configuration")
                            config_list = []
                            if config_obj:
                                config_list = port_obj.find("configuration").findAll("config")
                            port_description = [str(x.attrs["name"]) + ": " + str(x.get_text()) for x in config_list]
                            port_description = "\n".join(port_description)
                            port_description = port_description.strip()

                            current_port_id = db.select_host_port(current_host_id, port_num, is_tcp)
                            if current_port_id:
                                if port_service and port_service != "unknown" and port_description:
                                    db.update_port_proto_description(current_port_id[0]['id'], port_service,
                                                                     port_description)
                                elif port_service and port_service != "unknown" and port_description == "":
                                    db.update_port_proto_description(current_port_id[0]['id'], port_service,
                                                                     current_port_id[0]['description'])
                                current_port_id = current_port_id[0]['id']
                            else:
                                current_port_id = db.insert_host_port(current_host_id, port_num, is_tcp, port_service,
                                                                      port_description,
                                                                      current_user['id'], current_project['id'])

                            # issues

                            issues_list = port_obj.find("tests").findAll("test")
                            for issue_obj in issues_list:
                                issue_name = "{}".format(issue_obj.attrs["id"].replace('-', ' '))
                                issue_description = str(issue_obj.find("paragraph").get_text()).strip()

                                issue_cve = []
                                if 'cve-' in issue_obj.attrs["id"]:
                                    issue_cve.append('CVE-' + '-'.join(issue_obj.attrs["id"].split('cve-')[1].split('-')[:2]))

                                services = {current_port_id: ["0"]}

                                issue_db = vuln_db.findAll(attrs={"id": issue_obj.attrs["id"]}, recursive=False)
                                cvss_vector = ''
                                cvss_score = 0
                                issue_fix = ''
                                issue_tech = ''
                                issue_references = []
                                if issue_db:
                                    issue_tech = issue_description
                                    issue_db = issue_db[0]
                                    print(issue_db)
                                    issue_name = issue_db.attrs["title"]
                                    issue_description = issue_db.find("description").get_text()
                                    if "cvssvector" in issue_db.attrs:
                                        cvss_vector = str(issue_db.attrs["cvssvector"])
                                    if "cvssscore" in issue_db.attrs:
                                        cvss_score = float(issue_db.attrs["cvssscore"])
                                    for reference_obj in issue_db.find("references").findAll("reference"):
                                        if reference_obj.attrs["source"] == "URL":
                                            issue_references.append(reference_obj.get_text().strip())
                                        elif reference_obj.attrs["source"] == "CVE":
                                            issue_cve.append(reference_obj.get_text().strip())
                                        elif reference_obj.attrs["source"] == "BID":
                                            pass  # ignore - it has CVE
                                        elif reference_obj.attrs["source"] == "MSKB":
                                            pass  # ignore - it has CVE
                                        elif reference_obj.attrs["source"] == "CERT":
                                            issue_references.append("https://www.us-cert.gov/ncas/alerts/{}"
                                                                    .format(reference_obj.get_text().strip()))
                                        else:
                                            print(reference_obj.attrs["source"])
                                    issue_fix = issue_db.find("solution").get_text().strip(" \r\n\t")
                                    for link_obj in issue_db.find("solution").findAll("URLLink"):
                                        issue_fix += "\n" + link_obj.attrs["href"].strip()
                                    issue_fix = issue_fix.strip(" \r\n\t")

                                # description fix
                                issue_description = issue_description.strip()
                                issue_description = issue_description.replace('\t', ' ').replace('\r', '')
                                while '  ' in issue_description:
                                    issue_description = issue_description.replace('  ', ' ')
                                while '\n \n' in issue_description:
                                    issue_description = issue_description.replace('\n \n', '\n')
                                while '\n\n' in issue_description:
                                    issue_description = issue_description.replace('\n\n', '\n')

                                # tech fix
                                issue_tech = issue_tech.strip()
                                issue_tech = issue_tech.replace('\t', ' ').replace('\r', '')
                                while '  ' in issue_tech:
                                    issue_tech = issue_tech.replace('  ', ' ')
                                while '\n \n' in issue_tech:
                                    issue_tech = issue_tech.replace('\n \n', '\n')
                                while '\n\n' in issue_tech:
                                    issue_tech = issue_tech.replace('\n\n', '\n')

                                # fix fix :)
                                issue_fix = issue_fix.strip()
                                issue_fix = issue_fix.replace('\t', ' ').replace('\r', '')
                                while '  ' in issue_fix:
                                    issue_fix = issue_fix.replace('  ', ' ')
                                while '\n \n' in issue_fix:
                                    issue_fix = issue_fix.replace('\n \n', '\n')
                                while '\n\n' in issue_fix:
                                    issue_fix = issue_fix.replace('\n\n', '\n')

                                # refs fix
                                issue_references = set(issue_references)
                                # cve fix
                                issue_cve = set(issue_cve)

                                issue_id = db.insert_new_issue_no_dublicate(
                                    issue_name, issue_description, '',
                                    cvss_score, current_user['id'],
                                    services, "Need to recheck",
                                    current_project['id'],
                                    cve=','.join(issue_cve), fix=issue_fix,
                                    technical=issue_tech,
                                    references='\n'.join(issue_references)
                                )
                                if cvss_vector:
                                    fields_dict = {
                                        "cvss_vector": {
                                            "type": "text",
                                            "val": "CVSS:3.1/" + cvss_vector.strip("()")
                                        }
                                    }

                                    db.update_issue_fields(str(issue_id), fields_dict)


        except OverflowError as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing XML report!"

    return ""
