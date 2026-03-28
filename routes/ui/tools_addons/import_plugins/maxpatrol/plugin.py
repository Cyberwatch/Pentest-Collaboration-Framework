######## Imports #########
import ipaddress
import json
import logging

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "maxpatrol"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/x6C6fJB/positive-technologies.png",
        "Official name": "MaxPatrol Scanner",
        "Short name": "maxpatrol",
        "Description": "A network vulnerability scanner with audit/pentest/certification modes.",
        "URL": "https://www.ptsecurity.com/ru-ru/products/mp8/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(
        label='xml_files',
        description='.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from MaxPatrol scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description (if empty)',
        default='Added from MaxPatrol scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 1}
    )


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)
    # xml files
    for bin_file_data in input_dict['xml_files']:
        try:
            # scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            scan_result = BeautifulSoup(bin_file_data.decode('utf-8'), "lxml")
            hosts_list = scan_result.find("content").data
            vulns_db = scan_result.find("content").find("vulners", recursive=False)
            for host in hosts_list.findAll('host'):
                ip = host.attrs["ip"]
                ipaddress.ip_address(ip)

                current_host = db.select_project_host_by_ip(current_project['id'], ip)
                if current_host:
                    current_host_id = current_host[0]['id']
                else:
                    current_host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                     comment=input_dict['hosts_description'])

                scans = host.scan_objects

                for port_obj in scans.findAll("soft"):
                    port = int(port_obj.attrs["port"])
                    is_tcp = True
                    if 0 <= port <= 63353:
                        port_service = port_obj.find("name").text

                        current_port_id = db.select_host_port(current_host_id, port, is_tcp)
                        if current_port_id:
                            if port_service:
                                db.update_port_proto_description(current_port_id[0]['id'], port_service,
                                                                 current_port_id[0]['description'])
                            current_port_id = current_port_id[0]['id']
                        else:
                            current_port_id = db.insert_host_port(current_host_id, port, is_tcp, port_service,
                                                                  input_dict['ports_description'],
                                                                  current_user['id'], current_project['id'])

                        port_issues = port_obj.vulners
                        if port_issues:
                            for issue_obj in port_issues.findAll("vulner"):
                                issue_level = int(issue_obj.attrs["level"])
                                issue_db_id = issue_obj.attrs["id"]
                                if issue_level > 0:
                                    # TODO: add table integration from PoC

                                    issue_db_obj = vulns_db.find("vulner", {"id": issue_db_id})
                                    issue_name = issue_db_obj.title.text
                                    issue_short = issue_db_obj.short_description.text
                                    issue_description = issue_db_obj.description.text
                                    issue_fix = issue_db_obj.how_to_fix.text
                                    issue_links = issue_db_obj.links.text.strip('\n').replace('\n', '\n- ')
                                    cvss3 = float(issue_db_obj.cvss3.attrs["base_score"])
                                    cvss3_decomp = issue_db_obj.cvss3.attrs["base_score_decomp"].strip('()')

                                    if cvss3 == 0:
                                        cvss3 = float(issue_db_obj.cvss.attrs["base_score"])

                                    issue_cve = ''
                                    issue_pub_date = issue_db_obj.publication_date.text if issue_db_obj.publication_date else ''
                                    if issue_db_obj.global_id and "name" in issue_db_obj.global_id.attrs and \
                                            issue_db_obj.global_id.attrs["name"] == "CVE":
                                        issue_cve = issue_db_obj.global_id.attrs["value"]

                                    # fstec fields
                                    issue_fstec = ''
                                    for fstec_obj in issue_db_obj.findAll("global_id", {"name": "fstec"}):
                                        issue_fstec += fstec_obj.attrs["value"] + ','
                                    issue_fstec = issue_fstec.strip(',')

                                    issue_description_full = issue_short
                                    issue_description_full += '\n\n' + issue_description
                                    if issue_links:
                                        issue_description_full += '\n\nLinks:\n' + issue_links
                                    if issue_pub_date:
                                        issue_description_full += '\n\nPublication date:\n' + issue_pub_date
                                    if issue_fstec:
                                        issue_description_full += '\n\nFSTEC:\n' + issue_fstec

                                    services = {current_port_id: ["0"]}

                                    issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_description_full,
                                                                                '', cvss3, current_user['id'],
                                                                                services, "Need to recheck",
                                                                                current_project['id'], issue_cve,
                                                                                fix=issue_fix)
                                    if cvss3_decomp:
                                        db.update_issue_field(issue_id, "cvss_vector", "text", cvss3_decomp)

        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing XML report!"

    return ""
