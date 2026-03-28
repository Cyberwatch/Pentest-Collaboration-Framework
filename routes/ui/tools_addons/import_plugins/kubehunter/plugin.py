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
route_name = "kubehunter"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/JCFY6Tv/kube-hunter.png",
        "Official name": "kube-hunter",
        "Short name": "kubehunter",
        "Description": "Hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.",
        "URL": "https://github.com/aquasecurity/kube-hunter",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    json_files = MultipleFileField(
        label='json_files',
        description='.json reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from kube-hunter scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description',
        default='Added from kube-hunter scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
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
    for bin_file_data in input_dict['json_files']:
        try:
            json_report_data = bin_file_data.decode('charmap')
            scan_result = json.loads(json_report_data)

            # add node description
            for node_obj in scan_result['nodes']:
                try:
                    node_type = input_dict['hosts_description']
                    if 'type' in node_obj:
                        node_type = "Kubernetes " + node_obj['type']
                    node_ip = node_obj['location']

                    # check if valid ip
                    ipaddress.ip_address(node_ip)

                    current_host = db.select_ip_from_project(current_project['id'], node_ip)
                    if current_host:
                        current_host = current_host[0]
                        db.update_host_description(current_host['id'], node_type)
                    else:
                        current_host = db.insert_host(current_project['id'],
                                                      node_ip,
                                                      current_user['id'],
                                                      node_type)
                except Exception as e:
                    # next Node
                    pass

            # services

            for service_obj in scan_result['services']:
                try:
                    service_info = service_obj['service']
                    service_ip = service_obj['location'].split(':')[0]
                    service_port = int(service_obj['location'].split(':')[1])

                    # check ip
                    ipaddress.ip_address(service_ip)

                    # add host
                    current_host = db.select_ip_from_project(current_project['id'], service_ip)
                    if current_host:
                        current_host = current_host[0]
                    else:
                        current_host = db.insert_host(current_project['id'],
                                                      service_ip,
                                                      current_user['id'],
                                                      input_dict['hosts_description'])

                    # add port

                    current_port = db.select_ip_port(current_host['id'], service_port, is_tcp=True)
                    if current_port:
                        current_port = current_port[0]
                        db.update_port_service(current_port['id'],
                                               service_info)
                    else:
                        current_port = db.insert_host_port(current_host['id'],
                                                           service_port,
                                                           True,
                                                           service_info,
                                                           input_dict['ports_description'],
                                                           current_user['id'],
                                                           current_project['id'])
                except Exception as e:
                    # next service
                    pass

            # add issues

            for issue_obj in scan_result['vulnerabilities']:
                try:
                    issue_ip = issue_obj['location'].split(':')[0]
                    issue_port = 0
                    if ':' in issue_obj['location']:
                        issue_port = int(issue_obj['location'].split(':')[1])

                    # check ip
                    ipaddress.ip_address(issue_ip)

                    issue_cvss = 0
                    issue_severity = issue_obj['severity']
                    issue_name = issue_obj['vulnerability']
                    issue_category = issue_obj['category']
                    issue_num = issue_obj['vid']
                    issue_poc_str = issue_obj['evidence']
                    issue_link = issue_obj['avd_reference']
                    issue_script = issue_obj['hunter']
                    issue_description = issue_obj['description']

                    issue_full_description = 'Category: {}\nEvidence: {}\nModule: {}\nLink: {}\nNumber: {}\n\n{}'.format(
                        issue_category,
                        issue_poc_str,
                        issue_script,
                        issue_link,
                        issue_num,
                        issue_description
                    )

                    if issue_severity == 'low':
                        issue_cvss = 2.0
                    elif issue_severity == 'medium':
                        issue_cvss = 5.0
                    elif issue_severity == 'high':
                        issue_cvss = 8.0
                    elif issue_severity == 'critical':
                        issue_cvss = 10.0

                    # add host
                    current_host = db.select_ip_from_project(current_project['id'], issue_ip)
                    if current_host:
                        current_host = current_host[0]
                    else:
                        current_host = db.insert_host(current_project['id'],
                                                      issue_ip,
                                                      current_user['id'],
                                                      input_dict['hosts_description'])

                    # add port

                    current_port = db.select_ip_port(current_host['id'], issue_port, is_tcp=True)
                    if current_port:
                        current_port = current_port[0]
                        db.update_port_service(current_port['id'],
                                               input_dict['ports_description'])
                    else:
                        current_port = db.insert_host_port(current_host['id'],
                                                           issue_port,
                                                           True,
                                                           'kubernetes',
                                                           input_dict['ports_description'],
                                                           current_user['id'],
                                                           current_project['id'])

                    # add issue

                    services = {current_port['id']: ['0']}

                    current_issue = db.insert_new_issue_no_dublicate(issue_name,
                                                                     issue_full_description,
                                                                     '',
                                                                     issue_cvss,
                                                                     current_user['id'],
                                                                     services,
                                                                     'Need to recheck',
                                                                     current_project['id'],
                                                                     '',
                                                                     0,
                                                                     'custom',
                                                                     '',
                                                                     '')
                except Exception as e:
                    logging.error("Error during parsing report: {}".format(e))
                    pass
        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report"

    return ""
