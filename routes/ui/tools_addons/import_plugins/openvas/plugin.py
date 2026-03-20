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
route_name = "openvas"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/hdF6vVv/openvas.png",
        "Official name": "OpenVAS/GVM",
        "Short name": "openvas",
        "Description": "A software framework of several services and tools offering vulnerability scanning and vulnerability management. All OpenVAS products are free software, and most components are licensed under the GNU General Public License (GPL). Plugins for OpenVAS are written in the Nessus Attack Scripting Language, NASL.",
        "URL": "https://www.openvas.org/",
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
        default='Added from OpenVAS scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description',
        default='Added from OpenVAS scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 1}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from OpenVAS scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with settings.ini information
) -> str:  # returns error text or "" (if finished successfully)
    # xml files
    for bin_file_data in input_dict['xml_files']:
        try:
            scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            query_list = scan_result.find_all("result")
            for query in query_list:
                if query.find('host'):  # disables result tags inside issue description
                    issue_host = query.find('host').text.split('\n')[0]
                    issue_hostname = query.find('host').find('hostname').text
                    port_str = query.find('port').text.split('/')[0]
                    if port_str == 'general':
                        issue_port = 0
                    else:
                        issue_port = int(port_str)
                    issue_is_tcp = int(query.find('port').text.split('/')[1] == 'tcp')

                    nvt_obj = query.find('nvt')
                    issue_name = nvt_obj.find('name').text.strip()
                    issue_type = nvt_obj.find('family').text
                    issue_cvss = float(nvt_obj.find('cvss_base').text)
                    issue_long_description = nvt_obj.find('tags').text.strip()

                    solution_obj = nvt_obj.find('solution')
                    issue_solution = ''
                    if solution_obj.get('type') != 'WillNotFix':
                        issue_solution = solution_obj.text.strip()

                    cve_list = []
                    links_list = []
                    refs_objects = nvt_obj.find('refs')
                    if refs_objects:
                        refs_objects = refs_objects.findAll('ref')
                        for ref_obj in refs_objects:
                            if ref_obj.get('type') == 'url':
                                links_list.append(ref_obj.get('id'))
                            if ref_obj.get('type') == 'cve':
                                cve_list.append(ref_obj.get('id'))

                    issue_short_description = ''
                    if query.find('description'):
                        issue_short_description = query.find('description').text

                    # check if host exists

                    host_id = db.select_project_host_by_ip(current_project['id'], issue_host)
                    if not host_id:
                        host_id = db.insert_host(current_project['id'], issue_host,
                                                 current_user['id'], input_dict['hosts_description'])
                    else:
                        host_id = host_id[0]['id']

                    # check if port exists
                    port_id = db.select_host_port(host_id, issue_port, issue_is_tcp)
                    if not port_id:
                        port_id = db.insert_host_port(host_id, issue_port, issue_is_tcp, 'unknown',
                                                      input_dict['ports_description'],
                                                      current_user['id'], current_project['id'])
                    else:
                        port_id = port_id[0]['id']

                    # check if hostname exists
                    hostname_id = ''
                    if issue_hostname != '':
                        hostname_id = db.select_ip_hostname(host_id, issue_hostname)
                        if not hostname_id:
                            hostname_id = db.insert_hostname(host_id, issue_hostname,
                                                             input_dict['hostnames_description'], current_user['id'])
                        else:
                            hostname_id = hostname_id[0]['id']

                    full_description = 'Short description: \n{}\n\nFull description:\n{}'.format(
                        issue_short_description,
                        issue_long_description)
                    cve_str = ','.join(cve_list)
                    services = {
                        port_id: [hostname_id] if hostname_id else ['0']
                    }
                    db.insert_new_issue_no_dublicate(issue_name, full_description, '', issue_cvss,
                                                     current_user['id'],
                                                     services, 'Need to recheck', current_project['id'], cve_str,
                                                     0, 'custom', issue_solution, '', references='\n'.join(links_list))

        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report!"

    return ""
