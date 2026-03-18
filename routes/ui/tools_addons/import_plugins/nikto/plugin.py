######## Imports #########
import csv
import ipaddress
import json
import logging
from io import StringIO

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "nikto"

tools_description = [
    {
        "Icon file": "icon.jpg",
        "Icon URL": "https://i.ibb.co/Cbq096K/nikto.jpg",
        "Official name": "Nikto",
        "Short name": "nikto",
        "Description": "A free software command-line vulnerability scanner that scans webservers for dangerous files/CGIs, outdated server software and other problems. It performs generic and server type specific checks. It also captures and prints any cookies received. The Nikto code itself is free software, but the data files it uses to drive the program are not.",
        "URL": "https://github.com/sullo/nikto",
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

    csv_files = MultipleFileField(
        label='csv_files',
        description='.csv reports',
        default=None,
        validators=[],
        _meta={"display_row": 2, "display_column": 1, "file_extensions": ".csv"}
    )

    json_files = MultipleFileField(
        label='json_files',
        description='.json reports',
        default=None,
        validators=[],
        _meta={"display_row": 3, "display_column": 1, "file_extensions": ".json"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from Nikto scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description',
        default='Added from Nikto scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from Nikto scan',
        validators=[],
        _meta={"display_row": 3, "display_column": 2}
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
    for bin_file_data in input_dict['json_files']:
        if bin_file_data:
            try:
                json_report_data = bin_file_data.decode('charmap').replace(',]', ']').replace(',}', '}')
                scan_result = json.loads(json_report_data)
                host = scan_result['ip']
                hostname = scan_result['host'] if scan_result['ip'] != scan_result['host'] else ''
                issues = scan_result['vulnerabilities']
                port = int(scan_result['port'])
                protocol = 'https' if '443' in str(port) else 'http'
                is_tcp = 1
                port_description = 'Added by Nikto scan'
                if scan_result['banner']:
                    port_description = 'Nikto banner: {}'.format(
                        scan_result['banner'])

                # add host
                host_id = db.select_project_host_by_ip(current_project['id'],
                                                       host)
                if not host_id:
                    host_id = db.insert_host(current_project['id'],
                                             host,
                                             current_user['id'],
                                             input_dict['hosts_description'])
                else:
                    host_id = host_id[0]['id']

                # add hostname

                hostname_id = ''
                if hostname and hostname != host:
                    hostname_id = db.select_ip_hostname(host_id, hostname)
                    if not hostname_id:
                        hostname_id = db.insert_hostname(host_id,
                                                         hostname,
                                                         input_dict['hostnames_description'],
                                                         current_user['id'])
                    else:
                        hostname_id = hostname_id[0]['id']

                # add port
                port_id = db.select_ip_port(host_id, port, is_tcp)
                if not port_id:
                    port_id = db.insert_host_port(host_id,
                                                  port,
                                                  is_tcp,
                                                  protocol,
                                                  port_description,
                                                  current_user['id'],
                                                  current_project['id'])
                else:
                    port_id = port_id[0]['id']

                for issue in issues:
                    method = issue['method']
                    url = issue['url']
                    full_url = '{} {}'.format(method, url)
                    osvdb = int(issue['OSVDB'])
                    info = issue['msg']
                    full_info = 'OSVDB: {}\n\n{}'.format(osvdb, info)

                    services = {port_id: ['0']}
                    if hostname_id:
                        services = {port_id: ['0', hostname_id]}

                    db.insert_new_issue('Nikto scan', full_info, full_url, 0,
                                        current_user['id'], services,
                                        'need to check',
                                        current_project['id'],
                                        cve=0,
                                        cwe=0,
                                        )

            except Exception as e:
                logging.error("Error during parsing report: {}".format(e))
                return "Error during parsing JSON report"

    for bin_file_data in input_dict['csv_files']:
        if bin_file_data:
            try:
                f = StringIO(bin_file_data.decode('charmap'))

                scan_result = csv.reader(f, delimiter=',')

                for issue in scan_result:
                    if len(issue) == 7:
                        hostname = issue[0]
                        host = issue[1]
                        port = int(issue[2])
                        protocol = 'https' if '443' in str(port) else 'http'
                        is_tcp = 1
                        osvdb = issue[3]
                        full_url = '{} {}'.format(issue[4], issue[5])
                        full_info = 'OSVDB: {}\n{}'.format(osvdb, issue[6])

                        # add host
                        host_id = db.select_project_host_by_ip(
                            current_project['id'],
                            host)
                        if not host_id:
                            host_id = db.insert_host(current_project['id'],
                                                     host,
                                                     current_user['id'],
                                                     input_dict['hosts_description'])
                        else:
                            host_id = host_id[0]['id']

                        # add hostname
                        hostname_id = ''
                        if hostname and hostname != host:
                            hostname_id = db.select_ip_hostname(host_id,
                                                                hostname)
                            if not hostname_id:
                                hostname_id = db.insert_hostname(host_id,
                                                                 hostname,
                                                                 input_dict['hostnames_description'],
                                                                 current_user['id'])
                            else:
                                hostname_id = hostname_id[0]['id']

                        # add port
                        port_id = db.select_ip_port(host_id, port, is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id,
                                                          port,
                                                          is_tcp,
                                                          protocol,
                                                          input_dict['ports_description'],
                                                          current_user['id'],
                                                          current_project['id'])
                        else:
                            port_id = port_id[0]['id']

                        # add issue
                        services = {port_id: ['0']}
                        if hostname_id:
                            services = {port_id: ['0', hostname_id]}

                        db.insert_new_issue('Nikto scan', full_info, full_url,
                                            0,
                                            current_user['id'], services,
                                            'need to check',
                                            current_project['id'],
                                            cve=0,
                                            cwe=0,
                                            )

            except Exception as e:
                logging.error("Error during parsing report: {}".format(e))
                return "Error during parsing CSV report"

    for bin_file_data in input_dict['xml_files']:
        if bin_file_data:
            try:
                scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser").niktoscan.scandetails
                host = scan_result['targetip']
                port = int(scan_result['targetport'])
                is_tcp = 1
                port_banner = scan_result['targetbanner']
                hostname = scan_result['targethostname']
                issues = scan_result.findAll("item")
                protocol = 'https' if '443' in str(port) else 'http'
                port_description = ''
                if port_banner:
                    port_description = 'Nikto banner: {}'.format(
                        scan_result['targetbanner'])

                # add host
                host_id = db.select_project_host_by_ip(
                    current_project['id'],
                    host)
                if not host_id:
                    host_id = db.insert_host(current_project['id'],
                                             host,
                                             current_user['id'],
                                             input_dict['hosts_description.data'])
                else:
                    host_id = host_id[0]['id']

                # add hostname
                hostname_id = ''
                if hostname and hostname != host:
                    hostname_id = db.select_ip_hostname(host_id,
                                                        hostname)
                    if not hostname_id:
                        hostname_id = db.insert_hostname(host_id,
                                                         hostname,
                                                         input_dict['hostnames_description'],
                                                         current_user['id'])
                    else:
                        hostname_id = hostname_id[0]['id']

                # add port
                port_id = db.select_ip_port(host_id, port, is_tcp)
                if not port_id:
                    port_id = db.insert_host_port(host_id,
                                                  port,
                                                  is_tcp,
                                                  protocol,
                                                  port_description,
                                                  current_user['id'],
                                                  current_project['id'])
                else:
                    port_id = port_id[0]['id']

                for issue in issues:
                    method = issue['method']
                    url = issue.uri.contents[0]
                    full_url = '{} {}'.format(method, url)
                    references = issue.references.contents[0] if issue.references and issue.references.contents else ''
                    full_info = issue.description.contents[0]

                    # small fixes for https://gitlab.com/invuls/pentest-projects/pcf/-/issues/167
                    osvdb = int(issue['osvdbid']) if 'osvdbid' in issue else ''
                    if osvdb:
                        full_info = 'OSVDB: {}\n\n'.format(osvdb) + full_info

                    services = {port_id: ['0']}
                    if hostname_id:
                        services = {port_id: ['0', hostname_id]}

                    db.insert_new_issue('Nikto scan', full_info, full_url, 0,
                                        current_user['id'], services,
                                        'need to check',
                                        current_project['id'],
                                        cve=0,
                                        cwe=0,
                                        references=references
                                        )

            except Exception as e:
                logging.error("Error during parsing report: {}".format(e))
                return "Error during parsing XML report"

    return ""
