######## Imports #########
import ipaddress
import json

from IPy import IP
from libnessus.parser import NessusParser
import logging

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "nessus"

tools_description = [
    {
        "Icon file": "nessus.png",
        "Icon URL": "https://i.ibb.co/ypTJW9W/nessus.png",
        "Official name": "Nessus",
        "Short name": "nessus",
        "Description": "A proprietary vulnerability scanner developed by Tenable, Inc.",
        "URL": "https://www.tenable.com/products/nessus",
        "Plugin author": "@drakylar"
    },
    {
        "Icon file": "tenable.jpg",
        "Icon URL": "https://i.ibb.co/8NRr5mG/tenable.jpg",
        "Official name": "Tenable.sc",
        "Short name": "tenable",
        "Description": "A comprehensive vulnerability management solution that provides complete visibility into the security posture of your distributed and complex IT infrastructure.",
        "URL": "https://www.tenable.com/products/tenable-sc",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(
        label='xml_files',
        description='.nessus/.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml,.nessus"}
    )

    add_info_issues = BooleanField(label='add_info_issues',
                                   description="Import informational issues too (severity=0)",
                                   default=False,
                                   validators=[],
                                   _meta={"display_row": 2, "display_column": 1})

    add_technical_info = BooleanField(label='add_technical_info',
                                      description="Import plugin output strings",
                                      default=True,
                                      validators=[],
                                      _meta={"display_row": 3, "display_column": 1})

    only_import_network = BooleanField(label='only_import_network',
                                       description="Only import hosts/hostnames/ports",
                                       default=False,
                                       validators=[],
                                       _meta={"display_row": 4, "display_column": 1})

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from Nessus scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from Nessus scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description (if no other info)',
        default='Added from Nessus scan',
        validators=[],
        _meta={"display_row": 3, "display_column": 2}
    )


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    add_info_issues = input_dict['add_info_issues']
    # xml files
    for bin_file_data in input_dict['xml_files']:
        try:
            xml_report_data = bin_file_data.decode('charmap')
            scan_result = NessusParser.parse_fromstring(xml_report_data)

            # 1. Add hosts which are not exist
            ip_list = list(set([host_obj.ip for host_obj in scan_result.hosts]))

            found_hosts = {x['ip']: {'id': x['id'], 'os': x['os']} for x in
                           db.select_project_hosts_multiple_ip(current_project['id'], ip_list)}

            ips_to_add = []

            for ip_str in ip_list:
                if ip_str not in found_hosts:
                    try:
                        ipaddress.ip_address(ip_str)
                        ips_to_add.append(ip_str)
                    except Exception as e:
                        logging.error("Nessus - wrong IP: {}".format(e))
                        return "Wrong IP!"

            if ips_to_add:
                db.insert_host_multiple(
                    current_project['id'],
                    ips_to_add,
                    current_user['id'],
                    [input_dict['hosts_description'] for x in range(len(ips_to_add))],
                    [[] for x in range(len(ips_to_add))],
                    ['' for x in range(len(ips_to_add))]
                )

                added_hosts = {x['ip']: {'id': x['id'], 'os': x['os']} for x in
                               db.select_project_hosts_multiple_ip(current_project['id'], ips_to_add)}

                found_hosts.update(added_hosts)
            all_hosts = found_hosts

            # 1. Add hostnames
            hostnames_list = {}
            for host_obj in scan_result.hosts:
                hostname = ''
                if host_obj.name != host_obj.ip and host_obj.name:
                    hostname = host_obj.name.strip(' \r\n\t')
                elif 'host-fqdn' in host_obj.get_host_properties and host_obj.get_host_properties[
                    'host-fqdn'] != host_obj.ip:
                    hostname = host_obj.get_host_properties['host-fqdn'].strip(' \r\n\t')
                hostnames_list[host_obj.ip] = hostname

            hostnames_found = {x['id']: {'hostname': x['hostname'], 'ip': x['ip']} for x in
                               db.select_hostnames_ip_multiple(
                                   current_project['id'],
                                   [hostnames_list[x] for x in hostnames_list],
                                   [x for x in hostnames_list]
                               )}

            # search which hostname was not found
            hostnames_to_add = {}
            for hostname_ip in hostnames_list:
                hostname = hostnames_list[hostname_ip]
                if hostname:
                    found = 0
                    for found_hostname_id in hostnames_found:
                        found_hostname = hostnames_found[found_hostname_id]['hostname']
                        found_ip = hostnames_found[found_hostname_id]['ip']
                        if found_ip == hostname_ip and found_hostname == hostname:
                            found = 1
                    if not found:
                        host_id = all_hosts[hostname_ip]['id']
                        hostnames_to_add[host_id] = hostname

            # add not found hostnames
            added_list = db.insert_hostnames_multiple(
                [host_id for host_id in hostnames_to_add],
                [hostnames_to_add[host_id] for host_id in hostnames_to_add],
                [input_dict['hostnames_description'] for host_id in hostnames_to_add],
                current_user['id']
            )
            for x in added_list:
                for y in all_hosts:
                    if all_hosts[y]['id'] == added_list[x]['host_id']:
                        added_list[x]['ip'] = y

            hostnames_found.update(added_list)
            all_hostnames = hostnames_found

            # 3. Update hosts OS

            os_list = {}  # {'id':'os'}

            for host in scan_result.hosts:
                host_ip = host.ip
                for issue in host.get_report_items:
                    if issue.get_vuln_plugin["pluginName"] == 'OS Identification':
                        os = issue.get_vuln_plugin["plugin_output"].split('\n')[1].split(' : ')[1]
                        host_id = all_hosts[host_ip]['id']
                        os_list[host_id] = os

            db.update_host_os_multiple(
                [x for x in os_list],
                [os_list[x] for x in os_list]
            )

            # 4. Add ports

            ports_list = {}

            # get list of all used ports
            for host in scan_result.hosts:
                host_ip = host.ip
                host_id = all_hosts[host_ip]['id']
                ports_list[host_id] = []

                for issue in host.get_report_items:
                    is_tcp = issue.protocol == 'tcp'
                    if issue.protocol != 'tcp':
                        pass
                    port_num = int(issue.port)
                    service = issue.service

                    found = 0
                    for exists_port in ports_list[host_id]:
                        if exists_port['is_tcp'] == is_tcp and exists_port['port_num'] == port_num:
                            found = 1
                    if not found:
                        ports_list[host_id].append({
                            'port_num': port_num,
                            'is_tcp': int(is_tcp),
                            'service': service
                        })

            # get list of found ports
            port_num_list = []
            host_id_list = []
            is_tcp_list = []
            for host_id in ports_list:
                for port_obj in ports_list[host_id]:
                    port_num_list.append(port_obj['port_num'])
                    host_id_list.append(host_id)
                    if port_obj['port_num'] == 0:
                        port_obj['is_tcp'] = 1
                    is_tcp_list.append(port_obj['is_tcp'])
            ports_found = db.select_project_ports_multiple(
                current_project['id'],
                port_num_list,
                is_tcp_list,
                host_id_list
            )
            not_found_ports = {}
            for host_id in ports_list:
                for port_js in ports_list[host_id]:
                    found = 0
                    i = 0
                    while i < len(ports_found) and not found:
                        port_obj = ports_found[i]
                        if port_obj['is_tcp'] == port_js['is_tcp'] and \
                                port_obj['host_id'] == host_id and \
                                port_obj['port'] == port_js['port_num']:
                            found = 1
                        i += 1
                    if not found:
                        if host_id not in not_found_ports:
                            not_found_ports[host_id] = [port_js]
                        else:
                            found = 0
                            for port_obj1 in not_found_ports[host_id]:
                                try:
                                    if port_obj1['port_num'] == port_js['port_num'] and \
                                            port_obj1['is_tcp'] == port_js['is_tcp']:
                                        found = 1
                                except Exception as e:
                                    pass
                            if not found:
                                not_found_ports[host_id].append(port_js)

            # add not found ports

            port_num_list = []
            host_id_list = []
            is_tcp_list = []
            service_list = []
            description_list = []
            for host_id in not_found_ports:
                for port_obj in not_found_ports[host_id]:
                    port_num_list.append(port_obj['port_num'])
                    host_id_list.append(host_id)
                    is_tcp_list.append(port_obj['is_tcp'])
                    service_list.append(port_obj['service'])
                    description_list.append(input_dict['ports_description'])

            db.insert_project_ports_multiple(
                current_project['id'],
                current_user['id'],
                port_num_list,
                host_id_list,
                is_tcp_list,
                service_list,
                description_list
            )

            # update found ports description

            update_port_ids_list = []
            update_port_services_list = []

            for port_obj in ports_found:
                update_port_ids_list += [port_obj['id']]

                for host_id in ports_list:
                    for port_js in ports_list[host_id]:
                        if port_js['port_num'] == port_obj['port'] and \
                                port_js['is_tcp'] == port_obj['is_tcp'] and \
                                host_id == port_obj['host_id']:
                            update_port_services_list.append(port_js['service'])

            db.update_port_service_multiple(
                update_port_ids_list,
                update_port_services_list
            )

            all_ports = db.select_project_ports(current_project['id'])

            # 5. Add issues

            db_issues = db.select_project_issues(current_project['id'])
            issues_update_services = {}  # {issue_id:{port_id:["0",hostname_id]}}
            issue_create_list = []
            for host in scan_result.hosts:
                # get issue ip
                issue_ip = host.ip
                issue_host_id = ''
                if issue_ip in all_hosts:
                    issue_host_id = all_hosts[issue_ip]['id']

                # get issue hostname
                issue_hostname = host.name if host.name != host.ip else ''
                try:
                    test_hostname = IP(host.address)
                except ValueError:
                    test_hostname = ''
                if not issue_hostname and not test_hostname and host.address:
                    issue_hostname = host.address
                issue_hostname_id = '0'
                if issue_hostname:
                    for hostname_id in all_hostnames:
                        if all_hostnames[hostname_id]['ip'] == issue_ip and \
                                all_hostnames[hostname_id]['hostname'] == issue_hostname:
                            issue_hostname_id = hostname_id

                for issue in host.get_report_items:
                    plugin_id = int(issue.plugin_id)
                    issue_name = 'Nessus: {}'.format(issue.plugin_name)
                    issue_output = ''
                    if hasattr(issue, '__vuln_info') and \
                            'description' in issue.__vuln_info and \
                            issue.description.strip('\n') != '':
                        issue_output = issue.description.strip('\n')
                    elif 'plugin_output' in issue.get_vuln_info and issue.get_vuln_info['plugin_output']:
                        issue_output = issue.get_vuln_info['plugin_output'].strip('\n')
                    try:
                        issue_info = issue.synopsis
                    except KeyError:
                        issue_info = ''

                    if input_dict['add_technical_info']:
                        issue_description = 'Plugin name: {}\r\n\r\nInfo: \r\n{} \r\n\r\nOutput: \r\n {}'.format(
                            issue.plugin_name,
                            issue_info,
                            issue_output
                        )
                    else:
                        issue_description = 'Plugin name: {}\r\n\r\nInfo: \r\n{} \r\n'.format(
                            issue.plugin_name,
                            issue_info
                        )
                    issue_cve = issue.cve \
                        .replace('[', '') \
                        .replace(']', '') \
                        .replace("'", '') \
                        .replace(",", ', ') if issue.cve else ''
                    issue_severity = float(issue.severity)

                    if issue_severity == 0 and \
                            ('risk_factor' not in issue.get_vuln_info or
                             issue.get_vuln_info['risk_factor'] == 'None'):
                        issue_cvss = 0
                    elif 'cvss3_base_score' in issue.get_vuln_info:
                        issue_cvss = float(issue.get_vuln_info['cvss3_base_score'])
                    elif 'cvss_base_score' in issue.get_vuln_info:
                        issue_cvss = float(issue.get_vuln_info['cvss_base_score'])
                    else:
                        issue_cvss = issue_severity  # nessus tenable fix

                    issue_url_path = ''
                    issue_status = 'need to check'
                    issue_cwe = 0
                    issue_type = 'custom'
                    issue_fix = issue.solution if hasattr(issue, '__vuln_info') and \
                                                  'solution' in issue.__vuln_info else ''
                    issue_param = ''

                    # prepare services
                    issue_port = int(issue.port)
                    issue_is_tcp = int(issue.protocol == 'tcp')
                    if issue_port == 0:
                        issue_is_tcp = 1  # fix for traceroute 0/udp nessus plugin
                    issue_port_id = ''
                    for port_db in all_ports:
                        if port_db['port'] == issue_port and \
                                port_db['is_tcp'] == issue_is_tcp and \
                                port_db['host_id'] == issue_host_id:
                            issue_port_id = port_db['id']

                    if issue_severity > 0 or (issue_severity == 0 and add_info_issues):
                        # search dublicates in db
                        found = 0
                        for exist_issue in db_issues:
                            if not found and \
                                    exist_issue['name'] == issue_name and \
                                    exist_issue['description'] == issue_description and \
                                    exist_issue['url_path'] == issue_url_path and \
                                    exist_issue['cvss'] == issue_cvss and \
                                    exist_issue['status'] == issue_status and \
                                    exist_issue['cve'] == issue_cve and \
                                    exist_issue['cwe'] == issue_cwe and \
                                    exist_issue['type'] == issue_type and \
                                    exist_issue['fix'] == issue_fix and \
                                    exist_issue['param'] == issue_param:
                                found = 1

                                old_services = json.loads(exist_issue['services'])

                                # if already added
                                if exist_issue['id'] in issues_update_services:
                                    pass
                                else:
                                    # if not exists
                                    # {issue_id:{port_id:["0",hostname_id]}}
                                    issues_update_services[exist_issue['id']] = json.loads(exist_issue['services'])
                                    if issue_port_id not in issues_update_services[exist_issue['id']]:
                                        issues_update_services[exist_issue['id']][issue_port_id] = [
                                            issue_hostname_id]
                                    else:
                                        if issue_hostname_id not in issues_update_services[exist_issue['id']][
                                            issue_port_id]:
                                            issues_update_services[exist_issue['id']][issue_port_id].append(
                                                issue_hostname_id)
                                        else:
                                            pass  # not changed
                        if not found:
                            # search issue dublicates into new created
                            found = 0
                            for new_issue in issue_create_list:
                                if not found and \
                                        new_issue['name'] == issue_name and \
                                        new_issue['description'] == issue_description and \
                                        new_issue['url_path'] == issue_url_path and \
                                        new_issue['cvss'] == issue_cvss and \
                                        new_issue['status'] == issue_status and \
                                        new_issue['cve'] == issue_cve and \
                                        new_issue['cwe'] == issue_cwe and \
                                        new_issue['type'] == issue_type and \
                                        new_issue['fix'] == issue_fix and \
                                        new_issue['param'] == issue_param:
                                    found = 1

                                    old_services = new_issue['services']

                                    if issue_port_id not in old_services:
                                        old_services[issue_port_id] = [issue_hostname_id]
                                    else:
                                        if issue_hostname_id not in old_services[issue_port_id]:
                                            old_services[issue_port_id].append(issue_hostname_id)
                                        else:
                                            pass  # not changed
                        if not found:
                            # create new issue
                            issue_create_list.append(
                                {
                                    'name': issue_name,
                                    'description': issue_description,
                                    'url_path': issue_url_path,
                                    'cvss': issue_cvss,
                                    'status': issue_status,
                                    'cve': issue_cve,
                                    'cwe': issue_cwe,
                                    'type': issue_type,
                                    'fix': issue_fix,
                                    'param': issue_param,
                                    'services': {issue_port_id: [issue_hostname_id]},
                                    # {"nessus_plugin_id": {"val": 71049, "type": "number"}}
                                    'fields': {'nessus_plugin_id': {'type': 'number', 'val': plugin_id}},
                                    'technical': '',
                                    'risks': '',
                                    'references': '',
                                    'intruder': ''
                                })

            # 6. Update exists issues services
            if not input_dict['only_import_network']:
                db.update_issue_services_multiple(
                    [issue_id for issue_id in issues_update_services],
                    [issues_update_services[issue_id] for issue_id in issues_update_services]
                )

            # 7. Create new issues
            if not input_dict['only_import_network']:
                db.insert_issues_multiple(
                    [issue['name'] for issue in issue_create_list],
                    [issue['description'] for issue in issue_create_list],
                    [issue['url_path'] for issue in issue_create_list],
                    [issue['cvss'] for issue in issue_create_list],
                    current_user['id'],
                    [issue['services'] for issue in issue_create_list],
                    [issue['status'] for issue in issue_create_list],
                    current_project['id'],
                    [issue['cve'] for issue in issue_create_list],
                    [issue['cwe'] for issue in issue_create_list],
                    [issue['type'] for issue in issue_create_list],
                    [issue['fix'] for issue in issue_create_list],
                    [issue['param'] for issue in issue_create_list],
                    [issue['fields'] for issue in issue_create_list],
                    [issue['technical'] for issue in issue_create_list],
                    [issue['risks'] for issue in issue_create_list],
                    [issue['references'] for issue in issue_create_list],
                    [issue['intruder'] for issue in issue_create_list]
                )
        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report!"

    return ""
