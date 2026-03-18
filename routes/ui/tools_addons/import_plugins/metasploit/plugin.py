######## Imports #########
import base64
import ipaddress
import logging

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "metasploit"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/t8G47gd/2-ENTk2-K2-400x400.png",
        "Official name": "Metasploit",
        "Short name": "metasploit",
        "Description": "The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. It is owned by Boston, Massachusetts-based security company Rapid7.",
        "URL": "https://www.metasploit.com/",
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

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from Metasploit scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    only_nmap = BooleanField(label='only_nmap',
                                    description="Import only nmap result",
                                    default=True,
                                    validators=[],
                                    _meta={"display_row": 2, "display_column": 1})

    add_nmap_scripts = BooleanField(label='add_nmap_scripts',
                                    description="Add nmap scripts output to hosts/services info (!a lot of output!)",
                                    default=False,
                                    validators=[],
                                    _meta={"display_row": 2, "display_column": 2})


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
            soup = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")

            # Add hosts & ports
            hosts_obj = soup.find('hosts')

            scan_result = hosts_obj.findAll('host')

            hosts_dict = {}
            ports_dict = {}

            for host_row in scan_result:
                host_report_id = host_row.find('id').text
                host_ip = host_row.find('address').text
                host_mac = host_row.find('mac').text
                host_state = host_row.find('state').text
                host_os = host_row.find('os-name').text  # Linux
                host_os_flavor = host_row.find('os-flavor').text  # ???
                host_os_version = host_row.find('os-sp').text  # 2.6.X
                host_os_lang = host_row.find('os-lang').text  # ???
                host_os_arch = host_row.find('arch').text  # x86_64
                host_os_detected_arch = host_row.find('detected-arch').text  # x86_64
                host_os_family = host_row.find('os-family').text  # Linux
                host_type = host_row.find('purpose').text  # device
                host_info = host_row.find('info').text
                host_comments = host_row.find('comments').text

                # create Host OS string
                host_os_full = ''
                if host_os:
                    host_os_full += host_os
                if host_os_family and host_os_family != host_os:
                    host_os_full += '({})'.format(host_os_family)
                if host_os_flavor:
                    host_os_full += ' ' + host_os_flavor
                if host_os_version:
                    host_os_full += ' ' + host_os_version
                if host_os_lang:
                    host_os_full += ' Lang:{}'.format(host_os_lang)
                if host_os_arch:
                    host_os_full += ' Arch:{}'.format(host_os_arch)
                if host_os_detected_arch and host_os_detected_arch != host_os_arch:
                    host_os_full += ' Arch detected:{}'.format(host_os_detected_arch)

                # create host description string
                host_description_full = ''
                if host_mac:
                    host_description_full += '\nMAC: {}'.format(host_mac)
                if host_state:
                    host_description_full += '\nState: {}'.format(host_state)
                if host_type:
                    host_description_full += '\nType: {}'.format(host_type)
                if host_info:
                    host_description_full += '\nInfo: {}'.format(host_info)
                if host_comments:
                    host_description_full += '\nComments: {}'.format(host_comments)

                # check if ip correct
                ipaddress.ip_address(host_ip)

                hosts_dict[host_report_id] = {
                    'ip': host_ip,
                    'description': host_description_full.strip(' \t\n\r'),
                    'os': host_os_full
                }

                # add ports
                services_object = host_row.find('services')
                services_arr = services_object.findAll('service')

                # add all ports to ports_dict
                for port_row in services_arr:
                    port_report_id = port_row.find('id').text
                    port_num = int(port_row.find('port').text)  # 80
                    port_is_tcp = port_row.find('proto').text == 'tcp'
                    port_state = port_row.find('state').text  # open closed filtered TODO: add option which port to add
                    port_service = port_row.find('name').text  # ftp
                    port_info = port_row.find('info').text  # vsftpd 2.3.4
                    if port_num > 0 and port_num < 65536:
                        ports_dict[port_report_id] = {
                            'port': port_num,
                            'is_tcp': port_is_tcp,
                            'state': port_state,
                            'service': port_service,
                            'info': port_info,
                            'host_report_id': host_report_id
                        }

                # add notes to port objects - nmap scripts
                if input_dict['add_nmap_scripts']:
                    notes_object = host_row.find('notes')
                    notes_arr = notes_object.findAll('note')
                    for note_row in notes_arr:
                        script_name = note_row.find('ntype').text  # nmap.nse.smb-os-discovery.host
                        if script_name not in ['host.comments', 'host.info', 'host.os.nmap_fingerprint',
                                               'host.name']:
                            host_report_id = note_row.find('host-id').text
                            script_critical = note_row.find('critical').text  # ???
                            service_report_id = note_row.find('service-id').text
                            try:
                                script_data = base64.b64decode(note_row.find('data').text)[16:].decode(
                                    'charmap').strip(' \n\t\r')
                            except Exception as e:
                                script_data = note_row.find('data').text.strip(' \n\t\r')
                            while '  ' in script_data:
                                script_data = script_data.replace('  ', ' ')
                            note_full = 'Script: {}'.format(script_name)
                            if script_critical:
                                note_full += '\nCritical: {}'.format(script_critical)
                            if script_data:
                                note_full += '\nOutput:\n\n{}\n\n'.format(script_data)

                            note_full = note_full.strip(' \t\n\r')

                            if service_report_id:
                                ports_dict[service_report_id]['info'] += '\n' + note_full
                            elif host_report_id:
                                hosts_dict[host_report_id]['description'] += '\n' + note_full

            # add hosts
            for host_obj in hosts_dict:
                current_host = db.select_project_host_by_ip(current_project['id'], hosts_dict[host_obj]['ip'])
                if current_host:
                    host_id = current_host[0]['id']
                    if hosts_dict[host_obj]['description']:
                        db.update_host_description(host_id, hosts_dict[host_obj]['description'])
                    if hosts_dict[host_obj]['os']:
                        db.update_host_os(host_id, hosts_dict[host_obj]['os'])
                else:
                    host_id = db.insert_host(current_project['id'], hosts_dict[host_obj]['ip'], current_user['id'],
                                             hosts_dict[host_obj]['description'], os=hosts_dict[host_obj]['os'])
                hosts_dict[host_obj]['pcf_id'] = host_id

            # add ports
            for port_obj in ports_dict:
                current_port = db.select_host_port(hosts_dict[ports_dict[port_obj]['host_report_id']]['pcf_id'],
                                                   ports_dict[port_obj]['port'],
                                                   ports_dict[port_obj]['is_tcp'])
                if current_port:
                    port_id = current_port[0]['id']
                    db.update_port_proto_description(port_id, ports_dict[port_obj]['service'],
                                                     ports_dict[port_obj]['info'])
                else:
                    port_id = db.insert_host_port(hosts_dict[ports_dict[port_obj]['host_report_id']]['pcf_id'],
                                                  ports_dict[port_obj]['port'], ports_dict[port_obj]['is_tcp'],
                                                  ports_dict[port_obj]['service'],
                                                  ports_dict[port_obj]['info'], current_user['id'],
                                                  current_project['id'])
                ports_dict[port_obj]['pcf_id'] = port_id

            # ignoring websites due to it is connected with services which were added earlier

            if not input_dict['only_nmap']:
                # create websites_dict

                web_dict = {}

                websites_obj = soup.find('web_sites')

                website_row = websites_obj.findAll('web_site')

                for website_obj in website_row:
                    web_id = website_obj.find('id').text
                    service_id = website_obj.find('service-id').text
                    vhost = website_obj.find('vhost').text
                    pcf_port_id = ports_dict[service_id]['pcf_id']
                    pcf_host_id = hosts_dict[ports_dict[service_id]['host_report_id']]['pcf_id']
                    pcf_hostname_id = "0"
                    if vhost:
                        current_hostname = db.select_ip_hostname(pcf_host_id, vhost)
                        if current_hostname:
                            hostname_id = current_hostname[0]['id']
                        else:
                            hostname_id = db.insert_hostname(pcf_host_id, vhost,
                                                             input_dict['hostnames_description'],
                                                             current_user['id'])
                        pcf_hostname_id = hostname_id

                    web_dict[web_id] = {
                        'pcf_port_id': pcf_port_id,
                        'pcf_host_id': pcf_host_id,
                        'pcf_hostname_id': pcf_hostname_id
                    }
                # Add web vulns
                vulns_obj = soup.find('web_vulns')

                vuln_row = vulns_obj.findAll('web_vuln')

                for vuln_obj in vuln_row:
                    vuln_url = vuln_obj.find('path').text
                    vuln_method = vuln_obj.find('method').text
                    vuln_param = vuln_obj.find('pname').text
                    # I don't know how to parse better
                    vuln_params = base64.b64decode(vuln_obj.find('params').text).decode('charmap')[4:]
                    vuln_description = vuln_obj.find('description').text
                    vuln_payload = vuln_obj.find('payload').text
                    vuln_website_id = vuln_obj.find('web-site-id').text
                    vuln_cvss = float(vuln_obj.find('risk').text)
                    vuln_name = 'Metasploit: {}'.format(vuln_obj.find('name').text)
                    vuln_poc_str = vuln_obj.find('proof').text
                    vuln_query = vuln_obj.find('query').text

                    vuln_description_full = vuln_description
                    if vuln_poc_str:
                        vuln_description_full += '\nPoC: {}'.format(vuln_poc_str)
                    if vuln_query:
                        vuln_description_full += '\nQuery: {}'.format(vuln_query)
                    if vuln_params:
                        vuln_description_full += '\nParams: {}'.format(vuln_params)
                    if vuln_payload:
                        vuln_description_full += '\nPayload: {}'.format(vuln_payload)

                    vuln_param_full = '({}) {}'.format(vuln_method, vuln_param)

                    if vuln_cvss < 0 or vuln_cvss > 10:
                        vuln_cvss = 0

                    services = {
                        web_dict[vuln_website_id]['pcf_port_id']: [web_dict[vuln_website_id]['pcf_hostname_id']]}

                    issue_id = db.insert_new_issue_no_dublicate(vuln_name,
                                                                vuln_description_full,
                                                                vuln_url,
                                                                vuln_cvss,
                                                                current_user['id'],
                                                                services,
                                                                'Need to recheck',
                                                                current_project['id'],
                                                                cve='',
                                                                cwe='',
                                                                issue_type='web',
                                                                fix='',
                                                                param=vuln_param_full
                                                                )
        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing XML report!"

    return ""
