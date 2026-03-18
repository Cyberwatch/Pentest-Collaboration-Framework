######## Imports #########
import codecs
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
route_name = "dnsrecon"

tools_description = [
    {
        "Icon file": "icon.svg",
        "Icon URL": "https://svgshare.com/i/cVo.svg",
        "Official name": "DNSrecon",
        "Short name": "dnsrecon",
        "Description": "A simple python script that enables to gather DNS-oriented information on a given target.",
        "URL": "https://github.com/darkoperator/dnsrecon",
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
        default='Added from DNSrecon scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description',
        default='Added from DNSrecon scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )

    ignore_ipv6 = BooleanField(label='ignore_ipv6',
                               description="Ignore IPv6 addresses",
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
    hostnames_dict = {}
    ports_dict = {}

    # json files
    for bin_file_data in input_dict['json_files']:
        try:
            json_report_data = bin_file_data.decode('charmap')
            scan_result = json.loads(json_report_data)
            for hostname_row in scan_result:
                hostname = hostname_row['target'] if 'target' in hostname_row else ''
                hostname_name = hostname_row['mname'] if 'mname' in hostname_row else ''
                host_ip = hostname_row['address'] if 'address' in hostname_row else ''
                host_port = hostname_row['port'] if 'port' in hostname_row else ''
                hostname_info = hostname_row['strings'] if 'strings' in hostname_row else ''
                hostname_type = hostname_row['type'] if 'type' in hostname_row else ''

                '''
                1. Name <--> Address
                2. Target <--> Address
                3. Name <--> String
    
                (Port, Type)
                '''

                if host_ip:
                    # check if host_ip domain or IP
                    try:
                        ipaddress.ip_address(host_ip)
                    except Exception as e:
                        # its domain, need ip
                        host_ip_old = host_ip
                        host_ip = ''
                        for hostname_row_tmp in scan_result:
                            host_ip_tmp = hostname_row['address'] if 'address' in hostname_row else ''
                            domain_tmp = hostname_row['mname'] if 'mname' in hostname_row else ''
                            if host_ip_old == domain_tmp:
                                try:
                                    ipaddress.ip_address(host_ip_tmp)
                                    host_ip = host_ip_tmp
                                except Exception as e1:
                                    pass

                if hostname_name != '' and host_ip != '':
                    # 1. Name <--> Address
                    if hostname == '':
                        if hostname_name not in hostnames_dict:
                            hostnames_dict[hostname_name] = {
                                'ip': [host_ip],
                                'description': 'Type: {}'.format(hostname_type)
                            }
                        else:
                            if host_ip not in hostnames_dict[hostname_name]['ip']:
                                hostnames_dict[hostname_name]['ip'].append(host_ip)
                    # 1. Name <--> Address <--> Target
                    else:
                        if hostname not in hostnames_dict:
                            hostnames_dict[hostname] = {
                                'ip': [host_ip],
                                'description': 'Type: {}\nName: {}'.format(hostname_type, hostname_name)
                            }
                elif hostname_name != '' and host_ip == '' and hostname_info != '':
                    # Name <--> String
                    if hostname_name not in hostnames_dict:
                        hostnames_dict[hostname_name] = {
                            'ip': [],
                            'description': 'Type: {}\nInfo: {}'.format(hostname_type, hostname_info)
                        }
                    else:
                        hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type,
                                                                                                      hostname_info)
                elif hostname != '' and host_ip != '' and hostname_name == '':
                    # Target <--> Address
                    if hostname not in hostnames_dict:
                        hostnames_dict[hostname] = {
                            'ip': [host_ip],
                            'description': 'Type: {}'.format(hostname_type),
                        }
                # add ports
                if host_port != '' and host_ip != '':
                    if host_ip not in ports_dict:
                        ports_dict[host_ip] = [host_port]
                    else:
                        if host_port not in ports_dict[host_ip]:
                            ports_dict[host_ip].append(host_port)
        except Exception as e:
            logging.error("Exception with one of json-files: {}".format(e))
            return "Error during parsing json-file!"
    # csv load
    for bin_file_data in input_dict['csv_files']:
        try:
            str_data = bin_file_data.decode('utf-8')
            file = StringIO(str_data)
            scan_result = csv.DictReader(codecs.iterdecode(file, 'charmap'), delimiter=',')

            for hostname_row in scan_result:

                hostname = hostname_row['Target']
                hostname_name = hostname_row['Name']
                host_ip = hostname_row['Address']
                host_port = hostname_row['Port']
                hostname_info = hostname_row['String']
                hostname_type = hostname_row['Type']

                '''
                1. Name <--> Address
                2. Target <--> Address
                3. Name <--> String
    
                (Port, Type)
                '''
                if host_ip:
                    # check if host_ip domain or IP
                    try:
                        ipaddress.ip_address(host_ip)
                    except Exception as e:
                        # its domain, need ip
                        host_ip_old = host_ip
                        host_ip = ''
                        for hostname_row_tmp in scan_result:
                            host_ip_tmp = hostname_row_tmp['Address']
                            domain_tmp = hostname_row_tmp['Name']
                            if host_ip_old == domain_tmp:
                                try:
                                    ipaddress.ip_address(host_ip_tmp)
                                    host_ip = host_ip_tmp
                                except Exception as e1:
                                    pass

                if hostname_name != '' and host_ip != '':
                    # 1. Name <--> Address
                    if hostname == '':
                        if hostname_name not in hostnames_dict:
                            hostnames_dict[hostname_name] = {
                                'ip': [host_ip],
                                'description': 'Type: {}'.format(hostname_type)
                            }
                        else:
                            if host_ip not in hostnames_dict[hostname_name]['ip']:
                                hostnames_dict[hostname_name]['ip'].append(host_ip)
                    # 1. Name <--> Address <--> Target
                    else:
                        if hostname not in hostnames_dict:
                            hostnames_dict[hostname] = {
                                'ip': [host_ip],
                                'description': 'Type: {}\nName: {}'.format(hostname_type, hostname_name)
                            }
                elif hostname_name != '' and host_ip == '' and hostname_info != '':
                    # Name <--> String
                    if hostname_name not in hostnames_dict:
                        hostnames_dict[hostname_name] = {
                            'ip': [],
                            'description': 'Type: {}\nInfo: {}'.format(hostname_type, hostname_info)
                        }
                    else:
                        hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type,
                                                                                                      hostname_info)
                elif hostname != '' and host_ip != '' and hostname_name == '':
                    # Target <--> Address
                    if hostname not in hostnames_dict:
                        hostnames_dict[hostname] = {
                            'ip': [host_ip],
                            'description': 'Type: {}'.format(hostname_type),
                        }
                # add ports
                if host_port != '' and host_ip != '':
                    if host_ip not in ports_dict:
                        ports_dict[host_ip] = [host_port]
                    else:
                        if host_port not in ports_dict[host_ip]:
                            ports_dict[host_ip].append(host_port)
        except Exception as e:
            logging.error("Exception with one of csv-files: {}".format(e))
            return "Error during parsing csv-file!"

    for bin_file_data in input_dict['xml_files']:
        try:
            soup = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")

            scan_result = soup.findAll('record')

            for hostname_row in scan_result:

                hostname = hostname_row.get('target') if hostname_row.get('target') else ''
                hostname_name = hostname_row.get('name') if hostname_row.get('name') else ''
                host_ip = hostname_row.get('address') if hostname_row.get('address') else ''
                host_port = hostname_row.get('port') if hostname_row.get('port') else ''
                hostname_info = hostname_row.get('strings') if hostname_row.get('strings') else ''
                hostname_type = hostname_row.get('type') if hostname_row.get('type') else ''

                '''
                1. Name <--> Address
                2. Target <--> Address
                3. Name <--> String
    
                (Port, Type)
                '''
                if host_ip:
                    # check if host_ip domain or IP
                    try:
                        ipaddress.ip_address(host_ip)
                    except Exception as e:
                        # its domain, need ip
                        host_ip_old = host_ip
                        host_ip = ''
                        for hostname_row_tmp in scan_result:
                            host_ip_tmp = hostname_row_tmp.get('address') if hostname_row_tmp.get('address') else ''
                            domain_tmp = hostname_row_tmp.get('name') if hostname_row_tmp.get('name') else ''
                            if host_ip_old == domain_tmp:
                                try:
                                    ipaddress.ip_address(host_ip_tmp)
                                    host_ip = host_ip_tmp
                                except Exception as e1:
                                    pass

                if hostname_name != '' and host_ip != '':
                    # 1. Name <--> Address
                    if hostname == '':
                        if hostname_name not in hostnames_dict:
                            hostnames_dict[hostname_name] = {
                                'ip': [host_ip],
                                'description': 'Type: {}'.format(hostname_type)
                            }
                        else:
                            if host_ip not in hostnames_dict[hostname_name]['ip']:
                                hostnames_dict[hostname_name]['ip'].append(host_ip)
                    # 1. Name <--> Address <--> Target
                    else:
                        if hostname not in hostnames_dict:
                            hostnames_dict[hostname] = {
                                'ip': [host_ip],
                                'description': 'Type: {}\nName: {}'.format(hostname_type, hostname_name)
                            }
                elif hostname_name != '' and host_ip == '' and hostname_info != '':
                    # Name <--> String
                    if hostname_name not in hostnames_dict:
                        hostnames_dict[hostname_name] = {
                            'ip': [],
                            'description': 'Type: {}\nInfo: {}'.format(hostname_type, hostname_info)
                        }
                    else:
                        hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type,
                                                                                                      hostname_info)
                elif hostname != '' and host_ip != '' and hostname_name == '':
                    # Target <--> Address
                    if hostname not in hostnames_dict:
                        hostnames_dict[hostname] = {
                            'ip': [host_ip],
                            'description': 'Type: {}'.format(hostname_type),
                        }
                # add ports
                if host_port != '' and host_ip != '':
                    if host_ip not in ports_dict:
                        ports_dict[host_ip] = [host_port]
                    else:
                        if host_port not in ports_dict[host_ip]:
                            ports_dict[host_ip].append(host_port)
        except Exception as e:
            logging.error("Exception with one of xml-files: {}".format(e))
            return "Error during parsing xml-file!"

    # hostnames_dict = {'google.com':{'ip':[8.8.8.8], 'description': '...' }}

    for hostname in hostnames_dict:
        ip_array = hostnames_dict[hostname]['ip']
        description = hostnames_dict[hostname]['description']
        for ip_address in ip_array:
            # check if valid ip
            ip_obj = ipaddress.ip_address(ip_address)
            if (':' not in ip_address) or (':' in ip_address and not input_dict['ignore_ipv6']):

                current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
                if not current_host:
                    host_id = db.insert_host(current_project['id'], ip_address, current_user['id'],
                                             input_dict['hosts_description'])
                else:
                    host_id = current_host[0]['id']

                current_hostname = db.select_ip_hostname(host_id, hostname)
                if not current_hostname:
                    hostname_id = db.insert_hostname(host_id, hostname, description, current_user['id'])
                else:
                    hostname_id = current_hostname[0]['id']
                    db.update_hostname(hostname_id, description)

    # ports_dict = {'ip':['8888']}
    for ip_address in ports_dict:
        # check if valid ip
        ports_arr = list(set(ports_dict[ip_address]))
        ip_obj = ipaddress.ip_address(ip_address)
        if (':' not in ip_address) or (':' in ip_address and not input_dict['ignore_ipv6']):
            current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
            if not current_host:
                host_id = db.insert_host(current_project['id'], ip_address, current_user['id'],
                                         input_dict['hosts_description'])
            else:
                host_id = current_host[0]['id']

            for port_num in ports_arr:
                port_num_int = int(port_num)
                if 0 < port_num_int < 65536:
                    current_port = db.select_host_port(host_id, int(port_num), is_tcp=True)
                    if not current_port:
                        port_id = db.insert_host_port(host_id, port_num_int, True, 'unknown',
                                                      input_dict['ports_description'], current_user['id'],
                                                      current_project['id'])

    return ""
