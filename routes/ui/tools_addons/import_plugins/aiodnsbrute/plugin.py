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
route_name = "aiodnsbrute"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/wpNMjp1/tool-dns.png",
        "Official name": "aiodnsbrute",
        "Short name": "aiodnsbrute",
        "Description": "A Python 3.5+ tool that uses asyncio to brute force domain names asynchronously.",
        "URL": "https://github.com/blark/aiodnsbrute",
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
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".json"}
    )

    csv_files = MultipleFileField(
        label='csv_files',
        description='.csv reports (⚠️better don\'t use .csv - some info may be lost⚠️ - <a target="_blank" rel="noopener noreferrer" href="https://gitlab.com/invuls/pentest-projects/pcf/-/issues/138">more info</a>)',
        default=None,
        validators=[],
        _meta={"display_row": 2, "display_column": 1, "file_extensions": ".csv"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from aiodnsbrute scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from aiodnsbrute scan',
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

    for bin_file_data in input_dict['json_files']:
        try:
            json_report_data = bin_file_data.decode('charmap')
            scan_result = json.loads(json_report_data)
            for hostname_row in scan_result:
                hostname = hostname_row['domain']
                ip_list = hostname_row['ip'] if 'ip' in hostname_row else []
                cname = hostname_row['cname'] if 'cname' in hostname_row else ''
                aliases = hostname_row['aliases'] if 'aliases' in hostname_row else []

                # check ip addresses
                ip_list = list(set(ip_list))
                ip_list_tmp = list(filter(None, ip_list))
                ip_list = []
                for ip_str in ip_list_tmp:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if not (ip_obj.version == 6 and input_dict['ignore_ipv6'] == 1):
                            ip_list.append(ip_str)
                    except:
                        pass

                # check hostnames

                hostnames_list = [hostname, cname] + aliases
                hostnames_list = list(set(hostnames_list))
                hostnames_list = list(filter(None, hostnames_list))

                if ip_list and hostnames_list:
                    for ip_str in ip_list:
                        host_id = db.select_project_host_by_ip(current_project['id'], ip_str)
                        if host_id:
                            host_id = host_id[0]['id']
                        else:
                            host_id = db.insert_host(current_project['id'],
                                                     ip_str, current_user['id'],
                                                     input_dict['hosts_description'])

                        hostnames_existed = [x['hostname'] for x in db.select_ip_hostnames(host_id)]

                        for hostname_new in hostnames_list:
                            if hostname_new not in hostnames_existed:
                                hostname_id = db.insert_hostname(host_id, hostname_new,
                                                                 input_dict['hostnames_description'],
                                                                 current_user['id'])
        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing JSON report!"

    for bin_file_data in input_dict['csv_files']:
        try:
            str_data = bin_file_data.decode('utf-8')
            file = StringIO(str_data)
            scan_result = csv.DictReader(codecs.iterdecode(file, 'charmap'), delimiter=',')
            for hostname_row in scan_result:

                hostname = hostname_row['Hostname']
                cname = hostname_row['CNAME']
                host_ip = hostname_row['IPs']
                aliases = hostname_row['Aliases']

                # check ip addresses
                try:
                    ip_obj = ipaddress.ip_address(host_ip)
                    if ip_obj.version == 6 and input_dict['ignore_ipv6'] == 1:
                        host_ip = ''
                except:
                    host_ip = ''
                    pass

                # check hostnames

                hostnames_list = [hostname, cname, aliases]
                hostnames_list = list(set(hostnames_list))
                hostnames_list = list(filter(None, hostnames_list))

                if host_ip and hostnames_list:
                    host_id = db.select_project_host_by_ip(current_project['id'], host_ip)
                    if host_id:
                        host_id = host_id[0]['id']
                    else:
                        host_id = db.insert_host(current_project['id'],
                                                 host_ip, current_user['id'],
                                                 input_dict['hosts_description'])

                    hostnames_existed = [x['hostname'] for x in db.select_ip_hostnames(host_id)]

                    for hostname_new in hostnames_list:
                        if hostname_new not in hostnames_existed:
                            hostname_id = db.insert_hostname(host_id, hostname_new,
                                                             input_dict['hostnames_description'],
                                                             current_user['id'])
        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing CSV report!"

    return ""
