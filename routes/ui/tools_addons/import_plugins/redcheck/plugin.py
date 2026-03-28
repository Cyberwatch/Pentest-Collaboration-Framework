######## Imports #########
import csv
import ipaddress
import logging
from io import StringIO

from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "redcheck"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/DVWwGcS/redcheck.png",
        "Official name": "RedCheck",
        "Short name": "redcheck",
        "Description": "Network vulnerability scanner with whitebox testing mode.",
        "URL": "https://www.redcheck.ru/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    csv_files = MultipleFileField(
        label='csv_files',
        description='.csv reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".csv"}
    )

    hosts_description = StringField(
        'hosts_description',
        description='Hosts description',
        default='Added from RedCheck scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )
    hostnames_description = StringField(
        'hostnames_description',
        description='Hostnames description',
        default='Added from RedCheck scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )
    ports_description = StringField(
        'ports_description',
        description='Ports description (if no other info)',
        default='Added from RedCheck scan',
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

    # fields variables
    csv_files = input_dict["csv_files"]
    hosts_description = input_dict["hosts_description"]
    hostnames_description = input_dict["hostnames_description"]
    ports_description = input_dict["ports_description"]

    for bin_data in csv_files:
        if bin_data:
            str_data = bin_data.decode('utf-8')
            file = StringIO(str_data)
            scan_result = csv.DictReader(file, delimiter=',')

            for issue_row in scan_result:

                host_ip = issue_row['Хост'] if 'Хост' in issue_row else issue_row['\ufeffХост']
                cve_str = issue_row['Cve/AltxId']
                issue_port = int(issue_row['Порт']) if issue_row['Порт'] else 0
                is_tcp = issue_row['Протокол'] == 'tcp'
                issue_severity_ru = issue_row['Критичность']
                issue_description = issue_row['Описание']
                issue_cpe = issue_row['Cpe']
                service_name = issue_row['Имя сервиса'] if issue_row['Имя сервиса'] else 'unknown'
                issue_tech = issue_row['Детализация']
                issue_cvss2 = issue_row['Cvss2']
                issue_cvss2_vector = issue_row['Cvss2 Вектор']
                issue_cvss3 = issue_row['Cvss3']
                issue_cvss3_vector = issue_row['Cvss3 Вектор']
                issue_cve_url = issue_row['Cve Url'] if issue_row['Cve Url'] and \
                                                        issue_row['Cve Url'] != 'Нет данных' else ''

                issue_real_severity = 0
                if issue_cvss3:
                    issue_real_severity = float(issue_cvss3)
                elif issue_cvss2:
                    issue_real_severity = float(issue_cvss2)
                elif issue_severity_ru:
                    if issue_severity_ru == 'Критический':
                        issue_real_severity = 9.5
                    elif issue_severity_ru == 'Высокий':
                        issue_real_severity = 8.0
                    elif issue_severity_ru == 'Средний':
                        issue_real_severity = 2.0
                    elif issue_severity_ru == 'Низкий':
                        issue_real_severity = 0.0
                    else:
                        issue_real_severity = 0.0

                if issue_real_severity > 10 or issue_real_severity < 0:
                    issue_real_severity = 0

                # check ip addresses
                try:
                    ip_obj = ipaddress.ip_address(host_ip)
                except:
                    logging.error(host_ip)
                    return "Wrong ip-address!"
                # check port
                if issue_port < 0 or issue_port > 65535:
                    return "Wrong port number!"

                # Create host
                host_id = db.select_project_host_by_ip(current_project['id'], host_ip)
                if host_id:
                    host_id = host_id[0]['id']
                else:
                    host_id = db.insert_host(current_project['id'],
                                             host_ip, current_user['id'],
                                             hosts_description)

                # Create port
                port_id = db.select_host_port(host_id, issue_port, is_tcp)
                if port_id:
                    port_id = port_id[0]['id']
                else:
                    port_id = db.insert_host_port(host_id, issue_port, is_tcp, service_name,
                                                  ports_description, current_user['id'],
                                                  current_project['id'])

                # Create issue
                issue_id = db.insert_new_issue_no_dublicate(
                    "RedCheck: {}".format(cve_str),
                    issue_description,
                    '',
                    issue_real_severity,
                    current_user['id'],
                    {port_id: ["0"]},
                    "Need to recheck",
                    current_project['id'],
                    cve_str,
                    0,
                    'custom',
                    '',
                    '',
                    issue_tech,
                    '',
                    issue_cve_url
                )

                # Add additional fields
                fields_dict = {}
                if issue_cvss3_vector:
                    fields_dict["cvss_vector"] = {
                        "type": "text",
                        "val": "CVSS:3.1/" + issue_cvss3_vector.replace("CVSS:3.0/", "").replace("CVSS:3.1/", "")
                    }
                if issue_cvss2_vector:
                    fields_dict["cvss2_vector"] = {
                        "type": "text",
                        "val": issue_cvss2_vector
                    }
                if issue_cvss2:
                    fields_dict["cvss2"] = {
                        "type": "float",
                        "val": float(issue_cvss2)
                    }

                if issue_cpe:
                    fields_dict["cpe"] = {
                        "type": "text",
                        "val": issue_cpe
                    }

                if fields_dict:
                    db.update_issue_fields(issue_id, fields_dict)
    return ""
