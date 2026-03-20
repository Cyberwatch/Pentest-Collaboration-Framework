######## Imports #########
import ipaddress
import json

from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *

from system.db import Database

######## Description #############
route_name = "scanvus"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/mTfyrdf/scanvus.png",
        "Official name": "Scanvus",
        "Short name": "scanvus",
        "Description": "A Simple Credentialed Authenticated Network VUlnerability Scanner for Linux hosts and Docker images, which uses the Vulners Linux API under the hood.",
        "URL": "https://github.com/leonov-av/scanvus",
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

    ip = StringField(
        label='ip',
        description='Insert scanned IP',
        default='',
        validators=[DataRequired(message="'ip' is required!")],
        _meta={"display_row": 1, "display_column": 2}
    )

    host_description = StringField(
        label='host_description',
        description='New host description',
        default='Added from Scanvus',
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

    host_id = None
    port_id = None
    if input_dict['ip']:
        try:
            ipaddress.ip_address(input_dict['ip'])
            current_host = db.select_project_host_by_ip(current_project['id'], input_dict['ip'])
            if current_host:
                current_host = current_host[0]
                host_id = current_host['id']
            else:
                host_id = db.insert_host(current_project['id'], input_dict['ip'], current_user['id'],
                                         comment=input_dict['host_description'], os='Linux')
        except Exception as e:
            pass
    if host_id:
        port_id = db.select_host_port(host_id)[0]['id']
    for bin_file_data in input_dict['json_files']:
        json_report_data = bin_file_data.decode('charmap')
        scan_result = json.loads(json_report_data)
        for script_name in scan_result:
            vuln_versions = ''
            for package_name in scan_result[script_name]['packages']:
                package_obj = scan_result[script_name]['packages'][package_name]
                operator = package_obj['operator'].replace('lt', '<')
                operator = operator.replace('gt', '>')
                version = package_obj['bulletinVersion']
                if len(operator) in ['gt', 'lt']:
                    operator = '='
                vuln_versions += '{} {}{},'.format(package_name, operator, version)
            vuln_versions = vuln_versions.strip('\n')
            vuln_obj = scan_result[script_name]['vuln']
            vuln_level = vuln_obj['Level']
            vuln_cves = ','.join(vuln_obj['CVE List'])
            vuln_cvss_num = vuln_obj['CVSS']['score']
            vuln_cvss_vector = vuln_obj['CVSS']['vector']

            vuln_desc_full = ''
            if vuln_versions:
                vuln_desc_full += 'Vulnerable software: ' + vuln_versions

            vuln_services = {}
            if port_id:
                vuln_services = {port_id: ["0"]}

            issue_id = db.insert_new_issue_no_dublicate('Scanvus: {}'.format(script_name),
                                                        vuln_desc_full, '', vuln_cvss_num, current_user['id'],
                                                        vuln_services,
                                                        'Need to recheck', current_project['id'], cve=vuln_cves
                                                        )
    return ""
