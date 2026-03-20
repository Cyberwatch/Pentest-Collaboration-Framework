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
route_name = "qualys"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/N9D5ytT/qualys.png",
        "Official name": "Qualys",
        "Short name": "qualys",
        "Description": "Provides you with continuous security and compliance, allowing you to monitor, detect and protect your global network with instant, unparalleled \"single-pane-of-glass\" visibility.",
        "URL": "https://www.qualys.com/cloud-platform/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(
        label='xml_files',
        description='.xml reports ("Scan results" Qualys page)',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from Qualys scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description',
        default='Added from Qualys scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 1}
    )

    add_empty_host = BooleanField(label='add_empty_host',
                                  description="Add hosts without ports/issues",
                                  default=False,
                                  validators=[],
                                  _meta={"display_row": 2, "display_column": 2})


########### Request processing

def beautify_output(xml_str):
    xml_str = xml_str.replace('<p>', '\t').replace('<P>', '\t')
    xml_str = xml_str.replace('<BR>', '\n').replace('</p>', '\n')
    return xml_str


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
            scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            hosts_list = scan_result.find_all("ip")
            for host in hosts_list:
                host_id = ''
                hostname = ''
                # TODO: host??
                ip = host.attrs['value']
                tmp_host = db.select_project_host_by_ip(current_project['id'], ip)
                if tmp_host:
                    host_id = tmp_host[0]['id']
                if 'name' in host.attrs and ip != host.attrs['name']:
                    hostname = host.attrs['name']
                # TODO: dont forget to add 2hostname
                if input_dict['add_empty_host'] and not host_id:
                    host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                             input_dict['hosts_description'])
                ports_list = host.find('services')
                if ports_list:
                    for port_obj in ports_list.findAll('cat'):
                        if 'port' in port_obj.attrs and 'protocol' in port_obj.attrs:
                            if not host_id:
                                host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                         input_dict['hosts_description'])

                            port = int(port_obj.attrs['port'])
                            is_tcp = int(port_obj.attrs['protocol'] == 'tcp')
                            service = port_obj.attrs['value']

                            port_id = db.select_host_port(host_id, port, is_tcp)
                            if port_id:
                                port_id = port_id[0]['id']
                                db.update_port_service(port_id, service)
                            else:
                                port_id = db.insert_host_port(host_id, port, is_tcp, service,
                                                              input_dict['ports_description'],
                                                              current_user['id'], current_project['id'])

                issues_list = host.find('vulns')
                if issues_list:
                    for issue_obj in issues_list.findAll('cat'):
                        if not host_id:
                            host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                     input_dict['hosts_description'])
                        port_num = 0
                        is_tcp = 1
                        if 'port' in issue_obj.attrs and 'protocol' in issue_obj.attrs:
                            port_num = int(issue_obj.attrs['port'])
                            is_tcp = int(issue_obj.attrs['protocol'] == 'tcp')

                        port_id = db.select_host_port(host_id, port_num, is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id, port_num, is_tcp, 'unknown',
                                                          input_dict['ports_description'],
                                                          current_user['id'], current_project['id'])
                        else:
                            port_id = port_id[0]['id']
                        for vuln_object in issue_obj.findAll("vuln"):
                            cvss = 0
                            cvss_tmp1 = vuln_object.find('cvss3_base')
                            cvss_tmp2 = vuln_object.find('cvss3_temporal')
                            cvss_tmp3 = vuln_object.find('cvss_temporal')
                            if cvss_tmp1 and cvss_tmp1.text not in ['-', '']:
                                cvss = float(cvss_tmp1.text)
                            elif cvss_tmp2 and cvss_tmp2.text not in ['-', '']:
                                cvss = float(cvss_tmp2.text)
                            elif cvss_tmp3 and cvss_tmp3.text not in ['-', '']:
                                cvss = float(cvss_tmp3.text)
                            elif 'severity' in vuln_object.attrs:
                                sev_acunetix = int(vuln_object.attrs['severity'])
                                if sev_acunetix == 1:
                                    cvss = 0.0
                                elif sev_acunetix == 2:
                                    cvss = 2.0
                                elif sev_acunetix == 3:
                                    cvss = 5.0
                                elif sev_acunetix == 4:
                                    cvss = 8.0
                                elif sev_acunetix == 5:
                                    cvss = 9.5

                            issue_name = vuln_object.find('title').text
                            issue_diagnostic = vuln_object.find('diagnosis').text
                            issue_risks = vuln_object.find('consequence').text
                            issue_solution = beautify_output(vuln_object.find('solution').text)

                            # TODO: add PoC
                            issue_output = vuln_object.find('result')
                            try:
                                issue_output = vuln_object.find('result').text
                            except AttributeError:
                                issue_output = ''

                            issue_full_description = 'Diagnosis: \n{}'.format(issue_diagnostic)
                            issue_full_description = beautify_output(issue_full_description)
                            services = {port_id: ['0']}
                            issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_full_description, '', cvss,
                                                                        current_user['id'], services, 'Need to recheck',
                                                                        current_project['id'], '', 0, 'custom',
                                                                        issue_solution, '', risks=issue_risks)

                issues_list = host.find('practices')
                if issues_list:
                    for issue_obj in issues_list.findAll('practice'):
                        if not host_id:
                            host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                     input_dict['hosts_description'])
                        cve = ''
                        if 'cveid' in issue_obj.attrs:
                            cve = issue_obj.attrs['cveid']

                        issue_name = issue_obj.find('title').text
                        issue_diagnostic = issue_obj.find('diagnosis').text
                        issue_risks = issue_obj.find('consequence').text
                        issue_solution = beautify_output(issue_obj.find('solution').text)
                        # TODO: add PoC
                        issue_output = issue_obj.find('result')
                        try:
                            issue_output = issue_obj.find('result').text
                        except AttributeError:
                            issue_output = ''
                        issue_full_description = 'Diagnosis: \n{}'.format(issue_diagnostic)

                        issue_full_description = beautify_output(issue_full_description)

                        issue_links = []

                        for url in issue_obj.findAll('url'):
                            issue_links.append(url.text)
                        for url in issue_obj.findAll('link'):
                            issue_links.append(url.text)

                        if issue_links:
                            issue_full_description += '\n\nLinks:\n' + '\n'.join(
                                ['- ' + url for url in issue_links])

                        cvss = 0
                        cvss_tmp1 = issue_obj.find('cvss3_base')
                        cvss_tmp2 = issue_obj.find('cvss3_temporal')
                        cvss_tmp3 = issue_obj.find('cvss_temporal')
                        if cvss_tmp1 and cvss_tmp1.text not in ['-', '']:
                            cvss = float(cvss_tmp1.text)
                        elif cvss_tmp2 and cvss_tmp2.text not in ['-', '']:
                            cvss = float(cvss_tmp2.text)
                        elif cvss_tmp3 and cvss_tmp3.text not in ['-', '']:
                            cvss = float(cvss_tmp3.text)
                        elif 'severity' in issue_obj.attrs:
                            sev_acunetix = int(issue_obj.attrs['severity'])
                            if sev_acunetix == 1:
                                cvss = 0.0
                            elif sev_acunetix == 2:
                                cvss = 2.0
                            elif sev_acunetix == 3:
                                cvss = 5.0
                            elif sev_acunetix == 4:
                                cvss = 8.0
                            elif sev_acunetix == 5:
                                cvss = 9.5

                        # try to detect port
                        port = 0
                        is_tcp = 1

                        info_str = issue_output.split('\n')[0]
                        if ' detected on port ' in info_str:
                            port = int(info_str.split(' detected on port ')[1].split(' ')[0].split('.')[0])
                            if ' over ' in info_str.split(' detected on port ')[1]:
                                is_tcp = int(info_str.split(' detected on port ')[1].split(' over ')[1].split(' ')[
                                                 0] == 'TCP')

                        port_id = db.select_host_port(host_id, port, is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id, port, is_tcp, 'unknown',
                                                          input_dict['ports_description'],
                                                          current_user['id'], current_project['id'])
                        else:
                            port_id = port_id[0]['id']
                        services = {port_id: ['0']}
                        issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_full_description, cve, cvss,
                                                                    current_user['id'], services, 'Need to recheck',
                                                                    current_project['id'], '', 0, 'custom',
                                                                    issue_solution, '', risks=issue_risks)

        except OverflowError as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report, check that you upload \"Scan results\" XML file, not \"Reports\" XML."

    return ""
