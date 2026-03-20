######## Imports #########
import ipaddress
import json
import logging
import socket
import urllib

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "netsparker"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/MkzmkTC/netsparker.png",
        "Official name": "NetSparker",
        "Short name": "netsparker",
        "Description": "An automated, yet fully configurable, web application security scanner that enables you to scan websites, web applications and web services, and identify security flaws. Netsparker can scan all types of web applications, regardless of the platform or the language with which they are built.",
        "URL": "https://www.netsparker.com/support/what-is-netsparker/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(
        label='xml_files',
        description='.xml reports ',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hosts_description = StringField(
        label='hosts_description',
        description='Hosts description',
        default='Added from NetSparker scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 1}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostnames description',
        default='Added from NetSparker scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    ports_description = StringField(
        label='ports_description',
        description='Ports description (if empty)',
        default='Added from NetSparker scan',
        validators=[],
        _meta={"display_row": 2, "display_column": 2}
    )

    only_confirmed = BooleanField(label='only_confirmed',
                                  description="Only confirmed vulnerabilities",
                                  default=True,
                                  validators=[],
                                  _meta={"display_row": 3, "display_column": 1})


########### Request processing

def beautify_output(xml_str):
    if xml_str == '  ': xml_str = ''
    xml_str = xml_str.replace('<p>', '\t').replace('</p>', '\n')
    xml_str = xml_str.replace('<li>', '* ').replace('</li>', '\n')
    xml_str = xml_str.replace('<ol>', '\n').replace('</ol>', '\n')
    xml_str = xml_str.replace('<div>', '').replace('</div>', '\n')
    xml_str = xml_str.replace("<a target='_blank' href='", '').replace("'><i class='icon-external-link'></i>",
                                                                       ' - ')
    xml_str = xml_str.replace('<ul>', '').replace('</ul>', '')
    xml_str = xml_str.replace('</a>', '\n')
    return xml_str


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
            query_list = scan_result.find_all("vulnerability")

            for vuln in query_list:
                is_confirmed = vuln.get('confirmed') == 'True'
                if is_confirmed or (not input_dict['only_confirmed']):
                    vuln_url = vuln.find('url').text
                    vuln_name = 'Netsparker: ' + vuln.find('type').text
                    vuln_severity = vuln.find('severity').text  # High, Medium, Low, Information, BestPractice
                    vuln_description = beautify_output(vuln.find('description').text)
                    vuln_impact = beautify_output(vuln.find('impact').text)
                    vuln_fix = beautify_output(vuln.find('actionstotake').text)
                    vuln_fix1 = beautify_output(vuln.find('remedy').text)
                    vuln_skills = beautify_output(vuln.find('requiredskillsforexploitation').text)
                    vuln_links = beautify_output(vuln.find('externalreferences').text)
                    vuln_fix1_links = beautify_output(vuln.find('remedyreferences').text)
                    vuln_request = beautify_output(vuln.find('rawrequest').text)
                    vuln_response = beautify_output(vuln.find('rawresponse').text)
                    vuln_poc = beautify_output(vuln.find('proofofconcept').text)

                    vuln_path = ''
                    vuln_args = ''
                    # parse info
                    info_list = vuln.find('extrainformation').findAll('info')
                    for info_obj in info_list:
                        info_name = info_obj.get('name')
                        if info_name == 'ParserAnalyzerEngine_InputName':
                            vuln_args += ', (Input) ' + info_name
                        elif info_name == 'ParserAnalyzerEngine_FormTargetAction':
                            vuln_path = info_name
                        elif info_name == 'ParserAnalyzerEngine_IdentifiedFieldName':
                            vuln_args += ', (Input) ' + info_name
                        elif info_name == 'CookieAnalyzerEngine_IdentifiedCookies':
                            vuln_args += ', (Cookie) ' + info_name
                        elif info_name == 'ExtractedVersion':
                            vuln_description += '\n\nExtracted version: ' + info_name
                        elif info_name == 'IdentifiedErrorMessage':
                            vuln_description += '\n\nError message: \n' + info_name
                        elif info_name == 'ExtractedIPAddresses':
                            vuln_description += '\n\nExtracted IP: ' + info_name
                        elif info_name == 'CustomField_FormAction':
                            vuln_path = info_name
                        elif info_name == 'ParserAnalyzerEngine_ExternalLinks':
                            vuln_description += '\n\nExternal links: \n' + info_name
                        elif info_name == 'ParserAnalyzerEngine_FormName':
                            vuln_args += ', (Form) ' + info_name
                        elif info_name == 'EmailDisclosure_EmailAddresses':
                            vuln_description += '\n\nFound email: ' + info_name
                        elif info_name == 'Options_Allowed_Methods':
                            vuln_description += '\n\nAllowed methods: ' + info_name
                        elif info_name == 'ParserAnalyzerEngine_FormTargetAction':
                            vuln_description = '\n\nInternal path: ' + info_name

                    vuln_cwe = vuln.find('classification').find('cwe').text
                    if not vuln_cwe: vuln_cwe = 0
                    vuln_cvss = 0
                    classification_obj = vuln.find('classification')
                    if classification_obj.find('cvss'):
                        for cvss_obj in classification_obj.find('cvss').findAll('score'):
                            if cvss_obj.find('type').text == 'Base':
                                vuln_cvss = float(cvss_obj.find('value').text)

                    # parse url

                    splitted_url = urllib.parse.urlsplit(vuln_url)
                    vuln_scheme = splitted_url.scheme
                    if not vuln_scheme:
                        vuln_scheme = 'http'
                    vuln_host_unverified = splitted_url.hostname
                    vuln_path_unverified = splitted_url.path
                    vuln_port = splitted_url.port
                    if not vuln_port:
                        if vuln_scheme == 'https':
                            vuln_port = 443
                        elif vuln_scheme == 'ftp':
                            vuln_port = 21
                        else:
                            vuln_port = 80
                    vuln_port = int(vuln_port)
                    if not vuln_path:
                        vuln_path = vuln_path_unverified
                    is_ip = False
                    vuln_host = ''
                    vuln_hostname = ''
                    try:
                        vuln_host = str(ipaddress.ip_address(vuln_host_unverified))
                    except ValueError:
                        vuln_hostname = vuln_host_unverified

                    if not vuln_host and vuln_hostname:
                        try:
                            vuln_host = str(socket.gethostbyname(vuln_host_unverified))
                        except:
                            pass

                    hostname_id = ''
                    port_id = ''
                    host_id = ''
                    if vuln_host:
                        dublicate_host = db.select_project_host_by_ip(current_project['id'], vuln_host)

                        if not dublicate_host:
                            host_id = db.insert_host(current_project['id'],
                                                     vuln_host,
                                                     current_user['id'],
                                                     input_dict['hosts_description'])
                        else:
                            host_id = dublicate_host[0]['id']

                        # add port

                        dublicate_port = db.select_host_port(host_id, vuln_port, True)
                        if not dublicate_port:
                            port_id = db.insert_host_port(host_id, vuln_port, True,
                                                          vuln_scheme, input_dict['ports_description'],
                                                          current_user['id'], current_project['id'])
                        else:
                            port_id = dublicate_port[0]['id']

                        # add hostname

                        if vuln_hostname:
                            dublicate_hostname = db.select_ip_hostname(host_id, vuln_hostname)
                            if not dublicate_hostname:
                                hostname_id = db.insert_hostname(host_id, vuln_hostname,
                                                                 input_dict['hostnames_description'],
                                                                 current_user['id'])
                            else:
                                hostname_id = dublicate_hostname[0]['id']

                    # add issue

                    full_description = 'URL: {}\n\nDescription: \n{}\n\n'.format(vuln_url, vuln_description)
                    if vuln_impact:
                        full_description += 'Impact: ' + vuln_impact + '\n\n'
                    if vuln_skills:
                        full_description += 'Skills: ' + vuln_skills + '\n\n'
                    if vuln_poc:
                        full_description += 'PoC: ' + vuln_poc + '\n\n'
                    if vuln_links:
                        full_description += 'Links: \n' + vuln_links + '\n\n'

                    full_fix = 'Actions: ' + vuln_fix + '\n Fix:' + vuln_fix1 + '\n Links: ' + vuln_fix1_links

                    services = {}
                    if hostname_id:
                        services[port_id] = [hostname_id]
                    elif port_id:
                        services[port_id] = ["0"]

                    issue_id = db.insert_new_issue_no_dublicate(vuln_name, full_description,
                                                                vuln_path, vuln_cvss,
                                                                current_user['id'],
                                                                services,
                                                                'Need to recheck',
                                                                current_project['id'],
                                                                '', vuln_cwe, 'web', full_fix, vuln_args)
                    # create PoC
                    poc_text = vuln_request + vuln_response
                    poc_text = poc_text.replace('\r', '')

                    file_data = b''

                    if global_config['files']['poc_storage'] == 'database':
                        file_data = poc_text.encode('charmap')

                    poc_id = db.insert_new_poc(port_id if port_id else "0",
                                               'Added from Netsparker',
                                               'text',
                                               'HTTP.txt',
                                               issue_id,
                                               current_user['id'],
                                               hostname_id if hostname_id else '0',
                                               storage=global_config['files']['poc_storage'],
                                               data=file_data)

                    if global_config['files']['poc_storage'] == 'filesystem':
                        file_path = './static/files/poc/{}'.format(poc_id)
                        file_object = open(file_path, 'w')
                        file_object.write(poc_text)
                        file_object.close()

        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report, check that you upload \"Scan results\" XML file, not \"Reports\" XML."

    return ""
