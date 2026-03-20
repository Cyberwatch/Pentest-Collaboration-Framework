######## Imports #########
import base64
import ipaddress
import json
import logging
import urllib.parse
import socket

from IPy import IP

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "qualys_was"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/pzr4QN0/Qualys-logo.png",
        "Official name": "Qualys WAS (Web Application Scanner)",
        "Short name": "qualys_was",
        "Description": "An automated scanner that uses fault injection tests to find vulnerabilities. It inserts specially crafted character strings into your application form fields. WAS then examines the responses from your web application to determine the existence of vulnerability. You can see what is sent and how your application responded in WAS’s reporting capabilities. Qualys WAS enables organizations to scan their web applications for vulnerabilities. It assess, track, and remediate web application vulnerabilities.",
        "URL": "https://www.qualys.com/apps/web-app-scanning/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    files = MultipleFileField(
        label='files',
        description='.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    hostnames_file = StringField(
        label='hostnames_file',
        description='or take IPs from this field',
        default='127.0.0.1     vulnsite1.com,vulnsite2.com,subdomain.vulnsite2.com\n',
        validators=[],
        _meta={"display_row": 3, "display_column": 1, "multiline": True}
    )

    auto_resolve = BooleanField(label='auto_resolve',
                                description="Automatic resolve ip from PCF server",
                                default=True,
                                validators=[],
                                _meta={"display_row": 2, "display_column": 1})

    hosts_description = StringField(
        label='hosts_description',
        description='Host description',
        default='Added from Qualys WAS',
        validators=[],
        _meta={"display_row": 1, "display_column": 2, "multiline": False}
    )

    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostname description',
        default='Added from Qualys WAS',
        validators=[],
        _meta={"display_row": 3, "display_column": 2, "multiline": False}
    )


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # parse hostnames file
    hostnames_file = input_dict['hostnames_file'].lower()
    hostnames_file = hostnames_file.replace('127.0.0.1     vulnsite1.com,vulnsite2.com,subdomain.vulnsite2.com', '')
    hostnames_file = hostnames_file.replace('\r', '\n').replace('\t', ' ')
    hostnames_file = hostnames_file.strip(' \r\n\t')
    while '\n\n' in hostnames_file:
        hostnames_file = hostnames_file.replace('\n\n', '\n')
    while '  ' in hostnames_file:
        hostnames_file = hostnames_file.replace('  ', ' ')

    # {"example.com":{"8.8.8.8":"<uuid>"}}
    hostnames_dict = {}
    if hostnames_file:
        for line in hostnames_file.split('\n'):
            ip = line.split(' ')[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return "Wrong IP inside hostnames file!"
            hostnames_list = (''.join(line.split(' ')[1:])).split(',')

            for hostname_str in hostnames_list:
                if hostname_str and hostname_str != ip:
                    if hostname_str not in hostnames_dict:
                        hostnames_dict[hostname_str] = {}
                    if ip not in hostnames_dict[hostname_str]:

                        host_id = db.select_project_host_by_ip(current_project['id'], ip)
                        if not host_id:
                            host_id = db.insert_host(current_project['id'],
                                                     ip,
                                                     current_user['id'],
                                                     input_dict["hosts_description"])
                        else:
                            host_id = host_id[0]['id']

                        hostname_id = db.select_ip_hostname(host_id, hostname_str)
                        if not hostname_id:
                            hostname_id = db.insert_hostname(host_id,
                                                             hostname_str,
                                                             input_dict["hosts_description"],
                                                             current_user['id'])
                        else:
                            hostname_id = hostname_id[0]['id']
                        hostnames_dict[hostname_str][ip] = hostname_id

    # xml files
    for bin_file_data in input_dict['files']:
        try:
            scan_result = BeautifulSoup(bin_file_data.decode('utf8'), "html.parser")

            issue_wiki = list(scan_result.find("glossary").find("qid_list").findChildren(recursive=False))
            vuln_list = scan_result.find("vulnerability_list").findChildren(recursive=False)
            info_list = scan_result.findAll("information_gathered")

            # create wiki
            qid_wiki = {}
            for wiki_obj in issue_wiki:
                qid_id = int(wiki_obj.find("qid").text)  # 150456
                category = wiki_obj.find("category").text  # Potential Vulnerability
                severity = int(wiki_obj.find("severity").text)  # 4
                group_name = wiki_obj.find("group").text  # INFO
                title = wiki_obj.find(
                    "title").text  # Apache HTTP Server NULL pointer dereference and Server Side Request Forger
                owasp = wiki_obj.find("owasp").text if wiki_obj.find("owasp") else ''
                wasc = wiki_obj.find("wasc").text if wiki_obj.find("wasc") else ''  # WASC-26,WASC-13
                cwe = int(wiki_obj.find("cwe").text.split(',')[0].split('-')[1]) if wiki_obj.find("cwe") else 0
                cvss_base = float(wiki_obj.find("cvss_base").text) if wiki_obj.find("cvss_base") else 0.0
                cvss_v3 = float(str(wiki_obj.find("cvss_v3").find("base").next).strip(' \r\t\n')) if wiki_obj.find(
                    "cvss_v3") and wiki_obj.find("cvss_v3").find("base") else 0.0
                description = wiki_obj.find("description").text if wiki_obj.find("description").text != 'N/A' else ''
                risk = wiki_obj.find("impact").text if wiki_obj.find("impact").text != 'N/A' else ''
                fix = wiki_obj.find("solution").text if wiki_obj.find("solution").text != 'N/A' else ''

                cvss = 0

                if qid_id == 150263:
                    a = wiki_obj.find("cvss_v3")
                    b = wiki_obj.find("cvss_v3").find("base").next
                    pass

                # enum cvss
                if wiki_obj.find("cvss_v3") and 0 <= cvss_v3 <= 10:
                    cvss = cvss_v3
                elif wiki_obj.find("cvss_base") and 0 <= cvss_base <= 10:
                    cvss = cvss_base
                else:
                    # 0 - info, 1 - low, 2 - medium, 3 - medium, 4 - high, 5 - critical
                    if severity == 1:
                        cvss = 2.0
                    elif severity in [2, 3]:
                        cvss = 5.0
                    elif severity == 4:
                        cvss = 8.0
                    elif severity == 5:
                        cvss = 9.5

                # additional_fields

                add_fields_dict = {}

                if category:
                    add_fields_dict["qualys_was_catecory"] = {
                        'type': 'text',
                        'val': category
                    }
                if group_name:
                    add_fields_dict["qualys_was_group"] = {
                        'type': 'text',
                        'val': group_name
                    }
                if owasp:
                    add_fields_dict["owasp"] = {
                        'type': 'text',
                        'val': owasp
                    }
                if wasc:
                    add_fields_dict["wasc"] = {
                        'type': 'text',
                        'val': wasc
                    }

                references_list = []
                references_list += [x.attrs['href'] for x in BeautifulSoup(description).find_all("a")]
                references_list += [x.attrs['href'] for x in BeautifulSoup(fix).find_all("a")]
                references_list += [x.attrs['href'] for x in BeautifulSoup(risk).find_all("a")]
                references_list = list(set(references_list))

                qid_wiki[qid_id] = {
                    "name": title,
                    "description": BeautifulSoup(description).get_text(),
                    "cvss": cvss,
                    "fix": BeautifulSoup(fix).get_text(),
                    "risk": BeautifulSoup(risk).get_text(),
                    "cwe": cwe,
                    "add_fields_dict": add_fields_dict,
                    "references": '\n'.join(references_list)
                }

            for issue_obj in vuln_list:

                issue_qid = int(issue_obj.find("qid").text)
                current_wiki = qid_wiki[issue_qid]
                issue_url = issue_obj.find("url").text
                issue_is_ajax = issue_obj.find("ajax").text == "true"
                issue_authentication = 'Authentication: ' + issue_obj.find("authentication").text  # Not Required
                issue_is_potential = issue_obj.find("potential").text == "true"
                issue_ignored = issue_obj.find("ignored").text == "true"

                # urlparse
                url_parsed = urllib.parse.urlparse(issue_url)
                issue_protocol = "http"
                issue_port = 80
                if url_parsed.scheme.lower() == "https":
                    issue_protocol = "https"
                    issue_port = 443
                hostname_str = url_parsed.netloc.lower()
                issue_path = str(url_parsed.path)
                issue_get_params = str(url_parsed.query)
                if len(url_parsed.netloc.split(":")) == 2:
                    if 0 < int(url_parsed.netloc.split(":")[1]) < 65536:
                        issue_port = int(url_parsed.netloc.split(":")[1])
                        hostname_str = url_parsed.netloc.split(":")[0].lower()

                is_ip = False
                try:
                    ipaddress.ip_address(hostname_str)
                    is_ip = True
                except:
                    pass

                hostnames_uuids = []
                if hostname_str in hostnames_dict:
                    for ip_str in hostnames_dict:
                        hostnames_uuids += hostnames_dict[ip_str]

                hostnames_uuids = list(set(hostnames_uuids))

                services = {}

                if not hostnames_uuids:
                    if is_ip:
                        host_id = db.select_project_host_by_ip(current_project['id'], hostname_str)
                        if not host_id:
                            host_id = db.insert_host(current_project['id'],
                                                     hostname_str,
                                                     current_user['id'],
                                                     input_dict["hosts_description"])
                        else:
                            host_id = host_id[0]['id']

                        # add port
                        port_id = db.select_ip_port(host_id, issue_port)
                        if not port_id:
                            port_id = db.insert_host_port(host_id, issue_port, 1, issue_protocol, '',
                                                          current_user['id'], current_project['id'])
                        else:
                            old_description = port_id[0]['description']
                            db.update_port_proto_description(port_id[0]['id'], issue_protocol, old_description)
                            port_id = port_id[0]['id']

                        services[port_id] = ["0"]
                    elif input_dict['auto_resolve']:
                        try:
                            ips = socket.gethostbyname_ex(hostname_str)[2]
                        except Exception as e:
                            return "Error during resolving hostname!"
                        for ip_txt in ips:
                            # add ip
                            host_id = db.select_project_host_by_ip(current_project['id'], ip_txt)
                            if not host_id:
                                host_id = db.insert_host(current_project['id'],
                                                         ip_txt,
                                                         current_user['id'],
                                                         input_dict["hosts_description"])
                            else:
                                host_id = host_id[0]['id']

                            # add hostname
                            hostname_id = db.select_ip_hostname(host_id, hostname_str)
                            if not hostname_id:
                                hostname_id = db.insert_hostname(host_id,
                                                                 hostname_str,
                                                                 input_dict["hosts_description"],
                                                                 current_user['id'])
                            else:
                                hostname_id = hostname_id[0]['id']

                            # add port
                            port_id = db.select_ip_port(host_id, issue_port)
                            if not port_id:
                                port_id = db.insert_host_port(host_id, issue_port, 1, issue_protocol, '',
                                                              current_user['id'], current_project['id'])
                            else:
                                old_description = port_id[0]['description']
                                db.update_port_proto_description(port_id[0]['id'], issue_protocol, old_description)
                                port_id = port_id[0]['id']

                            if port_id not in services:
                                services[port_id] = []
                            if hostname_id not in services[port_id]:
                                services[port_id].append(hostname_id)
                    else:
                        return "Error during resolving hostnames"
                else:
                    # if hostname_uuids
                    for hostname_id in hostnames_uuids:
                        host_id = db.select_host_by_hostname_id(hostname_id)[0]['id']

                        # add port
                        port_id = db.select_ip_port(host_id, issue_port)
                        if not port_id:
                            port_id = db.insert_host_port(host_id, issue_port, 1, issue_protocol, '',
                                                          current_user['id'], current_project['id'])
                        else:
                            old_description = port_id[0]['description']
                            db.update_port_proto_description(port_id[0]['id'], issue_protocol, old_description)
                            port_id = port_id[0]['id']

                        if port_id not in services:
                            services[port_id] = []
                        if hostname_id not in services[port_id]:
                            services[port_id].append(hostname_id)

                payloads_list = issue_obj.find("payloads").findChildren(recursive=False)

                poc_txt_list = []
                for payload_obj in payloads_list:
                    poc_request_obj = payload_obj.find("request")
                    poc_method = poc_request_obj.find("method").text.strip(' \r\n\t')
                    poc_url = poc_request_obj.find("url").text.strip(' \r\n\t')
                    poc_headers = poc_request_obj.find("headers").findChildren(recursive=False)
                    poc_headers_list = [x.find("key").text.strip(' \r\n\t') +
                                        ": " + x.find("value").text.strip(' \r\n\t') for x in poc_headers]
                    poc_headers_txt = '\n'.join(poc_headers_list)
                    poc_body = poc_request_obj.find("body").text.strip(' \r\n\t')

                    poc_response_obj = payload_obj.find("response")
                    poc_response_content = base64.b64decode(
                        poc_response_obj.find('contents').text).decode('utf8').strip(' \r\n\t') if poc_response_obj \
                        .find('contents') else ''

                    poc_http_txt = '{} {} HTTP/1.1\n{}\n\n{}\n\n\n\n{}'.format(poc_method,
                                                                               poc_url,
                                                                               poc_headers_txt,
                                                                               poc_body,
                                                                               poc_response_content)
                    poc_http_txt = poc_http_txt.strip(' \r\n\t')
                    poc_txt_list.append(poc_http_txt)

                if not issue_ignored:
                    issue_id = db.insert_new_issue_no_dublicate(current_wiki["name"],
                                                                current_wiki["description"],
                                                                issue_path,
                                                                current_wiki["cvss"],
                                                                current_user['id'], services,
                                                                'Need to check',
                                                                current_project['id'],
                                                                cwe=current_wiki["cwe"],
                                                                issue_type='web',
                                                                fix=current_wiki['fix'],
                                                                param=issue_get_params,
                                                                technical='',
                                                                references=current_wiki['references'],
                                                                risks=current_wiki["risk"],
                                                                intruder=issue_authentication
                                                                )

                    current_issue = db.select_issue(issue_id)[0]
                    additional_fields = json.loads(current_issue['fields'])
                    new_fields = current_wiki["add_fields_dict"]
                    for new_field_name in new_fields:
                        additional_fields[new_field_name] = new_fields[new_field_name]
                    db.update_issue_fields(issue_id, additional_fields)

                    # add PoCs from poc_txt_list
                    counter = 1
                    for poc_str in poc_txt_list:
                        poc_id = db.insert_new_poc(
                            '0',
                            "HTTP request and response",
                            'text',
                            'http_request_response.txt',
                            issue_id,
                            current_user['id'],
                            '0', 'random', storage=global_config['files']['poc_storage']
                        )

                        f = open('static/files/poc/{}'.format(poc_id), 'wb')
                        f.write(poc_str.encode('utf8', errors='ignore'))
                        f.close()

        except OverflowError as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing Qualys WAS report!"

    return ""
