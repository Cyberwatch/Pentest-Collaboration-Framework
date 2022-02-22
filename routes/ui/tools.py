from routes.ui import routes
from app import check_session, db, redirect, render_template, request, \
    send_log_data, requires_authorization, csrf, config
from .project import check_project_access, check_project_archived
from urllib.parse import urlparse
from system.forms import *
from libnmap.parser import NmapParser
from libnessus.parser import NessusParser
import email_validator
import json
import codecs
import re
import io
from flask import Response, send_file
from bs4 import BeautifulSoup
import urllib.parse
from IPy import IP
import socket
import csv
import dicttoxml
import time
from xml.dom.minidom import parseString
import ipwhois
import shodan
from shutil import copyfile
import ipaddress
import whois
from os import path, remove
from system.crypto_functions import *
from system.security_functions import htmlspecialchars

from routes.ui.tools_addons import nmap_scripts


@routes.route('/project/<uuid:project_id>/tools/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def project_tools(project_id, current_project, current_user):
    return render_template('project/tools/list.html',
                           current_project=current_project,
                           tab_name='Tools')


@routes.route('/project/<uuid:project_id>/tools/nmap/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nmap_page(project_id, current_project, current_user):
    return render_template('project/tools/import/nmap.html',
                           current_project=current_project,
                           tab_name='Nmap')


@routes.route('/project/<uuid:project_id>/tools/nmap/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nmap_page_form(project_id, current_project, current_user):
    form = NmapForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        add_empty_hosts = form.add_no_open.data

        # parse ports
        ignore_ports = form.ignore_ports.data.replace(' ', '')
        ignore_port_arr1 = ignore_ports.split(',') if ignore_ports else []
        ignore_port_array = []
        for port_str in ignore_port_arr1:
            protocol = 'tcp'
            port_num = port_str
            if '/' in port_str:
                if port_str.split('/')[1].lower() == 'udp':
                    protocol = 'udp'
                port_num = port_str.split('/')[0]
            port_num = int(port_num)
            ignore_port_array.append([port_num, protocol])

        ignore_services_array = [service.lower() for service in form.ignore_services.data.replace(' ', '').split(',')]

        for file in form.files.data:
            try:
                xml_report_data = file.read().decode('charmap')
                nmap_report = NmapParser.parse_fromstring(xml_report_data)
            except:
                return render_template('project/tools/import/nmap.html',
                                       current_project=current_project,
                                       errors=['Оne of uploaded files was incorrect!'],
                                       success=1,
                                       tab_name='Nmap')
            try:
                command_str = nmap_report.commandline
            except:
                command_str = ''
            for host in nmap_report.hosts:
                # check if we will add host
                found = 0
                os = ''
                if host.os and host.os.osmatches:
                    os = host.os.osmatches[0].name
                for service in host.services:
                    protocol = service.protocol.lower()
                    port_num = int(service.port)
                    service_name = service.service.lower()
                    if [port_num, protocol] not in ignore_port_array and service_name not in ignore_services_array:
                        if service.state == 'open':
                            found = 1
                        elif service.state == 'filtered' and \
                                form.rule.data in ['filtered', 'closed']:
                            found = 1
                        elif service.state == 'closed' and \
                                form.rule.data == 'closed':
                            found = 1
                if found or add_empty_hosts:
                    host_id = db.select_project_host_by_ip(
                        current_project['id'], host.address)
                    if not host_id:
                        host_info = form.hosts_description.data
                        host_id = db.insert_host(current_project['id'],
                                                 host.address,
                                                 current_user['id'],
                                                 host_info)
                    else:
                        host_id = host_id[0]['id']
                    if os:
                        db.update_host_os(host_id, os)
                    for hostname in host.hostnames:
                        if hostname and hostname != host.address:
                            hostname_id = db.select_ip_hostname(host_id,
                                                                hostname)
                            if not hostname_id:
                                hostname_id = db.insert_hostname(host_id,
                                                                 hostname,
                                                                 form.hostnames_description.data,
                                                                 current_user[
                                                                     'id'])
                            else:
                                hostname_id = hostname_id[0]['id']
                    for service in host.services:
                        is_tcp = service.protocol == 'tcp'
                        protocol_str = service.protocol.lower()
                        port_num = int(service.port)
                        service_name = service.service
                        service_banner = service.banner
                        add = 0
                        if [port_num,
                            protocol_str] not in ignore_port_array and service_name.lower() not in ignore_services_array:
                            if service.state == 'open':
                                add = 1
                            elif service.state == 'filtered' and \
                                    form.rule.data in ['filtered', 'closed']:
                                add = 1
                                service_banner += '\nstate: filtered'
                            elif service.state == 'closed' and \
                                    form.rule.data == 'closed':
                                add = 1
                                service_banner += '\nstate: closed'
                        if add == 1:
                            port_id = db.select_ip_port(host_id, service.port,
                                                        is_tcp)
                            if not port_id:
                                port_id = db.insert_host_port(host_id,
                                                              service.port,
                                                              is_tcp,
                                                              service_name,
                                                              service_banner,
                                                              current_user[
                                                                  'id'],
                                                              current_project[
                                                                  'id'])
                            else:
                                port_id = port_id[0]['id']
                                db.update_port_proto_description(port_id,
                                                                 service_name,
                                                                 service_banner)

                            for script_xml in service.scripts_results:
                                for script in nmap_scripts.modules:
                                    script_class = script.nmap_plugin
                                    if script_class.script_id == script_xml['id'] and \
                                            script_class.script_source == 'service':
                                        script_obj = script_class(script_xml)

                                        if 'port_info' in script_obj.script_types:
                                            result = script_obj.port_info()
                                            update = False
                                            if 'protocol' in result and result['protocol'] and \
                                                    result['protocol'].lower() not in service_name.lower():
                                                service_name = result['protocol']
                                                update = True
                                            if 'info' in result and result['info'] and \
                                                    result['info'].lower() not in service_banner.lower():
                                                service_banner += '\n' + result['info']
                                                update = True
                                            if update:
                                                db.update_port_proto_description(port_id,
                                                                                 service_name,
                                                                                 service_banner)

                                        if 'issue' in script_obj.script_types:
                                            issues = script_obj.issues()
                                            for issue in issues:
                                                db.insert_new_issue_no_dublicate(issue['name'],
                                                                                 issue[
                                                                                     'description'] if 'description' in issue else '',
                                                                                 issue['path'] if 'path' in issue else '',
                                                                                 issue['cvss'] if 'cvss' in issue else 0.0,
                                                                                 current_user['id'],
                                                                                 {port_id: ['0']},
                                                                                 'need to recheck',
                                                                                 current_project['id'],
                                                                                 cve=issue['cve'] if 'cve' in issue else '',
                                                                                 cwe=issue['cwe'] if 'cwe' in issue else 0,
                                                                                 issue_type='service',
                                                                                 fix=issue['fix'] if 'fix' in issue else '',
                                                                                 param=issue[
                                                                                     'params'] if 'params' in issue else '')

                                        if 'credentials' in script_obj.script_types:
                                            credentials = script_obj.credentials()
                                            for cred in credentials:
                                                login = cred['login'] if 'login' in cred else ''
                                                cleartext = cred['cleartext'] if 'cleartext' in cred else ''
                                                hash_str = cred['hash'] if 'hash' in cred else ''
                                                description = cred['description'] if 'description' in cred else ''
                                                source = cred['source'] if 'source' in cred else ''

                                                dublicates_creds = db.select_creds_dublicates(current_project['id'],
                                                                                              login,
                                                                                              hash_str, cleartext,
                                                                                              description,
                                                                                              source,
                                                                                              '')

                                                if dublicates_creds:
                                                    dublicates_creds = dublicates_creds[0]
                                                    services = json.loads(dublicates_creds['services'])
                                                    if port_id not in services:
                                                        services[port_id] = ["0"]
                                                    else:
                                                        services[port_id].append("0")

                                                    db.update_creds(dublicates_creds['id'],
                                                                    login,
                                                                    hash_str,
                                                                    dublicates_creds['hash_type'],
                                                                    cleartext,
                                                                    description,
                                                                    source,
                                                                    services)
                                                else:
                                                    db.insert_new_cred(login,
                                                                       hash_str,
                                                                       'other',
                                                                       cleartext,
                                                                       description,
                                                                       source,
                                                                       {port_id: ["0"]},
                                                                       current_user['id'],
                                                                       current_project['id'])

                    current_host = db.select_host(host_id)[0]
                    host_zero_port = db.select_host_port(current_host['id'])[0]
                    for script_xml in host.scripts_results:
                        for script in nmap_scripts.modules:
                            script_class = script.nmap_plugin
                            if script_class.script_id == script_xml['id'] and \
                                    script_class.script_source == 'host':
                                script_obj = script_class(script_xml)

                                if 'server_info' in script_obj.script_types:
                                    result = script_obj.host_info()
                                    update = False
                                    if 'os' in result and result['os'] and \
                                            result['os'].lower() not in current_host['os'].lower():
                                        current_host['os'] = result['os']
                                        update = True
                                    if 'info' in result and result['info'] and \
                                            result['info'].lower() not in current_host['comment'].lower():
                                        current_host['comment'] += '\n' + result['info']
                                        update = True
                                    if update:
                                        db.update_host_comment_threats(current_host['id'],
                                                                       current_host['comment'],
                                                                       current_host['threats'],
                                                                       current_host['os'])
                                    if 'hostnames' in result:
                                        for hostname in result['hostnames']:
                                            hostnames_found = db.select_ip_hostname(current_host['id'], hostname)
                                            if not hostnames_found:
                                                db.insert_hostname(current_host['id'], hostname,
                                                                   form.hostnames_description.data, current_user['id'])

                                if 'issue' in script_obj.script_types:
                                    issues = script_obj.issues()
                                    for issue in issues:
                                        db.insert_new_issue_no_dublicate(issue['name'],
                                                                         issue[
                                                                             'description'] if 'description' in issue else '',
                                                                         issue['path'] if 'path' in issue else '',
                                                                         issue['cvss'] if 'cvss' in issue else 0.0,
                                                                         current_user['id'],
                                                                         {host_zero_port['id']: ['0']},
                                                                         'need to recheck',
                                                                         current_project['id'],
                                                                         cve=issue['cve'] if 'cve' in issue else '',
                                                                         cwe=issue['cwe'] if 'cwe' in issue else 0,
                                                                         issue_type='service',
                                                                         fix=issue['fix'] if 'fix' in issue else '',
                                                                         param=issue[
                                                                             'params'] if 'params' in issue else '')

                                if 'credentials' in script_obj.script_types:
                                    credentials = script_obj.credentials()
                                    for cred in credentials:
                                        login = cred['login'] if 'login' in cred else ''
                                        cleartext = cred['cleartext'] if 'cleartext' in cred else ''
                                        hash_str = cred['hash'] if 'hash' in cred else ''
                                        description = cred['description'] if 'description' in cred else ''
                                        source = cred['source'] if 'source' in cred else ''

                                        dublicates_creds = db.select_creds_dublicates(current_project['id'],
                                                                                      login,
                                                                                      hash_str, cleartext,
                                                                                      description,
                                                                                      source,
                                                                                      '')

                                        if dublicates_creds:
                                            dublicates_creds = dublicates_creds[0]
                                            services = json.loads(dublicates_creds['services'])
                                            if host_zero_port['id'] not in services:
                                                services[host_zero_port['id']] = ["0"]
                                            else:
                                                services[host_zero_port['id']].append("0")

                                            db.update_creds(dublicates_creds['id'],
                                                            login,
                                                            hash_str,
                                                            dublicates_creds['hash_type'],
                                                            cleartext,
                                                            description,
                                                            source,
                                                            services)
                                        else:
                                            db.insert_new_cred(login,
                                                               hash_str,
                                                               'other',
                                                               cleartext,
                                                               description,
                                                               source,
                                                               {host_zero_port['id']: ["0"]},
                                                               current_user['id'],
                                                               current_project['id'])

    return render_template('project/tools/import/nmap.html',
                           current_project=current_project,
                           errors=errors,
                           success=1,
                           tab_name='Nmap')


@routes.route('/project/<uuid:project_id>/tools/nessus/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nessus_page(project_id, current_project, current_user):
    return render_template('project/tools/import/nessus.html',
                           current_project=current_project,
                           tab_name='Nessus')


@routes.route('/project/<uuid:project_id>/tools/nessus/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nessus_page_form(project_id, current_project, current_user):
    form = NessusForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        add_info_issues = form.add_info_issues.data
        # xml files
        for file in form.xml_files.data:
            if file.filename:
                xml_report_data = file.read().decode('charmap')
                scan_result = NessusParser.parse_fromstring(xml_report_data)
                for host in scan_result.hosts:
                    host_id = db.select_project_host_by_ip(
                        current_project['id'], host.ip)
                    if not host_id:
                        host_id = db.insert_host(current_project['id'],
                                                 host.ip,
                                                 current_user['id'],
                                                 form.hosts_description.data)
                    else:
                        host_id = host_id[0]['id']

                    # add hostname
                    hostname_id = ''
                    hostname = host.name if host.name != host.ip else ''
                    try:
                        test_hostname = IP(host.address)
                    except ValueError:
                        test_hostname = ''
                    if not hostname and not test_hostname and host.address:
                        hostname = host.address
                    if hostname:
                        hostname_id = db.select_ip_hostname(host_id, hostname)
                        if not hostname_id:
                            hostname_id = db.insert_hostname(host_id,
                                                             hostname,
                                                             form.hostnames_description.data,
                                                             current_user['id'])
                        else:
                            hostname_id = hostname_id[0]['id']

                    for issue in host.get_report_items:

                        # create port

                        is_tcp = issue.protocol == 'tcp'
                        port_id = db.select_ip_port(host_id, int(issue.port),
                                                    is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id,
                                                          issue.port,
                                                          is_tcp,
                                                          issue.service,
                                                          form.ports_description.data,
                                                          current_user['id'],
                                                          current_project['id'])
                        else:
                            port_id = port_id[0]['id']
                            db.update_port_service(port_id,
                                                   issue.service)
                        # add issue to created port

                        name = 'Nessus: {}'.format(issue.plugin_name)
                        try:
                            issue_info = issue.synopsis
                        except KeyError:
                            issue_info = ''

                        description = 'Plugin name: {}\r\n\r\nInfo: \r\n{} \r\n\r\nOutput: \r\n {}'.format(
                            issue.plugin_name,
                            issue_info,
                            issue.description.strip('\n'))
                        # add host OS
                        if issue.get_vuln_plugin["pluginName"] == 'OS Identification':
                            os = issue.get_vuln_plugin["plugin_output"].split('\n')[1].split(' : ')[1]
                            db.update_host_os(host_id, os)
                        cve = issue.cve.replace('[', '').replace(']', '').replace("'", '').replace(",", ', ') if issue.cve else ''
                        cvss = 0
                        severity = float(issue.severity)
                        if severity == 0 and issue.get_vuln_info['risk_factor'] == 'None':
                            cvss = 0
                        elif 'cvss3_base_score' in issue.get_vuln_info:
                            cvss = float(issue.get_vuln_info['cvss3_base_score'])
                        elif 'cvss_base_score' in issue.get_vuln_info:
                            cvss = float(issue.get_vuln_info['cvss_base_score'])
                        else:
                            pass
                        if hostname_id:
                            services = {port_id: ['0', hostname_id]}
                        else:
                            services = {port_id: ['0']}
                        if severity > 0 or (severity == 0 and add_info_issues):
                            db.insert_new_issue_no_dublicate(name, description, '', cvss,
                                                             current_user['id'], services,
                                                             'need to check',
                                                             current_project['id'],
                                                             cve, cwe=0, issue_type='custom', fix=issue.solution)

    return render_template('project/tools/import/nessus.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Nessus')


@routes.route('/project/<uuid:project_id>/tools/nikto/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nikto_page(project_id, current_project, current_user):
    return render_template('project/tools/import/nikto.html',
                           current_project=current_project,
                           tab_name='Nikto')


@routes.route('/project/<uuid:project_id>/tools/nikto/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nikto_page_form(project_id, current_project, current_user):
    form = NiktoForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        # json files
        for file in form.json_files.data:
            if file.filename:
                json_report_data = file.read().decode('charmap').replace(',]', ']').replace(',}', '}')
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
                                             form.hosts_description.data)
                else:
                    host_id = host_id[0]['id']

                # add hostname

                hostname_id = ''
                if hostname and hostname != host:
                    hostname_id = db.select_ip_hostname(host_id, hostname)
                    if not hostname_id:
                        hostname_id = db.insert_hostname(host_id,
                                                         hostname,
                                                         form.hostnames_description.data,
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
        # csv load
        for file in form.csv_files.data:
            if file.filename:
                scan_result = csv.reader(codecs.iterdecode(file, 'charmap'),
                                         delimiter=',')

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
                                                     form.hosts_description.data)
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
                                                                 form.hostnames_description.data,
                                                                 current_user[
                                                                     'id'])
                            else:
                                hostname_id = hostname_id[0]['id']

                        # add port
                        port_id = db.select_ip_port(host_id, port, is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id,
                                                          port,
                                                          is_tcp,
                                                          protocol,
                                                          form.ports_description.data,
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

        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser").niktoscan.scandetails
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
                                             form.hosts_description.data)
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
                                                         form.hostnames_description.data,
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
                    osvdb = int(issue['osvdbid'])
                    info = issue.description.contents[0]
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

    return render_template('project/tools/import/nikto.html',
                           current_project=current_project,
                           tab_name='Nikto',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/acunetix/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def acunetix_page(project_id, current_project, current_user):
    return render_template('project/tools/import/acunetix.html',
                           current_project=current_project,
                           tab_name='Acunetix')


@routes.route('/project/<uuid:project_id>/tools/acunetix/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def acunetix_page_form(project_id, current_project, current_user):
    form = AcunetixForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        auto_resolve = form.auto_resolve.data == 1

        # xml files
        for file in form.files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser").scangroup.scan
                start_url = scan_result.starturl.contents[0]
                parsed_url = urllib.parse.urlparse(start_url)
                protocol = parsed_url.scheme
                hostname = parsed_url.hostname
                if hostname is None:
                    hostname = parsed_url.path
                port = parsed_url.port
                os_descr = scan_result.os.contents[0]
                port_banner = scan_result.banner.contents[0]
                web_banner = scan_result.webserver.contents[0]
                port_description = 'Banner: {} Web: {}'.format(port_banner,
                                                               web_banner)
                host_description = 'OS: {}'.format(os_descr)
                is_tcp = 1
                if not port:
                    port = 80
                    if protocol == 'https':
                        port = 443
                try:
                    IP(hostname)
                    host = hostname
                    hostname = ''
                except:
                    if form.host.data:
                        IP(form.host.data)
                        host = form.host.data
                    elif form.auto_resolve.data == 1:
                        host = socket.gethostbyname(hostname)
                    else:
                        errors.append('ip not resolved!')

                if not errors:
                    # add host
                    host_id = db.select_project_host_by_ip(current_project['id'], host)
                    if not host_id:
                        host_id = db.insert_host(current_project['id'],
                                                 host,
                                                 current_user['id'],
                                                 host_description)
                    else:
                        host_id = host_id[0]['id']
                        db.update_host_description(host_id, host_description)

                    # add hostname
                    hostname_id = ''
                    if hostname and hostname != host:
                        hostname_id = db.select_ip_hostname(host_id,
                                                            hostname)
                        if not hostname_id:
                            hostname_id = db.insert_hostname(host_id,
                                                             hostname,
                                                             'Added from Acunetix scan',
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
                        db.update_port_proto_description(port_id, protocol,
                                                         port_description)
                    issues = scan_result.reportitems.findAll("reportitem")

                    for issue in issues:
                        issue_name = issue.contents[1].contents[0]
                        module_name = issue.modulename.contents[0]
                        uri = issue.affects.contents[0]
                        request_params = issue.parameter.contents[0]
                        full_uri = '{} params:{}'.format(uri, request_params)
                        impact = issue.impact.contents[0]
                        issue_description = issue.description.contents[0]
                        recomendations = issue.recommendation.contents[0]
                        issue_request = issue.technicaldetails.request.contents[
                            0]
                        cwe = 0
                        if issue.cwe:
                            cwe = int(issue.cwe['id'].replace('CWE-', ''))
                        cvss = float(issue.cvss.score.contents[0])
                        # TODO: check CVE field

                        full_info = '''Module: \n{}\n\nDescription: \n{}\n\nImpact: \n{}\n\nRecomendations: \n{}\n\nRequest: \n{}'''.format(
                            module_name, issue_description, impact,
                            recomendations, issue_request)

                        services = {port_id: ['0']}
                        if hostname_id:
                            services = {port_id: ['0', hostname_id]}

                        db.insert_new_issue(issue_name,
                                            full_info, full_uri,
                                            cvss,
                                            current_user['id'], services,
                                            'need to check',
                                            current_project['id'],
                                            cve=0,
                                            cwe=cwe
                                            )
    return render_template('project/tools/import/acunetix.html',
                           current_project=current_project,
                           tab_name='Acunetix',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/exporter/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def exporter_page(project_id, current_project, current_user):
    return render_template(
        'project/tools/export/exporter.html',
        current_project=current_project,
        tab_name='Exporter')


@routes.route('/project/<uuid:project_id>/tools/exporter/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def exporter_page_form(project_id, current_project, current_user):
    form = ExportHosts()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        result_hosts = db.search_hostlist(project_id=current_project['id'],
                                          network=form.network.data,
                                          ip_hostname=form.ip_hostname.data,
                                          issue_name=form.issue_name.data,
                                          port=form.port.data,
                                          service=form.service.data,
                                          comment=form.comment.data,
                                          threats=form.threats.data)
    else:
        return render_template(
            'project/tools/export/exporter.html',
            current_project=current_project,
            tab_name='Exporter',
            errors=errors)

    result = ''
    separator = '\n' if form.separator.data == '[newline]' \
        else form.separator.data
    host_export = form.hosts_export.data

    ports_array = []
    if form.port.data:
        ports_array = [[int(port.split('/')[0]), port.split('/')[1] == 'tcp']
                       for port in form.port.data.split(',')]

    prefix = form.prefix.data
    postfix = form.postfix.data

    if form.filetype.data == 'txt':
        # txt worker
        response_type = 'text/plain'
        if not form.add_ports.data:
            # no ports
            ips = [host['ip'] for host in result_hosts]
            ips_hostnames = {}
            hostnames = []
            for host in result_hosts:
                host_hostname = db.select_ip_hostnames(host['id'])
                hostnames += [hostname['hostname'] for hostname in
                              host_hostname]
                ips_hostnames[host['ip']] = host_hostname
            hostnames = list(set(hostnames))
            if host_export == 'ip':
                result = separator.join([prefix + x + postfix for x in ips])
            elif host_export == 'hostname':
                result = separator.join([prefix + x + postfix for x in hostnames])
            elif host_export == 'ip&hostname':
                result = separator.join([prefix + x + postfix for x in ips + hostnames])
            elif host_export == 'ip&hostname_unique':
                host_hostnames_arr = []
                for ip in ips_hostnames:
                    if not ips_hostnames[ip]:
                        host_hostnames_arr.append(ip)
                    else:
                        host_hostnames_arr += [hostname['hostname'] for
                                               hostname in ips_hostnames[ip]]
                result = separator.join([prefix + x + postfix for x in host_hostnames_arr])
        else:
            # with ports

            # preparation: issues

            if form.issue_name.data:
                port_ids = db.search_issues_port_ids(current_project['id'],
                                                     form.issue_name.data)

            for host in result_hosts:
                ports = db.select_host_ports(host['id'])
                hostnames = db.select_ip_hostnames(host['id'])
                for port in ports:
                    if (not form.port.data) or (
                            [port['port'], port['is_tcp']] in ports_array):
                        if form.service.data in port['service']:

                            if (not form.issue_name.data) or (
                                    port['id'] in port_ids):

                                if host_export == 'ip&hostname':
                                    result += '{}{}{}:{}{}'.format(separator,
                                                                   prefix,
                                                                   host['ip'],
                                                                   port['port'],
                                                                   postfix)
                                    for hostname in hostnames:
                                        result += '{}{}{}:{}{}'.format(separator,
                                                                       prefix,
                                                                       hostname[
                                                                           'hostname'],
                                                                       port['port'],
                                                                       postfix)
                                elif host_export == 'ip':
                                    result += '{}{}{}:{}{}'.format(separator,
                                                                   prefix,
                                                                   host['ip'],
                                                                   port['port'],
                                                                   postfix)

                                elif host_export == 'hostname':
                                    for hostname in hostnames:
                                        result += '{}{}{}:{}{}'.format(separator,
                                                                       prefix,
                                                                       hostname[
                                                                           'hostname'],
                                                                       port['port'],
                                                                       postfix)

                                elif host_export == 'ip&hostname_unique':
                                    if hostnames:
                                        for hostname in hostnames:
                                            result += '{}{}{}:{}{}'.format(
                                                separator,
                                                prefix,
                                                hostname[
                                                    'hostname'],
                                                port['port'],
                                                postfix)
                                    else:
                                        result += '{}{}{}:{}{}'.format(
                                            separator,
                                            prefix,
                                            host['ip'],
                                            port['port'],
                                            postfix)
            if result:
                result = result[len(separator):]

    elif form.filetype.data == 'csv':
        response_type = 'text/plain'
        # 'host/hostname','port', 'type', 'service', 'description'

        # always with ports

        csvfile = io.StringIO()
        csv_writer = csv.writer(csvfile, dialect='excel', delimiter=';')

        columns = ['host', 'port', 'type', 'service', 'description']
        csv_writer.writerow(columns)

        # preparation: issues

        if form.issue_name.data:
            port_ids = db.search_issues_port_ids(current_project['id'],
                                                 form.issue_name.data)

        for host in result_hosts:
            ports = db.select_host_ports(host['id'])
            hostnames = db.select_ip_hostnames(host['id'])
            for port in ports:
                if (not form.port.data) or ([port['port'], port['is_tcp']]
                                            in ports_array):
                    if form.service.data in port['service']:
                        if (not form.issue_name.data) or (
                                port['id'] in port_ids):
                            if host_export == 'ip&hostname':
                                csv_writer.writerow([host['ip'],
                                                     port['port'],
                                                     'tcp' if port[
                                                         'is_tcp'] else 'udp',
                                                     port['service'],
                                                     port['description']])
                                for hostname in hostnames:
                                    csv_writer.writerow([hostname['hostname'],
                                                         port['port'],
                                                         'tcp' if port[
                                                             'is_tcp'] else 'udp',
                                                         port['service'],
                                                         port['description']])
                            elif host_export == 'ip':
                                csv_writer.writerow([host['ip'],
                                                     port['port'],
                                                     'tcp' if port[
                                                         'is_tcp'] else 'udp',
                                                     port['service'],
                                                     port['description']])

                            elif host_export == 'hostname':
                                for hostname in hostnames:
                                    csv_writer.writerow([hostname['hostname'],
                                                         port['port'],
                                                         'tcp' if port[
                                                             'is_tcp'] else 'udp',
                                                         port['service'],
                                                         port['description']])

                            elif host_export == 'ip&hostname_unique':
                                if hostnames:
                                    for hostname in hostnames:
                                        csv_writer.writerow(
                                            [hostname['hostname'],
                                             port['port'],
                                             'tcp' if port[
                                                 'is_tcp'] else 'udp',
                                             port['service'],
                                             port['description']])
                                else:
                                    csv_writer.writerow([host['ip'],
                                                         port['port'],
                                                         'tcp' if port[
                                                             'is_tcp'] else 'udp',
                                                         port['service'],
                                                         port['description']])
        result = csvfile.getvalue()

    elif form.filetype.data == 'json' or form.filetype.data == 'xml':

        if form.filetype.data == 'xml':
            response_type = 'text/xml'
        else:
            response_type = 'application/json'

        # first generates json

        # [{"<ip>":"","hostnames":["<hostname_1",..],
        # "ports":[ {"num":"<num>", "type":"tcp", "service":"<service>",
        # "description": "<comment>"},...],},...]

        json_object = []

        # preparation: issues

        if form.issue_name.data:
            port_ids = db.search_issues_port_ids(current_project['id'],
                                                 form.issue_name.data)

        for host in result_hosts:
            ports = db.select_host_ports(host['id'])
            hostnames = db.select_ip_hostnames(host['id'])

            host_object = {}
            host_object['ip'] = host['ip']
            host_object['hostnames'] = [hostname['hostname'] for hostname in
                                        hostnames]
            host_object['ports'] = []
            for port in ports:
                if (not form.port.data) or ([port['port'], port['is_tcp']]
                                            in ports_array):
                    if form.service.data in port['service']:
                        port_object = {}
                        port_object['num'] = port['port']
                        port_object['type'] = 'tcp' if port['is_tcp'] else 'udp'
                        port_object['service'] = port['service']
                        port_object['description'] = port['description']

                        if (not form.issue_name.data) or (
                                port['id'] in port_ids):
                            host_object['ports'].append(port_object)

            if not ((not host_object['ports']) and (form.port.data or
                                                    form.service.data or
                                                    form.issue_name.data)):
                json_object.append(host_object)

        if form.filetype.data == 'xml':
            s = dicttoxml.dicttoxml(json_object)
            dom = parseString(s)
            result = dom.toprettyxml()
        else:
            result = json.dumps(json_object, sort_keys=True, indent=4)

    if form.open_in_browser.data:
        return Response(result, content_type=response_type)

    else:
        return send_file(io.BytesIO(result.encode()),
                         attachment_filename='{}.{}'.format(form.filename.data,
                                                            form.filetype.data),
                         mimetype=response_type,
                         as_attachment=True)


@routes.route('/project/<uuid:project_id>/tools/http-sniffer/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def http_sniffer(project_id, current_project, current_user):
    return render_template('project/tools/sniffers/http.html',
                           current_project=current_project,
                           tab_name='HTTP-Sniffer')


@routes.route('/project/<uuid:project_id>/tools/http-sniffer/add',
              methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def http_sniffer_add_form(project_id, current_project, current_user):
    form = NewHTTPSniffer()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        sniffer_id = db.insert_new_http_sniffer(form.name.data, current_project['id'])
        return redirect(
            '/project/{}/tools/http-sniffer/#/sniffer_{}'.format(current_project['id'], sniffer_id))
    return redirect(
        '/project/{}/tools/http-sniffer/'.format(current_project['id']))


@routes.route(
    '/project/<uuid:project_id>/tools/http-sniffer/<uuid:sniffer_id>/edit',
    methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def http_sniffer_edit_form(project_id, current_project, current_user,
                           sniffer_id):
    # check if sniffer in project
    current_sniffer = db.select_http_sniffer_by_id(str(sniffer_id))
    if not current_sniffer or current_sniffer[0]['project_id'] != \
            current_project['id']:
        return redirect(
            '/project/{}/tools/http-sniffer/'.format(current_project['id']))

    current_sniffer = current_sniffer[0]

    form = EditHTTPSniffer()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        if form.submit.data == 'Clear':
            db.delete_http_sniffer_requests(current_sniffer['id'])
        elif form.submit.data == 'Update':
            db.update_http_sniffer(current_sniffer['id'],
                                   form.status.data,
                                   form.location.data,
                                   form.body.data,
                                   form.save_credentials.data)
    return redirect(
        '/project/{}/tools/http-sniffer/#/sniffer_{}'.format(current_project['id'], current_sniffer['id']))


@routes.route('/http_sniff/<uuid:sniffer_id>/', defaults={"route_path": ""},
              methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT',
                       'OPTIONS', 'TRACE', 'PATCH'])
@csrf.exempt
@routes.route('/http_sniff/<uuid:sniffer_id>/<path:route_path>',
              methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT',
                       'OPTIONS', 'TRACE', 'PATCH'])
@csrf.exempt
def http_sniffer_capture_page(sniffer_id, route_path):
    current_sniffer = db.select_http_sniffer_by_id(str(sniffer_id))

    if not current_sniffer:
        return redirect('/')

    current_sniffer = current_sniffer[0]

    http_start_header = '''{} {} {}'''.format(request.method,
                                              request.environ['RAW_URI'],
                                              request.environ[
                                                  'SERVER_PROTOCOL'])

    http_headers = str(request.headers)

    data = request.get_data().decode('charmap')

    ip = request.remote_addr

    if current_sniffer['save_credentials']:
        data_headers = http_headers.replace('\r', '')
        post_data = ''
        if '\n\n' in post_data:
            post_data = data_headers.split('\n\n')[1]

        # worker of headers
        for header_str in data_headers.split('\n\n')[0].split('\n'):
            header_name = header_str.split(':')[0].strip().lower()
            header_data = ''
            if ':' in header_str:
                header_data = header_str.split(':')[1].strip()
            if header_data:
                # token header
                if header_name == 'token':
                    db.insert_new_cred('',
                                       '',
                                       'other',
                                       header_data,
                                       '"Token" header',
                                       "HTTP sniffer, source ip: {}".format(ip),
                                       {},
                                       '',
                                       current_sniffer['project_id']
                                       )
                if header_name == 'authorization':
                    auth_type = header_data.split(' ')[0].lower()
                    auth_data = ''
                    if ' ' in header_data:
                        auth_data = ' '.join(header_data.split(' ')[1:]).strip()
                    if auth_data:
                        if auth_type in ['bearer', 'token']:
                            db.insert_new_cred('',
                                               '',
                                               'other',
                                               auth_data,
                                               '"Authorization" bearer token',
                                               "HTTP sniffer, source ip: {}".format(ip),
                                               {},
                                               '',
                                               current_sniffer['project_id']
                                               )
                        elif auth_type == 'basic':
                            try:
                                decoded = base64.b64decode(auth_data.encode('charmap')).decode('charmap')
                                login = decoded.split(':')[0]
                                password = ''
                                if ':' in decoded:
                                    password = ':'.join(decoded.split(':')[1:])
                                if login or password:
                                    db.insert_new_cred(login,
                                                       '',
                                                       'other',
                                                       password,
                                                       '"Authorization" basic header',
                                                       "HTTP sniffer, source ip: {}".format(ip),
                                                       {},
                                                       '',
                                                       current_sniffer['project_id']
                                                       )
                            except Exception as e:
                                pass
                        elif auth_type == 'digest':
                            username = ""
                            if 'username="' in auth_data:
                                username = auth_data.split('username="')[1].split('"')[0]
                            if "username='" in auth_data:
                                username = auth_data.split("username='")[1].split("'")[0]

                            db.insert_new_cred(username,
                                               '',
                                               'other',
                                               auth_data,
                                               '"Authorization" digest header',
                                               "HTTP sniffer, source ip: {}".format(ip),
                                               {},
                                               '',
                                               current_sniffer['project_id']
                                               )
                        elif auth_type == 'ntlm':
                            db.insert_new_cred('',
                                               '',
                                               'other',
                                               auth_data,
                                               '"Authorization" unknown header',
                                               "HTTP sniffer, source ip: {}".format(ip),
                                               {},
                                               '',
                                               current_sniffer['project_id']
                                               )
                        else:
                            db.insert_new_cred('',
                                               '',
                                               'other',
                                               auth_data,
                                               '"Authorization" NTLM header',
                                               "HTTP sniffer, source ip: {}".format(ip),
                                               {},
                                               '',
                                               current_sniffer['project_id']
                                               )

        # worker of post data
        post_params = list(request.form)
        login = ''
        login_name = ''
        password = ''
        password_name = ''
        for param_name in post_params:
            param_value = request.form[param_name]
            if param_name.lower() in ['pwd', 'pass', 'password', 'key', 'keyphrase', 'secret', 'token']:
                password = param_value
                password_name = param_name
            elif param_name.lower() in ['login', 'user', 'username', 'email', 'id']:
                login = param_value
                login_name = param_name
        if password_name:
            db.insert_new_cred(login,
                               '',
                               'other',
                               password,
                               'POST data "{}" parameter'.format(password_name),
                               "HTTP sniffer, source ip: {}".format(ip),
                               {},
                               '',
                               current_sniffer['project_id']
                               )

    current_time = int(time.time() * 1000)

    full_request_str = '''{}\n{}{}'''.format(http_start_header, http_headers,
                                             data)

    db.insert_new_http_sniffer_package(current_sniffer['id'], current_time,
                                       ip, full_request_str)

    if current_sniffer['location']:
        return current_sniffer['body'], current_sniffer['status'], {
            'Content-Location': current_sniffer['location'],
            'Location': current_sniffer['location'],
            'Content-Type': 'text/plain'}
    else:
        return current_sniffer['body'], current_sniffer['status'], \
               {'Content-Type': 'text/plain'}


@routes.route(
    '/project/<uuid:project_id>/tools/http-sniffer/<uuid:sniffer_id>/delete',
    methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def http_sniffer_delete_form(project_id, current_project, current_user,
                             sniffer_id):
    # check if sniffer in project
    current_sniffer = db.select_http_sniffer_by_id(str(sniffer_id))
    if not current_sniffer or current_sniffer[0]['project_id'] != \
            current_project['id']:
        return redirect(
            '/project/{}/tools/http-sniffer/'.format(current_project['id']))

    current_sniffer = current_sniffer[0]

    db.safe_delete_http_sniffer(current_sniffer['id'])
    return redirect(
        '/project/{}/tools/http-sniffer/'.format(current_project['id']))


@routes.route('/project/<uuid:project_id>/tools/ipwhois/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def ipwhois_page(project_id, current_project, current_user):
    return render_template('project/tools/scanners/ipwhois.html',
                           current_project=current_project,
                           tab_name='IPWhois')


@routes.route('/project/<uuid:project_id>/tools/ipwhois/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def ipwhois_page_form(project_id, current_project, current_user):
    form = IPWhoisForm()
    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if form.ip.data:
        try:
            ip_object = ipwhois.IPWhois(form.ip.data)
            ip_data = ip_object.lookup_rdap()
            asn_num = ip_data["asn"]
            if asn_num != 'NA':
                network = ip_data["asn_cidr"]
                gateway = network.split('/')[0]
                mask = int(network.split('/')[1])
                country = ip_data["asn_country_code"]
                description = ip_data["asn_description"]
                asn_date = ip_data['asn_date']
                ip_version = ip_data["network"]["ip_version"]

                # insert_new_network(self, ip, mask, asn, comment,
                # project_id, user_id,is_ipv6):

                full_description = "Country: {}\nDate: {}\nDescription: {}".format(
                    country,
                    asn_date,
                    description)

                # check if exist

                network = db.select_network_by_ip(current_project['id'],
                                                  gateway,
                                                  mask,
                                                  ipv6=(ip_version == 'v6'))
                if not network:
                    network_id = db.insert_new_network(gateway, mask, asn_num,
                                                       full_description,
                                                       current_project['id'],
                                                       current_user['id'],
                                                       ip_version == 'v6')
                else:
                    network_id = network[0]['id']
                    db.update_network(network_id, current_project['id'], gateway, mask, asn_num,
                                      full_description, ip_version == 'v6', network[0]['internal_ip'],
                                      network[0]['cmd'], json.loads(network[0]['access_from']), network[0]['name'])
                return redirect(
                    '/project/{}/networks/'.format(current_project['id']))
            else:
                errors.append('ASN does not exist!')

        except ipwhois.IPDefinedError:
            errors.append('IP was defined in standards')
        except ValueError:
            errors.append('IP was defined in standards')
    if form.hosts.data:
        for host in form.hosts.data:
            try:
                ip_object = ipwhois.IPWhois(host)
                ip_data = ip_object.lookup_rdap()
                asn_num = ip_data["asn"]
                if asn_num != 'NA':
                    network = ip_data["asn_cidr"]
                    gateway = network.split('/')[0]
                    mask = int(network.split('/')[1])
                    country = ip_data["asn_country_code"]
                    description = ip_data["asn_description"]
                    asn_date = ip_data['asn_date']
                    ip_version = ip_data["network"]["ip_version"]

                    # insert_new_network(self, ip, mask, asn, comment,
                    # project_id, user_id,is_ipv6):

                    full_description = "Country: {}\nDate: {}\nDescription: {}".format(
                        country,
                        asn_date,
                        description)

                    # check if exist

                    network = db.select_network_by_ip(current_project['id'],
                                                      gateway,
                                                      mask,
                                                      ipv6=(ip_version == 'v6'))
                    if not network:
                        network_id = db.insert_new_network(gateway, mask,
                                                           asn_num,
                                                           full_description,
                                                           current_project[
                                                               'id'],
                                                           current_user['id'],
                                                           ip_version == 'v6')
                    else:
                        network_id = network[0]['id']
                        db.update_network(network_id, current_project['id'], gateway, mask,
                                          asn_num, full_description, ip_version == 'v6', network[0]['internal_ip'],
                                          network[0]['cmd'], json.loads(network[0]['access_from']), network[0]['name'])
                else:
                    errors.append('ASN does not exist!')
            except ipwhois.IPDefinedError:
                errors.append('IP was defined in standards')
            except ValueError:
                errors.append('IP was defined in standards')

    if form.networks.data:
        for host in form.networks.data:
            try:
                ip_object = ipwhois.IPWhois(host)
                ip_data = ip_object.lookup_rdap()
                asn_num = ip_data["asn"]
                if asn_num != 'NA':
                    network = ip_data["asn_cidr"]
                    gateway = network.split('/')[0]
                    mask = int(network.split('/')[1])
                    country = ip_data["asn_country_code"]
                    description = ip_data["asn_description"]
                    asn_date = ip_data['asn_date']
                    ip_version = ip_data["network"]["ip_version"]

                    # insert_new_network(self, ip, mask, asn, comment,
                    # project_id, user_id,is_ipv6):

                    full_description = "Country: {}\nDate: {}\nDescription: {}".format(
                        country,
                        asn_date,
                        description)

                    # check if exist

                    network = db.select_network_by_ip(current_project['id'],
                                                      gateway,
                                                      mask,
                                                      ipv6=(ip_version == 'v6'))
                    if not network:
                        network_id = db.insert_new_network(gateway, mask,
                                                           asn_num,
                                                           full_description,
                                                           current_project[
                                                               'id'],
                                                           current_user['id'],
                                                           ip_version == 'v6')
                    else:
                        network_id = network[0]['id']
                        db.update_network(network_id, current_project['id'], gateway, mask, asn_num,
                                          full_description, ip_version == 'v6', network[0]['internal_ip'],
                                          network[0]['cmd'], json.loads(network[0]['access_from']), network[0]['name'])
                else:
                    errors.append('ASN does not exist!')
            except ipwhois.IPDefinedError:
                errors.append('IP was defined in standards')
            except ValueError:
                errors.append('Wrong ip format')

    return render_template('project/tools/scanners/ipwhois.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='IPWhois')


@routes.route('/project/<uuid:project_id>/tools/shodan/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def shodan_page(project_id, current_project, current_user):
    return render_template('project/tools/scanners/shodan.html',
                           current_project=current_project,
                           tab_name='Shodan')


@routes.route('/project/<uuid:project_id>/tools/shodan/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def shodan_page_form(project_id, current_project, current_user):
    form = ShodanForm()
    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    # api_key

    shodan_api_key = form.api_key.data

    if form.api_id.data and is_valid_uuid(form.api_id.data):
        users_configs = db.select_configs(team_id='0',
                                          user_id=current_user['id'],
                                          name='shodan')

        for team in db.select_user_teams(current_user['id']):
            users_configs += db.select_configs(team_id=team['id'],
                                               user_id='0',
                                               name='shodan')

        for config in users_configs:
            if config['id'] == form.api_id.data:
                shodan_api_key = config['data']

    if not shodan_api_key:
        errors.append('Key not found!')

    shodan_api = shodan.Shodan(shodan_api_key)

    # checker
    try:
        shodan_api.host('8.8.8.8')
    except shodan.exception.APIError:
        errors.append('Wrong API Shodan key!')

    if not errors:
        if form.ip.data:
            try:
                shodan_json = shodan_api.host(form.ip.data)
                asn = int(shodan_json['asn'].replace('AS', ''))
                os_info = shodan_json['os']
                ip = shodan_json['ip_str']
                ip_version = IP(ip).version()
                asn_info = shodan_json['isp']
                coords = ''
                if 'latitude' in shodan_json:
                    coords = "lat {} long {}".format(shodan_json['latitude'],
                                                     shodan_json['longitude'])
                country = ''
                if 'country_name' in shodan_json:
                    country = shodan_json['country_name']
                city = ''
                if 'city' in shodan_json:
                    city = shodan_json['city']
                organization = shodan_json['org']

                if form.need_network.data:
                    # create network
                    net_tmp = ipwhois.net.Net('8.8.8.8')
                    asn_tmp = ipwhois.asn.ASNOrigin(net_tmp)
                    asn_full_data = asn_tmp.lookup(asn='AS{}'.format(asn))
                    for network in asn_full_data['nets']:
                        if ipaddress.ip_address(ip) in \
                                ipaddress.ip_network(network['cidr'], False):
                            cidr = network['cidr']
                            net_ip = cidr.split('/')[0]
                            net_mask = int(cidr.split('/')[1])
                            net_descr = network['description']
                            net_maintain = network['maintainer']
                            full_network_description = 'ASN info: {}\nCountry: {}\nCity: {}\nCoords: {}\nDescription: {}\nMaintainer: {}'.format(
                                asn_info, country, city,
                                coords, net_descr, net_maintain)

                            network_id = db.select_network_by_ip(
                                current_project['id'], net_ip, net_mask,
                                ip_version == 6)

                            if not network_id:
                                network_id = db.insert_new_network(net_ip,
                                                                   net_mask,
                                                                   asn,
                                                                   full_network_description,
                                                                   current_project[
                                                                       'id'],
                                                                   current_user[
                                                                       'id'],
                                                                   ip_version == 6)
                            else:
                                network_id = network_id[0]['id']
                                db.update_network(network_id, current_project['id'], net_ip, net_mask,
                                                  asn, full_network_description, ip_version == 6, network_id[0]['internal_ip'],
                                                  network_id[0]['cmd'], json.loads(network_id[0]['access_from']), network_id[0]['name'])

                # create host
                full_host_description = "Country: {}\nCity: {}\nOrganization: {}".format(
                    country, city, organization)
                # hostnames = shodan_json["hostnames"]

                host_id = db.select_project_host_by_ip(
                    current_project['id'],
                    ip)
                if host_id:
                    host_id = host_id[0]['id']
                    db.update_host_description(host_id,
                                               full_host_description)
                else:
                    host_id = db.insert_host(current_project['id'],
                                             ip,
                                             current_user['id'],
                                             full_host_description)
                # add hostnames
                for hostname in shodan_json["hostnames"]:
                    hostname_obj = db.select_ip_hostname(host_id, hostname)
                    if not hostname_obj:
                        hostname_id = db.insert_hostname(host_id,
                                                         hostname,
                                                         'Added from Shodan',
                                                         current_user['id'])

                # add ports with cve
                for port in shodan_json['data']:
                    product = ''
                    if 'product' in port:
                        product = port['product']
                    is_tcp = (port['transport'] == 'tcp')
                    port_num = int(port['port'])
                    port_info = ''
                    protocol = port['_shodan']["module"]
                    if 'info' in port:
                        port_info = port['info']

                    full_port_info = "Product: {}\nInfo: {}".format(
                        product,
                        port_info
                    )

                    port_id = db.select_ip_port(host_id, port_num,
                                                is_tcp=is_tcp)

                    if port_id:
                        port_id = port_id[0]['id']
                        db.update_port_proto_description(port_id,
                                                         protocol,
                                                         full_port_info)
                    else:
                        port_id = db.insert_host_port(host_id, port_num,
                                                      is_tcp,
                                                      protocol,
                                                      full_port_info,
                                                      current_user['id'],
                                                      current_project['id'])

                    # add vulnerabilities
                    if "vulns" in port:
                        vulns = port['vulns']
                        for cve in vulns:
                            cvss = vulns[cve]['cvss']
                            summary = vulns[cve]['summary']
                            services = {port_id: ["0"]}

                            issue_id = db.insert_new_issue(cve, summary, '',
                                                           cvss,
                                                           current_user[
                                                               'id'],
                                                           services,
                                                           'need to check',
                                                           current_project[
                                                               'id'],
                                                           cve=cve)

            except shodan.exception.APIError as e:
                errors.append(e)
            except ValueError:
                errors.append('Wrong ip!')
        elif form.hosts.data:
            for host in form.hosts.data.split(','):
                try:
                    shodan_json = shodan_api.host(host)
                    asn = int(shodan_json['asn'].replace('AS', ''))
                    os_info = shodan_json['os']
                    ip = shodan_json['ip_str']
                    ip_version = IP(ip).version()
                    asn_info = shodan_json['isp']
                    coords = ''
                    if 'latitude' in shodan_json:
                        coords = "lat {} long {}".format(
                            shodan_json['latitude'],
                            shodan_json['longitude'])
                    country = ''
                    if 'country_name' in shodan_json:
                        country = shodan_json['country_name']
                    city = ''
                    if 'city' in shodan_json:
                        city = shodan_json['city']
                    organization = shodan_json['org']

                    if form.need_network.data:
                        # create network
                        net_tmp = ipwhois.net.Net('8.8.8.8')
                        asn_tmp = ipwhois.asn.ASNOrigin(net_tmp)
                        asn_full_data = asn_tmp.lookup(asn='AS{}'.format(asn))
                        for network in asn_full_data['nets']:
                            if ipaddress.ip_address(ip) in \
                                    ipaddress.ip_network(network['cidr'],
                                                         False):
                                cidr = network['cidr']
                                net_ip = cidr.split('/')[0]
                                net_mask = int(cidr.split('/')[1])
                                net_descr = network['description']
                                net_maintain = network['maintainer']
                                full_network_description = 'ASN info: {}\nCountry: {}\nCity: {}\nCoords: {}\nDescription: {}\nMaintainer: {}'.format(
                                    asn_info, country, city,
                                    coords, net_descr, net_maintain)

                                network_id = db.select_network_by_ip(
                                    current_project['id'], net_ip, net_mask,
                                    ip_version == 6)

                                if not network_id:
                                    network_id = db.insert_new_network(net_ip,
                                                                       net_mask,
                                                                       asn,
                                                                       full_network_description,
                                                                       current_project[
                                                                           'id'],
                                                                       current_user[
                                                                           'id'],
                                                                       ip_version == 6)
                                else:
                                    network_id = network_id[0]['id']
                                    db.update_network(network_id, current_project['id'], net_ip, net_mask,
                                                      asn, full_network_description, ip_version == 6, network_id[0]['internal_ip'],
                                                      network_id[0]['cmd'], json.loads(network_id[0]['access_from']), network_id[0]['name'])

                    # create host
                    full_host_description = "Country: {}\nCity: {}\nOS: {}\nOrganization: {}".format(
                        country, city, organization)
                    # hostnames = shodan_json["hostnames"]

                    host_id = db.select_project_host_by_ip(
                        current_project['id'],
                        ip)
                    if host_id:
                        host_id = host_id[0]['id']
                        db.update_host_description(host_id,
                                                   full_host_description)
                    else:
                        host_id = db.insert_host(current_project['id'],
                                                 ip,
                                                 current_user['id'],
                                                 full_host_description)
                    if os_info:
                        db.update_host_os(host_id, os_info)
                    # add hostnames
                    for hostname in shodan_json["hostnames"]:
                        hostname_obj = db.select_ip_hostname(host_id, hostname)
                        if not hostname_obj:
                            hostname_id = db.insert_hostname(host_id,
                                                             hostname,
                                                             'Added from Shodan',
                                                             current_user['id'])

                    # add ports with cve
                    for port in shodan_json['data']:
                        product = ''
                        if 'product' in port:
                            product = port['product']
                        is_tcp = (port['transport'] == 'tcp')
                        port_num = int(port['port'])
                        port_info = ''
                        protocol = port['_shodan']["module"]
                        if 'info' in port:
                            port_info = port['info']

                        full_port_info = "Product: {}\nInfo: {}".format(
                            product,
                            port_info
                        )

                        port_id = db.select_ip_port(host_id, port_num,
                                                    is_tcp=is_tcp)

                        if port_id:
                            port_id = port_id[0]['id']
                            db.update_port_proto_description(port_id,
                                                             protocol,
                                                             full_port_info)
                        else:
                            port_id = db.insert_host_port(host_id, port_num,
                                                          is_tcp,
                                                          protocol,
                                                          full_port_info,
                                                          current_user['id'],
                                                          current_project['id'])

                        # add vulnerabilities
                        if "vulns" in port:
                            vulns = port['vulns']
                            for cve in vulns:
                                cvss = vulns[cve]['cvss']
                                summary = vulns[cve]['summary']
                                services = {port_id: ["0"]}

                                issue_id = db.insert_new_issue(cve, summary, '',
                                                               cvss,
                                                               current_user[
                                                                   'id'],
                                                               services,
                                                               'need to check',
                                                               current_project[
                                                                   'id'],
                                                               cve=cve)
                except shodan.exception.APIError as e:
                    errors.append(e)
                except ValueError:
                    errors.append('Wrong ip!')
                time.sleep(1.1)  # shodan delay

        elif form.networks.data:
            for network_id in form.networks.data.split(','):
                if is_valid_uuid(network_id):
                    current_network = db.select_network(network_id)
                    if current_network and current_network[0]['asn'] and \
                            current_network[0]['asn'] > 0:
                        asn = int(current_network[0]['asn'])

                        result = shodan_api.search('asn:AS{}'.format(asn),
                                                   limit=1000)
                        for shodan_json in result['matches']:
                            try:
                                os_info = shodan_json['os']
                                ip = shodan_json['ip_str']
                                ip_version = IP(ip).version()
                                asn_info = shodan_json['isp']
                                coords = ''
                                if 'latitude' in shodan_json:
                                    coords = "lat {} long {}".format(
                                        shodan_json['latitude'],
                                        shodan_json['longitude'])
                                country = ''
                                if 'country_name' in shodan_json:
                                    country = shodan_json['country_name']
                                city = ''
                                if 'city' in shodan_json:
                                    city = shodan_json['city']
                                organization = shodan_json['org']

                                if form.need_network.data:
                                    # create network
                                    net_tmp = ipwhois.net.Net('8.8.8.8')
                                    asn_tmp = ipwhois.asn.ASNOrigin(net_tmp)
                                    asn_full_data = asn_tmp.lookup(
                                        asn='AS{}'.format(asn))
                                    for network in asn_full_data['nets']:
                                        if ipaddress.ip_address(ip) in \
                                                ipaddress.ip_network(
                                                    network['cidr'],
                                                    False):
                                            cidr = network['cidr']
                                            net_ip = cidr.split('/')[0]
                                            net_mask = int(cidr.split('/')[1])
                                            net_descr = network['description']
                                            net_maintain = network['maintainer']
                                            full_network_description = 'ASN info: {}\nCountry: {}\nCity: {}\nCoords: {}\nDescription: {}\nMaintainer: {}'.format(
                                                asn_info, country, city,
                                                coords, net_descr, net_maintain)

                                            network_id = db.select_network_by_ip(
                                                current_project['id'], net_ip,
                                                net_mask,
                                                ip_version == 6)

                                            if not network_id:
                                                network_id = db.insert_new_network(
                                                    net_ip,
                                                    net_mask,
                                                    asn,
                                                    full_network_description,
                                                    current_project[
                                                        'id'],
                                                    current_user[
                                                        'id'],
                                                    ip_version == 6)
                                            else:
                                                network_id = network_id[0]['id']
                                                db.update_network(network_id,
                                                                  current_project['id'],
                                                                  net_ip,
                                                                  net_mask,
                                                                  asn,
                                                                  full_network_description,
                                                                  ip_version == 6, network_id[0]['internal_ip'],
                                                                  network_id[0]['cmd'], json.loads(network_id[0]['access_from']),
                                                                  network_id[0]['name'])

                                # create host
                                full_host_description = "Country: {}\nCity: {}\nOS: {}\nOrganization: {}".format(
                                    country, city, os_info, organization)
                                # hostnames = shodan_json["hostnames"]

                                host_id = db.select_project_host_by_ip(
                                    current_project['id'],
                                    ip)
                                if host_id:
                                    host_id = host_id[0]['id']
                                    db.update_host_description(host_id,
                                                               full_host_description)
                                else:
                                    host_id = db.insert_host(
                                        current_project['id'],
                                        ip,
                                        current_user['id'],
                                        full_host_description)
                                # add hostnames
                                for hostname in shodan_json["hostnames"]:
                                    hostname_obj = db.select_ip_hostname(
                                        host_id, hostname)
                                    if not hostname_obj:
                                        hostname_id = db.insert_hostname(host_id,
                                                                         hostname,
                                                                         'Added from Shodan',
                                                                         current_user['id'])

                                # add ports with cve
                                port_num = int(shodan_json['port'])
                                product = ''
                                if 'product' in shodan_json:
                                    product = shodan_json['product']
                                is_tcp = int(shodan_json['transport'] == 'tcp')
                                port_info = ''
                                protocol = shodan_json['_shodan']["module"]
                                if 'info' in shodan_json:
                                    port_info = shodan_json['info']

                                full_port_info = "Product: {}\nInfo: {}".format(
                                    product,
                                    port_info
                                )

                                port_id = db.select_ip_port(host_id,
                                                            port_num,
                                                            is_tcp=is_tcp)

                                if port_id:
                                    port_id = port_id[0]['id']
                                    db.update_port_proto_description(
                                        port_id,
                                        protocol,
                                        full_port_info)
                                else:
                                    port_id = db.insert_host_port(host_id,
                                                                  port_num,
                                                                  is_tcp,
                                                                  protocol,
                                                                  full_port_info,
                                                                  current_user[
                                                                      'id'],
                                                                  current_project[
                                                                      'id'])

                                # add vulnerabilities
                                if "vulns" in shodan_json:
                                    vulns = shodan_json['vulns']
                                    for cve in vulns:
                                        cvss = vulns[cve]['cvss']
                                        summary = vulns[cve]['summary']
                                        services = {port_id: ["0"]}

                                        issue_id = db.insert_new_issue(cve,
                                                                       summary,
                                                                       '',
                                                                       cvss,
                                                                       current_user[
                                                                           'id'],
                                                                       services,
                                                                       'need to check',
                                                                       current_project[
                                                                           'id'],
                                                                       cve=cve)
                            except shodan.exception.APIError as e:
                                pass  # a lot of errors
                            except ValueError:
                                pass  # a lot of errors
                            time.sleep(1.1)  # shodan delay
    return render_template('project/tools/scanners/shodan.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Shodan')


@routes.route('/project/<uuid:project_id>/tools/checkmarx/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def checkmarx_page(project_id, current_project, current_user):
    return render_template('project/tools/import/checkmarx.html',
                           current_project=current_project,
                           tab_name='Checkmarx')


@routes.route('/project/<uuid:project_id>/tools/checkmarx/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def checkmarx_page_form(project_id, current_project, current_user):
    form = CheckmaxForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:

        # xml files
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser")
                query_list = scan_result.find_all("query")
                for query in query_list:
                    vulnerability_name = re.sub(' Version:[0-9]+', '', query.attrs['querypath'].split('\\')[-1])
                    language = query.attrs['language']
                    cwe = query.attrs['cweid']
                    vuln_array = query.find_all("result")
                    for vuln_example in vuln_array:
                        criticality = vuln_example.attrs['severity']  # High
                        filename = vuln_example.attrs['filename']
                        path_find = vuln_example.find_all("path")
                        paths_str_arrays = []
                        for path_obj in path_find:
                            paths_str = ''
                            path_nodes = vuln_example.find_all("pathnode")
                            if path_nodes:
                                paths_str = '########## Path {} ###########\n'.format(path_find.index(path_obj) + 1)
                            for path_node in path_nodes:
                                filename = path_node.find_all("filename")[0].text
                                line_num = int(path_node.find_all("line")[0].text)
                                colum_num = int(path_node.find_all("column")[0].text)
                                code_arr = path_node.find_all("code")
                                node_str = 'Filename: {}\nLine: {} Column: {}'.format(filename, line_num, colum_num)
                                for code in code_arr:
                                    node_str += '\n' + code.text.strip(' \t')
                                paths_str += node_str + '\n\n'

                            if paths_str:
                                paths_str_arrays.append(paths_str + '\n\n')
                        all_paths_str = '\n'.join(paths_str_arrays)

                        if criticality == 'High':
                            cvss = 9.5
                        elif criticality == 'Medium':
                            cvss = 8.0
                        elif criticality == 'Low':
                            cvss = 2.0
                        else:
                            cvss = 0
                        issue_id = db.insert_new_issue(vulnerability_name,
                                                       'Language: {}\n'.format(language) + all_paths_str, filename,
                                                       cvss, current_user['id'],
                                                       {}, 'need to check', current_project['id'], cwe=cwe,
                                                       issue_type='custom')
    return render_template('project/tools/import/checkmarx.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Checkmarx')


@routes.route('/project/<uuid:project_id>/tools/depcheck/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def depcheck_page(project_id, current_project, current_user):
    return render_template('project/tools/import/depcheck.html',
                           current_project=current_project,
                           tab_name='DepCheck')


@routes.route('/project/<uuid:project_id>/tools/depcheck/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def depcheck_page_form(project_id, current_project, current_user):
    form = Depcheck()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser")
                query_list = scan_result.find_all("dependency")
                for query in query_list:

                    filename = query.find("filename").text
                    filepath = query.find("filepath").text

                    vuln_array = query.find_all("vulnerability")
                    for vuln_example in vuln_array:
                        name = vuln_example.find('name').text
                        cve = ''
                        if name.startswith('CVE'):
                            cve = name
                        cvss_obj = vuln_example.find('cvssv3')
                        if cvss_obj:
                            cvss = float(cvss_obj.find('basescore').text)
                        elif vuln_example.find('cvssscore'):
                            cvss = float(vuln_example.find('cvssscore').text)
                        elif vuln_example.find('cvssv2'):
                            cvss = float(vuln_example.find('cvssv2').find('score').text)
                        else:
                            cvss = 0
                        cwes = vuln_example.find_all("cwe")
                        cwe = 0
                        if cwes:
                            cwe = int(cwes[0].text.replace('CWE-', '').split(' ')[0])
                        description = vuln_example.find('description').text
                        soft_search = vuln_example.find_all("software")
                        software_arr = []
                        for path_obj in soft_search:
                            s = str(path_obj.text)
                            versions = ''
                            if 'versionstartincluding' in path_obj.attrs:
                                versions += str(path_obj.attrs['versionstartincluding']) + '<=x'
                            if 'versionstartexcluding' in path_obj.attrs:
                                versions += str(path_obj.attrs['versionendexcluding']) + '<x'
                            if 'versionendincluding' in path_obj.attrs:
                                versions += '<=' + str(path_obj.attrs['versionendincluding'])
                            if 'versionendexcluding' in path_obj.attrs:
                                versions += '<' + str(path_obj.attrs['versionendexcluding'])

                            if versions:
                                s += ' versions ({})'.format(versions)
                            software_arr.append(s)

                        all_software_str = '\n\n'.join(software_arr)

                        full_description = 'File: ' + filepath + '\n\n' + description \
                                           + '\n\nVulnerable versions: \n' + all_software_str

                        issue_id = db.insert_new_issue(name, full_description, filepath, cvss, current_user['id'],
                                                       '{}', 'need to recheck', current_project['id'], cve, cwe,
                                                       'custom', '', filename)
    return render_template('project/tools/import/depcheck.html',
                           current_project=current_project,
                           tab_name='DepCheck',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/openvas/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def openvas_page(project_id, current_project, current_user):
    return render_template('project/tools/import/openvas.html',
                           current_project=current_project,
                           tab_name='OpenVAS')


@routes.route('/project/<uuid:project_id>/tools/openvas/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def openvas_page_form(project_id, current_project, current_user):
    form = Openvas()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser")
                query_list = scan_result.find_all("result")
                for query in query_list:
                    if query.find('host'):  # disables result tags inside issue description
                        issue_host = query.find('host').text.split('\n')[0]
                        issue_hostname = query.find('host').find('hostname').text
                        port_str = query.find('port').text.split('/')[0]
                        if port_str == 'general':
                            issue_port = 0
                        else:
                            issue_port = int(port_str)
                        issue_is_tcp = int(query.find('port').text.split('/')[1] == 'tcp')

                        nvt_obj = query.find('nvt')
                        issue_name = nvt_obj.find('name').text
                        issue_type = nvt_obj.find('family').text
                        issue_cvss = float(nvt_obj.find('cvss_base').text)
                        issue_long_description = nvt_obj.find('tags').text

                        solution_obj = nvt_obj.find('solution')
                        issue_solution = ''
                        if solution_obj.get('type') != 'WillNotFix':
                            issue_solution = solution_obj.text

                        cve_list = []
                        links_list = []
                        refs_objects = nvt_obj.find('refs')
                        if refs_objects:
                            refs_objects = refs_objects.findAll('ref')
                            for ref_obj in refs_objects:
                                if ref_obj.get('type') == 'url':
                                    links_list.append(ref_obj.get('id'))
                                if ref_obj.get('type') == 'cve':
                                    cve_list.append(ref_obj.get('id'))

                        issue_short_description = ''
                        if query.find('description'):
                            issue_short_description = query.find('description').text

                        # check if host exists

                        host_id = db.select_project_host_by_ip(current_project['id'], issue_host)
                        if not host_id:
                            host_id = db.insert_host(current_project['id'], issue_host,
                                                     current_user['id'], form.hosts_description.data)
                        else:
                            host_id = host_id[0]['id']

                        # check if port exists
                        port_id = db.select_host_port(host_id, issue_port, issue_is_tcp)
                        if not port_id:
                            port_id = db.insert_host_port(host_id, issue_port, issue_is_tcp, 'unknown', form.ports_description.data,
                                                          current_user['id'], current_project['id'])
                        else:
                            port_id = port_id[0]['id']

                        # check if hostname exists
                        hostname_id = ''
                        if issue_hostname != '':
                            hostname_id = db.select_ip_hostname(host_id, issue_hostname)
                            if not hostname_id:
                                hostname_id = db.insert_hostname(host_id, issue_hostname,
                                                                 form.hostnames_description.data, current_user['id'])
                            else:
                                hostname_id = hostname_id[0]['id']

                        full_description = 'Short description: \n{}\n\nFull description:\n{}'.format(
                            issue_short_description,
                            issue_long_description)
                        cve_str = ','.join(cve_list)
                        if links_list:
                            full_description += '\n\nLinks:\n' + '\n'.join(links_list)
                        services = {
                            port_id: [hostname_id] if hostname_id else ['0']
                        }
                        db.insert_new_issue_no_dublicate(issue_name, full_description, '', issue_cvss, current_user['id'],
                                                         services, 'need to recheck', current_project['id'], cve_str,
                                                         0, 'custom', issue_solution, '')

    return render_template('project/tools/import/openvas.html',
                           current_project=current_project,
                           tab_name='OpenVAS',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/netsparker/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def netsparker_page(project_id, current_project, current_user):
    return render_template('project/tools/import/netsparker.html',
                           current_project=current_project,
                           tab_name='NetSparker')


@routes.route('/project/<uuid:project_id>/tools/netsparker/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def netsparker_page_form(project_id, current_project, current_user):
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

    form = Netsparker()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(),
                                            "html.parser")
                query_list = scan_result.find_all("vulnerability")

                for vuln in query_list:
                    is_confirmed = vuln.get('confirmed') == 'True'
                    if is_confirmed or (not form.only_confirmed):
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
                                                         form.hosts_description.data)
                            else:
                                host_id = dublicate_host[0]['id']

                            # add port

                            dublicate_port = db.select_host_port(host_id, vuln_port, True)
                            if not dublicate_port:
                                port_id = db.insert_host_port(host_id, vuln_port, True,
                                                              vuln_scheme, form.ports_description.data,
                                                              current_user['id'], current_project['id'])
                            else:
                                port_id = dublicate_port[0]['id']

                            # add hostname

                            if vuln_hostname:
                                dublicate_hostname = db.select_ip_hostname(host_id, vuln_hostname)
                                if not dublicate_hostname:
                                    hostname_id = db.insert_hostname(host_id, vuln_hostname,
                                                                     form.hostnames_description.data,
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
                                                                    'need to recheck',
                                                                    current_project['id'],
                                                                    '', vuln_cwe, 'web', full_fix, vuln_args)
                        # create PoC
                        poc_text = vuln_request + vuln_response
                        poc_text = poc_text.replace('\r', '')

                        file_data = b''

                        if config['files']['poc_storage'] == 'database':
                            file_data = poc_text.encode('charmap')

                        poc_id = db.insert_new_poc(port_id if port_id else "0",
                                                   'Added from Netsparker',
                                                   'text',
                                                   'HTTP.txt',
                                                   issue_id,
                                                   current_user['id'],
                                                   hostname_id if hostname_id else '0',
                                                   storage=config['files']['poc_storage'],
                                                   data=file_data)

                        if config['files']['poc_storage'] == 'filesystem':
                            file_path = './static/files/poc/{}'.format(poc_id)
                            file_object = open(file_path, 'w')
                            file_object.write(poc_text)
                            file_object.close()

    return render_template('project/tools/import/netsparker.html',
                           current_project=current_project,
                           tab_name='NetSparker',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/qualys/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def qualys_page(project_id, current_project, current_user):
    return render_template('project/tools/import/qualys.html',
                           current_project=current_project,
                           tab_name='Qualys')


@routes.route('/project/<uuid:project_id>/tools/qualys/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def qualys_form(project_id, current_project, current_user):
    def beautify_output(xml_str):
        xml_str = xml_str.replace('<p>', '\t').replace('<P>', '\t')
        xml_str = xml_str.replace('<BR>', '\n').replace('</p>', '\n')
        return xml_str

    form = QualysForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        # xml files
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(), "html.parser")
                hosts_list = scan_result.find_all("ip")
                for host in hosts_list:
                    host_id = ''
                    hostname = ''
                    ip = host.attrs['value']
                    tmp_host = db.select_project_host_by_ip(current_project['id'], ip)
                    if tmp_host:
                        host_id = tmp_host[0]['id']
                    if 'name' in host.attrs and ip != host.attrs['name']:
                        hostname = host.attrs['name']
                    # TODO: dont forget to add hostname
                    if form.add_empty_host and not host_id:
                        host_id = db.insert_host(current_project['id'], ip, current_user['id'], form.hosts_description.data)
                    ports_list = host.find('services')
                    if ports_list:
                        for port_obj in ports_list.findAll('cat'):
                            if 'port' in port_obj.attrs and 'protocol' in port_obj.attrs:
                                if not host_id:
                                    host_id = db.insert_host(current_project['id'], ip, current_user['id'], form.hosts_description.data)

                                port = int(port_obj.attrs['port'])
                                is_tcp = int(port_obj.attrs['protocol'] == 'tcp')
                                service = port_obj.attrs['value']

                                port_id = db.select_host_port(host_id, port, is_tcp)
                                if port_id:
                                    port_id = port_id[0]['id']
                                    db.update_port_service(port_id, service)
                                else:
                                    port_id = db.insert_host_port(host_id, port, is_tcp, service, form.ports_description.data,
                                                                  current_user['id'], current_project['id'])

                    issues_list = host.find('vulns')
                    if issues_list:
                        for issue_obj in issues_list.findAll('cat'):
                            if not host_id:
                                host_id = db.insert_host(current_project['id'], ip, current_user['id'], form.hosts_description.data)
                            port_num = 0
                            is_tcp = 1
                            if 'port' in issue_obj.attrs and 'protocol' in issue_obj.attrs:
                                port_num = int(issue_obj.attrs['port'])
                                is_tcp = int(issue_obj.attrs['protocol'] == 'tcp')

                            port_id = db.select_host_port(host_id, port_num, is_tcp)
                            if not port_id:
                                port_id = db.insert_host_port(host_id, port_num, is_tcp, 'unknown', form.ports_description.data,
                                                              current_user['id'], current_project['id'])
                            else:
                                port_id = port_id[0]['id']
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

                            issue_name = issue_obj.find('title').text
                            issue_diagnostic = issue_obj.find('diagnosis').text
                            issue_description = issue_obj.find('consequence').text
                            issue_solution = beautify_output(issue_obj.find('solution').text)

                            # TODO: add PoC
                            issue_output = issue_obj.find('result')
                            try:
                                issue_output = issue_obj.find('result').text
                            except AttributeError:
                                issue_output = ''

                            issue_full_description = 'Diagnosis: \n{} \n\nConsequence: \n{}'.format(issue_diagnostic, issue_description)
                            issue_full_description = beautify_output(issue_full_description)
                            services = {port_id: ['0']}
                            issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_full_description, '', cvss, current_user['id'], services, 'need to recheck',
                                                                        current_project['id'], '', 0, 'custom', issue_solution, '')

                    issues_list = host.find('practices')
                    if issues_list:
                        for issue_obj in issues_list.findAll('practice'):
                            if not host_id:
                                host_id = db.insert_host(current_project['id'], ip, current_user['id'], form.hosts_description.data)
                            cve = ''
                            if 'cveid' in issue_obj.attrs:
                                cve = issue_obj.attrs['cveid']

                            issue_name = issue_obj.find('title').text
                            issue_diagnostic = issue_obj.find('diagnosis').text
                            issue_description = issue_obj.find('consequence').text
                            issue_solution = beautify_output(issue_obj.find('solution').text)
                            # TODO: add PoC
                            issue_output = issue_obj.find('result')
                            try:
                                issue_output = issue_obj.find('result').text
                            except AttributeError:
                                issue_output = ''
                            issue_full_description = 'Diagnosis: \n{} \n\nConsequence: \n{}'.format(issue_diagnostic, issue_description)

                            issue_full_description = beautify_output(issue_full_description)

                            issue_links = []

                            for url in issue_obj.findAll('url'):
                                issue_links.append(url.text)
                            for url in issue_obj.findAll('link'):
                                issue_links.append(url.text)

                            if issue_links:
                                issue_full_description += '\n\nLinks:\n' + '\n'.join(['- ' + url for url in issue_links])

                            cvss = 0
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

                            # try to detect port
                            port = 0
                            is_tcp = 1

                            info_str = issue_output.split('\n')[0]
                            if ' detected on port ' in info_str:
                                port = int(info_str.split(' detected on port ')[1].split(' ')[0].split('.')[0])
                                if ' over ' in info_str.split(' detected on port ')[1]:
                                    is_tcp = int(info_str.split(' detected on port ')[1].split(' over ')[1].split(' ')[0] == 'TCP')

                            port_id = db.select_host_port(host_id, port, is_tcp)
                            if not port_id:
                                port_id = db.insert_host_port(host_id, port, is_tcp, 'unknown', form.ports_description.data,
                                                              current_user['id'], current_project['id'])
                            else:
                                port_id = port_id[0]['id']
                            services = {port_id: ['0']}
                            issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_full_description, cve, cvss, current_user['id'], services, 'need to recheck',
                                                                        current_project['id'], '', 0, 'custom', issue_solution, '')

    return render_template('project/tools/import/qualys.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Qualys')


@routes.route('/project/<uuid:project_id>/tools/whois/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def whois_page(project_id, current_project, current_user):
    return render_template('project/tools/scanners/whois.html',
                           current_project=current_project,
                           tab_name='Whois')


@routes.route('/project/<uuid:project_id>/tools/whois/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def whois_page_form(project_id, current_project, current_user):
    form = WhoisForm()
    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        if form.host_id.data and is_valid_uuid(form.host_id.data):
            host = db.select_project_host(current_project['id'], form.host_id.data)
            if not host:
                errors.append('Host not found!')
            else:
                host_id = host[0]['id']
                hostname = db.select_ip_hostname(host_id, form.hostname.data)
                if not hostname:
                    errors.append('Hostname not found!')
                else:
                    hostname_id = hostname[0]['id']

    if not errors:
        if form.host_id.data:
            whois_obj = whois.whois(form.hostname.data)
            result_str = ''
            if 'registrar' in whois_obj and whois_obj['registrar']:
                result_str += 'Registrar: {}\n'.format(whois_obj['registrar'])
            if 'whois_server' in whois_obj and whois_obj['whois_server']:
                result_str += 'Whois server: {}\n'.format(whois_obj['whois_server'])
            if 'referral_url' in whois_obj and whois_obj['referral_url']:
                result_str += 'Referral URL: {}\n'.format(whois_obj['referral_url'])
            if 'name_servers' in whois_obj and whois_obj['name_servers']:
                result_str += 'Name servers: \n{}\n'.format('\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
            if 'emails' in whois_obj and whois_obj['emails']:
                result_str += 'Emails: \n{}\n'.format('\n'.join(['    ' + x for x in set(whois_obj['emails'])]))
            if 'dnssec' in whois_obj and whois_obj['dnssec']:
                result_str += 'DNSSec: {}\n'.format(whois_obj['dnssec'])
            if 'name' in whois_obj and whois_obj['name']:
                result_str += 'Name: {}\n'.format(whois_obj['name'])
            if 'org' in whois_obj and whois_obj['org']:
                result_str += 'Organization: {}\n'.format(whois_obj['org'])
            if 'address' in whois_obj and whois_obj['address']:
                result_str += 'Address: {}\n'.format(whois_obj['address'])
            if 'city' in whois_obj and whois_obj['city']:
                result_str += 'DNSSec: {}\n'.format(whois_obj['city'])
            if 'state' in whois_obj and whois_obj['state']:
                result_str += 'State: {}\n'.format(whois_obj['state'])
            if 'zipcode' in whois_obj and whois_obj['zipcode']:
                result_str += 'Zipcode: {}\n'.format(whois_obj['zipcode'])
            if 'country' in whois_obj and whois_obj['country']:
                result_str += 'Country: {}\n'.format(whois_obj['country'])

            if result_str:
                db.update_hostnames_description(current_project['id'], form.hostname.data, result_str)

            referer = request.headers.get("Referer")
            referer += '#/hostnames'
            return redirect(referer)

        if form.hostname.data:
            whois_obj = whois.whois(form.hostname.data)
            result_str = ''
            if 'registrar' in whois_obj and whois_obj['registrar']:
                result_str += 'Registrar: {}\n'.format(whois_obj['registrar'])
            if 'whois_server' in whois_obj and whois_obj['whois_server']:
                result_str += 'Whois server: {}\n'.format(whois_obj['whois_server'])
            if 'referral_url' in whois_obj and whois_obj['referral_url']:
                result_str += 'Referral URL: {}\n'.format(whois_obj['referral_url'])
            if 'name_servers' in whois_obj and whois_obj['name_servers']:
                result_str += 'Name servers: \n{}\n'.format('\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
            if 'emails' in whois_obj and whois_obj['emails']:
                result_str += 'Emails: \n{}\n'.format('\n'.join(['    ' + x for x in set(whois_obj['emails'])]))
            if 'dnssec' in whois_obj and whois_obj['dnssec']:
                result_str += 'DNSSec: {}\n'.format(whois_obj['dnssec'])
            if 'name' in whois_obj and whois_obj['name']:
                result_str += 'Name: {}\n'.format(whois_obj['name'])
            if 'org' in whois_obj and whois_obj['org']:
                result_str += 'Organization: {}\n'.format(whois_obj['org'])
            if 'address' in whois_obj and whois_obj['address']:
                result_str += 'Address: {}\n'.format(whois_obj['address'])
            if 'city' in whois_obj and whois_obj['city']:
                result_str += 'DNSSec: {}\n'.format(whois_obj['city'])
            if 'state' in whois_obj and whois_obj['state']:
                result_str += 'State: {}\n'.format(whois_obj['state'])
            if 'zipcode' in whois_obj and whois_obj['zipcode']:
                result_str += 'Zipcode: {}\n'.format(whois_obj['zipcode'])
            if 'country' in whois_obj and whois_obj['country']:
                result_str += 'Country: {}\n'.format(whois_obj['country'])

            # add even with result_str is empty
            try:
                ip = socket.gethostbyname(form.hostname.data)
                hosts = db.select_ip_from_project(current_project['id'], ip)
                if not hosts:
                    host_id = db.insert_host(current_project['id'],
                                             ip,
                                             current_user['id'],
                                             'Added from Whois information')
                else:
                    host_id = hosts[0]['id']

                hostname_obj = db.select_ip_hostname(host_id, form.hostname.data)
                if not hostname_obj:
                    hostname_id = db.insert_hostname(host_id, form.hostname.data, '', current_user['id'])
            except:
                pass

            db.update_hostnames_description(current_project['id'], form.hostname.data, result_str)

        if form.hostnames.data:
            for hostname in form.hostnames.data:
                whois_obj = whois.whois(hostname)
                result_str = ''
                if 'registrar' in whois_obj and whois_obj['registrar']:
                    result_str += 'Registrar: {}\n'.format(whois_obj['registrar'])
                if 'whois_server' in whois_obj and whois_obj['whois_server']:
                    result_str += 'Whois server: {}\n'.format(whois_obj['whois_server'])
                if 'referral_url' in whois_obj and whois_obj['referral_url']:
                    result_str += 'Referral URL: {}\n'.format(whois_obj['referral_url'])
                if 'name_servers' in whois_obj and whois_obj['name_servers']:
                    result_str += 'Name servers: \n{}\n'.format('\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
                if 'emails' in whois_obj and whois_obj['emails']:
                    result_str += 'Emails: \n{}\n'.format('\n'.join(['    ' + x for x in set(whois_obj['emails'])]))
                if 'dnssec' in whois_obj and whois_obj['dnssec']:
                    result_str += 'DNSSec: {}\n'.format(whois_obj['dnssec'])
                if 'name' in whois_obj and whois_obj['name']:
                    result_str += 'Name: {}\n'.format(whois_obj['name'])
                if 'org' in whois_obj and whois_obj['org']:
                    result_str += 'Organization: {}\n'.format(whois_obj['org'])
                if 'address' in whois_obj and whois_obj['address']:
                    result_str += 'Address: {}\n'.format(whois_obj['address'])
                if 'city' in whois_obj and whois_obj['city']:
                    result_str += 'DNSSec: {}\n'.format(whois_obj['city'])
                if 'state' in whois_obj and whois_obj['state']:
                    result_str += 'State: {}\n'.format(whois_obj['state'])
                if 'zipcode' in whois_obj and whois_obj['zipcode']:
                    result_str += 'Zipcode: {}\n'.format(whois_obj['zipcode'])
                if 'country' in whois_obj and whois_obj['country']:
                    result_str += 'Country: {}\n'.format(whois_obj['country'])

                # add even with result_str is empty
                try:
                    ip = socket.gethostbyname(hostname)
                    hosts = db.select_ip_from_project(current_project['id'], ip)
                    if not hosts:
                        host_id = db.insert_host(current_project['id'],
                                                 ip,
                                                 current_user['id'],
                                                 'Added from Whois information')
                    else:
                        host_id = hosts[0]['id']

                    hostname_obj = db.select_ip_hostname(host_id, hostname)
                    if not hostname_obj:
                        hostname_id = db.insert_hostname(host_id, hostname, '', current_user['id'])
                except:
                    pass

                db.update_hostnames_description(current_project['id'], hostname, result_str)

    return render_template('project/tools/scanners/whois.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Whois')


@routes.route('/project/<uuid:project_id>/tools/duplicator/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def duplicator_page(project_id, current_project, current_user):
    return render_template('project/tools/export/duplicator.html',
                           current_project=current_project,
                           tab_name='Duplicator')


@routes.route('/project/<uuid:project_id>/tools/duplicator/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def duplicator_page_form(project_id, current_project, current_user):
    form = DuplicatorForm()
    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    destination_project = db.check_user_project_access(form.destination_project.data, current_user['id'])
    if not destination_project:
        errors.append("Destination project not found!")

    if not errors:
        if not (destination_project['status'] and not (destination_project['auto_archive'] and destination_project['end_date'] < time.time())):
            errors.append("Destination project is in archive!")

    if not errors:
        if form.copy_info.data:
            destination_project['description'] = current_project['description']
        if form.copy_scope.data:
            destination_project['scope'] = current_project['scope']
        if form.copy_deadline.data:
            destination_project['end_date'] = current_project['end_date']
            destination_project['auto_archive'] = 0
            destination_project['status'] = 1
            if int(destination_project['end_date']) < int(destination_project['start_date']):
                destination_project['start_date'] = current_project['start_date']
        if form.copy_users.data:
            old_users = json.loads(destination_project['testers'])
            new_users = old_users + json.loads(current_project['testers'])
            new_users = list(set(new_users))
            destination_project['testers'] = json.dumps(new_users)
        if form.copy_teams.data:
            old_teams = json.loads(destination_project['teams'])
            new_teams = old_teams + json.loads(current_project['teams'])
            new_teams = list(set(new_teams))
            destination_project['teams'] = json.dumps(new_teams)
        db.update_project_settings(destination_project['id'],
                                   destination_project['name'],
                                   destination_project['description'],
                                   destination_project['type'],
                                   destination_project['scope'],
                                   destination_project['start_date'],
                                   destination_project['end_date'],
                                   destination_project['auto_archive'],
                                   json.loads(destination_project['testers']),
                                   json.loads(destination_project['teams']))

        # check paths
        paths_ids_list = list(set(form.paths.data))
        hosts_ids_list = list(set(form.hosts.data))
        networks_ids_list = list(set(form.networks.data))

        for path_id in paths_ids_list:
            current_path = db.select_path(path_id=path_id,
                                          project_id=current_project['id'])
            if current_path:
                current_path = current_path[0]
                if current_path['host_out'] and current_path['host_out'] not in hosts_ids_list:
                    hosts_ids_list.append(current_path['host_out'])
                if current_path['host_in'] and current_path['host_in'] not in hosts_ids_list:
                    hosts_ids_list.append(current_path['host_in'])
                if current_path['network_in'] and current_path['network_in'] not in networks_ids_list:
                    networks_ids_list.append(current_path['network_in'])
                if current_path['network_out'] and current_path['network_out'] not in networks_ids_list:
                    networks_ids_list.append(current_path['network_out'])

        # hosts
        for host_id in hosts_ids_list:
            current_host = db.select_project_host(current_project['id'], host_id)
            if current_host:
                current_host = current_host[0]
                # if same host exists
                destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                current_host['ip'])
                if destination_host:
                    destination_host = destination_host[0]
                    destination_host_id = destination_host['id']
                    db.update_host_comment_threats(destination_host_id,
                                                   current_host['comment'],
                                                   json.loads(current_host['threats']),
                                                   current_host['os'])
                else:
                    destination_host_id = db.insert_host(destination_project['id'],
                                                         current_host['ip'],
                                                         current_user['id'])
                    db.update_host_comment_threats(destination_host_id,
                                                   current_host['comment'],
                                                   json.loads(current_host['threats']),
                                                   current_host['os'])

                # insert ports
                current_ports = db.select_host_ports(current_host['id'])
                for current_port in current_ports:
                    # check if port exists
                    destination_port = db.select_host_port(destination_host_id,
                                                           int(current_port['port']),
                                                           bool(current_port['is_tcp']))
                    if destination_port:
                        destination_port_id = destination_port[0]['id']
                    else:
                        destination_port_id = db.insert_host_port(destination_host_id,
                                                                  int(current_port['port']),
                                                                  bool(current_port['is_tcp']),
                                                                  '', '', current_user['id'],
                                                                  destination_project['id'])
                    db.update_port_proto_description(destination_port_id,
                                                     current_port['service'],
                                                     current_port['description'])

                # insert hostnames
                current_hostnames = db.select_ip_hostnames(current_host['id'])
                for current_hostname in current_hostnames:
                    # check if exists
                    destination_hostname = db.select_ip_hostname(destination_host_id, current_hostname['hostname'])
                    if destination_hostname:
                        destination_hostname_id = destination_hostname[0]['id']
                        db.update_hostname(destination_hostname_id, current_hostname['description'])
                    else:
                        hostname_id = db.insert_hostname(destination_host_id, current_hostname['hostname'],
                                                         current_hostname['description'],
                                                         current_user['id'])
        # issues

        for issue_id in form.issues.data:
            current_issue = db.select_issue(issue_id)
            if current_issue and current_issue[0]['project_id'] == current_project['id']:
                current_issue = current_issue[0]
                # fullfill issue hosts
                current_ports_dict = json.loads(current_issue['services'])
                destination_ports_dict = {}
                for current_port_id in current_ports_dict:
                    current_port = db.select_project_port(current_project['id'],
                                                          current_port_id)
                    if current_port:
                        current_port = current_port[0]
                        current_host = db.select_project_host(current_project['id'],
                                                              current_port['host_id'])
                        if current_host:
                            current_host = current_host[0]
                            destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                            current_host['ip'])
                            if destination_host:
                                destination_host = destination_host[0]
                                destination_port = db.select_host_port(destination_host['id'],
                                                                       int(current_port['port']),
                                                                       bool(current_port['is_tcp']))
                                if destination_port:
                                    destination_port = destination_port[0]
                                    # hostname search
                                    for current_hostname_id in current_ports_dict[current_port_id]:
                                        if current_hostname_id == "0":
                                            if destination_port['id'] not in destination_ports_dict:
                                                destination_ports_dict[destination_port['id']] = [current_hostname_id]
                                            else:
                                                destination_ports_dict[destination_port['id']].append(current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port['host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_port['host_id'],
                                                                                             current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(destination_hostname['id'])
                                else:
                                    # get 0 port if port not found
                                    destination_host_port_id = db.select_host_port(destination_host['id'])[0]['id']
                                    if destination_host_port_id not in destination_ports_dict:
                                        destination_ports_dict[destination_host_port_id] = [""]
                                    elif "" not in destination_ports_dict[destination_host_port_id]:
                                        destination_ports_dict[destination_host_port_id].append("")
                                    else:
                                        # port was already added
                                        pass
                destination_issue_id = db.insert_new_issue_no_dublicate(
                    current_issue['name'], current_issue['description'],
                    current_issue['url_path'], current_issue['cvss'],
                    current_user['id'], destination_ports_dict, current_issue['status'],
                    destination_project['id'], current_issue['cve'],
                    current_issue['cwe'], current_issue['type'],
                    current_issue['fix'], current_issue['param']
                )

                # add PoCs

                current_pocs = db.select_issue_pocs(current_issue['id'])
                for current_poc in current_pocs:
                    current_poc_path = path.join('./static/files/poc/', current_poc['id'])
                    destination_poc_id = gen_uuid()
                    destination_poc_path = path.join('./static/files/poc/', destination_poc_id)
                    if current_poc['port_id'] == "0":
                        copyfile(current_poc_path, destination_poc_path)

                        file_data = b''

                        if config['files']['poc_storage'] == 'database':
                            f = open(destination_poc_path, 'rb')
                            file_data = f.read()
                            f.close()
                            remove(destination_poc_path)

                        poc_id = db.insert_new_poc(
                            "0",
                            current_poc['description'],
                            current_poc['type'],
                            current_poc['filename'],
                            destination_issue_id,
                            current_user['id'],
                            "0",
                            destination_poc_id,
                            storage=config['files']['poc_storage'],
                            data=file_data
                        )
                    else:
                        current_port = db.select_project_port(current_project['id'], current_poc['port_id'])
                        if current_port:
                            current_port = current_port[0]
                            current_host = db.select_project_host(current_project['id'], current_port['host_id'])
                            if current_host:
                                current_host = current_host[0]
                                destination_host = db.select_project_host_by_ip(destination_project['id'], current_host['ip'])
                                if destination_host:
                                    destination_host = destination_host[0]
                                    destination_port = db.select_host_port(destination_host['id'],
                                                                           current_port['port'],
                                                                           current_port['is_tcp'])
                                    if destination_port:
                                        destination_port = destination_port[0]
                                        if current_poc['hostname_id'] == "0":
                                            # add poc with port
                                            copyfile(current_poc_path, destination_poc_path)

                                            file_data = b''

                                            if config['files']['poc_storage'] == 'database':
                                                f = open(destination_poc_path, 'rb')
                                                file_data = f.read()
                                                f.close()
                                                remove(destination_poc_path)

                                            poc_id = db.insert_new_poc(
                                                destination_port['id'],
                                                current_poc['description'],
                                                current_poc['type'],
                                                current_poc['filename'],
                                                destination_issue_id,
                                                current_user['id'],
                                                "0",
                                                destination_poc_id,
                                                storage=config['files']['poc_storage'],
                                                data=file_data
                                            )
                                        else:
                                            current_hostname = db.select_project_hostname(current_project['id'], current_poc['hostname_id'])
                                            if current_hostname:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_host['id'], current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add poc with hostname
                                                    destination_hostname = destination_hostname[0]
                                                    copyfile(current_poc_path, destination_poc_path)

                                                    file_data = b''

                                                    if config['files']['poc_storage'] == 'database':
                                                        f = open(destination_poc_path, 'rb')
                                                        file_data = f.read()
                                                        f.close()
                                                        remove(destination_poc_path)

                                                    poc_id = db.insert_new_poc(
                                                        destination_port['id'],
                                                        current_poc['description'],
                                                        current_poc['type'],
                                                        current_poc['filename'],
                                                        destination_issue_id,
                                                        current_user['id'],
                                                        destination_hostname['id'],
                                                        destination_poc_id,
                                                        storage=config['files']['poc_storage'],
                                                        data=file_data
                                                    )
                                                else:
                                                    # add poc without hostname
                                                    copyfile(current_poc_path, destination_poc_path)

                                                    file_data = b''

                                                    if config['files']['poc_storage'] == 'database':
                                                        f = open(destination_poc_path, 'rb')
                                                        file_data = f.read()
                                                        f.close()
                                                        remove(destination_poc_path)

                                                    poc_id = db.insert_new_poc(
                                                        destination_port['id'],
                                                        current_poc['description'],
                                                        current_poc['type'],
                                                        current_poc['filename'],
                                                        destination_issue_id,
                                                        current_user['id'],
                                                        "0",
                                                        destination_poc_id,
                                                        storage=config['files']['poc_storage'],
                                                        data=file_data
                                                    )

        # files
        for current_file_id in form.files.data:
            current_file = db.select_files(current_file_id)
            if current_file and current_file[0]['project_id'] == current_project['id']:
                current_file = current_file[0]
                current_file_path = path.join('./static/files/code/', current_file['id'])
                destination_file_id = gen_uuid()
                destination_file_path = path.join('./static/files/code/', destination_file_id)

                current_ports_dict = json.loads(current_file['services'])

                # services
                destination_ports_dict = {}
                for current_port_id in current_ports_dict:
                    current_port = db.select_project_port(current_project['id'],
                                                          current_port_id)
                    if current_port:
                        current_port = current_port[0]
                        current_host = db.select_project_host(current_project['id'],
                                                              current_port['host_id'])
                        if current_host:
                            current_host = current_host[0]
                            destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                            current_host['ip'])
                            if destination_host:
                                destination_host = destination_host[0]
                                destination_port = db.select_host_port(destination_host['id'],
                                                                       int(current_port['port']),
                                                                       bool(current_port['is_tcp']))
                                if destination_port:
                                    destination_port = destination_port[0]
                                    # hostname search
                                    for current_hostname_id in current_ports_dict[current_port_id]:
                                        if current_hostname_id == "0":
                                            if destination_port['id'] not in destination_ports_dict:
                                                destination_ports_dict[destination_port['id']] = [current_hostname_id]
                                            else:
                                                destination_ports_dict[destination_port['id']].append(current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port['host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_port['host_id'],
                                                                                             current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(destination_hostname['id'])
                                else:
                                    # get 0 port if port not found
                                    destination_host_port_id = db.select_host_port(destination_host['id'])[0]['id']
                                    if destination_host_port_id not in destination_ports_dict:
                                        destination_ports_dict[destination_host_port_id] = [""]
                                    elif "" not in destination_ports_dict[destination_host_port_id]:
                                        destination_ports_dict[destination_host_port_id].append("")
                                    else:
                                        # port was already added
                                        pass

                file_data = b''
                if config["files"]["files_storage"] == 'database':
                    f = open(destination_file_path, 'rb')
                    file_data = f.read()
                    f.close()
                    remove(destination_file_path)

                db.insert_new_file(destination_file_id,
                                   destination_project['id'],
                                   current_file['filename'],
                                   current_file['description'],
                                   destination_ports_dict,
                                   current_file['type'],
                                   current_user['id'],
                                   storage=config["files"]["files_storage"],
                                   data=file_data
                                   )
                copyfile(current_file_path, destination_file_path)
        # creds
        for cred_id in form.creds.data:
            current_cred = db.select_creds(cred_id)
            if current_cred and current_cred[0]['project_id'] == current_project['id']:
                current_cred = current_cred[0]

                current_ports_dict = json.loads(current_cred['services'])

                # services
                destination_ports_dict = {}
                for current_port_id in current_ports_dict:
                    current_port = db.select_project_port(current_project['id'],
                                                          current_port_id)
                    if current_port:
                        current_port = current_port[0]
                        current_host = db.select_project_host(current_project['id'],
                                                              current_port['host_id'])
                        if current_host:
                            current_host = current_host[0]
                            destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                            current_host['ip'])
                            if destination_host:
                                destination_host = destination_host[0]
                                destination_port = db.select_host_port(destination_host['id'],
                                                                       int(current_port['port']),
                                                                       bool(current_port['is_tcp']))
                                if destination_port:
                                    destination_port = destination_port[0]
                                    # hostname search
                                    for current_hostname_id in current_ports_dict[current_port_id]:
                                        if current_hostname_id == "0":
                                            if destination_port['id'] not in destination_ports_dict:
                                                destination_ports_dict[destination_port['id']] = [current_hostname_id]
                                            else:
                                                destination_ports_dict[destination_port['id']].append(current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port['host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_port['host_id'],
                                                                                             current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(destination_hostname['id'])
                                else:
                                    # get 0 port if port not found
                                    destination_host_port_id = db.select_host_port(destination_host['id'])[0]['id']
                                    if destination_host_port_id not in destination_ports_dict:
                                        destination_ports_dict[destination_host_port_id] = [""]
                                    elif "" not in destination_ports_dict[destination_host_port_id]:
                                        destination_ports_dict[destination_host_port_id].append("")
                                    else:
                                        # port was already added
                                        pass
                dublicate_creds = db.select_creds_dublicates(
                    destination_project['id'],
                    current_cred['login'],
                    current_cred['hash'],
                    current_cred['cleartext'],
                    current_cred['description'],
                    current_cred['source'],
                    current_cred['hash_type']
                )
                if dublicate_creds:
                    dublicate_creds = dublicate_creds[0]
                    joined_services = json.loads(dublicate_creds['services'])
                    for port_id in destination_ports_dict:
                        if port_id not in joined_services:
                            joined_services[port_id] = []
                        for hostname_id in destination_ports_dict[port_id]:
                            if hostname_id not in joined_services[port_id]:
                                joined_services[port_id].append(hostname_id)
                    db.update_creds(
                        dublicate_creds['id'],
                        dublicate_creds['login'],
                        dublicate_creds['hash'],
                        dublicate_creds['hash_type'],
                        dublicate_creds['cleartext'],
                        dublicate_creds['description'],
                        dublicate_creds['source'],
                        joined_services
                    )
                else:
                    dumplicate_cred_id = db.insert_new_cred(
                        current_cred['login'],
                        current_cred['hash'],
                        current_cred['hash_type'],
                        current_cred['cleartext'],
                        current_cred['description'],
                        current_cred['source'],
                        destination_ports_dict,
                        current_user['id'],
                        destination_project['id']
                    )

        # networks
        for network_id in networks_ids_list:
            current_network = db.select_project_networks_by_id(
                current_project['id'],
                network_id)
            if current_network:
                current_network = current_network[0]

                current_ports_dict = json.loads(current_network['access_from'])
                # services
                destination_ports_dict = {}
                for current_port_id in current_ports_dict:
                    current_port = db.select_project_port(current_project['id'],
                                                          current_port_id)
                    if current_port:
                        current_port = current_port[0]
                        current_host = db.select_project_host(current_project['id'],
                                                              current_port['host_id'])
                        if current_host:
                            current_host = current_host[0]
                            destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                            current_host['ip'])
                            if destination_host:
                                destination_host = destination_host[0]
                                destination_port = db.select_host_port(destination_host['id'],
                                                                       int(current_port['port']),
                                                                       bool(current_port['is_tcp']))
                                if destination_port:
                                    destination_port = destination_port[0]
                                    # hostname search
                                    for current_hostname_id in current_ports_dict[current_port_id]:
                                        if current_hostname_id == "0":
                                            if destination_port['id'] not in destination_ports_dict:
                                                destination_ports_dict[destination_port['id']] = [current_hostname_id]
                                            else:
                                                destination_ports_dict[destination_port['id']].append(current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port['host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_port['host_id'],
                                                                                             current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(destination_hostname['id'])
                                else:
                                    # get 0 port if port not found
                                    destination_host_port_id = db.select_host_port(destination_host['id'])[0]['id']
                                    if destination_host_port_id not in destination_ports_dict:
                                        destination_ports_dict[destination_host_port_id] = [""]
                                    elif "" not in destination_ports_dict[destination_host_port_id]:
                                        destination_ports_dict[destination_host_port_id].append("")
                                    else:
                                        # port was already added
                                        pass
                # check duplicates
                duplicate_network = db.select_network_by_ip(destination_project['id'],
                                                            current_network['ip'],
                                                            current_network['mask'],
                                                            current_network['is_ipv6'])
                if duplicate_network:
                    duplicate_network = duplicate_network[0]

                    joined_services = json.loads(duplicate_network['access_from'])
                    for port_id in destination_ports_dict:
                        if port_id not in joined_services:
                            joined_services[port_id] = []
                        for hostname_id in destination_ports_dict[port_id]:
                            if hostname_id not in joined_services[port_id]:
                                joined_services[port_id].append(hostname_id)

                    db.update_network(duplicate_network['id'],
                                      destination_project['id'],
                                      current_network['ip'],
                                      current_network['mask'],
                                      current_network['asn'],
                                      current_network['comment'],
                                      current_network['is_ipv6'],
                                      current_network['internal_ip'],
                                      current_network['cmd'],
                                      joined_services,
                                      current_network['name'])
                else:
                    network_id = db.insert_new_network(
                        current_network['ip'],
                        current_network['mask'],
                        current_network['asn'],
                        current_network['comment'],
                        destination_project['id'],
                        current_user['id'],
                        current_network['is_ipv6'],
                        current_network['internal_ip'],
                        current_network['cmd'],
                        destination_ports_dict,
                        current_network['name']
                    )

        # notes

        for note_id in form.notes.data:
            current_note = db.select_note(note_id)
            if current_note and current_note[0]['project_id'] == current_project['id']:
                current_note = current_note[0]
                db.insert_new_note(
                    destination_project['id'],
                    current_note['name'],
                    current_user['id'],
                    '',
                    current_note['text']
                )

        # host notes
        for host_id in form.note_hosts.data:
            current_host_notes = db.select_host_notes(host_id, current_project['id'])
            for current_note in current_host_notes:
                current_host = db.select_project_host(current_project['id'], current_note['host_id'])
                if current_host:
                    current_host = current_host[0]
                    destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                    current_host['ip'])
                    if destination_host:
                        destination_host = destination_host[0]
                        destination_host_id = destination_host['id']
                    else:
                        destination_host_id = db.insert_host(destination_project['id'],
                                                             current_host['ip'],
                                                             current_user['id'])
                    db.insert_new_note(
                        destination_project['id'],
                        current_note['name'],
                        current_user['id'],
                        destination_host_id,
                        current_note['text']
                    )

        # network paths
        for path_id in paths_ids_list:
            current_path = db.select_path(path_id=path_id,
                                          project_id=current_project['id'])
            if current_path:
                host_in = ''
                network_in = ''
                host_out = ''
                network_out = ''

                current_path = current_path[0]
                if current_path['host_out']:
                    source_host = db.select_host(current_path['host_out'])[0]
                    host_out = db.select_project_host_by_ip(destination_project['id'], source_host['ip'])[0]['id']
                if current_path['host_in']:
                    source_host = db.select_host(current_path['host_in'])[0]
                    host_in = db.select_project_host_by_ip(destination_project['id'], source_host['ip'])[0]['id']
                if current_path['network_out']:
                    source_network = db.select_network(current_path['network_out'])[0]
                    network_out = db.select_network_by_ip(destination_project['id'],
                                                          source_network['ip'],
                                                          source_network['mask'],
                                                          source_network['is_ipv6'])[0]['id']
                if current_path['network_in']:
                    source_network = db.select_network(current_path['network_in'])[0]
                    network_in = db.select_network_by_ip(destination_project['id'],
                                                         source_network['ip'],
                                                         source_network['mask'],
                                                         source_network['is_ipv6'])[0]['id']

                # search dublicates
                dublicate_paths = db.search_path(project_id=destination_project['id'],
                                                 out_host=host_out,
                                                 out_network=network_out,
                                                 in_host=host_in,
                                                 in_network=network_in)
                if not dublicate_paths:
                    path_id = db.insert_path(project_id=destination_project['id'],
                                             out_host=host_out,
                                             out_network=network_out,
                                             in_host=host_in,
                                             in_network=network_in,
                                             description=current_path['description'],
                                             path_type=current_path['type'],
                                             direction=current_path['direction'])

    return render_template('project/tools/export/duplicator.html',
                           current_project=current_project,
                           tab_name='Duplicator',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/wpscan/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def wpscan_page(project_id, current_project, current_user):
    return render_template('project/tools/import/wpscan.html',
                           current_project=current_project,
                           tab_name='WPScan')


@routes.route('/project/<uuid:project_id>/tools/wpscan/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def wpscan_page_form(project_id, current_project, current_user):
    form = WPScanForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        # json files
        for file in form.json_files.data:
            if file.filename:

                file_content = file.read().decode('charmap')
                try:
                    file_dict = json.loads(file_content)
                    current_ip = file_dict['target_ip']
                    # validate ip
                    ipaddress.ip_address(current_ip)
                    current_host = db.select_project_host_by_ip(current_project['id'], current_ip)
                    if current_host:
                        current_host_id = current_host[0]['id']
                    else:
                        current_host_id = db.insert_host(current_project['id'],
                                                         current_ip,
                                                         current_user['id'],
                                                         "Added from WPScan")
                    # get protocol
                    current_url = file_dict['target_url']
                    current_url_obj = urllib.parse.urlparse(current_url)
                    current_scheme = current_url_obj.scheme.lower()
                    note_output = "<h1>Scan of {} </h1></br></br>".format(current_url)
                    if current_url_obj.port:
                        current_port_num = int(current_url_obj.port)
                    else:
                        if current_scheme == 'http':
                            current_port_num = 80
                        elif current_scheme == 'https':
                            current_port_num = 443
                    current_wordpress_path = current_url_obj.path

                    if current_port_num < 1 or current_port_num > 65535:
                        raise Exception

                    # create port
                    current_port_obj = db.select_host_port(current_host_id,
                                                           current_port_num,
                                                           True)
                    if current_port_obj:
                        current_port_id = current_port_obj[0]['id']
                    else:
                        current_port_id = db.insert_host_port(current_host_id,
                                                              current_port_num,
                                                              True,
                                                              current_scheme,
                                                              'WordPress',
                                                              current_user['id'],
                                                              current_project['id'])

                    # create hostname
                    hostname = current_url_obj.hostname
                    if hostname == current_ip:
                        current_hostname_id = "0"
                    else:
                        current_hostname = db.select_ip_hostname(current_host_id,
                                                                 hostname)
                        if current_hostname:
                            current_hostname_id = current_hostname[0]['id']
                        else:
                            current_hostname_id = db.insert_hostname(
                                current_host_id,
                                hostname,
                                "Added from WPScan",
                                current_user['id']
                            )
                    # Interesting findings
                    interest_obj = file_dict['interesting_findings']
                    if interest_obj:
                        note_output += "<h1>Interesting findings </h1></br>"
                        for find_obj in interest_obj:
                            note_output += "<h2><b>URL:</b> " + find_obj["url"] + "</h2></br>"
                            note_output += "<b>Type:</b> " + find_obj["type"] + "</br>"
                            note_output += "<b>Description:</b> " + find_obj["to_s"] + "</br>"
                            note_output += "<b>Found by:</b> " + find_obj["found_by"] + "</br>"
                            note_output += "<b>Interesting entries:</b> <ol>"
                            for entry in find_obj["interesting_entries"]:
                                note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                            note_output += "</ol></br>"
                            if "url" in find_obj["references"]:
                                note_output += "<b>Reference urls:</b> <ol>"
                                for url in find_obj["references"]["url"]:
                                    note_output += "<li>" + htmlspecialchars(url) + "</li>"
                                note_output += "</ol></br>"
                            if "metasploit" in find_obj["references"]:
                                note_output += "<b>Reference metasploit:</b> <ol>"
                                for url in find_obj["references"]["metasploit"]:
                                    note_output += "<li>" + htmlspecialchars(url) + "</li>"
                                note_output += "</ol></br>"

                    # Versions issues detection
                    version_obj = file_dict['version']
                    if version_obj:
                        note_output += "<h1>Version detection </h1></br>"
                        note_output += "<b>Version:</b> " + version_obj["number"] + "</br>"
                        note_output += "<b>Found by:</b> " + version_obj["found_by"] + "</br>"
                        note_output += "<b>Interesting entries:</b> <ol>"
                        for entry in version_obj["interesting_entries"]:
                            note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                        note_output += "</ol></br>"
                        for current_issue in version_obj["vulnerabilities"]:
                            issue_name = current_issue["title"]
                            issue_fix = "Upgrade WordPress to version >= " + current_issue["fixed_in"]
                            issue_cve = ",".join(current_issue["references"]["cve"])
                            issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name,
                                                                                         "\n".join([" - " + x for x in current_issue["references"]["url"]]),
                                                                                         ", ".join(current_issue["references"]["wpvulndb"]))
                            if "exploitdb" in current_issue:
                                issue_description += "\n\nExploitDB: {}".format(current_issue["exploitdb"])
                            if "youtube" in current_issue:
                                issue_description += "\n\nYoutube: {}".format(current_issue["youtube"])

                            issue_id = db.insert_new_issue_no_dublicate(
                                issue_name,
                                issue_description,
                                current_wordpress_path,
                                0,
                                current_user['id'],
                                {current_port_id: [current_hostname_id]},
                                "Need to recheck",
                                current_project['id'],
                                issue_cve,
                                0,
                                "web",
                                issue_fix,
                                ""
                            )

                    # Theme
                    main_theme_obj = file_dict['main_theme']
                    if main_theme_obj:
                        note_output += "<h1>Main theme </h1></br>"
                        note_output += "<b>Name:</b> " + main_theme_obj["slug"] + "</br>"
                        note_output += "<b>Location:</b> " + main_theme_obj["location"] + "</br>"
                        if "readme_url" in main_theme_obj:
                            note_output += "<b>Readme URL:</b> " + main_theme_obj["readme_url"] + "</br>"
                        if "style_uri" in main_theme_obj:
                            note_output += "<b>Official URL:</b> " + main_theme_obj["style_uri"] + "</br>"
                        if "version" in main_theme_obj and main_theme_obj["version"]:
                            note_output += "<b>Version:</b> " + main_theme_obj["version"]["number"] + "</br>"

                            note_output += "<b>Interesting entries:</b> <ol>"
                            for entry in main_theme_obj["version"]["interesting_entries"]:
                                note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                            note_output += "</ol></br>"

                        for current_issue in main_theme_obj["vulnerabilities"]:
                            issue_name = current_issue["title"]
                            issue_fix = "Upgrade main theme {} to version >= {}".format(main_theme_obj["slug"], current_issue["fixed_in"])
                            issue_cve = ",".join(current_issue["references"]["cve"])
                            issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name,
                                                                                         "\n".join([" - " + x for x in current_issue["references"]["url"]]),
                                                                                         ", ".join(current_issue["references"]["wpvulndb"]))
                            if "exploitdb" in current_issue:
                                issue_description += "\n\nExploitDB: {}".format(current_issue["exploitdb"])
                            if "youtube" in current_issue:
                                issue_description += "\n\nYoutube: {}".format(current_issue["youtube"])

                            issue_id = db.insert_new_issue_no_dublicate(
                                issue_name,
                                issue_description,
                                current_wordpress_path,
                                0,
                                current_user['id'],
                                {current_port_id: [current_hostname_id]},
                                "Need to recheck",
                                current_project['id'],
                                issue_cve,
                                0,
                                "web",
                                issue_fix,
                                ""
                            )

                    # Plugins
                    plugins_obj = file_dict['plugins']
                    if plugins_obj:
                        note_output += "<h1>Plugins</h1></br>"
                        for plugin_name in plugins_obj:
                            plugin_obj = plugins_obj[plugin_name]
                            note_output += "<h2>" + plugin_name + "</h2></br>"
                            note_output += "<b>Location:</b> " + plugin_obj["location"] + "</br>"
                            note_output += "<b>Found by:</b> " + plugin_obj["found_by"] + "</br>"
                            if "error_log_url" in plugins_obj and plugin_obj["error_log_url"]:
                                note_output += "<b>Error log URL:</b> " + plugin_obj["error_log_url"] + "</br>"
                            if "directory_listing" in plugin_obj and plugin_obj["directory_listing"]:
                                note_output += "<b>Dir listing URL:</b> " + plugin_obj["directory_listing"] + "</br>"
                            if "changelog_url" in plugin_obj and plugin_obj["changelog_url"]:
                                note_output += "<b>Changelog URL:</b> " + plugin_obj["changelog_url"] + "</br>"
                            if "readme_url" in plugin_obj and plugin_obj["readme_url"]:
                                note_output += "<b>Readme URL:</b> " + plugin_obj["readme_url"] + "</br>"
                            note_output += "<b>Interesting entries:</b> <ol>"
                            for entry in plugin_obj["interesting_entries"]:
                                note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                            note_output += "</ol></br>"
                            if "version" in plugin_obj and plugin_obj["version"]:
                                note_output += "<b>Version:</b> " + plugin_obj["version"]["number"] + "</br>"
                                note_output += "<b>Version entries:</b> <ol>"
                                for entry in plugin_obj["version"]["interesting_entries"]:
                                    note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                                note_output += "</ol></br>"
                            for current_issue in plugin_obj["vulnerabilities"]:
                                issue_name = current_issue["title"]
                                issue_fix = "Upgrade plugin {} to version >= {}".format(plugin_name, current_issue["fixed_in"])
                                issue_cve = ",".join(current_issue["references"]["cve"])
                                issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name,
                                                                                             "\n".join([" - " + x for x in current_issue["references"]["url"]]),
                                                                                             ", ".join(current_issue["references"]["wpvulndb"]))
                                if "exploitdb" in current_issue:
                                    issue_description += "\n\nExploitDB: {}".format(current_issue["exploitdb"])
                                if "youtube" in current_issue:
                                    issue_description += "\n\nYoutube: {}".format(current_issue["youtube"])

                                issue_id = db.insert_new_issue_no_dublicate(
                                    issue_name,
                                    issue_description,
                                    current_wordpress_path,
                                    0,
                                    current_user['id'],
                                    {current_port_id: [current_hostname_id]},
                                    "Need to recheck",
                                    current_project['id'],
                                    issue_cve,
                                    0,
                                    "web",
                                    issue_fix,
                                    ""
                                )
                    # Add note
                    note_id = db.insert_new_note(current_project['id'],
                                                 "WPScan: {}".format(current_port_num),
                                                 current_user['id'],
                                                 current_host_id,
                                                 note_output)



                except ValueError as e:
                    errors.append('One of files was corrupted: {}'.format(e))

    return render_template('project/tools/import/wpscan.html',
                           current_project=current_project,
                           tab_name='WPScan',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/kube-hunter/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def kubehunter_page(project_id, current_project, current_user):
    return render_template('project/tools/import/kubehunter.html',
                           current_project=current_project,
                           tab_name='kube-hunter')


@routes.route('/project/<uuid:project_id>/tools/kube-hunter/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def kubehunter_form(project_id, current_project, current_user):
    form = KuberHunter()
    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        for file in form.json_files.data:
            if file.filename:
                json_report_data = file.read().decode('charmap')
                scan_result = json.loads(json_report_data)

                # add node description
                for node_obj in scan_result['nodes']:
                    try:
                        node_type = form.hosts_description.data
                        if 'type' in node_obj:
                            node_type = "Kubernetes " + node_obj['type']
                        node_ip = node_obj['location']

                        # check if valid ip
                        ipaddress.ip_address(node_ip)

                        current_host = db.select_ip_from_project(current_project['id'], node_ip)
                        if current_host:
                            current_host = current_host[0]
                            db.update_host_description(current_host['id'], node_type)
                        else:
                            current_host = db.insert_host(current_project['id'],
                                                          node_ip,
                                                          current_user['id'],
                                                          node_type)
                    except Exception as e:
                        # next Node
                        pass

                # services

                for service_obj in scan_result['services']:
                    try:
                        service_info = service_obj['service']
                        service_ip = service_obj['location'].split(':')[0]
                        service_port = int(service_obj['location'].split(':')[1])

                        # check ip
                        ipaddress.ip_address(service_ip)

                        # add host
                        current_host = db.select_ip_from_project(current_project['id'], service_ip)
                        if current_host:
                            current_host = current_host[0]
                        else:
                            current_host = db.insert_host(current_project['id'],
                                                          service_ip,
                                                          current_user['id'],
                                                          form.hosts_description.data)

                        # add port

                        current_port = db.select_ip_port(current_host['id'], service_port, is_tcp=True)
                        if current_port:
                            current_port = current_port[0]
                            db.update_port_service(current_port['id'],
                                                   service_info)
                        else:
                            current_port = db.insert_host_port(current_host['id'],
                                                               service_port,
                                                               True,
                                                               service_info,
                                                               form.ports_description.data,
                                                               current_user['id'],
                                                               current_project['id'])
                    except Exception as e:
                        # next service
                        pass

                # add issues

                for issue_obj in scan_result['vulnerabilities']:
                    try:
                        issue_ip = issue_obj['location'].split(':')[0]
                        issue_port = 0
                        if ':' in issue_obj['location']:
                            issue_port = int(issue_obj['location'].split(':')[1])

                        # check ip
                        ipaddress.ip_address(issue_ip)

                        issue_cvss = 0
                        issue_severity = issue_obj['severity']
                        issue_name = issue_obj['vulnerability']
                        issue_category = issue_obj['category']
                        issue_num = issue_obj['vid']
                        issue_poc_str = issue_obj['evidence']
                        issue_link = issue_obj['avd_reference']
                        issue_script = issue_obj['hunter']
                        issue_description = issue_obj['description']

                        issue_full_description = 'Category: {}\nEvidence: {}\nModule: {}\nLink: {}\nNumber: {}\n\n{}'.format(
                            issue_category,
                            issue_poc_str,
                            issue_script,
                            issue_link,
                            issue_num,
                            issue_description
                        )

                        if issue_severity == 'low':
                            issue_cvss = 2.0
                        elif issue_severity == 'medium':
                            issue_cvss = 5.0
                        elif issue_severity == 'high':
                            issue_cvss = 8.0
                        elif issue_severity == 'critical':
                            issue_cvss = 10.0

                        # add host
                        current_host = db.select_ip_from_project(current_project['id'], issue_ip)
                        if current_host:
                            current_host = current_host[0]
                        else:
                            current_host = db.insert_host(current_project['id'],
                                                          issue_ip,
                                                          current_user['id'],
                                                          form.hosts_description.data)

                        # add port

                        current_port = db.select_ip_port(current_host['id'], issue_port, is_tcp=True)
                        if current_port:
                            current_port = current_port[0]
                            db.update_port_service(current_port['id'],
                                                   form.ports_description.data)
                        else:
                            current_port = db.insert_host_port(current_host['id'],
                                                               issue_port,
                                                               True,
                                                               'kubernetes',
                                                               form.ports_description.data,
                                                               current_user['id'],
                                                               current_project['id'])

                        # add issue

                        services = {current_port['id']: ['0']}

                        current_issue = db.insert_new_issue_no_dublicate(issue_name,
                                                                         issue_full_description,
                                                                         '',
                                                                         issue_cvss,
                                                                         current_user['id'],
                                                                         services,
                                                                         'need to recheck',
                                                                         current_project['id'],
                                                                         '',
                                                                         0,
                                                                         'custom',
                                                                         '',
                                                                         '')
                    except Exception as e:
                        print(e)
                        pass

        return render_template('project/tools/import/kubehunter.html',
                               current_project=current_project,
                               tab_name='kube-hunter',
                               errors=errors)

    return render_template('project/tools/import/kubehunter.html',
                           current_project=current_project,
                           tab_name='kube-hunter',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/burp_enterprise/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def burp_enterprise_page(project_id, current_project, current_user):
    return render_template('project/tools/import/burp_enterprise.html',
                           current_project=current_project,
                           tab_name='Burp Suite Enterprise Edition')


@routes.route('/project/<uuid:project_id>/tools/burp_enterprise/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def burp_enterprise_form(project_id, current_project, current_user):
    form = BurpEnterpriseForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if errors:
        return render_template('project/tools/import/burp_enterprise.html',
                               current_project=current_project,
                               tab_name='Burp Suite Enterprise Edition',
                               errors=errors)

    # hostnames dict
    if len(form.hostnames.data) != len(form.ips.data):
        return render_template('project/tools/import/burp_enterprise.html',
                               current_project=current_project,
                               tab_name='Burp Suite Enterprise Edition',
                               errors=['Error with hostnames'])
    i = 0
    hostname_dict = {}
    for i in range(len(form.hostnames.data)):
        hostname_dict[form.hostnames.data[i]] = form.ips.data[i]

    auto_resolve = form.auto_resolve.data == 1

    # xml files
    for file in form.html_files.data:
        if file.filename:
            html_data = file.read()
            scan_result = BeautifulSoup(html_data, "html.parser")

            # find list of issues

            site_array = scan_result.select('h1:contains("Issues found on")')

            for site_obj in site_array:
                url = site_obj.string.split('Issues found on ')[1].strip()
                parsed_url = urllib.parse.urlparse(url)
                protocol = parsed_url.scheme
                hostname = parsed_url.netloc
                port = 80
                ip = ''
                if not parsed_url.port:
                    if protocol == 'https':
                        port = 443
                    else:
                        port = 80
                else:
                    port = int(parsed_url.port)
                pass

                # check ip
                try:
                    ipaddress.ip_address(hostname)
                    ip = hostname
                    hostname = ''
                except Exception as e:
                    pass

                if hostname:
                    try:
                        email_validator.validate_email_domain_part(hostname)
                    except email_validator.EmailNotValidError:
                        errors.append('Hostname not valid!')
                        hostname = ''

                # check hostname

                if ip == '':
                    if hostname in hostname_dict:
                        ip = hostname_dict[hostname]
                    elif auto_resolve:
                        ip = socket.gethostbyname(hostname)

                if ip and not errors:
                    # add host
                    current_host = db.select_ip_from_project(current_project['id'], ip)
                    if current_host:
                        current_host = current_host[0]
                    else:
                        current_host = db.insert_host(current_project['id'],
                                                      ip,
                                                      current_user['id'],
                                                      form.hosts_description.data)

                    # add port

                    current_port = db.select_ip_port(current_host['id'], port, is_tcp=True)
                    if current_port:
                        current_port = current_port[0]
                        db.update_port_service(current_port['id'],
                                               protocol)
                    else:
                        current_port = db.insert_host_port(current_host['id'],
                                                           port,
                                                           True,
                                                           protocol,
                                                           form.ports_description.data,
                                                           current_user['id'],
                                                           current_project['id'])

                    # add hostname
                    current_hostname = None
                    if hostname:
                        current_hostname = db.select_ip_hostname(current_host['id'],
                                                                 hostname)
                        if current_hostname:
                            current_hostname = current_hostname[0]
                        else:
                            hostname_id = db.insert_hostname(current_host['id'], hostname,
                                                             form.hostnames_description.data,
                                                             current_user['id'])
                            current_hostname = db.select_hostname(hostname_id)

                    # issues loop

                    rows_array = site_obj.parent.find_all('tr')[1:]
                    issue_name = ''
                    i = 0
                    for issue_header_obj in rows_array:
                        i += 1
                        if 'class' in issue_header_obj.attrs and 'issue-type-row' in issue_header_obj.attrs['class']:
                            issue_name = issue_header_obj.find('td').string.split(' [')[0]
                        else:
                            td_arr = issue_header_obj.find_all('td')
                            issue_path = issue_header_obj.find('td', {"class": "issue-path"}).string.strip()
                            dom_id = issue_header_obj.find('a').attrs['href'].replace('#', '')
                            severity = td_arr[1].string
                            issue_cvss = 0.0
                            if severity == 'Low':
                                issue_cvss = 2.0
                            elif severity == 'Medium':
                                issue_cvss = 5.0
                            elif severity == 'High':
                                issue_cvss = 8.0
                            elif severity == 'Critical':
                                issue_cvss = 10.0

                            # goto issue container
                            issue_container = scan_result.find('a', {"name": dom_id}).parent
                            issue_name = issue_container.find('h2').string
                            issue_description_container = issue_container.find('div')
                            issue_description_text = str(issue_description_container.getText())
                            while '  ' in issue_description_text:
                                issue_description_text = issue_description_text.replace('  ', ' ')
                            while '\n\n\n' in issue_description_text:
                                issue_description_text = issue_description_text.replace('\n\n\n', '\n\n')
                            print(1)

                            # ignoring Remediation detail

                            # Remidiation == fix
                            issue_fix_short_header = issue_container.select('h3:contains("Remediation detail")')
                            issue_fix_short1_header = issue_container.select('h3:contains("Issue remediation")')
                            issue_fix = ''
                            if issue_fix_short_header:
                                next_elem = issue_fix_short_header[0].find_next()
                                issue_fix += str(next_elem.getText()) + '\n\n'
                            if issue_fix_short1_header:
                                next_elem = issue_fix_short1_header[0].find_next()
                                issue_fix += str(next_elem.getText())

                            # issue_fix = issue_fix.replace('<ul>', '\n').replace('<li>', ' - ').replace('</li>', '\n').replace('</ul>', '').replace('\t', '').replace('<div>', '').replace('</div>', '').replace('<b>', '').replace('</b>', '')
                            while '  ' in issue_fix:
                                issue_fix = issue_fix.replace('  ', ' ')
                            while '\n\n\n' in issue_fix:
                                issue_fix = issue_fix.replace('\n\n\n', '\n\n')

                            # References
                            issue_ref_header = issue_container.select('h3:contains("References")')
                            issue_ref = ''
                            if issue_ref_header:
                                issue_ref_header = issue_ref_header[0].find_next()
                                issue_ref = '\n\nReferences:\n'
                                links = issue_ref_header.find_all('a')
                                for link_obj in links:
                                    issue_ref += ' - ' + link_obj.string + ': ' + link_obj.attrs['href'] + '\n'

                            # Vulnerability classifications

                            issue_class_header = issue_container.select('h3:contains("Vulnerability classifications")')
                            issue_class = ''
                            if issue_class_header:
                                issue_class_header = issue_class_header[0].find_next()
                                issue_class = '\n\nClassification:\n'
                                links = issue_class_header.find_all('a')
                                for link_obj in links:
                                    issue_class += link_obj.string + ': ' + link_obj.attrs['href'] + '\n'
                            # add issue
                            issue_full_description = issue_description_text + issue_ref + issue_class

                            while '  ' in issue_full_description:
                                issue_full_description = issue_full_description.replace('  ', ' ')
                            while '\n\n\n' in issue_full_description:
                                issue_full_description = issue_full_description.replace('\n\n\n', '\n\n')
                            try:
                                services = {current_port['id']: ['0']}
                                if current_hostname:
                                    services = {current_port['id']: [current_hostname['id']]}
                            except Exception as e:
                                pass

                            current_issue_id = db.insert_new_issue_no_dublicate(
                                name='Burp: ' + issue_name,
                                description=str(issue_full_description),
                                url_path=str(issue_path),
                                cvss=float(issue_cvss),
                                user_id=current_user['id'],
                                services=services,
                                status='Need to recheck',
                                project_id=current_project['id'],
                                cve='',
                                cwe=0,
                                issue_type='web',
                                fix=str(issue_fix),
                                param=''
                            )

                            # PoC Request
                            issue_request_header = issue_container.select('h3:contains("Request:")')
                            if issue_request_header:
                                next_elem = issue_request_header[0].find_next()
                                poc_text = str(next_elem.getText()).replace('\r', '')
                                # add poc

                                file_data = b''

                                if config['files']['poc_storage'] == 'database':
                                    file_data = poc_text.encode('charmap')

                                poc_id = db.insert_new_poc(current_port['id'],
                                                           'HTTP request',
                                                           'text',
                                                           'request.txt',
                                                           current_issue_id,
                                                           current_user['id'],
                                                           current_hostname['id'] if current_hostname else '0',
                                                           storage=config['files']['poc_storage'],
                                                           data=file_data)
                                if config['files']['poc_storage'] == 'filesystem':
                                    file_path = './static/files/poc/{}'.format(poc_id)
                                    file_object = open(file_path, 'w')
                                    file_object.write(poc_text)
                                    file_object.close()

                            # PoC Response
                            issue_response_header = issue_container.select('h3:contains("Response:")')
                            if issue_response_header:
                                next_elem = issue_response_header[0].find_next()
                                poc_text = str(next_elem.getText()).replace('\r', '')
                                # add poc

                                file_data = b''

                                if config['files']['poc_storage'] == 'database':
                                    file_data = poc_text.encode('charmap')

                                poc_id = db.insert_new_poc(current_port['id'],
                                                           'HTTP response',
                                                           'text',
                                                           'response.txt',
                                                           current_issue_id,
                                                           current_user['id'],
                                                           current_hostname['id'] if current_hostname else '0',
                                                           storage=config['files']['poc_storage'],
                                                           data=file_data)

                                if config['files']['poc_storage'] == 'filesystem':
                                    file_path = './static/files/poc/{}'.format(poc_id)
                                    file_object = open(file_path, 'w')
                                    file_object.write(poc_text)
                                    file_object.close()

    return render_template('project/tools/import/burp_enterprise.html',
                           current_project=current_project,
                           tab_name='Burp Suite Enterprise Edition',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/dnsrecon/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def dnsrecon_page(project_id, current_project, current_user):
    return render_template('project/tools/import/dnsrecon.html',
                           current_project=current_project,
                           tab_name='DNSrecon')


@routes.route('/project/<uuid:project_id>/tools/dnsrecon/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def dnsrecon_page_form(project_id, current_project, current_user):
    form = DNSreconForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:

        hostnames_dict = {}
        ports_dict = {}

        # json files
        for file in form.json_files.data:
            if file.filename:
                json_report_data = file.read().decode('charmap')
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
                            hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type, hostname_info)
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

        # csv load
        for file in form.csv_files.data:
            if file.filename:
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
                            hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type, hostname_info)
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

        for file in form.xml_files.data:
            if file.filename:
                soup = BeautifulSoup(file.read(), "html.parser")

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
                            hostnames_dict[hostname_name]['description'] += '\nType: {}\nInfo: {}'.format(hostname_type, hostname_info)
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

        # hostnames_dict = {'google.com':{'ip':[8.8.8.8], 'description': '...' }}

        for hostname in hostnames_dict:
            ip_array = hostnames_dict[hostname]['ip']
            description = hostnames_dict[hostname]['description']
            for ip_address in ip_array:
                # check if valid ip
                ip_obj = ipaddress.ip_address(ip_address)
                if (':' not in ip_address) or (':' in ip_address and not form.ignore_ipv6.data):

                    current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
                    if not current_host:
                        host_id = db.insert_host(current_project['id'], ip_address, current_user['id'], form.hosts_description.data)
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
            if (':' not in ip_address) or (':' in ip_address and not form.ignore_ipv6.data):
                current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
                if not current_host:
                    host_id = db.insert_host(current_project['id'], ip_address, current_user['id'], form.hosts_description.data)
                else:
                    host_id = current_host[0]['id']

                for port_num in ports_arr:
                    port_num_int = int(port_num)
                    if port_num_int > 0 and port_num_int < 65536:
                        current_port = db.select_host_port(host_id, int(port_num), is_tcp=True)
                        if not current_port:
                            port_id = db.insert_host_port(host_id, port_num_int, True, 'unknown', form.ports_description.data, current_user['id'], current_project['id'])

    return render_template('project/tools/import/dnsrecon.html',
                           current_project=current_project,
                           tab_name='DNSrecon',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/theharvester/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def theharvester_page(project_id, current_project, current_user):
    return render_template('project/tools/import/theharvester.html',
                           current_project=current_project,
                           tab_name='theHarvester')


@routes.route('/project/<uuid:project_id>/tools/theharvester/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
@check_project_archived
def theharvester_page_form(project_id, current_project, current_user):
    form = theHarvesterForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        for file in form.xml_files.data:
            if file.filename:
                soup = BeautifulSoup(file.read(), "html.parser")

                scan_result = soup.findAll('host')

                for hostname_row in scan_result:
                    ips_str = hostname_row.find('ip').text
                    hostname = hostname_row.find('hostname').text

                    ip_array = ips_str.split(', ')
                    for ip_address in ip_array:
                        # check valid ip
                        ipaddress.ip_address(ip_address)

                        current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
                        if current_host:
                            host_id = current_host[0]['id']
                        else:
                            host_id = db.insert_host(current_project['id'], ip_address, current_user['id'],
                                                     form.hosts_description.data)

                        current_hostname = db.select_ip_hostname(host_id, hostname)
                        if not current_hostname:
                            hostname_id = db.insert_hostname(host_id, hostname, form.hostnames_description.data, current_user['id'])

    return render_template('project/tools/import/theharvester.html',
                           current_project=current_project,
                           tab_name='theHarvester',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/metasploit/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def metasploit_page(project_id, current_project, current_user):
    return render_template('project/tools/import/metasploit.html',
                           current_project=current_project,
                           tab_name='Metasploit')


@routes.route('/project/<uuid:project_id>/tools/metasploit/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
@check_project_archived
def metasploit_page_form(project_id, current_project, current_user):
    form = MetasploitForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    '''
    <MetasploitV5>
    1. <hosts> - hosts info (domain/ip) - ignore <vulns>
    2. <events> - ignoring
    3. <web_sites>
    4. <web_pages> - ignoring
    5. <web_forms> - ignoring
    6. <web_vuln>
    
    Steps:
    1. Add hosts
    2. Add sites
    3. Add site vulns
    
    '''

    if not errors:
        for file in form.xml_files.data:
            if file.filename:
                soup = BeautifulSoup(file.read(), "html.parser")

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
                    if form.add_nmap_scripts.data:
                        notes_object = host_row.find('notes')
                        notes_arr = notes_object.findAll('note')
                        for note_row in notes_arr:
                            script_name = note_row.find('ntype').text  # nmap.nse.smb-os-discovery.host
                            if script_name not in ['host.comments', 'host.info', 'host.os.nmap_fingerprint', 'host.name']:
                                host_report_id = note_row.find('host-id').text
                                script_critical = note_row.find('critical').text  # ???
                                service_report_id = note_row.find('service-id').text
                                try:
                                    script_data = base64.b64decode(note_row.find('data').text)[16:].decode('charmap').strip(' \n\t\r')
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
                        db.update_port_proto_description(port_id, ports_dict[port_obj]['service'], ports_dict[port_obj]['info'])
                    else:
                        port_id = db.insert_host_port(hosts_dict[ports_dict[port_obj]['host_report_id']]['pcf_id'],
                                                      ports_dict[port_obj]['port'], ports_dict[port_obj]['is_tcp'], ports_dict[port_obj]['service'],
                                                      ports_dict[port_obj]['info'], current_user['id'], current_project['id'])
                    ports_dict[port_obj]['pcf_id'] = port_id

                # ignoring websites due to it is connected with services which were added earlier

                if not form.only_nmap.data:
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
                        pcf_hostname_id = 0
                        if vhost:
                            current_hostname = db.select_ip_hostname(pcf_host_id, vhost)
                            if current_hostname:
                                hostname_id = current_hostname[0]['id']
                            else:
                                hostname_id = db.insert_hostname(pcf_host_id, vhost, form.hostnames_description.data, current_user['id'])
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
                        vuln_params = base64.b64decode(vuln_obj.find('params').text).decode('charmap')[4:]  # i dont know how to parse better
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

                        services = {web_dict[vuln_website_id]['pcf_port_id']: [web_dict[vuln_website_id]['pcf_hostname_id']]}

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

    return render_template('project/tools/import/metasploit.html',
                           current_project=current_project,
                           tab_name='Metasploit',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/nuclei/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def nuclei_page(project_id, current_project, current_user):
    return render_template('project/tools/import/nuclei.html',
                           current_project=current_project,
                           tab_name='Nuclei')


@routes.route('/project/<uuid:project_id>/tools/nuclei/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def nuclei_page_form(project_id, current_project, current_user):
    form = NucleiForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if errors:
        return render_template('project/tools/import/nuclei.html',
                               current_project=current_project,
                               tab_name='Nuclei',
                               errors=errors)

    # hostnames dict
    if len(form.hostnames.data) != len(form.ips.data):
        return render_template('project/tools/import/nuclei.html',
                               current_project=current_project,
                               tab_name='Nuclei',
                               errors=['Error with hostnames'])
    i = 0
    hostname_dict = {}
    for i in range(len(form.hostnames.data)):
        hostname_dict[form.hostnames.data[i]] = form.ips.data[i]

    auto_resolve = form.auto_resolve.data == 1

    # json files
    for file in form.json_files.data:
        if file.filename:
            json_data = json.loads('[{}]'.format(file.read().decode('charmap').strip(' \t\r\n').replace('\r', '').replace('\n', ',')))
            for issue_obj in json_data:
                # important fields
                issue_name = 'Nuclei: {}'.format(issue_obj['info']['name'])
                issue_tags = 'Tags: {}'.format(', '.join(issue_obj['info']['tags'])) if issue_obj['info']['tags'] else ""
                issue_description = issue_obj['info']['description'] if 'description' in issue_obj['info'] else ''
                issue_references = "Links:\n{}".format('\n'.join([' - {}'.format(x) for x in issue_obj['info']['reference']])) if issue_obj['info']['reference'] else ""
                issue_severity = "info"
                issue_matcher_name = 'Matched: {}'.format(issue_obj['matcher-name']) if 'matcher-name' in issue_obj else ""
                issue_cvss = 0.0
                if issue_severity == 'low':
                    issue_cvss = 2.0
                elif issue_severity == 'medium':
                    issue_cvss = 5.0
                elif issue_severity == 'high':
                    issue_cvss = 8.0
                elif issue_severity == 'critical':
                    issue_cvss = 10.0
                issue_type = 'Script type: {}'.format(issue_obj['type']) if issue_obj['type'] else ""
                issue_curl_cmd = 'Curl: {}'.format(issue_obj["curl-command"]) if "curl-command" in issue_obj else ''
                issue_ip = issue_obj["ip"] if "ip" in issue_obj else ""  # 142.250.185.78
                issue_host = issue_obj["host"] if "host" in issue_obj else ''  # https://google.com
                issue_url = ''
                issue_protocol = issue_obj["protocol"] if "protocol" in issue_obj else ''  # i dont know key "protocol
                issue_port = 0
                issue_hostname = ''
                issue_cve = issue_obj["cve"] if "cve" in issue_obj else ''
                issue_cwe = issue_obj["cwe"] if "cwe" in issue_obj else ''

                # validate ip
                if issue_ip:
                    try:
                        ipaddress.ip_address(issue_ip)
                    except Exception as e:
                        issue_ip = ''

                if issue_host:
                    # check if url
                    url_obj = None
                    try:
                        url_obj = urlparse(issue_host)
                    except Exception as e:
                        # wrong url
                        pass
                    if url_obj:
                        # its web!

                        # check protocol
                        issue_protocol = 'http'
                        if url_obj.scheme:
                            issue_protocol = url_obj.scheme

                        # check port
                        if issue_protocol == 'http':
                            issue_port = 80
                        elif issue_protocol == 'https':
                            issue_port = 443
                        if url_obj.port:
                            issue_port = url_obj.port

                        # check url path
                        if issue_obj["matched-at"].startswith(issue_host):
                            issue_url = issue_obj["matched-at"][len(issue_host):]
                        if not issue_url:
                            issue_path = '/'

                        # ip or hostname
                        if not issue_ip and url_obj.hostname:
                            try:
                                ip_obj = ipaddress.ip_address(url_obj.hostname)
                                issue_ip = url_obj.hostname
                            except Exception as e:
                                issue_hostname = url_obj.hostname
                                pass
                        elif url_obj.hostname:
                            issue_hostname = url_obj.hostname
                if 'port' in issue_obj:
                    issue_port = int(issue_obj['port'])

                blacklist_tags = ["template-id", "info", "host", "matched-at",
                                  "timestamp", "curl-command", "type", "port",
                                  "matcher-name", "matcher-status", "template",
                                  "template-url", "protocol", "cve", "cwe", "ip"]

                issue_other_fields = ''
                for key_name in issue_obj:
                    if key_name not in blacklist_tags:
                        issue_other_fields += '{}: {}\n'.format(key_name, str(issue_obj[key_name]))

                if issue_port < 0 or issue_port > 65535:
                    issue_port = 0
                # resolve ip
                if not issue_ip and issue_hostname:
                    if issue_hostname in hostname_dict:
                        issue_ip = hostname_dict[issue_hostname]
                    elif auto_resolve:
                        try:
                            issue_ip = socket.gethostbyname(issue_hostname)
                        except Exception as e:
                            pass

                # if ip, port (, hostname)
                # create them in db
                services = {}
                if issue_ip:
                    # create host
                    current_host = db.select_project_host_by_ip(current_project['id'], issue_ip)
                    if current_host:
                        host_id = current_host[0]['id']
                    else:
                        host_id = db.insert_host(current_project['id'], issue_ip, current_user['id'],
                                                 comment=form.hosts_description.data)

                    # create port
                    current_port = db.select_host_port(host_id, issue_port, True)
                    if current_port:
                        port_id = current_port[0]['id']
                    else:
                        port_id = db.insert_host_port(host_id, issue_port, True, issue_protocol,
                                                      form.ports_description.data, current_user['id'],
                                                      current_project['id'])

                    # create hostname
                    hostname_id = 0
                    if issue_hostname:
                        current_hostname = db.select_ip_hostname(host_id, issue_hostname)
                        if current_hostname:
                            hostname_id = current_hostname[0]['id']
                        else:
                            hostname_id = db.insert_hostname(host_id, issue_hostname, form.hostnames_description.data,
                                                             current_user['id'])

                    services = {port_id: [hostname_id]}

                # create description
                issue_full_description = issue_description + '\n'
                if issue_matcher_name:
                    issue_full_description += '\n' + issue_matcher_name
                if issue_tags:
                    issue_full_description += '\n' + issue_tags
                if issue_type:
                    issue_full_description += '\n' + issue_type
                if issue_curl_cmd:
                    issue_full_description += '\n' + issue_curl_cmd
                if issue_references:
                    issue_full_description += '\n' + issue_references
                if issue_other_fields:
                    issue_full_description += '\n' + issue_other_fields

                # create issue

                issue_id = db.insert_new_issue_no_dublicate(issue_name,
                                                            issue_full_description,
                                                            issue_url,
                                                            issue_cvss,
                                                            current_user['id'],
                                                            services,
                                                            'Need to recheck',
                                                            current_project['id'],
                                                            issue_cve,
                                                            issue_cwe,
                                                            'web' if issue_protocol.startswith('http') else 'custom',
                                                            fix='',
                                                            param=''
                                                            )

    return render_template('project/tools/import/nuclei.html',
                           current_project=current_project,
                           tab_name='Nuclei')


@routes.route('/project/<uuid:project_id>/tools/nmap-helper/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def nmap_helper_page(project_id, current_project, current_user):
    return render_template('project/tools/helpers/nmap-helper.html',
                           current_project=current_project,
                           tab_name='Nmap Helper')


@routes.route('/project/<uuid:project_id>/tools/msfvenom-helper/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@send_log_data
def msfvenom_helper_page(project_id, current_project, current_user):
    return render_template('project/tools/helpers/msfvenom-helper.html',
                           current_project=current_project,
                           tab_name='MSFVenom Helper')


@routes.route('/project/<uuid:project_id>/tools/pingcastle/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def pingcastle_page(project_id, current_project, current_user):
    return render_template('project/tools/import/pingcastle.html',
                           current_project=current_project,
                           tab_name='PingCastle')


@routes.route('/project/<uuid:project_id>/tools/pingcastle/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def pingcastle_page_form(project_id, current_project, current_user):
    form = PingCastleForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        # prepare issues database
        f = open('./routes/ui/tools_files/PingCastle/PingCastleDescription.resx')
        s = f.read()
        f.close()
        issues_database = {}
        issues_database_xml = BeautifulSoup(s, 'html.parser')
        for issue_obj in issues_database_xml.findAll('data'):
            issues_database[issue_obj.attrs['name']] = issue_obj.findAll('value')[0].text

        # xml files
        for file in form.xml_files.data:
            if file.filename:
                scan_result = BeautifulSoup(file.read(), "html.parser")
                scan_obj = scan_result.healthcheckdata

                # add DCs
                domain_controllers = scan_obj.domaincontrollers
                dc_ports_dict = {}
                if domain_controllers:
                    for domain_obj in domain_controllers.findAll('healthcheckdomaincontroller'):
                        host_description = ''
                        host_os = '' if not domain_obj.operatingsystem else domain_obj.operatingsystem.text
                        if domain_obj.dcname: host_description += 'DC name: {}\n'.format(domain_obj.dcname.text)
                        if domain_obj.lastcomputerlogondate: host_description += 'Last Logon: {}\n'.format(domain_obj.lastcomputerlogondate.text)
                        if domain_obj.distinguishedname: host_description += 'Distinguished Name: {}\n'.format(domain_obj.distinguishedname.text)
                        if domain_obj.ownersid: host_description += 'Owner SID: {}\n'.format(domain_obj.ownersid.text)
                        if domain_obj.ownername: host_description += 'Owner Name: {}\n'.format(domain_obj.ownername.text)
                        if domain_obj.hasnullsession and domain_obj.hasnullsession == 'true': host_description += 'Has null session!\n'
                        if domain_obj.supportsmb1 and domain_obj.supportsmb1.text == 'true':
                            host_description += 'Supports SMB1!\n'
                            if domain_obj.smb1securitymode and domain_obj.smb1securitymode.text == 'NotTested':
                                host_description += 'SMB1SecurityMode: {}\n'.format(domain_obj.smb1securitymode.text)
                        if domain_obj.supportsmb2orsmb3 and domain_obj.supportsmb2orsmb3.text == 'true': host_description += 'Supports SMBv2 or SMBv3.\n'
                        if domain_obj.smb2securitymode: host_description += 'SMB2 security mode: {}\n'.format(domain_obj.smb2securitymode.text)
                        if domain_obj.remotespoolerdetected and domain_obj.remotespoolerdetected.text == 'true': host_description += 'Detected remote spooler.\n'
                        if domain_obj.pwdlastset: host_description += 'Last pwd set: {}.\n'.format(domain_obj.pwdlastset.text)
                        if domain_obj.rodc and domain_obj.rodc.text == 'true': host_description += 'Read-Only DC\n'
                        if domain_obj.sysvoloverwrite and domain_obj.sysvoloverwrite == 'true': host_description += 'SYSVOL overwrite\n'

                        if domain_obj.fsmo:
                            fsmo_result = ', '.join([x.text for x in domain_obj.fsmo.findAll("string")])
                            if fsmo_result:
                                host_description += 'FSMO: {}\n'.format(fsmo_result)

                        host_description = host_description.strip(' \n\t\r')
                        # TODO: fields LDAPSProtocols
                        try:
                            ip_obj = domain_obj.ip
                            for host_ip_obj in ip_obj.findAll('string'):
                                host_ip = host_ip_obj.text
                                # check for valid ip
                                ipaddress.ip_address(host_ip)
                                current_host = db.select_project_host_by_ip(current_project['id'], host_ip)
                                if current_host:
                                    current_host_id = current_host[0]['id']
                                    if host_os:
                                        db.update_host_os(current_host_id, host_os)

                                else:
                                    current_host_id = db.insert_host(current_project['id'], host_ip, current_user['id'], 'Added from PingCastle', os=host_os)
                                # add 88 port
                                current_port = db.select_host_port(current_host_id, port_num=88, is_tcp=True)
                                if current_port:
                                    current_port_id = current_port[0]['id']
                                    if host_description:
                                        db.update_port_proto_description(current_port_id, 'kerberos', host_description)
                                else:
                                    current_port_id = db.insert_host_port(current_host_id, 88, True, 'kerberos',
                                                                          host_description, current_user['id'], current_project['id'])
                                dc_ports_dict[current_port_id] = ['0']
                        except Exception as e:
                            pass

                # Issues - RiskRules
                risk_rules = scan_obj.riskrules
                for risk_obj in risk_rules.findAll('healthcheckriskrule'):
                    issue_points = int(risk_obj.points.text)
                    issue_category = risk_obj.category.text  # PrivilegedAccounts
                    issue_model = risk_obj.model.text  # AccountTakeOver
                    issue_riskid = risk_obj.riskid.text.replace('-', '_')  # A_AdminSDHolder
                    issue_briefly = risk_obj.rationale.text
                    issue_links = issues_database[issue_riskid + '_Documentation'].replace(' ', '') if (issue_riskid + '_Documentation') in issues_database else ''
                    issue_purpose = issues_database[issue_riskid + '_Description'] if (issue_riskid + '_Description') in issues_database else ''
                    issue_fix = issues_database[issue_riskid + '_Solution'] if (issue_riskid + '_Solution') in issues_database else ''
                    issue_technical_description = issues_database[issue_riskid + '_TechnicalExplanation'] if (issue_riskid + '_TechnicalExplanation') in issues_database else ''
                    issue_name = 'PingCastle: {}'.format(issues_database[issue_riskid + '_Title'])

                    issue_full_description = 'Brief: {}\n\nTechnical information: {}\n\nTest purpose: {}\n\nLinks: \n{}'.format(
                        issue_briefly,
                        issue_technical_description,
                        issue_purpose,
                        issue_links
                    )
                    if issue_points < 1:
                        issue_cvss = 0
                    elif issue_points < 10:
                        issue_cvss = 3
                    elif issue_points < 30:
                        issue_cvss = 6
                    else:
                        issue_cvss = 9.5

                    issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_full_description, '', issue_cvss,
                                                                current_user['id'], dc_ports_dict, 'need to recheck',
                                                                current_project['id'], fix=issue_fix)
    return render_template('project/tools/import/pingcastle.html',
                           current_project=current_project,
                           tab_name='PingCastle',
                           errors=errors)


@routes.route('/project/<uuid:project_id>/tools/maxpatrol/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def maxpatrol_page(project_id, current_project, current_user):
    return render_template('project/tools/import/maxpatrol.html',
                           current_project=current_project,
                           tab_name='MaxPatrol')


@routes.route('/project/<uuid:project_id>/tools/maxpatrol/', methods=['POST'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
@send_log_data
def maxpatrol_form(project_id, current_project, current_user):
    form = MaxpatrolForm()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)

    if not errors:
        # xml files
        for file in form.xml_files.data:
            if file.filename:
                file_data = file.read()
                file_len = len(file_data)
                scan_result = BeautifulSoup(file_data, "lxml")
                hosts_list = scan_result.find("content").data
                vulns_db = scan_result.find("content").find("vulners", recursive=False)
                for host in hosts_list.findAll('host'):
                    ip = host.attrs["ip"]
                    ipaddress.ip_address(ip)

                    current_host = db.select_project_host_by_ip(current_project['id'], ip)
                    if current_host:
                        current_host_id = current_host[0]['id']
                    else:
                        current_host_id = db.insert_host(current_project['id'], ip, current_user['id'],
                                                         comment=form.hosts_description.data)

                    scans = host.scan_objects

                    for port_obj in scans.findAll("soft"):
                        port = int(port_obj.attrs["port"])
                        is_tcp = True
                        if 0 <= port <= 63353:
                            port_service = port_obj.find("name").text

                            current_port_id = db.select_host_port(current_host_id, port, is_tcp)
                            if current_port_id:
                                if port_service:
                                    db.update_port_proto_description(current_port_id[0]['id'], port_service, current_port_id[0]['description'])
                                current_port_id = current_port_id[0]['id']
                            else:
                                current_port_id = db.insert_host_port(current_host_id, port, is_tcp, port_service,
                                                                      form.ports_description.data, current_user['id'], current_project['id'])

                            port_issues = port_obj.vulners
                            if port_issues:
                                for issue_obj in port_issues.findAll("vulner"):
                                    issue_level = int(issue_obj.attrs["level"])
                                    issue_db_id = issue_obj.attrs["id"]
                                    if issue_level > 0:
                                        # TODO: add table integration from PoC

                                        issue_db_obj = vulns_db.find("vulner", {"id": issue_db_id})
                                        issue_name = issue_db_obj.title.text
                                        issue_short = issue_db_obj.short_description.text
                                        issue_description = issue_db_obj.description.text
                                        issue_fix = issue_db_obj.how_to_fix.text
                                        issue_links = issue_db_obj.links.text.strip('\n').replace('\n', '\n- ')
                                        cvss3 = float(issue_db_obj.cvss3.attrs["base_score"])
                                        cvss3_decomp = issue_db_obj.cvss3.attrs["base_score_decomp"].strip('()')

                                        if cvss3 == 0:
                                            cvss3 = float(issue_db_obj.cvss.attrs["base_score"])

                                        issue_cve = ''
                                        issue_pub_date = issue_db_obj.publication_date.text if issue_db_obj.publication_date else ''
                                        if issue_db_obj.global_id and "name" in issue_db_obj.global_id.attrs and issue_db_obj.global_id.attrs["name"] == "CVE":
                                            issue_cve = issue_db_obj.global_id.attrs["value"]

                                        # fstec fields
                                        issue_fstec = ''
                                        for fstec_obj in issue_db_obj.findAll("global_id", {"name": "fstec"}):
                                            issue_fstec += fstec_obj.attrs["value"] + ','
                                        issue_fstec = issue_fstec.strip(',')

                                        issue_description_full = issue_short
                                        issue_description_full += '\n\n' + issue_description
                                        if issue_links:
                                            issue_description_full += '\n\nLinks:\n' + issue_links
                                        if issue_pub_date:
                                            issue_description_full += '\n\nPublication date:\n' + issue_pub_date
                                        if issue_fstec:
                                            issue_description_full += '\n\nFSTEC:\n' + issue_fstec

                                        services = {current_port_id: ["0"]}

                                        issue_id = db.insert_new_issue_no_dublicate(issue_name, issue_description_full, '', cvss3, current_user['id'],
                                                                                    services, "need to recheck",
                                                                                    current_project['id'], issue_cve, fix=issue_fix)
                                        if cvss3_decomp:
                                            db.update_issue_field(issue_id, "cvss_vector", "text", cvss3_decomp)
    return render_template('project/tools/import/maxpatrol.html',
                           current_project=current_project,
                           tab_name='MaxPatrol',
                           errors=errors)
