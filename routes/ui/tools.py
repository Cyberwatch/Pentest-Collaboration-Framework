import glob
import importlib
import logging
import os
import sys

import wtforms

from routes.ui import routes
from app import check_session, db, redirect, render_template, request, \
    send_log_data, requires_authorization, csrf, config
import app
from .project import check_project_access, check_project_archived
from urllib.parse import urlparse
from system.forms import *
from libnmap.parser import NmapParser
import email_validator
import json
import codecs
import re
import io
from flask import Response, send_file, render_template_string
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
    # get list of plugins
    modules_path = path.join("routes", "ui", "tools_addons", "import_plugins")
    search_path = path.join(modules_path, "*")
    modules = [path.basename(d) for d in glob.glob(search_path) if os.path.isdir(d)]

    tools_list = []

    for module_name in modules:
        path_to_module = path.join(modules_path, module_name)
        path_to_python = path.join(path_to_module, "plugin.py")
        spec = importlib.util.spec_from_file_location("import_plugin", path_to_python)
        import_plugin = importlib.util.module_from_spec(spec)
        sys.modules["import_plugin"] = import_plugin
        spec.loader.exec_module(import_plugin)

        # tmp_vars
        route_name = import_plugin.route_name
        tools_description = import_plugin.tools_description

        for tool_info_obj in tools_description:
            tools_list.append({
                "name": tool_info_obj["Official name"],
                "description": tool_info_obj["Description"],
                "route": route_name
            })

    return render_template('project/tools/list.html',
                           current_project=current_project,
                           tools_list=tools_list,
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
            except Exception as e:
                logging.error("Wrong nmap XML file:", e)
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
                                                                                 issue[
                                                                                     'path'] if 'path' in issue else '',
                                                                                 issue[
                                                                                     'cvss'] if 'cvss' in issue else 0.0,
                                                                                 current_user['id'],
                                                                                 {port_id: ['0']},
                                                                                 'Need to recheck',
                                                                                 current_project['id'],
                                                                                 cve=issue[
                                                                                     'cve'] if 'cve' in issue else '',
                                                                                 cwe=issue[
                                                                                     'cwe'] if 'cwe' in issue else 0,
                                                                                 issue_type='service',
                                                                                 fix=issue[
                                                                                     'fix'] if 'fix' in issue else '',
                                                                                 param=issue[
                                                                                     'params'] if 'params' in issue else '')

                                        if 'credentials' in script_obj.script_types:
                                            credentials = script_obj.credentials()
                                            for cred in credentials:
                                                login = cred['login'] if 'login' in cred else '_BLANC'
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
                                                                         'Need to recheck',
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
            ports_unique_list = []
            for host in result_hosts:
                ports = db.select_host_ports(host['id'])
                hostnames = db.select_ip_hostnames(host['id'])
                for port in ports:
                    if (not form.port.data) or (
                            [port['port'], port['is_tcp']] in ports_array):
                        if form.service.data == '' or port['service'] in form.service.data.split(","):
                            if (not form.issue_name.data) or (
                                    port['id'] in port_ids):

                                if host_export == 'ip&hostname':
                                    ports_unique_list.append(port['port'])
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
                                    ports_unique_list.append(port['port'])
                                    result += '{}{}{}:{}{}'.format(separator,
                                                                   prefix,
                                                                   host['ip'],
                                                                   port['port'],
                                                                   postfix)

                                elif host_export == 'hostname':
                                    ports_unique_list.append(port['port'])
                                    for hostname in hostnames:
                                        result += '{}{}{}:{}{}'.format(separator,
                                                                       prefix,
                                                                       hostname['hostname'],
                                                                       port['port'],
                                                                       postfix)

                                elif host_export == 'ip&hostname_unique':
                                    ports_unique_list.append(port['port'])
                                    if hostnames:
                                        for hostname in hostnames:
                                            result += '{}{}{}:{}{}'.format(
                                                separator,
                                                prefix,
                                                hostname['hostname'],
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
                if form.add_ports.data and form.only_ports.data:
                    ports_unique_list = list(set(ports_unique_list))
                    ports_unique_list.sort()
                    result = separator.join(['{}{}{}'.format(prefix, x, postfix) for x in ports_unique_list])

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

    uri = '/broken/'
    if 'RAW_URI' in request.environ:
        uri = request.environ['RAW_URI']
    elif 'REQUEST_URI' in request.environ:
        uri = request.environ['REQUEST_URI']

    http_start_header = '''{} {} {}'''.format(request.method,
                                              uri,
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

                network = db.select_network_by_mask(current_project['id'],
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

                    network = db.select_network_by_mask(current_project['id'],
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

                    network = db.select_network_by_mask(current_project['id'],
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

                            network_id = db.select_network_by_mask(
                                current_project['id'], net_ip, net_mask,
                                ip_version == 6)

                            if not network_id:
                                network_id = db.insert_new_network(net_ip,
                                                                   net_mask,
                                                                   asn,
                                                                   full_network_description,
                                                                   current_project['id'],
                                                                   current_user['id'],
                                                                   ip_version == 6)
                            else:
                                # network_id = network_id[0]['id']
                                db.update_network(network_id[0]['id'], current_project['id'], net_ip, net_mask,
                                                  asn, full_network_description, ip_version == 6,
                                                  network_id[0]['internal_ip'],
                                                  network_id[0]['cmd'], json.loads(network_id[0]['access_from']),
                                                  network_id[0]['name'])

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
                            cvss = float(vulns[cve]['cvss']) if 'cvss' in vulns[cve] and vulns[cve]['cvss'] else 0
                            summary = str(vulns[cve]['summary']) if 'summary' in vulns[cve] else ''
                            services = {port_id: ["0"]}

                            issue_id = db.insert_new_issue_no_dublicate("Shodan: " + cve, summary, '', cvss,
                                                                        current_user['id'],
                                                                        services, 'need to check',
                                                                        current_project['id'], cve=cve)

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

                                network_id = db.select_network_by_mask(
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
                                    # network_id = network_id[0]['id']
                                    db.update_network(network_id[0]['id'], current_project['id'], net_ip, net_mask,
                                                      asn, full_network_description, ip_version == 6,
                                                      network_id[0]['internal_ip'],
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
                                cvss = float(vulns[cve]['cvss']) if 'cvss' in vulns[cve] and vulns[cve]['cvss'] else 0
                                summary = str(vulns[cve]['summary']) if 'summary' in vulns[cve] else ''
                                services = {port_id: ["0"]}
                                issue_id = db.insert_new_issue_no_dublicate("Shodan: " + cve, summary, '', cvss,
                                                                            current_user['id'],
                                                                            services, 'need to check',
                                                                            current_project['id'], cve=cve)
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

                                            network_id = db.select_network_by_mask(
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
                                                # network_id = network_id[0]['id']
                                                db.update_network(network_id[0]['id'],
                                                                  current_project['id'],
                                                                  net_ip,
                                                                  net_mask,
                                                                  asn,
                                                                  full_network_description,
                                                                  ip_version == 6, network_id[0]['internal_ip'],
                                                                  network_id[0]['cmd'],
                                                                  json.loads(network_id[0]['access_from']),
                                                                  network_id[0]['name'])

                                # create host
                                full_host_description = "Country: {}\nCity: {}\nOrganization: {}".format(
                                    country, city, organization)

                                host_id = db.select_project_host_by_ip(
                                    current_project['id'],
                                    ip)
                                if host_id:
                                    host_id = host_id[0]['id']
                                    db.update_host_description(host_id,
                                                               full_host_description)
                                    if os_info:
                                        db.update_host_os(host_id, os_info)
                                else:
                                    host_id = db.insert_host(
                                        current_project['id'],
                                        ip,
                                        current_user['id'],
                                        full_host_description, os=os_info)
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
                                        cvss = float(vulns[cve]['cvss']) if 'cvss' in vulns[cve] and vulns[cve][
                                            'cvss'] else 0
                                        summary = str(vulns[cve]['summary']) if 'summary' in vulns[cve] else ''
                                        services = {port_id: ["0"]}
                                        issue_id = db.insert_new_issue_no_dublicate("Shodan: " + cve, summary, '', cvss,
                                                                                    current_user['id'],
                                                                                    services, 'need to check',
                                                                                    current_project['id'], cve=cve)

                            except shodan.exception.APIError as e:
                                pass  # a lot of errors
                            except ValueError:
                                pass  # a lot of errors
                            time.sleep(1.1)  # shodan delay
    return render_template('project/tools/scanners/shodan.html',
                           current_project=current_project,
                           errors=errors,
                           tab_name='Shodan')


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
                result_str += 'Name servers: \n{}\n'.format(
                    '\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
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
                result_str += 'Name servers: \n{}\n'.format(
                    '\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
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
                    result_str += 'Name servers: \n{}\n'.format(
                        '\n'.join(['    ' + x.lower() for x in set(whois_obj['name_servers'])]))
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
        if not (destination_project['status'] and not (
                destination_project['auto_archive'] and destination_project['end_date'] < time.time())):
            errors.append("Destination project is in archive!")

    if not errors:
        if form.copy_info.data:
            destination_project['description'] = current_project['description']
        if form.copy_scope.data:
            destination_project['scope'] = current_project['scope']
        if form.copy_folder.data:
            destination_project['folder'] = current_project['folder']
        if form.copy_report_title.data:
            destination_project['report_title'] = current_project['report_title']
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
                                   json.loads(destination_project['teams']),
                                   destination_project['folder'],
                                   destination_project['report_title'])

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
                                                destination_ports_dict[destination_port['id']].append(
                                                    current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port[
                                                'host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(
                                                    destination_port['host_id'],
                                                    current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [
                                                            destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(
                                                            destination_hostname['id'])
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
                                destination_host = db.select_project_host_by_ip(destination_project['id'],
                                                                                current_host['ip'])
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
                                            current_hostname = db.select_project_hostname(current_project['id'],
                                                                                          current_poc['hostname_id'])
                                            if current_hostname:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(destination_host['id'],
                                                                                             current_hostname[
                                                                                                 'hostname'])
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
                                                destination_ports_dict[destination_port['id']].append(
                                                    current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port[
                                                'host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(
                                                    destination_port['host_id'],
                                                    current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [
                                                            destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(
                                                            destination_hostname['id'])
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
                                                destination_ports_dict[destination_port['id']].append(
                                                    current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port[
                                                'host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(
                                                    destination_port['host_id'],
                                                    current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [
                                                            destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(
                                                            destination_hostname['id'])
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
                                                destination_ports_dict[destination_port['id']].append(
                                                    current_hostname_id)
                                        else:
                                            current_hostname = db.select_hostname(current_hostname_id)
                                            if current_hostname and current_hostname[0]['host_id'] == current_port[
                                                'host_id']:
                                                current_hostname = current_hostname[0]
                                                destination_hostname = db.select_ip_hostname(
                                                    destination_port['host_id'],
                                                    current_hostname['hostname'])
                                                if destination_hostname:
                                                    # add hostname to issue
                                                    destination_hostname = destination_hostname[0]
                                                    if destination_port['id'] not in destination_ports_dict:
                                                        destination_ports_dict[destination_port['id']] = [
                                                            destination_hostname['id']]
                                                    else:
                                                        destination_ports_dict[destination_port['id']].append(
                                                            destination_hostname['id'])
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
                duplicate_network = db.select_network_by_mask(destination_project['id'],
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
                    network_out = db.select_network_by_mask(destination_project['id'],
                                                            source_network['ip'],
                                                            source_network['mask'],
                                                            source_network['is_ipv6'])[0]['id']
                if current_path['network_in']:
                    source_network = db.select_network(current_path['network_in'])[0]
                    network_in = db.select_network_by_mask(destination_project['id'],
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


@routes.route('/project/<uuid:project_id>/tools/burp_enterprise/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
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
                            # TODO: fix this
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


@routes.route('/project/<uuid:project_id>/tools/nuclei/', methods=['GET'])
@requires_authorization
@check_session
@check_project_access
@check_project_archived
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
    hostname_dict = {}
    for i in range(len(form.hostnames.data)):
        hostname_dict[form.hostnames.data[i]] = form.ips.data[i]

    auto_resolve = form.auto_resolve.data == 1

    # json files
    for file in form.json_files.data:
        if file.filename:
            bin_data = file.read().decode('charmap').strip(' \t\r\n')
            json_data = []
            if bin_data.startswith('['):
                json_data = json.loads(bin_data)
            else:
                json_data = json.loads('[{}]'.format(bin_data.replace('\r', '').replace('\n', ',')))
            for issue_obj in json_data:
                # important fields
                issue_name = issue_obj['info']['name']
                issue_tags = 'Tags: {}'.format(', '.join(issue_obj['info']['tags'])) if issue_obj['info'][
                    'tags'] else ""
                issue_description = issue_obj['info']['description'] if 'description' in issue_obj['info'] else ''
                issue_references = '\n'.join([' - {}'.format(x)
                                              for x in issue_obj['info']['reference']]) \
                    if 'reference' in issue_obj['info'] and issue_obj['info']['reference'] else ""
                issue_severity = "info"
                issue_matcher_name = 'Matched: {}'.format(
                    issue_obj['matcher-name']) if 'matcher-name' in issue_obj else ""
                issue_cvss = 0.0

                if "info" in issue_obj and "severity" in issue_obj["info"]:
                    issue_severity = str(issue_obj["info"]["severity"]).lower()

                if issue_severity in form.severity.data:

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
                    issue_protocol = issue_obj[
                        "protocol"] if "protocol" in issue_obj else ''  # i dont know key "protocol
                    issue_port = 0
                    issue_hostname = ''
                    issue_cve = issue_obj["cve"] if "cve" in issue_obj else ''
                    issue_cwe = issue_obj["cwe"] if "cwe" in issue_obj else 0

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
                            if "matched-at" in issue_obj:
                                if issue_obj["matched-at"].startswith(issue_host):
                                    issue_url = str(issue_obj["matched-at"][len(issue_host):])
                            if not issue_url:
                                issue_url = '/'

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
                        hostname_id = "0"
                        if issue_hostname:
                            current_hostname = db.select_ip_hostname(host_id, issue_hostname)
                            if current_hostname:
                                hostname_id = current_hostname[0]['id']
                            else:
                                hostname_id = db.insert_hostname(host_id, issue_hostname,
                                                                 form.hostnames_description.data,
                                                                 current_user['id'])

                        services = {port_id: [hostname_id]}

                    # create description
                    issue_full_description = issue_description + '\n'

                    poc_data = ''

                    if issue_matcher_name:
                        poc_data += '\n' + issue_matcher_name
                    if issue_tags:
                        poc_data += '\n' + issue_tags
                    if issue_type:
                        poc_data += '\n' + issue_type
                    if issue_curl_cmd:
                        poc_data += '\n' + issue_curl_cmd
                    if issue_other_fields:
                        poc_data += '\n' + issue_other_fields

                    # create issue

                    issue_full_description = issue_full_description.strip('\n\r\t ')
                    poc_data = poc_data.strip('\n\r\t ')

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
                                                                'web' if issue_protocol.startswith(
                                                                    'http') else 'custom',
                                                                fix='',
                                                                param='',
                                                                references=issue_references
                                                                )

                    if poc_data:
                        port_id = "0"
                        hostname_id = "0"
                        if services:
                            port_id = list(services)[0]
                            hostname_id = services[port_id][0]

                        if config['files']['poc_storage'] == "database":
                            poc_id = db.insert_new_poc(port_id, "Nuclei technical data",
                                                       "text", "poc.txt", issue_id,
                                                       current_user['id'], hostname_id, storage="database",
                                                       data=poc_data.encode("charmap", errors="ignore"))
                        elif config['files']['poc_storage'] == "filesystem":
                            poc_id = db.insert_new_poc(port_id, "Nuclei technical data",
                                                       "text", "poc.txt", issue_id,
                                                       current_user['id'], hostname_id,
                                                       storage="filesystem")
                            file_path = './static/files/poc/{}'.format(poc_id)
                            file_object = open(file_path, 'wb')
                            file_object.write(poc_data.encode("charmap", errors="ignore"))
                            file_object.close()

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


### Process each module

modules_path = path.join("routes", "ui", "tools_addons", "import_plugins")
search_path = path.join(modules_path, "*")
modules = [path.basename(d) for d in glob.glob(search_path) if os.path.isdir(d)]

for module_name in modules:
    path_to_module = path.join(modules_path, module_name)
    path_to_python = path.join(path_to_module, "plugin.py")
    spec = importlib.util.spec_from_file_location("import_plugin", path_to_python)
    import_plugin = importlib.util.module_from_spec(spec)
    sys.modules["import_plugin"] = import_plugin
    spec.loader.exec_module(import_plugin)

    # tmp_vars
    route_name = import_plugin.route_name
    route_endpoint = "/project/<uuid:project_id>/tools/{}/".format(route_name)
    tools_description = import_plugin.tools_description
    ToolArguments = import_plugin.ToolArguments
    process_request = import_plugin.process_request


    def render_page(current_project, current_user, import_plugin, path_to_module, errors=None):
        # plugin data
        route_name = import_plugin.route_name
        tools_description = import_plugin.tools_description
        ToolArguments = import_plugin.ToolArguments
        process_request = import_plugin.process_request
        tool_name_joined = '/'.join([x["Official name"] for x in tools_description])

        # get images
        for tool_description_object in tools_description:
            tool_description_object["image_content_type"] = "image/*"
            if "Icon file" in tool_description_object and tool_description_object["Icon file"]:
                image_data = open(path.join(path_to_module, tool_description_object["Icon file"]), 'rb').read()
                image_b64 = base64.b64encode(image_data).decode()
                tool_description_object["image_b64"] = image_b64
                extension = tool_description_object["Icon file"].split(".")[-1]
                if extension.lower() == 'svg':
                    tool_description_object["image_content_type"] = "image/svg+xml"
            else:
                tool_description_object["image_b64"] = ""

        # process input parameters
        input_param_names = [x for x in ToolArguments.__dict__ if not x.startswith("_")]
        max_column = max(
            [getattr(getattr(ToolArguments, x), 'kwargs')["_meta"]["display_column"] for x in input_param_names])
        max_row = max([getattr(getattr(ToolArguments, x), 'kwargs')["_meta"]["display_row"] for x in input_param_names])

        display_table = [["" for x in range(max_column)] for y in range(max_row)]

        css_classes = [None, "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]

        for input_name in input_param_names:
            input_obj = getattr(ToolArguments, input_name)
            field_class = getattr(input_obj, 'field_class')
            field_kwargs = getattr(input_obj, 'kwargs')
            input_meta = getattr(input_obj, 'kwargs')["_meta"]
            required_str = "required" if wtforms.validators.DataRequired in [x.__class__ for x in
                                                                             field_kwargs['validators']] else ""
            input_html = ""
            if field_class == wtforms.fields.simple.MultipleFileField:
                input_html = """
                            <label>{}:</label>
                            <input type="file" name="{}" placeholder="" multiple accept="{}">
                        """.format(field_kwargs["description"], input_name, input_meta["file_extensions"])
            elif field_class == wtforms.fields.simple.StringField:
                multiline_field = False if "multiline" not in input_meta else bool(input_meta["multiline"])
                default_str = field_kwargs['default'] if 'default' in field_kwargs else ''
                if not multiline_field:
                    input_html = """
                                <label>{}:</label>
                                <input type="text" name="{}" placeholder="{}" value="{}" {}>""".format(
                        field_kwargs["description"],
                        input_name,
                        default_str,
                        default_str,
                        required_str)
                else:
                    input_html = """
                                <label>{}:</label>
                                <textarea name="{}" placeholder="{}" style="min-width: 305px;" {}>{}</textarea>""".format(
                        field_kwargs["description"],
                        input_name,
                        default_str,
                        required_str,
                        default_str
                        .replace("&", "&amp;")
                        .replace('"', "&quot;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;"))
            elif field_class == wtforms.fields.IntegerField:
                input_html = """
                            <label>{}:</label>
                            <input type="number" name="{}" placeholder="{}" value="{}" {}>
                        """.format(field_kwargs["description"],
                                   input_name,
                                   field_kwargs['default'] if 'default' in field_kwargs else '',
                                   field_kwargs['default'] if 'default' in field_kwargs else '',
                                   required_str)
            elif field_class == wtforms.fields.BooleanField:
                input_html = """
                        <div class="ui checkbox" style="margin-top: 10px;">
                            <input type="checkbox" {} name="{}" value="1" {}>
                            <label>{}</label>
                        </div>""".format("checked" if 'default' in field_kwargs and field_kwargs['default'] else "",
                                         input_name, required_str,
                                         field_kwargs["description"])
            display_table[input_meta["display_row"] - 1][input_meta["display_column"] - 1] = input_html
        # template processing
        route_py_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_file = os.path.join(route_py_path, "ui", "tools_addons", "import_plugins", "import_form.html")
        template_data = open(template_file).read()  # sorry :)))
        if errors is None:
            return render_template_string(template_data,
                                          current_project=current_project,
                                          current_user=current_user,
                                          tools_description=tools_description,
                                          tool_name_joined=tool_name_joined,
                                          route_name=route_name,
                                          rows_name=css_classes[max_column],
                                          display_table=display_table
                                          )
        else:
            return render_template_string(template_data,
                                          current_project=current_project,
                                          current_user=current_user,
                                          tools_description=tools_description,
                                          tool_name_joined=tool_name_joined,
                                          route_name=route_name,
                                          rows_name=css_classes[max_column],
                                          display_table=display_table,
                                          errors=errors
                                          )


    def create_view_func(func, import_plugin, path_to_module):
        @requires_authorization
        @check_session
        @check_project_access
        @check_project_archived
        @send_log_data
        def view_func(project_id, current_project, current_user):
            function_result = func(project_id, current_project, current_user, import_plugin, path_to_module)
            return function_result

        return view_func


    def import_plugin_page(project_id, current_project, current_user, import_plugin, path_to_module):
        return render_page(current_project, current_user, import_plugin, path_to_module)


    def import_plugin_form(project_id, current_project, current_user, import_plugin, path_to_module):
        # plugin data
        ToolArguments = import_plugin.ToolArguments
        process_request = import_plugin.process_request
        route_name = import_plugin.route_name

        form = ToolArguments()
        form.validate()
        errors = []
        if form.errors:
            for field in form.errors:
                for error in form.errors[field]:
                    errors.append(error)

        if not errors:
            # process input parameters
            input_param_names = [x for x in ToolArguments.__dict__ if not x.startswith("_")]
            input_dict = {}
            for input_name in input_param_names:
                input_obj = getattr(form, input_name)
                class_name = input_obj.__class__
                if class_name in [wtforms.fields.simple.BooleanField,
                                  wtforms.fields.numeric.IntegerField,
                                  wtforms.fields.simple.StringField]:
                    input_dict[input_name] = input_obj.data
                elif class_name == wtforms.fields.simple.MultipleFileField:
                    input_dict[input_name] = []
                    for file_obj in input_obj.data:
                        if file_obj.filename:
                            file_data = file_obj.read()  # codecs.iterdecode(file, 'utf-8')
                            input_dict[input_name].append(file_data)
            try:
                error_str = process_request(current_user, current_project, db, input_dict, config)
            except OverflowError as e:
                error_str = "Unhandled python exception in plugin!"
                logging.error("Error with {} plugin: {}".format(import_plugin.route_name, e))
            if error_str:
                errors.append(error_str)
        return render_page(current_project, current_user, import_plugin, path_to_module, errors)


    routes.add_url_rule(rule=route_endpoint,
                        endpoint=route_name + "_get",
                        view_func=create_view_func(import_plugin_page, import_plugin, path_to_module),
                        methods=["GET"])
    routes.add_url_rule(rule=route_endpoint,
                        endpoint=route_name + "_post",
                        view_func=create_view_func(import_plugin_form, import_plugin, path_to_module),
                        methods=["POST"])
