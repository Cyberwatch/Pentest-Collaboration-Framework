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
route_name = "pingcastle"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/0M2xrf3/pingcastle-big.png",
        "Official name": "PingCastle",
        "Short name": "pingcastle",
        "Description": "A tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.",
        "URL": "https://www.pingcastle.com/",
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

########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with settings.ini information
) -> str:  # returns error text or "" (if finished successfully)

    f = open('./routes/ui/tools_addons/import_plugins/pingcastle/PingCastleDescription.resx')
    s = f.read()
    f.close()
    issues_database = {}
    issues_database_xml = BeautifulSoup(s, 'html.parser')
    for issue_obj in issues_database_xml.findAll('data'):
        issues_database[issue_obj.attrs['name']] = issue_obj.findAll('value')[0].text

    # xml files
    for bin_file_data in input_dict['xml_files']:
        try:
            scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser")
            scan_obj = scan_result.healthcheckdata

            # add DCs
            domain_controllers = scan_obj.domaincontrollers
            dc_ports_dict = {}
            if domain_controllers:
                for domain_obj in domain_controllers.findAll('healthcheckdomaincontroller'):
                    host_description = ''
                    host_os = '' if not domain_obj.operatingsystem else domain_obj.operatingsystem.text
                    if domain_obj.dcname: host_description += 'DC name: {}\n'.format(domain_obj.dcname.text)
                    if domain_obj.lastcomputerlogondate: host_description += 'Last Logon: {}\n'.format(
                        domain_obj.lastcomputerlogondate.text)
                    if domain_obj.distinguishedname: host_description += 'Distinguished Name: {}\n'.format(
                        domain_obj.distinguishedname.text)
                    if domain_obj.ownersid: host_description += 'Owner SID: {}\n'.format(domain_obj.ownersid.text)
                    if domain_obj.ownername: host_description += 'Owner Name: {}\n'.format(
                        domain_obj.ownername.text)
                    if domain_obj.hasnullsession and domain_obj.hasnullsession == 'true': host_description += 'Has null session!\n'
                    if domain_obj.supportsmb1 and domain_obj.supportsmb1.text == 'true':
                        host_description += 'Supports SMB1!\n'
                        if domain_obj.smb1securitymode and domain_obj.smb1securitymode.text == 'NotTested':
                            host_description += 'SMB1SecurityMode: {}\n'.format(domain_obj.smb1securitymode.text)
                    if domain_obj.supportsmb2orsmb3 and domain_obj.supportsmb2orsmb3.text == 'true': host_description += 'Supports SMBv2 or SMBv3.\n'
                    if domain_obj.smb2securitymode: host_description += 'SMB2 security mode: {}\n'.format(
                        domain_obj.smb2securitymode.text)
                    if domain_obj.remotespoolerdetected and domain_obj.remotespoolerdetected.text == 'true': host_description += 'Detected remote spooler.\n'
                    if domain_obj.pwdlastset: host_description += 'Last pwd set: {}.\n'.format(
                        domain_obj.pwdlastset.text)
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
                                current_host_id = db.insert_host(current_project['id'], host_ip, current_user['id'],
                                                                 'Added from PingCastle', os=host_os)
                            # add 88 port
                            current_port = db.select_host_port(current_host_id, port_num=88, is_tcp=True)
                            if current_port:
                                current_port_id = current_port[0]['id']
                                if host_description:
                                    db.update_port_proto_description(current_port_id, 'kerberos', host_description)
                            else:
                                current_port_id = db.insert_host_port(current_host_id, 88, True, 'kerberos',
                                                                      host_description, current_user['id'],
                                                                      current_project['id'])
                            dc_ports_dict[current_port_id] = ['0']
                    except Exception as e:
                        pass

            # Issues - RiskRules
            risk_rules = scan_obj.riskrules
            for risk_obj in risk_rules.findAll('healthcheckriskrule'):
                issue_points = int(risk_obj.points.text)
                issue_category = risk_obj.category.text  # PrivilegedAccounts / Anomalies
                issue_model = risk_obj.model.text  # AccountTakeOver / GoldenTicket
                issue_riskid = risk_obj.riskid.text.replace('-', '_')  # A_AdminSDHolder / A-Krbtgt
                issue_briefly = risk_obj.rationale.text
                issue_links = issues_database[issue_riskid + '_Documentation'].replace(' ', '') \
                    if (issue_riskid + '_Documentation') in issues_database else ''
                issue_purpose = issues_database[issue_riskid + '_Description'] \
                    if (issue_riskid + '_Description') in issues_database else ''
                issue_fix = issues_database[issue_riskid + '_Solution'] \
                    if (issue_riskid + '_Solution') in issues_database else ''
                issue_technical_description = issues_database[issue_riskid + '_TechnicalExplanation'] \
                    if (issue_riskid + '_TechnicalExplanation') in issues_database else ''
                issue_name = 'PingCastle: {}'.format(
                    issues_database[issue_riskid + '_Title']
                    if (issue_riskid + '_Title') in issues_database else risk_obj.riskid.text
                )

                issue_full_description = 'Brief: {}\n\nTest purpose: {}\n\nPoints: {}\nCategory: {}\nModel:{}'.format(
                    issue_briefly,
                    issue_purpose,
                    issue_points,
                    issue_category,
                    issue_model
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
                                                            current_user['id'], dc_ports_dict, 'Need to recheck',
                                                            current_project['id'], fix=issue_fix,
                                                            technical=issue_technical_description,
                                                            references=issue_links)

        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing report"

    return ""
