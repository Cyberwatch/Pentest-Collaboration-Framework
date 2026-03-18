######## Imports #########
import ipaddress

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "theharvester"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/CQfVf1P/the-Harvester-logo.png",
        "Official name": "theHarvester",
        "Short name": "theharvester",
        "Description": "A very simple to use, yet powerful and effective tool designed to be used in the early stages of a penetration test or red team engagement. Use it for open source intelligence (OSINT) gathering to help determine a company's external threat landscape on the internet.",
        "URL": "https://github.com/laramies/theHarvester",
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

    hosts_description = StringField(
        'hosts_description',
        description='Hosts description',
        default='Added from theHarvester scan',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    hostnames_description = StringField(
        'hostnames_description',
        description='Hostnames description',
        default='Added from theHarvester scan',
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

    for bin_data in input_dict['xml_files']:
        try:
            soup = BeautifulSoup(bin_data.decode('charmap'), "html.parser")
            scan_result = soup.findAll('host')
            for hostname_row in scan_result:
                if hostname_row.find('ip') and hostname_row.find('hostname'):
                    ips_str = hostname_row.find('ip').text
                    hostname = hostname_row.find('hostname').text

                    # some theHarvester's hosts don't have IP (only hostname)
                    if ips_str == '':
                        continue

                    ip_array = ips_str.replace(' ', '').split(',')
                    for ip_address in ip_array:
                        # check valid ip
                        ipaddress.ip_address(ip_address)

                        current_host = db.select_project_host_by_ip(current_project['id'], ip_address)
                        if current_host:
                            host_id = current_host[0]['id']
                        else:
                            host_id = db.insert_host(current_project['id'], ip_address, current_user['id'],
                                                     input_dict['hosts_description'])

                        current_hostname = db.select_ip_hostname(host_id, hostname)
                        if not current_hostname:
                            hostname_id = db.insert_hostname(host_id,
                                                             hostname,
                                                             input_dict['hostnames_description'],
                                                             current_user['id'])
        except Exception as e:
            return 'One of files is corrupted!'
    return ''


