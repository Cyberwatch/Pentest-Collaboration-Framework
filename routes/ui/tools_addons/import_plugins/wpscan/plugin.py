######## Imports #########
import csv
import ipaddress
import json
import logging
import urllib
from io import StringIO
import socket

from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database
from system.security_functions import htmlspecialchars

######## Description #############
route_name = "wpscan"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/HgbG161/wpscan.png",
        "Official name": "WPScan",
        "Short name": "wpscan",
        "Description": "A free, for non-commercial use, black box WordPress security scanner written for security professionals and blog maintainers to test the security of their sites.",
        "URL": "https://github.com/wpscanteam/wpscan",
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

    host = StringField(
        'host',
        description='Host IP (only if scan was with DNS-name URL)',
        default='',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )
    auto_resolve = BooleanField(label='auto_resolve',
                                description="Automatic resolve ip from server (only if scan was with DNS-name URL)",
                                # short description
                                default=False,
                                validators=[],
                                _meta={"display_row": 2, "display_column": 2})


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with settings.ini information
) -> str:  # returns error text or "" (if finished successfully)

    host_field = input_dict['host']
    if host_field:
        try:
            ipaddress.ip_address(host_field)
        except Exception as e:
            return "Host IP field is wrong!"

    # json files
    for file_bin_content in input_dict['json_files']:
        file_content = file_bin_content.decode('charmap')
        try:
            file_dict = json.loads(file_content)

            # get protocol
            current_url = file_dict['target_url']
            current_url_obj = urllib.parse.urlparse(current_url)
            current_scheme = current_url_obj.scheme.lower()
            hostname = current_url_obj.hostname

            if 'target_ip' in file_dict:
                current_ip = file_dict['target_ip']
                # validate ip
                ipaddress.ip_address(current_ip)
            elif host_field:
                current_ip = host_field
            elif input_dict['auto_resolve']:
                current_ip = socket.gethostbyname(hostname)
            else:
                return "IP not found!"
            current_host = db.select_project_host_by_ip(current_project['id'], current_ip)
            if current_host:
                current_host_id = current_host[0]['id']
            else:
                current_host_id = db.insert_host(current_project['id'],
                                                 current_ip,
                                                 current_user['id'],
                                                 "Added from WPScan")
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
                    issue_cve = ",".join(current_issue["references"]["cve"]) if "cve" in current_issue[
                        "references"] else ""
                    urls = "\n".join([" - " + x for x in current_issue["references"]["url"]]) if "url" in \
                                                                                                 current_issue["references"] else ""
                    issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name,
                                                                                 urls,
                                                                                 ", ".join(current_issue[
                                                                                               "references"][
                                                                                               "wpvulndb"]))
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
                if "readme_url" in main_theme_obj and main_theme_obj["readme_url"]:
                    note_output += "<b>Readme URL:</b> " + main_theme_obj["readme_url"] + "</br>"
                if "style_uri" in main_theme_obj and main_theme_obj["style_uri"]:
                    note_output += "<b>Official URL:</b> " + main_theme_obj["style_uri"] + "</br>"
                if "version" in main_theme_obj and main_theme_obj["version"]:
                    note_output += "<b>Version:</b> " + main_theme_obj["version"]["number"] + "</br>"

                    note_output += "<b>Interesting entries:</b> <ol>"
                    for entry in main_theme_obj["version"]["interesting_entries"]:
                        note_output += "<li>" + htmlspecialchars(entry) + "</li>"
                    note_output += "</ol></br>"

                for current_issue in main_theme_obj["vulnerabilities"]:
                    issue_name = current_issue["title"]
                    issue_fix = "Upgrade main theme {} to version >= {}".format(main_theme_obj["slug"],
                                                                                current_issue["fixed_in"])
                    issue_cve = ''
                    if "cve" in current_issue["references"] and current_issue["references"]["cve"]:
                        issue_cve = ",".join(current_issue["references"]["cve"])
                    urls = "\n".join([" - " + x for x in current_issue["references"]["url"]]) if "url" in \
                                                                                                 current_issue[
                                                                                                     "references"] else ""
                    issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name,
                                                                                 urls,
                                                                                 ", ".join(current_issue[
                                                                                               "references"][
                                                                                               "wpvulndb"]))
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
                        issue_fix = "Upgrade plugin {} to version >= {}".format(plugin_name,
                                                                                current_issue["fixed_in"])
                        issue_cve = ",".join(current_issue["references"]["cve"]) if "cve" in current_issue[
                            "references"] else ""
                        urls = "\n".join([" - " + x for x in current_issue["references"]["url"]]) if "url" in \
                                                                                                     current_issue[
                                                                                                         "references"] else ""
                        issue_description = "{}\n\nURLs:\n{}\n\nwpvulndb: {}".format(issue_name, urls,
                                                                                     ", ".join(
                                                                                         current_issue["references"][
                                                                                             "wpvulndb"]))
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
        except Exception as e:
            logging.error(e)
            return 'One of files was corrupted!'

    return ""
