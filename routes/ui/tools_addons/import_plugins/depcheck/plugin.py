######## Imports #########
import csv
import ipaddress
import logging
from io import StringIO

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "depcheck"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/NFhJ27D/depcheck.png",
        "Official name": "Dependency-Check",
        "Short name": "depcheck",
        "Description": "An open source solution the OWASP Top 10 2013 entry. Dependency-check can currently be used to scan Java and .NET applications to identify the use of known vulnerable components. Experimental analyzers for Python, Ruby, PHP (composer), and Node.js applications; these are experimental due to the possible false positive and false negative rates.",
        "URL": "https://jeremylong.github.io/DependencyCheck/index.html",
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
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # fields variables
    xml_files = input_dict["xml_files"]

    for bin_data in xml_files:
        try:
            if bin_data:
                scan_result = BeautifulSoup(bin_data.decode("charmap"), "html.parser")
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
                                                       '{}', 'Need to recheck', current_project['id'], cve, cwe,
                                                       'custom', '', filename)
        except Exception as e:
            logging.error("Exception during file import: {}".format(e))
            return "One of files was corrupted!"
    return ""
