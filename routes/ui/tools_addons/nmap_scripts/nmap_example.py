class nmap_plugin():
    # user-defined
    script_id = 'example'
    script_source = 'service'  # or 'host' - <hostscript> in xml
    script_types = ['issue', 'port_info', 'server_info', 'credentials']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

    def port_info(self):
        # if script_source == 'service'
        # if script_types == 'port_info'
        """
        return
            {
                "protocol": "http",
                "info": "Nginx 1.12.0"
            }
        """
        info_object = {}
        if False:
            info_object = {
                'protocol': '',
                'info': ''
            }
        return info_object

    def issues(self):
        # if script_types == 'issue'
        """
        return
            [
                {
                    "cve":"1234-1234",                              # default ''
                    "cvss": 0.1,                                    # default 0.0
                    "description": "coool\nmultiline\ndescription", # default ''
                    "name": "CSRF",                                 # MUST NOT BE EMPTY!
                    "fix": "Add CSRF tokens",                       # default ''
                    "path": "/admin",                               # default ''
                    "params": "(GET) id=1",                         # default ''
                    "cwe": 123,                                     # default 0
                },
                ...
            ]
        """
        issues_arr = []
        if False:
            issue_obj = {
                'cve': cve,
                'cvss': cvss,
                'description': link,  # link
                'name': name,
                'fix': '',
                'path': '',
                'params': '',
                'cwe': 0
            }
            issues_arr.append(issue_obj)

        return issues_arr

    def credentials(self):
        # if script_types == 'credentials'
        """
        [
            {
                "login": "",   ##### if it is empty -> will become _BLANC automatically
                "cleartext": "",
                "hash": "",
                "description": "",
                "source": ""
            }
        ]
        """
        credentials_arr = []

        for cred in []:
            creds_obj = {
                "login": "anonymous",
                "cleartext": "anonymous",
                "hash": "",
                "description": "",
                "source": ""
            }
            credentials_arr.append(creds_obj)

        return credentials_arr

    def host_info(self):
        # if script_source == 'host'
        # if script_types == 'server_info'
        """
        return
            {
                "info": "Deploy server",
                "os": "Windows 7",
                "hostnames": [
                    "localhost",
                    "mail.google.com"
                ]
            }
        """
        info_object = {}
        if False:
            info_object = {
                "info": "Deploy server",
                "os": "Windows 7",
                "domains": [
                    "localhost"
                ]
            }
        return info_object
