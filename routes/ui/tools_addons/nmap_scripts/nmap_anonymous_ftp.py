

class nmap_plugin():

    # user-defined
    script_id = 'Anonymous FTP'
    script_source = 'service'
    script_types = ['port_info', 'credentials', 'issue']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

    def port_info(self):
        """
        return
            {
                "protocol": "http",
                "info": "Nginx 1.12.0"
            }
        """
        info_object = {
            'protocol':'ftp'
        }
        return info_object

    def issues(self):
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
        if 'Anonymous login allowed' in self.output:
            issues_arr = [
                {
                    "name": "Anonymous access",
                    "description": "Anonymous access to ftp server anonymous/anonymous",
                    "fix": "Turn off anonymous account access",
                    "path": "FTP Server",
                }
            ]
        return issues_arr

    def credentials(self):
        """
        [
            {
                "login": "",
                "cleartext": "",
                "hash": "",
                "description": "",
                "source": ""
            }
        ]
        """
        credentials_arr = []

        if 'Anonymous login allowed' in self.output:
            credentials_arr = [
                {
                    "login": "anonymous",
                    "cleartext": "anonymous",
                    "hash": "",
                    "description": "FTP anonymous account",
                    "source": ""
                }
            ]

        return credentials_arr
