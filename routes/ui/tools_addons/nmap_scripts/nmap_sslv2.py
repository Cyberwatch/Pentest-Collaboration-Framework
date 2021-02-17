

class nmap_plugin():

    # user-defined
    script_id = 'SSLv2'
    script_source = 'service'
    script_types = ['port_info', 'issue']

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
            'protocol':'ssl',
            'info': 'SSL info:\n'+self.output
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
        if 'server still supports SSLv2' in self.output or \
            'SSLv2 supported' in self.output:
            issue_obj = {
                'cve': '',
                'cvss': 2.0,
                'description': 'Server supports SSLv2\n\nOutput nmap: \n'+ self.output,  # link
                'name': 'SSLv2 support',
                'fix': 'Disable SSLv2',
                'path': '',
                'params': '',
                'cwe': 0
            }
            issues_arr.append(issue_obj)

        return issues_arr