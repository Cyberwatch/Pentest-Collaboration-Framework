class nmap_plugin():
    # user-defined
    script_id = 'zone-transfer'
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
            'protocol': 'dns'
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
        if self.output:
            issues_arr = [
                {
                    "name": "DNS Zone Transfer",
                    "description": "Rezolved domains:\n\n" + self.output,
                    "cvss": 2.0,
                    "path": "DNS service",
                    "fix": "Create list of trusted DNS servers for zone transfer."
                }
            ]

        return issues_arr
