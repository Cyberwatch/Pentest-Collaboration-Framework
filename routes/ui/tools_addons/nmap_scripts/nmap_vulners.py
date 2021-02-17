

class nmap_plugin():

    # user-defined
    script_id = 'vulners'
    script_source = 'service'
    script_types = ['issue'] #, 'port_info', 'credentials']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

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
        str_arr = self.output.replace(' ', '').split('\n')
        for s in str_arr:
            if s.lower().strip('\t').startswith('cve-'):
                cve = s.split('\t')[1]
                cvss = float(s.split('\t')[2])
                link = s.split('\t')[3]
                name = 'Vulners: {}'.format(cve)

                issue_obj = {
                    'cve': cve,
                    'cvss': cvss,
                    'description': link, # link
                    'name': name,
                    'fix': '',
                    'path': '',
                    'params': '',
                    'cwe': 0
                }
                issues_arr.append(issue_obj)

        return issues_arr