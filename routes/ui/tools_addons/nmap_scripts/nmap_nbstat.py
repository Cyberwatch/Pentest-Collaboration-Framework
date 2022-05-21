class nmap_plugin():
    # user-defined
    script_id = 'nbstat'
    script_source = 'host'
    script_types = ['server_info']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

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
        if 'NetBios name:' in self.output:
            info_object["domains"] = [self.output.split('NetBIOS name: ')[1].split(',')[0]]

        if ' Statistics' in self.output:
            info_object["info"] = self.output.split(' Statistics')[0]

        return info_object
