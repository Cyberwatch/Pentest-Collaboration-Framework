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
        # TODO: if netbios name not recognised
        netbios_name = self.output.split('NetBIOS name: ')[1].split(',')[0]
        netbios_info = self.output.split(' Statistics')[0]

        info_object = {
            "info": netbios_info,
            "domains": [
                netbios_name
            ]
        }
        return info_object
