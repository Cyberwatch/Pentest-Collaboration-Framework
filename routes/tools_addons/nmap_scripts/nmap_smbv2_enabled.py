class nmap_plugin():
    # user-defined
    script_id = 'smbv2-enabled'
    script_source = 'host'  # or 'host'
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
        if "Server supports SMBv2 protocol" in self.output:
            return {
                "Supports SMBv2!"
            }
        return {}
