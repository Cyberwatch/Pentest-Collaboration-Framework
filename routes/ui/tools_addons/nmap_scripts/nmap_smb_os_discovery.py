class nmap_plugin():
    # user-defined
    script_id = 'smb-os-discovery'
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
        info_object = {}

        info_str = ''

        if 'os' in self.script_obj['elements'] and self.script_obj['elements']['os'] and \
                self.script_obj['elements']['os'] != 'nil':
            info_object['os'] = self.script_obj['elements']['os']

        if 'fqdn' in self.script_obj['elements'] and self.script_obj['elements']['fqdn'] and \
                self.script_obj['elements']['fqdn'] != 'nil':
            info_object['domains'] = [ self.script_obj['elements']['fqdn'] ]

        if 'lanmanager' in self.script_obj['elements'] and self.script_obj['elements']['lanmanager'] and \
                self.script_obj['elements']['lanmanager'] != 'nil':
            info_str += '\nLan manager: ' + self.script_obj['elements']['lanmanager']

        if 'domain' in self.script_obj['elements'] and self.script_obj['elements']['domain'] and \
                self.script_obj['elements']['domain'] != 'nil':
            info_str += '\nDomain: ' + self.script_obj['elements']['domain']

        if 'server' in self.script_obj['elements'] and self.script_obj['elements']['server'] and \
                self.script_obj['elements']['server'] != 'nil':
            info_str += '\nServer: ' + self.script_obj['elements']['server']

        if 'domain_dns' in self.script_obj['elements'] and self.script_obj['elements']['domain_dns'] and \
                self.script_obj['elements']['domain_dns'] != 'nil':
            info_str += '\nDomain DNS: ' + self.script_obj['elements']['domain_dns']

        if 'forest_dns' in self.script_obj['elements'] and self.script_obj['elements']['forest_dns'] and \
                self.script_obj['elements']['forest_dns'] != 'nil':
            info_str += '\nForest DNS: ' + self.script_obj['elements']['forest_dns']

        if 'workgroup' in self.script_obj['elements'] and self.script_obj['elements']['workgroup'] and \
                self.script_obj['elements']['workgroup'] != 'nil':
            info_str += '\nWorkgroup: ' + self.script_obj['elements']['workgroup']

        info_str = info_str.strip('\r\n\t ')

        info_object['info'] = info_str

        return info_object
