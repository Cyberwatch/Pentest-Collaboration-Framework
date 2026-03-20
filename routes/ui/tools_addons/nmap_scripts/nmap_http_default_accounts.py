class nmap_plugin():
    script_id = 'http-default-accounts'
    script_source = 'service'
    script_types = ['credentials']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

    def credentials(self):
        credentials_arr = []

        for software_name in self.script_obj['elements']:
            # software_name == "Apache Tomcat"
            url_path = self.script_obj['elements'][software_name]['path']
            for cred_key in self.script_obj['elements'][software_name]['credentials']:
                username = self.script_obj['elements'][software_name]['credentials'][cred_key]['username']
                password = self.script_obj['elements'][software_name]['credentials'][cred_key]['password']
                creds_obj = {
                    "login": username,
                    "cleartext": password,
                    "hash": "",
                    "description": 'Credentials for {} url path'.format(url_path),
                    "source": 'Default credentials for "{}" software'.format(software_name)
                }
                credentials_arr.append(creds_obj)

        return credentials_arr
