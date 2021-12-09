class nmap_plugin():
    script_id = 'smb2-security-mode'
    script_source = 'host'
    script_types = ['issue']

    script_obj = None
    output = ''

    def __init__(self, script_object):
        self.script_obj = script_object
        self.output = script_object['output']

    def issues(self):
        if 'Message signing enabled but not required' in self.output:

            return [
                {
                    "cvss": 6,
                    "description": "SMBv2 message signing enabled but not required",
                    "name": "SMBv2 without required message signing",
                    "fix": "Add SMBv2 required message signing",
                    "path": "SMB service",
                },
            ]
        elif 'Message signing is disabled' in self.output:
            return [
                {
                    "cvss": 6,
                    "description": "SMBv2 disabled message signing",
                    "name": "SMBv2 without message signing",
                    "fix": "Enable SMBv2 message signing",
                    "path": "SMB service",
                },
            ]
        return []
