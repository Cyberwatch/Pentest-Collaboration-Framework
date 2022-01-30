from webargs import fields
from webargs import validate

token_create_args = {
    'email': fields.Email(required=True),
    'password': fields.Str(required=True),
    'name': fields.Str(required=False, missing=''),
    'duration': fields.Int(required=False,
                           missing=24 * 60 * 60,
                           validate=lambda p: p > 0)
    # validate=lambda p: (24 * 60 * 60 * 30) > p > 0)
}

only_token_args = {
    'access_token': fields.UUID(required=True)
}

project_logs_args = {
    'access_token': fields.UUID(required=True),
    'offset': fields.Int(required=False,
                         missing=0,
                         validate=lambda p: p >= 0),
    'limit': fields.Int(required=False,
                        missing=100,
                        validate=lambda p: p >= 0)
}

project_change_info_args = {
    'access_token': fields.UUID(required=True),
    'name': fields.String(required=False),
    'description': fields.String(required=False, ),
    'admin_email': fields.String(required=False)
}

project_add_user_args = {
    'access_token': fields.UUID(required=True),
    'email': fields.Email(required=True),
    'is_admin': fields.Boolean(required=False, missing=False)
}

project_user_action_args = {
    'access_token': fields.UUID(required=True),
    'user_id': fields.UUID(required=True)
}

project_update_args = {
    'access_token': fields.UUID(required=True),
    'name': fields.String(required=False, missing=None),
    'description': fields.String(required=False, missing=None),
    'type': fields.String(required=False, missing=None,
                          validate=validate.OneOf(["pentest"])),
    'scope': fields.String(required=False, missing=None),
    'start_date': fields.Integer(required=False, missing=None),
    'end_date': fields.Integer(required=False, missing=None),
    'auto_archive': fields.Boolean(required=False, missing=None),
    'status': fields.String(required=False, missing=None,
                            validate=validate.OneOf(["active", "archived"])),
    'testers': fields.List(fields.UUID(required=False), required=False,
                           missing=None),
    'teams': fields.List(fields.UUID(required=False), required=False,
                         missing=None)
}

new_project_args = {
    'access_token': fields.UUID(required=True),
    'name': fields.String(required=True),
    'description': fields.String(required=False, missing=''),
    'type': fields.String(required=True,
                          validate=validate.OneOf(["pentest"])),
    'scope': fields.String(required=False, missing=''),
    'start_date': fields.Integer(required=False, missing=None),
    'end_date': fields.Integer(required=False, missing=None),
    'auto_archive': fields.Boolean(required=False, missing=None),
    'testers': fields.List(fields.UUID(required=False), required=False,
                           missing=[]),
    'teams': fields.List(fields.UUID(required=False), required=False,
                         missing=[])
}

host_edit_args = {
    'access_token': fields.UUID(required=True),
    'description': fields.String(required=False, missing=None),
    'threats': fields.List(fields.String(required=False,
                                         validate=validate.OneOf(["high",
                                                                  "medium",
                                                                  "low",
                                                                  "info",
                                                                  "check",
                                                                  "checked",
                                                                  "noscope",
                                                                  "recheck",
                                                                  "firewall",
                                                                  "offline",
                                                                  "inwork",
                                                                  "scope",
                                                                  "critical",
                                                                  "slow"])),
                           required=False, missing=None)
}

port_edit_args = {
    'access_token': fields.UUID(required=True),
    'service': fields.String(required=False, missing=None),
    'description': fields.String(required=False, missing=None)
}

new_port_args = {
    'access_token': fields.UUID(required=True),
    'host_id': fields.UUID(required=True),
    'port': fields.Integer(required=True,
                           validate=lambda p: 25565 >= p > 0),
    'is_tcp': fields.Boolean(required=False,
                             missing=True),
    'service': fields.String(required=False,
                             missing=''),
    'description': fields.String(required=False,
                                 missing='')
}

new_host_args = {
    'access_token': fields.UUID(required=True),
    'ip': fields.IP(required=True),
    'description': fields.String(required=False, missing='')
}

network_edit_args = {
    'access_token': fields.UUID(required=True),
    'description': fields.String(required=False, missing=None),
    'ip': fields.IP(required=False, missing=None),
    'name': fields.String(required=False, missing=None),
    'mask': fields.Integer(required=False, missing=None, validate=validate.Range(min=0, max=128)),
    'asn': fields.Integer(required=False, missing=None),
    'internal_ip': fields.String(required=False, missing=None),
    'cmd': fields.String(required=False, missing=None),
    'access_from': fields.Dict(keys=fields.String(required=True),
                               values=fields.List(fields.String(required=False)),
                               required=False,
                               missing=None)
}

network_create_args = {
    'access_token': fields.UUID(required=True),
    'description': fields.String(required=False, missing=''),
    'name': fields.String(required=False, missing=''),
    'ip': fields.IP(required=True),
    'mask': fields.Integer(required=True, validate=validate.Range(min=0, max=128)),
    'asn': fields.Integer(required=False, missing=0),
    'internal_ip': fields.String(required=False, missing=''),
    'cmd': fields.String(required=False, missing=''),
    'access_from': fields.Dict(keys=fields.String(required=True),
                               values=fields.List(fields.String(required=False)),
                               required=False,
                               missing={})
}

issue_create_args = {
    'access_token': fields.UUID(required=True),
    "name": fields.String(required=True),
    "cvss": fields.Float(required=False, missing=0, validate=validate.Range(min=0, max=10)),
    "url_path": fields.String(required=False, missing=''),
    "description": fields.String(required=False, missing=''),
    "cve": fields.String(required=False, missing=''),
    "cwe": fields.Integer(required=False, missing=0),
    "status": fields.String(required=False, missing='need to recheck'),
    "fix": fields.String(required=False, missing=''),
    "type": fields.String(required=False, missing='custom'),
    "param": fields.String(required=False, missing=''),
    "services": fields.Dict(keys=fields.String(required=True),
                            values=fields.List(fields.String(required=False)),
                            required=False,
                            missing={}),
    "dublicate_find": fields.Boolean(required=False, missing=False)
}

issue_edit_args = {
    'access_token': fields.UUID(required=True),
    "name": fields.String(required=False, missing=None),
    "cvss": fields.Float(required=False, missing=None, validate=validate.Range(min=0, max=10)),
    "url_path": fields.String(required=False, missing=None),
    "description": fields.String(required=False, missing=None),
    "cve": fields.String(required=False, missing=None),
    "cwe": fields.Integer(required=False, missing=None),
    "status": fields.String(required=False, missing=None),
    "fix": fields.String(required=False, missing=None),
    "type": fields.String(required=False, missing=None),
    "param": fields.String(required=False, missing=None),
    "services": fields.Dict(keys=fields.String(required=True),
                            values=fields.List(fields.String(required=False)),
                            required=False,
                            missing=None)
}

new_hostname_args = {
    'access_token': fields.UUID(required=True),
    'description': fields.String(required=False,
                                 missing=''),
    'hostname': fields.String(required=True),
    'host_id': fields.UUID(required=True)
}

new_poc_args = {
    'access_token': fields.UUID(required=True),
    'description': fields.String(required=False,
                                 missing=''),
    'type': fields.String(required=True, validate=validate.OneOf(["image", "text"])),
    'b64content': fields.String(required=True),
    'port_id': fields.String(required=False, missing='0'),
    'hostname_id': fields.String(required=False, missing='0')
}
