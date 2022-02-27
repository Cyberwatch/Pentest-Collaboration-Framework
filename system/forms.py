from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, \
    FieldList, DateField, validators, ValidationError, FloatField, FileField, \
    MultipleFileField, SelectMultipleField
from flask_wtf.file import FileRequired
from wtforms.validators import DataRequired, Email, Length, EqualTo, AnyOf, \
    IPAddress, HostnameValidation, UUID, NumberRange
import datetime
from uuid import UUID as check_uuid


class NonValidatingSelectMultipleField(SelectMultipleField):
    """
    Attempt to make an open ended select multiple field that can accept dynamic
    choices added by the browser.
    """

    def pre_validate(self, form):
        pass


def check_hostname(form, field, message='Wrong hostname!'):
    check = validators.HostnameValidation(allow_ip=False)
    if not check(field.data):
        raise ValidationError(message)


def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = check_uuid(uuid_to_test, version=version)
    except ValueError:
        return False

    return str(uuid_obj) == uuid_to_test


def host_port_validator(form, field, message='Wrong host-port id format!'):
    try:
        m = field.data.split(':')
        if len(m) != 2:
            raise ValueError
        if not is_valid_uuid(m[0]) or not is_valid_uuid(m[1]):
            raise ValueError
    except ValueError:
        raise ValidationError(message)


def ip_host_port_validator(form, field, message='Wrong host-port id format!'):
    if field.data == '0:0':
        return
    try:
        m = field.data.split(':')
        if len(m) != 2:
            raise ValueError
        if not is_valid_uuid(m[0]):
            raise ValueError
        if not is_valid_uuid(m[1]) and m[1] != '0':
            raise ValueError
    except ValueError:
        raise ValidationError(message)


class RegistrationForm(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(message='Email required!'),
                                    Email(message='Wrong email format!')])
    password1 = PasswordField('password1', [
        EqualTo('password2', message='Passwords must match!'),
        Length(min=8, message='Minimum password len=8!')
    ])
    password2 = StringField('password2',
                            validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(message='Email required!'),
                                    Email(message='Wrong email format!')])
    password = PasswordField('password',
                             [DataRequired(message='Password required!')])


class ChangeProfileInfo(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(message='Email required!'),
                                    Email(message='Wrong email format!')])
    fname = StringField('fname', validators=[], default='')
    lname = StringField('lname', validators=[], default='')
    company = StringField('company', validators=[], default='')
    password = PasswordField('password',
                             [Length(min=8, message='Minimum password len=8!')])


class ChangeProfilePassword(FlaskForm):
    oldpassword = PasswordField('oldpassword', [
        Length(min=8, message='Minimum password len=8!')])
    password1 = PasswordField('password1', [
        EqualTo('password2', message='Passwords must match!'),
        Length(min=8, message='Minimum password len=8!')
    ])
    password2 = StringField('password2', validators=[DataRequired()])


class CreateNewTeam(FlaskForm):
    name = StringField('name', validators=[DataRequired('Name required!')])
    description = StringField('description', validators=[], default='')


class EditTeamInfo(FlaskForm):
    name = StringField('name',
                       validators=[DataRequired(message='Name required!')])
    email = StringField('email',
                        validators=[DataRequired(message='Email required!'),
                                    Email(message='Wrong email format!')])
    description = StringField('description', validators=[], default='')
    action = StringField('action', validators=[AnyOf(['Save', 'Delete'], message='Wrong action!')], default='Save')


class AddUserToProject(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(message='Email required!'),
                                    Email(message='Wrong email format!')])
    role = StringField('email',
                       validators=[DataRequired(message='Role required!'),
                                   AnyOf(['tester', 'admin'],
                                         message='Wrong role!')])


class AddNewProject(FlaskForm):
    name = StringField('name',
                       validators=[DataRequired(message='Name required!')])
    description = StringField('description', default='')
    project_type = StringField('type', validators=[
        DataRequired(message='Type required!'),
        AnyOf(['pentest'])], default='pentest')
    scope = StringField('scope', default='')
    archive = IntegerField('archive', default=0)
    start_date = DateField('start_date', format='%d/%m/%Y',
                           default=datetime.date.today())
    end_date = DateField('end_date', format='%d/%m/%Y',
                         default=datetime.date(3000, 4, 13))
    teams = NonValidatingSelectMultipleField('teams')
    users = NonValidatingSelectMultipleField('users')


class NewHost(FlaskForm):
    ip = StringField('ip',
                     validators=[DataRequired(message='IP required!'),
                                 IPAddress(ipv4=True, ipv6=True,
                                           message='Wrong IPv4 or TPv6 format!')])

    description = StringField('description', default='')


class UpdateHostDescription(FlaskForm):
    comment = StringField('comment', default='')
    threats = FieldList(StringField('threats',
                                    validators=[AnyOf(['high',
                                                       'medium',
                                                       'low',
                                                       'check',
                                                       'info',
                                                       'checked',
                                                       'noscope',
                                                       "recheck",
                                                       "firewall",
                                                       "offline",
                                                       "inwork",
                                                       "scope",
                                                       "critical",
                                                       "slow"],
                                                      message='Wrong threat type!')]
                                    ), default=[]
                        )
    os = StringField('os', default='')
    os_input = StringField('os_input', default='')


class AddPort(FlaskForm):
    port = StringField('port', default='',
                       validators=[DataRequired(message='Insert port!')])
    service = StringField('other', default='')
    service_text = StringField('service_text', default='')
    description = StringField('description', default='')


class AddHostname(FlaskForm):
    hostname = StringField('hostname',
                           validators=[DataRequired(message='Domain required!'),
                                       check_hostname])
    comment = StringField('comment', default='')


class DeleteHostname(FlaskForm):
    hostname_id = StringField('hostname_id',
                              validators=[DataRequired(
                                  message='Hostname ID required!'),
                                  UUID(message='Wrong hostname-ID format!')])


class NewIssue(FlaskForm):
    name = StringField('name',
                       validators=[DataRequired(message='Name required!')])
    description = StringField('description', default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    url = StringField('url', default='')
    cve = StringField('cve', default='')
    cvss = FloatField('cvss', default=0.0, validators=[
        validators.NumberRange(min=0, max=10,
                               message="CVSS must be from 0.0 to 10.0!")])
    status = StringField('status', default='Need to check')
    criticality = FloatField('criticality', default=-1, validators=[
        validators.NumberRange(min=-1, max=10,
                               message="criticality must be from 0.0 to 10.0!")])
    fix = StringField('fix', default='')
    param = StringField('param', default='')
    issue_type = StringField('issue_type', default='custom',
                             validators=[AnyOf(
                                 ['custom', 'web', 'credentials', 'service'])])
    additional_field_name = NonValidatingSelectMultipleField(StringField('additional_field_name',
                                                                         validators=[]
                                                                         )
                                                             )
    additional_field_type = NonValidatingSelectMultipleField(StringField('additional_field_type',
                                                                         validators=[AnyOf(
                                                                             ['', 'text', 'number', 'float',
                                                                              'boolean'])]
                                                                         )
                                                             )
    additional_field_value = NonValidatingSelectMultipleField(StringField('additional_field_value',
                                                                          validators=[]
                                                                          )
                                                              )
    additional_field_filename = NonValidatingSelectMultipleField(StringField('additional_field_filename',
                                                                             validators=[]
                                                                             )
                                                                 )
    additional_field_file = MultipleFileField('additional_field_file', validators=[])


class EditIssueFields(FlaskForm):
    additional_field_name = NonValidatingSelectMultipleField(StringField('additional_field_name',
                                                                         validators=[]
                                                                         )
                                                             )
    additional_field_type = NonValidatingSelectMultipleField(StringField('additional_field_type',
                                                                         validators=[AnyOf(
                                                                             ['', 'text', 'number', 'float',
                                                                              'boolean'])]
                                                                         )
                                                             )
    additional_field_value = NonValidatingSelectMultipleField(StringField('additional_field_value',
                                                                          validators=[]
                                                                          )
                                                              )


class EditIssueFiles(FlaskForm):
    additional_field_name = NonValidatingSelectMultipleField(StringField('additional_field_filename',
                                                                         validators=[]
                                                                         )
                                                             )
    additional_field_file = MultipleFileField('additional_field_file', validators=[])

    additional_field_old_file = NonValidatingSelectMultipleField(StringField('additional_field_old_file',
                                                                             validators=[]
                                                                             )
                                                                 )


class UpdateIssue(FlaskForm):
    name = StringField('name',
                       validators=[DataRequired(message='Name required!')])
    description = StringField('description', default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    url = StringField('url', default='')
    cvss = FloatField('cvss', default=0.0, validators=[
        validators.NumberRange(min=0, max=10,
                               message="CVSS must be from 0.0 to 10.0!")])
    status = StringField('status', default='Need to check')
    cve = StringField('cve', default='')
    cwe = IntegerField('cwe', default=0)
    criticality = FloatField('criticality', default=-1, validators=[
        validators.NumberRange(min=-1, max=10,
                               message="criticality must be from 0.0 to 10.0!")])
    fix = StringField('fix', default='')
    param = StringField('param', default='')
    issue_type = StringField('issue_type', default='custom',
                             validators=[AnyOf(
                                 ['custom', 'web', 'credentials', 'service'])])


class NewPOC(FlaskForm):
    file = FileField('file',
                     validators=[FileRequired(message='File required!')])
    service = StringField('service', validators=[ip_host_port_validator],
                          default='')
    comment = StringField('comment', default='')


class EditIssueField(FlaskForm):
    additional_field_name = StringField('additional_field_name',
                                        validators=[]
                                        )
    additional_field_type = StringField('additional_field_type',
                                        validators=[AnyOf(
                                            ['', 'text', 'number', 'float',
                                             'boolean'])]
                                        )
    additional_field_value = StringField('additional_field_value',
                                         validators=[]
                                         )


class DeletePOC(FlaskForm):
    poc_id = StringField('poc_id',
                         validators=[DataRequired(message='POC id required!'),
                                     UUID(message='POC id invalid!')])


class SetPoCPriority(FlaskForm):
    poc_id = StringField('poc_id',
                         validators=[DataRequired(message='POC id required!'),
                                     UUID(message='POC id invalid!')])
    priority = IntegerField('priority',
                            validators=[DataRequired(message='Priority id required!'),
                                        AnyOf([0, 1])
                                        ],
                            default=1)


class NewNetwork(FlaskForm):
    ip = StringField('ip',
                     validators=[DataRequired(message='IP required!'),
                                 IPAddress(ipv4=True, ipv6=True,
                                           message='Wrong IPv4 or TPv6 format!')])
    mask = IntegerField('mask', default=0, validators=[
        validators.NumberRange(min=0, max=128, message="Mask must be 0..128!"),
        DataRequired(message='Mask required!')
    ])
    asn = IntegerField('asn', default=0, validators=[validators.Optional()])
    comment = StringField('comment', default='')
    name = StringField('name', default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    cmd = StringField('cmd', default='')
    internal_ip = StringField('internal_ip', default='')


class EditNetwork(FlaskForm):
    ip = StringField('ip',
                     validators=[DataRequired(message='IP required!'),
                                 IPAddress(ipv4=True, ipv6=True,
                                           message='Wrong IPv4 or TPv6 format!')])
    mask = IntegerField('mask', default=0, validators=[
        validators.NumberRange(min=0, max=128, message="Mask must be 0..128!"),
        DataRequired(message='Mask required!')
    ])
    asn = IntegerField('asn', default=0)
    comment = StringField('comment', default='')
    name = StringField('name', default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    cmd = StringField('cmd', default='')
    internal_ip = StringField('internal_ip', default='')
    action = StringField('action',
                         validators=[AnyOf(['Update', 'Delete'])],
                         default='Update')


class NewCredentials(FlaskForm):
    login = StringField('login',
                        validators=[],
                        default='')
    password_hash = StringField('password_hash',
                                validators=[],
                                default='')
    hash_type = StringField('hash_type',
                            validators=[],
                            default='')
    cleartext_password = StringField('cleartext_password',
                                     validators=[],
                                     default='')
    comment = StringField('comment',
                          validators=[],
                          default='')
    info_source = StringField('info_source',
                              validators=[],
                              default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    check_pwd = StringField('check_pwd',
                            validators=[AnyOf(['', 'top10k'])],
                            default='')


class MultipleAddCreds(FlaskForm):
    login = StringField('login',
                        validators=[],
                        default='')
    password_hash = StringField('password_hash',
                                validators=[],
                                default='')
    hash_type = StringField('hash_type',
                            validators=[],
                            default='')
    cleartext_password = StringField('cleartext_password',
                                     validators=[],
                                     default='')
    comment = StringField('comment',
                          validators=[],
                          default='')
    info_source = StringField('info_source',
                              validators=[],
                              default='')
    check_pwd = StringField('check_pwd',
                            validators=[AnyOf(['', 'top10k'])],
                            default='')
    login_num = IntegerField('login_num',
                             validators=[
                                 NumberRange(min=0, max=100, message="Login index must be in 1..100 (0 if ignore)!"), ],
                             default=0)
    hash_num = IntegerField('hash_num',
                            validators=[
                                NumberRange(min=0, max=100, message="Hash index must be in 1..100 (0 if ignore)!"), ],
                            default=0)
    cleartext_num = IntegerField('cleartext_num',
                                 validators=[
                                     NumberRange(min=0, max=100,
                                                 message="Cleartext password index must be in 1..100 (0 if ignore)!"), ],
                                 default=0)
    comment_num = IntegerField('comment_num',
                               validators=[
                                   NumberRange(min=0, max=100,
                                               message="Comment index must be in 1..100 (0 if ignore)!"), ],
                               default=0)
    source_num = IntegerField('source_num',
                              validators=[
                                  NumberRange(min=0, max=100,
                                              message="Info source must be in 1..100 (0 if ignore)!"), ],
                              default=0)
    delimiter = StringField('delimiter',
                            validators=[],
                            default=';')
    file = FileField('file',
                     validators=[])
    content = StringField('content',
                          validators=[],
                          default='')
    do_not_check_columns = IntegerField('do_not_check_columns',
                                        validators=[],
                                        default=0)
    do_not_check_dublicates = IntegerField('do_not_check_dublicates',
                                           validators=[],
                                           default=0)


class UpdateCredentials(FlaskForm):
    login = StringField('login',
                        validators=[],
                        default='')
    password_hash = StringField('password_hash',
                                validators=[],
                                default='')
    hash_type = StringField('hash_type',
                            validators=[],
                            default='')
    cleartext_password = StringField('cleartext_password',
                                     validators=[],
                                     default='')
    comment = StringField('comment',
                          validators=[],
                          default='')
    info_source = StringField('info_source',
                              validators=[],
                              default='')
    ip_port = FieldList(StringField('ip_port',
                                    validators=[UUID(message='Wrong port id!')]
                                    ), default=[]
                        )
    host_port = FieldList(StringField('host_port',
                                      validators=[
                                          host_port_validator]
                                      ), default=[]
                          )
    action = StringField('action',
                         validators=[],
                         default='')


class ExportCredsForm(FlaskForm):
    divider = StringField('divider',
                          validators=[],
                          default=':')
    export_type = StringField('export_type',
                              validators=[AnyOf(['passwords',
                                                 'user_pass',
                                                 'user_pass_variations',
                                                 'usernames'])],
                              default='')

    empty_passwords = IntegerField('empty_passwords',
                                   validators=[],
                                   default=0)

    login_as_password = IntegerField('login_as_password',
                                     validators=[],
                                     default=0)

    show_in_browser = IntegerField('show_in_browser',
                                   validators=[],
                                   default=0)

    password_wordlist = NonValidatingSelectMultipleField(StringField('password_wordlist',
                                                                     validators=[AnyOf(['top10k', 'top1000', 'top100'])]
                                                                     ), default=[]
                                                         )


class NewNote(FlaskForm):
    name = StringField('name',
                       validators=[
                           DataRequired(message='Note name required!')])
    host_id = StringField('host_id', default='')


class EditNote(FlaskForm):
    note_id = StringField('note_id',
                          validators=[UUID(message='Wrong note id!')])
    text = StringField('text', validators=[], default='')
    action = StringField('action',
                         validators=[AnyOf(['Update', 'Delete', 'Rename'])],
                         default='Update')


class NewFile(FlaskForm):
    file = FileField('file',
                     validators=[FileRequired(message='File required!')])
    services = NonValidatingSelectMultipleField(StringField('services',
                                                            validators=[
                                                                host_port_validator]
                                                            ), default=[]
                                                )
    description = StringField('description', default='')

    filetype = StringField('filetype',
                           validators=[AnyOf(['binary', 'text', 'image'])],
                           default='')


class EditFile(FlaskForm):
    action = StringField('action',
                         validators=[AnyOf(['delete'])],
                         default='delete')


class EditProjectSettings(FlaskForm):
    name = StringField('name',
                       validators=[DataRequired(message='Name required!')])
    description = StringField('description', default='')
    project_type = StringField('type', validators=[
        DataRequired(message='Type required!'),
        AnyOf(['pentest'])], default='pentest')
    scope = StringField('scope', default='')
    archive = IntegerField('archive', default=0)
    start_date = DateField('start_date', format='%d/%m/%Y',
                           default=datetime.date.today())
    end_date = DateField('end_date', format='%d/%m/%Y',
                         default=datetime.date(3000, 4, 13))
    teams = NonValidatingSelectMultipleField('teams')
    users = NonValidatingSelectMultipleField('users')
    action = StringField('action',
                         validators=[AnyOf(['Update', 'Archive', 'Activate', 'Delete'])],
                         default='Update')


class NmapForm(FlaskForm):
    files = MultipleFileField('files')
    add_no_open = IntegerField('add_no_open', default=0)
    rule = StringField('rule',
                       validators=[AnyOf(['open', 'filtered', 'closed'])],
                       default='open')
    ignore_ports = StringField('ignore_ports', default='')
    ignore_services = StringField('ignore_services', default='')
    hosts_description = StringField('hosts_description', default='Added from NMAP scan')
    hostnames_description = StringField('hostnames_description', default='Added from NMAP scan')


class NessusForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    add_info_issues = IntegerField('add_info_issues', default=0)
    hosts_description = StringField('hosts_description', default='Added from Nessus scan')
    hostnames_description = StringField('hostnames_description', default='Added from Nessus scan')
    ports_description = StringField('ports_description', default='Added from Nessus scan')


class QualysForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    add_empty_host = IntegerField('add_empty_host', default=0)
    hosts_description = StringField('hosts_description', default='Added from Qualys scan')
    ports_description = StringField('ports_description', default='Added from Qualys scan')


class DeleteHostIssue(FlaskForm):
    issue_id = StringField('issue_id',
                           validators=[UUID(message='Wrong issue id!')]
                           )


class MultipleDeleteHosts(FlaskForm):
    host = FieldList(
        StringField('host', validators=[UUID(message='Wrong host id!')]))


class MultipleDeleteIssues(FlaskForm):
    issue = FieldList(
        StringField('issue', validators=[UUID(message='Wrong issue id!')]))


class DeletePort(FlaskForm):
    port_id = StringField('port_id',
                          validators=[UUID(message='Wrong port id!')]
                          )


class NiktoForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    csv_files = MultipleFileField('csv_files')
    json_files = MultipleFileField('json_files')
    hosts_description = StringField('hosts_description', default='Added from Nikto scan')
    hostnames_description = StringField('hostnames_description', default='Added from Nikto scan')
    ports_description = StringField('ports_description', default='Added from Nikto scan')


class AcunetixForm(FlaskForm):
    files = MultipleFileField('files')
    auto_resolve = IntegerField('auto_resolve', default=0)
    host = StringField('host', default='')


class MultiplePortHosts(FlaskForm):
    port = StringField('port',
                       validators=[DataRequired(message='Port required!')])
    service = StringField('service', default='other')
    description = StringField('description', default='')
    host = FieldList(
        StringField('host', validators=[UUID(message='Wrong host id!')],
                    default=''))


class NewChat(FlaskForm):
    name = StringField('name',
                       validators=[
                           DataRequired(message='Chat name required!')])


class EditChat(FlaskForm):
    name = StringField('name',
                       validators=[
                           DataRequired(message='Chat name required!')])
    action = StringField('action', validators=[AnyOf(["rename", "delete"])])
    del_messages = IntegerField('del_messages', validators=[AnyOf([0, 1])], default=0)


class NewMessage(FlaskForm):
    message = StringField('host', validators=[
        DataRequired(message='Does not allow empty messages!')])


class ExportHosts(FlaskForm):
    network = StringField('network', default='')
    port = StringField('port', default='')
    ip_hostname = StringField('ip_hostname', default='')
    service = StringField('service', default='')
    issue_name = StringField('issue_name', default='')
    comment = StringField('comment', default='')
    threats = SelectMultipleField('threats', choices=[('high', 'high'),
                                                      ('medium', 'medium'),
                                                      ('low', 'low'),
                                                      ('info', 'info'),
                                                      ('check', 'check'),
                                                      ('checked', 'checked'),
                                                      ('noscope', 'noscope'),
                                                      ("recheck", "recheck"),
                                                      ("firewall", "firewall"),
                                                      ("offline", "offline"),
                                                      ("inwork", "inwork"),
                                                      ("scope", "scope"),
                                                      ("critical", "critical"),
                                                      ("slow", "slow")
                                                      ])
    separator = StringField('separator', default='[newline]')
    filename = StringField('filename', default='export')
    filetype = StringField('filetype',
                           validators=[AnyOf(['txt', 'xml', 'csv', 'json'])])
    hosts_export = StringField('hosts_export',
                               validators=[AnyOf(['ip&hostname',
                                                  'ip',
                                                  'hostname',
                                                  'ip&hostname_unique'])])
    add_ports = IntegerField('add_ports', default=0)
    open_in_browser = IntegerField('open_in_browser', default=0)
    prefix = StringField('prefix', default='')
    postfix = StringField('postfix', default='')


class NewHTTPSniffer(FlaskForm):
    name = StringField('name', validators=[
        DataRequired(message='Does not allow empty name!')])


class EditHTTPSniffer(FlaskForm):
    status = IntegerField('status', default=200, validators=[
        validators.NumberRange(min=100, max=526,
                               message="Status must be from 100 to 526!")])
    location = StringField('location', default='')
    body = StringField('body', default='')
    submit = StringField('submit', default='Update',
                         validators=[AnyOf(['Update', 'Clear'])])
    save_credentials = IntegerField('save_credentials', default=1, validators=[AnyOf([0, 1])])


class AddConfig(FlaskForm):
    config_name = StringField('config_name',
                              validators=[AnyOf(['shodan', 'zeneye'])])
    config_value = StringField('config_value',
                               validators=[
                                   DataRequired(message='Data required!')])
    action = StringField('action',
                         validators=[AnyOf(['Add', 'Delete'])])


class AddReportTemplate(FlaskForm):
    template_name = StringField('template_name',
                                validators=[
                                    DataRequired(message='Data required!')])
    file = FileField('file',
                     validators=[FileRequired(message='Template required!')])


class DeleteReportTemplate(FlaskForm):
    template_id = StringField('template_id',
                              validators=[UUID(message='Wrong template id!')],
                              default='')


class ReportGenerate(FlaskForm):
    template_id = StringField('template_id',
                              validators=[],
                              default='')
    file = FileField('file',
                     validators=[])
    extentions = StringField('extentions',
                             validators=[],
                             default='')


class IPWhoisForm(FlaskForm):
    ip = StringField('ip', default='')
    hosts = NonValidatingSelectMultipleField(StringField('hosts', validators=[IPAddress(ipv4=True, ipv6=False,
                                                                                        message='Wrong IPv4 format!')]))
    networks = NonValidatingSelectMultipleField(StringField('networks'))


class WhoisForm(FlaskForm):
    hostname = StringField('hostname', default='')
    hostnames = NonValidatingSelectMultipleField(StringField('hostnames'))
    host_id = StringField('host_id', default='')


class ShodanForm(FlaskForm):
    ip = StringField('ip', default='')
    hosts = StringField('hosts', default='')
    networks = StringField('networks', default='')
    api_key = StringField('api_key', default='')
    api_id = StringField('api_id', default='')
    need_network = IntegerField('need_networks', default=0)


class CheckmaxForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    csv_files = MultipleFileField('csv_files')


class Depcheck(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    # csv_files = MultipleFileField('csv_files')


class Openvas(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    # csv_files = MultipleFileField('csv_files')
    hosts_description = StringField('hosts_description', default='Added from OpenVAS scan')
    hostnames_description = StringField('hostnames_description', default='Added from OpenVAS scan')
    ports_description = StringField('ports_description', default='Added from OpenVAS scan')


class Netsparker(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    only_confirmed = IntegerField('only_confirmed', default=0)
    hosts_description = StringField('hosts_description', default='Added from NetSparker scan')
    hostnames_description = StringField('hostnames_description', default='Added from NetSparker scan')
    ports_description = StringField('ports_description', default='Added from NetSparker scan')
    # csv_files = MultipleFileField('csv_files')


class EditServiceForm(FlaskForm):
    port = StringField('port', validators=[DataRequired(message='Port number required!')])
    service = StringField('service', default='')
    description = StringField('description', default='')
    old_port = StringField('old_port', validators=[DataRequired(message='Old port number required!')])
    old_service = StringField('old_service', default='')
    old_description = StringField('old_description', default='')
    host = FieldList(
        StringField('host', validators=[UUID(message='Wrong host id!')],
                    default=''))


class DuplicatorForm(FlaskForm):
    destination_project = StringField('destination_project',
                                      validators=[DataRequired(
                                          message='Project ID required!'),
                                          UUID(message='Wrong project-ID format!')])
    copy_scope = IntegerField('copy_scope', default=0)
    copy_teams = IntegerField('copy_teams', default=0)
    copy_deadline = IntegerField('copy_deadline', default=0)
    copy_users = IntegerField('copy_users', default=0)
    copy_info = IntegerField('copy_info', default=0)
    hosts = NonValidatingSelectMultipleField(StringField('hosts',
                                                         validators=[UUID(message='Wrong host-ID format!')]
                                                         ), default=[]
                                             )
    issues = NonValidatingSelectMultipleField(StringField('issues',
                                                          validators=[UUID(message='Wrong issues-ID format!')]
                                                          ), default=[]
                                              )
    creds = NonValidatingSelectMultipleField(StringField('creds',
                                                         validators=[UUID(message='Wrong credentials-ID format!')]
                                                         ), default=[]
                                             )
    files = NonValidatingSelectMultipleField(StringField('files',
                                                         validators=[UUID(message='Wrong files-ID format!')]
                                                         ), default=[]
                                             )
    networks = NonValidatingSelectMultipleField(StringField('networks',
                                                            validators=[UUID(message='Wrong networks-ID format!')]
                                                            ), default=[]
                                                )
    note_hosts = NonValidatingSelectMultipleField(StringField('note_hosts',
                                                              validators=[UUID(message='Wrong note_host-ID format!')]
                                                              ), default=[]
                                                  )
    notes = NonValidatingSelectMultipleField(StringField('notes',
                                                         validators=[UUID(message='Wrong note-ID format!')]
                                                         ), default=[]
                                             )
    paths = NonValidatingSelectMultipleField(StringField('paths',
                                                         validators=[UUID(message='Wrong path-ID format!')]
                                                         ), default=[]
                                             )


class WPScanForm(FlaskForm):
    json_files = MultipleFileField('json_files')


class NewIssueTemplate(FlaskForm):
    name = StringField('name', default='')
    description = StringField('description', default='')
    url = StringField('url', default='')
    cve = StringField('cve', default='')
    cvss = FloatField('cvss', default=0.0, validators=[
        validators.NumberRange(min=0, max=10,
                               message="CVSS must be from 0.0 to 10.0!")])
    status = StringField('status', default='Need to check')
    criticality = FloatField('criticality', default=-1, validators=[
        validators.NumberRange(min=-1, max=10,
                               message="criticality must be from 0.0 to 10.0!")])
    fix = StringField('fix', default='')
    param = StringField('param', default='')
    issue_type = StringField('issue_type', default='custom',
                             validators=[AnyOf(
                                 ['custom', 'web', 'credentials', 'service'])])
    additional_field_name = NonValidatingSelectMultipleField(StringField('additional_field_name',
                                                                         validators=[]
                                                                         )
                                                             )
    additional_field_type = NonValidatingSelectMultipleField(StringField('additional_field_type',
                                                                         validators=[AnyOf(
                                                                             ['', 'text', 'number', 'float',
                                                                              'boolean'])]
                                                                         )
                                                             )
    additional_field_value = NonValidatingSelectMultipleField(StringField('additional_field_value',
                                                                          validators=[]
                                                                          )
                                                              )
    variable_name = NonValidatingSelectMultipleField(StringField('variable_name',
                                                                 validators=[]
                                                                 )
                                                     )
    variable_type = NonValidatingSelectMultipleField(StringField('variable_type',
                                                                 validators=[
                                                                     AnyOf(['', 'text', 'number', 'float', 'boolean'])]
                                                                 )
                                                     )
    variable_value = NonValidatingSelectMultipleField(StringField('variable_value',
                                                                  validators=[]
                                                                  )
                                                      )

    team_id = StringField('team_id', default='')

    template_name = StringField('template_name', default='')

    cwe = IntegerField('cwe', default=0)


class ExportIssueTemplates(FlaskForm):
    template_id = NonValidatingSelectMultipleField(StringField('template_id',
                                                               validators=[UUID(message='Invalid issue template uuid!')]
                                                               )
                                                   )


class DeleteIssueTemplates(FlaskForm):
    template_id = NonValidatingSelectMultipleField(StringField('template_id',
                                                               validators=[UUID(message='Invalid issue template uuid!')]
                                                               )
                                                   )


class ImportIssueTemplates(FlaskForm):
    team_id = StringField('team_id', default='')
    json_files = MultipleFileField('json_files')
    prefix = StringField('prefix', default='')


class EditIssueTemplate(FlaskForm):
    tpl_name = StringField('tpl_name', default='')
    name = StringField('name', default='')
    description = StringField('description', default='')
    url = StringField('url', default='')
    cve = StringField('cve', default='')
    cvss = FloatField('cvss', default=0.0, validators=[
        validators.NumberRange(min=0, max=10,
                               message="CVSS must be from 0.0 to 10.0!")])
    status = StringField('status', default='Need to check')
    criticality = FloatField('criticality', default=-1, validators=[
        validators.NumberRange(min=-1, max=10,
                               message="criticality must be from 0.0 to 10.0!")])
    fix = StringField('fix', default='')
    param = StringField('param', default='')
    issue_type = StringField('issue_type', default='custom',
                             validators=[AnyOf(
                                 ['custom', 'web', 'credentials', 'service'])])
    additional_field_name = NonValidatingSelectMultipleField(StringField('additional_field_name',
                                                                         validators=[]
                                                                         )
                                                             )
    additional_field_type = NonValidatingSelectMultipleField(StringField('additional_field_type',
                                                                         validators=[AnyOf(
                                                                             ['', 'text', 'number', 'float',
                                                                              'boolean'])]
                                                                         )
                                                             )
    additional_field_value = NonValidatingSelectMultipleField(StringField('additional_field_value',
                                                                          validators=[]
                                                                          )
                                                              )
    variable_name = NonValidatingSelectMultipleField(StringField('variable_name',
                                                                 validators=[]
                                                                 )
                                                     )
    variable_type = NonValidatingSelectMultipleField(StringField('variable_type',
                                                                 validators=[
                                                                     AnyOf(['', 'text', 'number', 'float', 'boolean'])]
                                                                 )
                                                     )
    variable_value = NonValidatingSelectMultipleField(StringField('variable_value',
                                                                  validators=[]
                                                                  )
                                                      )

    team_id = StringField('team_id', default='')

    cwe = IntegerField('cwe', default=0)

    action = StringField('action', validators=[AnyOf(['Delete', 'Update'])])


class NewIssueFromTemplate(FlaskForm):
    variable_name = NonValidatingSelectMultipleField(StringField('variable_name',
                                                                 validators=[]
                                                                 )
                                                     )
    variable_type = NonValidatingSelectMultipleField(StringField('variable_type',
                                                                 validators=[
                                                                     AnyOf(['', 'text', 'number', 'float', 'boolean'])]
                                                                 )
                                                     )
    variable_value = NonValidatingSelectMultipleField(StringField('variable_value',
                                                                  validators=[]
                                                                  )
                                                      )

class EditIssueFromTemplate(FlaskForm):
    variable_name = NonValidatingSelectMultipleField(StringField('variable_name',
                                                                 validators=[]
                                                                 )
                                                     )
    variable_type = NonValidatingSelectMultipleField(StringField('variable_type',
                                                                 validators=[
                                                                     AnyOf(['', 'text', 'number', 'float', 'boolean'])]
                                                                 )
                                                     )
    variable_value = NonValidatingSelectMultipleField(StringField('variable_value',
                                                                  validators=[]
                                                                  )
                                                      )


class NewTemplateFromIssue(FlaskForm):
    issue_id = StringField('issue_id',
                           validators=[UUID(message='Invalid issue template uuid!'), DataRequired()]
                           )


class KuberHunter(FlaskForm):
    json_files = MultipleFileField('json_files')
    hosts_description = StringField('hosts_description', default='Added from kube-hunter scan')
    ports_description = StringField('ports_description', default='Added from kube-hunter scan')


class BurpEnterpriseForm(FlaskForm):
    html_files = MultipleFileField('html_files')
    auto_resolve = IntegerField('auto_resolve', default=0)
    hostnames = NonValidatingSelectMultipleField(StringField('hostnames',
                                                             validators=[DataRequired(message='Hostname required'),
                                                                         check_hostname]
                                                             )
                                                 )
    ips = NonValidatingSelectMultipleField(StringField('ips',
                                                       validators=[DataRequired(message='IPs required'),
                                                                   IPAddress(ipv4=True, ipv6=True,
                                                                             message='Wrong IPv4 or TPv6 format!')
                                                                   ]
                                                       )
                                           )
    hosts_description = StringField('hosts_description', default='Added from BurpSuite scan')
    hostnames_description = StringField('hostnames_description', default='Added from BurpSuite scan')
    ports_description = StringField('ports_description', default='Added from BurpSuite scan')


class MultipleAddHosts(FlaskForm):
    host = StringField('host',
                       validators=[],
                       default='')
    hostname = StringField('hostname',
                           validators=[],
                           default='')
    description = StringField('description',
                              validators=[],
                              default='')
    os = StringField('os',
                     validators=[],
                     default='')

    host_num = IntegerField('host_num',
                            validators=[
                                NumberRange(min=0, max=100, message="Host index must be in 1..100 (0 if ignore)!"), ],
                            default=0)
    hostname_num = IntegerField('hostname_num',
                                validators=[
                                    NumberRange(min=0, max=100,
                                                message="Hostname index must be in 1..100 (0 if ignore)!"), ],
                                default=0)
    description_num = IntegerField('description_num',
                                   validators=[
                                       NumberRange(min=0, max=100,
                                                   message="Description index must be in 1..100 (0 if ignore)!"), ],
                                   default=0)
    os_num = IntegerField('os_num',
                          validators=[
                              NumberRange(min=0, max=100,
                                          message="OS index must be in 1..100 (0 if ignore)!"), ],
                          default=0)
    online_num = IntegerField('online_num',
                              validators=[
                                  NumberRange(min=0, max=100,
                                              message="Online status must be in 1..100 (0 if ignore)!"), ],
                              default=0)
    scope_num = IntegerField('scope_num',
                             validators=[
                                 NumberRange(min=0, max=100,
                                             message="Scope status must be in 1..100 (0 if ignore)!"), ],
                             default=0)

    threats = NonValidatingSelectMultipleField(
        StringField('threats',
                    validators=[
                        AnyOf(['high',
                               'medium',
                               'low',
                               'check',
                               'info',
                               'checked',
                               'noscope',
                               "recheck",
                               "firewall",
                               "offline",
                               "inwork",
                               "scope",
                               "critical",
                               "slow"],
                              message='Wrong threat type!')
                    ],
                    default='')
    )

    delimiter = StringField('delimiter',
                            validators=[],
                            default=';')
    file = FileField('file',
                     validators=[])
    content = StringField('content',
                          validators=[],
                          default='')
    do_not_check_columns = IntegerField('do_not_check_columns',
                                        validators=[],
                                        default=0)
    do_not_check_dublicates = IntegerField('do_not_check_dublicates',
                                           validators=[],
                                           default=0)


class DNSreconForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    csv_files = MultipleFileField('csv_files')
    json_files = MultipleFileField('json_files')
    hosts_description = StringField('hosts_description', default='Added from DNSrecon scan')
    ports_description = StringField('ports_description', default='Added from DNSrecon scan')
    ignore_ipv6 = IntegerField('ignore_ipv6', default=0)


class theHarvesterForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    hosts_description = StringField('hosts_description', default='Added from theHarvester scan')
    hostnames_description = StringField('hostnames_description', default='Added from theHarvester scan')


class MetasploitForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    ports_description = StringField('ports_description', default='Added from Metasploit scan')
    hostnames_description = StringField('hostnames_description', default='Added from Metasploit scan')
    add_nmap_scripts = IntegerField('add_nmap_scripts', default=0)
    only_nmap = IntegerField('only_nmap', default=0)


class NucleiForm(FlaskForm):
    json_files = MultipleFileField('json_files')
    auto_resolve = IntegerField('auto_resolve', default=0)
    hostnames = NonValidatingSelectMultipleField(StringField('hostnames',
                                                             validators=[DataRequired(message='Hostname required'),
                                                                         check_hostname]
                                                             )
                                                 )
    ips = NonValidatingSelectMultipleField(StringField('ips',
                                                       validators=[DataRequired(message='IPs required'),
                                                                   IPAddress(ipv4=True, ipv6=True,
                                                                             message='Wrong IPv4 or TPv6 format!')
                                                                   ]
                                                       )
                                           )
    hosts_description = StringField('hosts_description', default='Added from Nuclei scan')
    hostnames_description = StringField('hostnames_description', default='Added from Nuclei scan')
    ports_description = StringField('ports_description', default='Added from Nuclei scan')


class NewPath(FlaskForm):
    out_id = StringField('out_id',
                         validators=[UUID(message='Wrong UUID!'),
                                     DataRequired(message='Need out UUID!')])
    in_id = StringField('in_id',
                        validators=[UUID(message='Wrong UUID!'),
                                    DataRequired(message='Need in UUID!')])
    type_out = StringField('type_out',
                           validators=[AnyOf(['host', 'network'])])
    type_in = StringField('type_in',
                          validators=[AnyOf(['host', 'network'])])
    description = StringField('description', default='')
    type = StringField('type',
                       validators=[AnyOf(['connection', 'attack'])],
                       default='connection')
    direction = StringField('direction',
                            validators=[AnyOf(['forward', 'backward', 'two_side'])],
                            default='forward')


class DeletePath(FlaskForm):
    path_id = StringField('path_id',
                          validators=[UUID(message='Wrong UUID!')])


class PingCastleForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')


class MaxpatrolForm(FlaskForm):
    xml_files = MultipleFileField('xml_files')
    add_empty_host = IntegerField('add_empty_host', default=0)
    hosts_description = StringField('hosts_description', default='Added from MaxPatrol scan')
    ports_description = StringField('ports_description', default='Added from MaxPatrol scan')