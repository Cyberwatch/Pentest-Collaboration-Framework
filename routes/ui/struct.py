from app import session, render_template, redirect, request, \
    requires_authorization, cache
from flask import send_from_directory, jsonify, Response, send_file, make_response
import json
from os import stat, remove
import calendar
from urllib.parse import urlparse
import urllib.parse
from functools import wraps

import io

from system.crypto_functions import check_hash, gen_uuid

from system.forms import *

from routes.ui import routes

from app import check_session, check_team_access, db, send_log_data, \
    config

import base64


@cache.cached(timeout=120)
@routes.route('/static/files/code/<uuid:file_id>')
def getStaticCodeFile(file_id):
    current_file = db.select_files(str(file_id))[0]

    if current_file['storage'] == 'filesystem':
        return send_from_directory('static/files/code', str(file_id),
                                   as_attachment=True,
                                   attachment_filename=
                                   current_file['filename'])
    else:
        return send_file(
            io.BytesIO(base64.b64decode(current_file['base64'])),
            as_attachment=True,
            attachment_filename=current_file['filename']
        )


@cache.cached(timeout=120)
@routes.route('/static/files/poc/<uuid:poc_id>')
def getStaticPoCFile(poc_id):
    current_poc = db.select_poc(str(poc_id))[0]
    if current_poc['storage'] == 'filesystem':
        return send_from_directory('static/files/poc', str(poc_id),
                                   as_attachment=True,
                                   attachment_filename=
                                   current_poc['filename'])
    else:

        return send_file(
            io.BytesIO(base64.b64decode(current_poc['base64'])),
            as_attachment=True,
            attachment_filename=current_poc['filename']
        )


@cache.cached(timeout=120)
@routes.route('/static/files/templates/<uuid:template_id>')
def getStaticTemplateFile(template_id):
    current_template = db.select_report_templates(template_id=str(template_id))[0]

    if current_template['storage'] == 'filesystem':
        return send_from_directory('static/files/templates', str(template_id),
                                   as_attachment=True,
                                   attachment_filename=current_template['filename'])
    else:
        return send_file(
            io.BytesIO(base64.b64decode(current_template['base64'])),
            as_attachment=True,
            attachment_filename=current_template['filename']
        )


@cache.cached(timeout=120)
@routes.route('/static/<path:path>')
def getStaticFile(path):
    return send_from_directory('static', path, as_attachment=True)


def check_template_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        template_id = kwargs['template_id']
        current_user = kwargs['current_user']
        current_template = db.check_user_issue_template_access(str(template_id), current_user['id'], current_user['email'])
        if not current_template:
            return redirect('/projects/')
        kwargs['current_template'] = current_template[0]
        return fn(*args, **kwargs)

    return decorated_view


@routes.route('/')
@requires_authorization
@check_session
def index(current_user):
    if current_user:
        return redirect('/projects/')
    return render_template('index.html')


@routes.route('/robots.txt')
@requires_authorization
def robots_txt():
    f = open('configuration/robots.txt')
    s = f.read()
    f.close()
    response = make_response(s, 200)
    response.mimetype = "text/plain"
    return response


@routes.route('/login', methods=['GET'])
@requires_authorization
def login():
    if session.get('id'):
        return redirect('/projects/')
    return render_template('login.html',
                           tab_name='Login')


@routes.route('/login', methods=['POST'])
@requires_authorization
def login_form():
    form = LoginForm()
    error = None
    if config['security']['enable_form_login'] == '0':
        error = 'Authorization was disabled!'
    elif form.validate():
        try:
            data = db.select_user_by_email(form.email.data)[0]
        except IndexError:
            data = []
        if not data:
            error = 'Email does not exist!'
        else:
            if not check_hash(data['password'], form.password.data):
                error = 'Wrong password!'
            else:
                session.update(data)
        if not error:
            if request.args.get('redirect') is not None:
                return redirect(urlparse(request.args.get('redirect')).path)
            return redirect('/projects/')
    return render_template('login.html', form=form, error=error,
                           tab_name='Login')


@routes.route('/register', methods=['GET'])
@requires_authorization
def register():
    return render_template('register.html',
                           tab_name='Register')


@routes.route('/register', methods=['POST'])
@requires_authorization
def register_form():
    form = RegistrationForm()
    error = None
    if config['security']['enable_form_registration'] == '0':
        error = 'Registration was disabled!'
    elif form.validate():
        if len(db.select_user_by_email(form.email.data)) > 0:
            error = 'Email already exist!'
        else:
            db.insert_user(form.email.data, form.password1.data)
    return render_template('register.html', form=form, error=error,
                           tab_name='Register')


@routes.route('/profile', methods=['GET'])
@requires_authorization
@check_session
@send_log_data
def profile(current_user):
    return render_template('profile.html', user_data=current_user,
                           tab_name='Profile')


@routes.route('/profile', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def profile_form(current_user):
    form1 = ChangeProfileInfo()
    form2 = ChangeProfilePassword()
    add_config_form = AddConfig()
    add_report_form = AddReportTemplate()
    delete_report_form = DeleteReportTemplate()

    errors = []
    success_message = ''
    error_type = ''
    success_type = ''

    # editing profile data
    if 'change_profile' in request.form:
        form1.validate()
        if form1.errors:
            for field in form1.errors:
                errors += form1.errors[field]
            error_type = 'change_profile'
        if not errors:
            # check email
            find_user = db.select_user_by_email(form1.email.data)
            if find_user and find_user[0]['id'] != session['id']:
                errors.append('Email connected to another user!')
                error_type = 'change_profile'

        if not errors:
            if not check_hash(current_user['password'], form1.password.data):
                errors.append('Wrong password!')
                error_type = 'change_profile'
            else:
                db.update_user_info(session['id'],
                                    fname=form1.fname.data,
                                    lname=form1.lname.data,
                                    email=form1.email.data,
                                    company=form1.company.data)
                success_message = 'Profile information was updated!'
                success_type = 'change_profile'

    # editing profile password
    elif 'change_password' in request.form:
        form2.validate()
        if form2.errors:
            for field in form2.errors:
                errors += form2.errors[field]
            error_type = 'change_password'
        else:
            if form2.oldpassword.data == form2.password1.data:
                errors.append('New password is equal to old!')
                error_type = 'change_password'
            else:
                if not check_hash(current_user['password'],
                                  form2.oldpassword.data):
                    errors.append('Wrong password!')
                    error_type = 'change_password'
                else:
                    db.update_user_password(current_user['id'],
                                            form2.password1.data)
                    success_message = 'Password was updated!'
                    success_type = 'change_password'
    elif 'add_config' in request.form:
        add_config_form.validate()
        if add_config_form.errors:
            for field in add_config_form.errors:
                errors += add_config_form.errors[field]
            error_type = 'add_config'
        else:
            if add_config_form.action.data == 'Add':
                display_name = ''
                config_name = add_config_form.config_name.data
                visible = 0
                if config_name == 'shodan':
                    display_name = 'Shodan API key'
                    visible = 0

                if config_name == 'zeneye':
                    display_name = 'Zeneye API key'
                    visible = 0

                # check if exist
                same_config = db.select_configs(user_id=current_user['id'],
                                                name=config_name)
                if same_config:
                    db.update_config(user_id=current_user['id'],
                                     name=config_name,
                                     value=add_config_form.config_value.data)
                else:
                    config_id = db.insert_config(user_id=current_user['id'],
                                                 name=config_name,
                                                 display_name=display_name,
                                                 data=add_config_form.config_value.data,
                                                 visible=0)
            elif add_config_form.action.data == 'Delete':
                db.delete_config(user_id=current_user['id'],
                                 name=add_config_form.config_name.data)
    elif 'add_template' in request.form:
        add_report_form.validate()
        errors = []
        if add_report_form.errors:
            for field in add_report_form.errors:
                errors += add_report_form.errors[field]
            error_type = 'add_template'
        else:
            template_id = gen_uuid()
            file = request.files.get('file')
            tmp_file_path = './static/files/templates/{}'.format(template_id)
            file.save(tmp_file_path)
            file.close()
            file_size = stat(tmp_file_path).st_size
            if file_size > int(config['files']['template_max_size']):
                errors.append("File too large!")
                remove(tmp_file_path)
                error_type = 'add_template'
            else:
                file_data = b''
                if config['files']['template_storage'] == 'database':
                    f = open(tmp_file_path, 'rb')
                    file_data = f.read()
                    f.close()
                    remove(tmp_file_path)

                template_id = db.insert_template(user_id=current_user['id'],
                                                 name=add_report_form.template_name.data,
                                                 template_id=template_id,
                                                 filename=file.filename,
                                                 storage=config['files']['template_storage'],
                                                 data=file_data
                                                 )
    elif 'delete_template' in request.form:
        delete_report_form.validate()
        errors = []
        if delete_report_form.errors:
            for field in delete_report_form.errors:
                errors += delete_report_form.errors[field]
            error_type = 'delete_template'
        else:
            template_id = delete_report_form.template_id.data
            current_template = db.select_report_templates(template_id=template_id,
                                                          user_id=current_user['id'])
            if not current_template:
                errors.append('Template not found!')
                error_type = 'delete_template'
            else:
                current_template = current_template[0]
                db.delete_template_safe(template_id=current_template['id'],
                                        user_id=current_user['id'])

    current_user = db.select_user_by_id(session['id'])[0]
    return render_template('profile.html', user_data=current_user,
                           success_message=success_message, errors=errors,
                           tab_name='Profile', error_type=error_type,
                           success_type=success_type)


@routes.route('/logout')
@requires_authorization
def logout():
    try:
        del session['id']
    except:
        pass
    if 'redirect' in request.args and request.args.get('redirect'):
        return redirect('/login?redirect={}'.format(
            urllib.parse.quote(request.args.get('redirect'))))
    return redirect('/login')


@routes.route('/create_team', methods=['GET'])
@requires_authorization
@check_session
@send_log_data
def create_team(current_user):
    return render_template('new_team.html',
                           tab_name='Create team')


@routes.route('/create_team', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def create_team_form(current_user):
    form = CreateNewTeam()
    form.validate()
    errors = []
    success_message = ''

    if form.errors:
        for field in form.errors:
            errors += form.errors[field]
    else:
        team_id = db.insert_team(form.name.data, form.description.data, session['id'])
        success_message = 'New team was created!'
        return redirect('/team/{}/'.format(team_id))
    return render_template('new_team.html',
                           tab_name='Create team', errors=errors, success_message=success_message)


@routes.route('/team/<uuid:team_id>/', methods=['GET'])
@requires_authorization
@check_session
@check_team_access
@send_log_data
def team_page(team_id, current_team, current_user):
    edit_error = request.args.get('edit_error', default='', type=str)

    return render_template('team.html', current_team=current_team,
                           edit_error=edit_error,
                           tab_name=current_team['name'] if current_team['name'] else 'Team info')


@routes.route('/team/<uuid:team_id>/logs', methods=['GET'])
@requires_authorization
@check_session
@check_team_access
@send_log_data
def team_logs(team_id, current_team, current_user):
    return render_template('team_logs.html', current_team=current_team,
                           tab_name=current_team['name'] + ' logs' if current_team['name'] else 'Team logs'), \
           200, \
           {'Content-Type': 'text/plain; charset=utf-8'}


@routes.route('/team/<uuid:team_id>/', methods=['POST'])
@requires_authorization
@check_session
@check_team_access
@send_log_data
def team_page_form(team_id, current_team, current_user):
    current_team_users = json.loads(current_team['users'])

    if current_team_users[current_user['id']] != 'admin':
        return render_template('team.html', current_team=current_team,
                               tab_name=current_team['name'] if current_team['name'] else 'Team info')

    # forms list

    team_info_form = EditTeamInfo()
    team_info_form.validate()
    team_user_add_form = AddUserToProject()
    team_user_add_form.validate()
    add_config_form = AddConfig()
    add_config_form.validate()
    add_report_form = AddReportTemplate()
    add_report_form.validate()
    delete_report_form = DeleteReportTemplate()
    delete_report_form.validate()

    errors = []
    # team info edit
    if 'change_info' in request.form:
        if team_info_form.errors:
            for field in team_info_form.errors:
                errors += team_info_form.errors[field]
            current_team = db.select_team_by_id(str(team_id))[0]
            return render_template('team.html', current_team=current_team,
                                   team_info_errors=errors,
                                   tab_name=current_team['name'] if current_team['name'] else 'Team info')
        if team_info_form.action.data == 'Save':
            db.update_team_info(str(team_id),
                                team_info_form.name.data,
                                team_info_form.email.data,
                                team_info_form.description.data, current_user['id'])
            current_team = db.select_team_by_id(str(team_id))[0]
            return render_template('team.html', current_team=current_team,
                                   tab_name=current_team['name'] if current_team['name'] else 'Team info',
                                   team_info_errors=[])
        elif team_info_form.action.data == 'Delete':
            db.delete_team_safe(current_team['id'])
            return redirect('/create_team')

    # team tester add
    elif 'add_user' in request.form:
        errors = []
        if team_user_add_form.errors:
            for field in team_user_add_form.errors:
                errors += team_user_add_form.errors[field]

        else:
            user_to_add = db.select_user_by_email(team_user_add_form.email.data)
            if not user_to_add:
                errors = ['User does not found!']
            elif user_to_add[0]['id'] in current_team_users:
                errors = ['User already added to {} group!'.format(
                    current_team_users[user_to_add[0]['id']])]
            else:
                db.update_new_team_user(current_team['id'],
                                        team_user_add_form.email.data,
                                        team_user_add_form.role.data)

        current_team = db.select_team_by_id(str(team_id))[0]
        if team_user_add_form.role.data == 'tester':
            return render_template('team.html', current_team=current_team,
                                   add_tester_errors=errors,
                                   tab_name=current_team['name'] if current_team['name'] else 'Team info')
        else:
            return render_template('team.html', current_team=current_team,
                                   add_admin_errors=errors,
                                   tab_name=current_team['name'] if current_team['name'] else 'Team info')

    elif 'add_config' in request.form:
        errors = []
        if add_config_form.errors:
            for field in add_config_form.errors:
                errors += add_config_form.errors[field]
        else:
            if add_config_form.action.data == 'Add':
                display_name = ''
                config_name = add_config_form.config_name.data
                visible = 0
                if config_name == 'shodan':
                    display_name = 'Shodan API key'
                    visible = 0

                if config_name == 'zeneye':
                    display_name = 'Zeneye API key'
                    visible = 0

                # check if exist
                same_config = db.select_configs(team_id=current_team['id'],
                                                name=config_name)
                if same_config:
                    db.update_config(team_id=current_team['id'],
                                     name=config_name,
                                     value=add_config_form.config_value.data)
                else:
                    config_id = db.insert_config(user_id='0',
                                                 team_id=current_team['id'],
                                                 name=config_name,
                                                 display_name=display_name,
                                                 data=add_config_form.config_value.data,
                                                 visible=0)
            elif add_config_form.action.data == 'Delete':
                db.delete_config(team_id=current_team['id'],
                                 user_id='0',
                                 name=add_config_form.config_name.data)
        return render_template('team.html', current_team=current_team,
                               add_config_errors=errors,
                               tab_name=current_team['name'] if current_team['name'] else 'Team info')
    elif 'add_template' in request.form:
        errors = []
        if add_report_form.errors:
            for field in add_report_form.errors:
                errors += add_report_form.errors[field]
        else:
            template_id = gen_uuid()
            file = request.files.get('file')
            tmp_file_path = './static/files/templates/{}'.format(template_id)
            file.save(tmp_file_path)
            file.close()
            file_size = stat(tmp_file_path).st_size
            if file_size > int(config['files']['template_max_size']):
                errors.append("File too large!")
                remove(tmp_file_path)
            else:

                file_data = b''
                if config['files']['template_storage'] == 'database':
                    f = open(tmp_file_path, 'rb')
                    file_data = f.read()
                    f.close()
                    remove(tmp_file_path)

                template_id = db.insert_template(team_id=current_team['id'],
                                                 name=add_report_form.template_name.data,
                                                 template_id=template_id,
                                                 filename=file.filename,
                                                 storage=config['files']['template_storage'],
                                                 data=file_data
                                                 )
        return render_template('team.html', current_team=current_team,
                               add_report_errors=errors,
                               tab_name=current_team['name'] if current_team['name'] else 'Team info')
    elif 'delete_template' in request.form:
        errors = []
        if delete_report_form.errors:
            for field in delete_report_form.errors:
                errors += delete_report_form.errors[field]
        else:
            template_id = delete_report_form.template_id.data
            current_template = db.select_report_templates(template_id=template_id, team_id=current_team['id'])
            if not current_template:
                errors.append('Template not found!')
            else:
                current_template = current_template[0]
                db.delete_template_safe(template_id=current_template['id'],
                                        team_id=current_team['id'])
        return render_template('team.html', current_team=current_team,
                               add_report_errors=errors,
                               tab_name=current_team['name'] if current_team['name'] else 'Team info')


@routes.route('/new_project', methods=['GET'])
@requires_authorization
@check_session
@send_log_data
def new_project(current_user):
    team_id = request.args.get('team_id', default='', type=str)
    if team_id != '':
        # team access check
        user_teams = db.select_user_teams(session['id'])
        current_team = {}
        for found_team in user_teams:
            if found_team['id'] == str(team_id):
                current_team = found_team
        if current_team == {}:
            return redirect('/projects/new_project')

    return render_template('new_project.html', team_id=team_id,
                           tab_name='New project')


@routes.route('/new_project', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def new_project_form(current_user):
    # team access check
    form = AddNewProject()
    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)
        return render_template('new_project.html', errors=errors,
                               tab_name='New project')

    # check teams access
    if not errors:
        for team_id in form.teams.data:
            current_team = db.select_team_by_id(team_id)
            if not current_team:
                errors.append('Team {} does not exist!'.format(team_id))
            elif session['id'] not in current_team[0]['users']:
                errors.append(
                    'User does not have access to team {}!'.format(team_id))

    # check user relationship

    form_users = [user for user in form.users.data if user]
    teams_array = db.select_user_teams(session['id'])
    if not errors:
        for user_id in form_users:
            found = 0
            for team in teams_array:
                if user_id in team['users']:
                    found = 1
            if not found or not db.select_user_by_id(user_id):
                errors.append('User {} not found!'.format(user_id))

    if errors:
        return render_template('new_project.html', errors=errors,
                               tab_name='New project')

    # creating project
    start_time = calendar.timegm(form.start_date.data.timetuple())
    end_time = calendar.timegm(form.end_date.data.timetuple())

    if current_user['id'] not in form_users:
        form_users.append(current_user['id'])

    project_id = db.insert_new_project(form.name.data,
                                       form.description.data,
                                       form.project_type.data,
                                       form.scope.data,
                                       start_time,
                                       end_time,
                                       form.archive.data,
                                       form_users,
                                       form.teams.data,
                                       session['id'],
                                       current_user['id'])

    return redirect('/project/{}/'.format(project_id))


@routes.route('/team/<uuid:team_id>/user/<uuid:user_id>/<action>',
              methods=['POST'])
@requires_authorization
@check_session
@check_team_access
@send_log_data
def team_user_edit(team_id, user_id, action, current_team, current_user):
    # check if user admin
    if not db.check_admin_team(str(team_id), session['id']):
        return redirect('/create_team')

    error = ''

    if action == 'kick':
        error = db.delete_user_from_team(str(team_id), str(user_id),
                                         current_user['id'])

    if action == 'devote':
        error = db.devote_user_from_team(str(team_id), str(user_id),
                                         current_user['id'])

    if action == 'set_admin':
        error = db.set_admin_team_user(str(team_id), str(user_id),
                                       current_user['id'])

    return redirect('/team/{}/?edit_error={}#/users'.format(str(team_id), error))


@routes.route('/profile/<uuid:user_id>/', methods=['GET'])
@requires_authorization
@check_session
def user_profile(user_id, current_user):
    # TODO: fix
    user_data = db.select_user_by_id(str(user_id))
    if not user_data:
        return redirect('/profile')
    user_data = user_data[0]
    return render_template('profile_noname.html', user_data=user_data,
                           tab_name='User: {}'.format(user_data['email']))


@routes.route('/projects/', methods=['GET'])
@requires_authorization
@check_session
def list_projects(current_user):
    return render_template('projects.html',
                           tab_name='Projects')


@routes.route('/new_issue_template', methods=['GET'])
@requires_authorization
@check_session
def new_issue_templates(current_user):
    return render_template('new_issue_template.html',
                           tab_name='New template')


@routes.route('/new_issue_template', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def new_issue_templates_form(current_user):
    form = NewIssueTemplate()

    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)

    if not (len(form.variable_value.data) == len(form.variable_type.data) == len(form.variable_name.data)):
        errors.append('Error with variables form!')

    if not (len(form.additional_field_name.data) == len(form.additional_field_type.data) == len(form.additional_field_value.data)):
        errors.append('Error with additional fields form!')

    user_uuid = ''
    team_uuid = ''
    # check team access
    if form.team_id.data and is_valid_uuid(form.team_id.data):
        user_teams = db.select_user_teams(current_user['id'])
        current_team = {}
        for found_team in user_teams:
            if found_team['id'] == form.team_id.data:
                current_team = found_team
                team_uuid = current_team['id']
        if not current_team:
            errors.append('Team not found!')
    else:
        user_uuid = current_user['id']

    if not errors:
        # add additional fields
        field_counter = 0
        add_fields_dict = {}
        for field_name in form.additional_field_name.data:
            field_type = form.additional_field_type.data[field_counter]
            field_value = form.additional_field_value.data[field_counter]
            if field_type in ["text", "number", "float", "boolean"]:
                # add text field
                try:
                    if field_type == "text":
                        type_func = str
                    elif field_type == "number":
                        type_func = int
                    elif field_type == "float":
                        type_func = float
                    elif field_type == "boolean":
                        type_func = lambda x: bool(int(x))
                    add_fields_dict[field_name] = {}
                    add_fields_dict[field_name]['value'] = type_func(field_value) if field_type == 'text' or field_value else type_func(0)
                    add_fields_dict[field_name]['type'] = field_type
                except:
                    pass
            field_counter += 1

        # add variables
        variables_counter = 0
        add_variables_dict = {}
        for variable_name in form.variable_name.data:
            variable_type = form.variable_type.data[variables_counter]
            variable_value = form.variable_value.data[variables_counter]
            if variable_type in ["text", "number", "float", "boolean"]:
                # add text field
                try:
                    if variable_type == "text":
                        type_func = str
                    elif variable_type == "number":
                        type_func = int
                    elif variable_type == "float":
                        type_func = float
                    elif variable_type == "boolean":
                        type_func = lambda x: bool(int(x))
                    add_variables_dict[variable_name] = {}
                    add_variables_dict[variable_name]['value'] = type_func(variable_value) if variable_type == 'text' or variable_value else type_func(0)
                    add_variables_dict[variable_name]['type'] = variable_type
                except:
                    pass
                variables_counter += 1

        # create IssueTemplate

        cvss = form.cvss.data
        criticality = form.criticality.data
        if 0 <= criticality <= 10:
            cvss = criticality

        template_id = db.insert_new_issue_template(form.template_name.data,
                                                   form.name.data,
                                                   form.description.data,
                                                   form.url.data, cvss, form.status.data,
                                                   form.cve.data, form.cwe.data, form.issue_type.data,
                                                   form.fix.data, form.param.data,
                                                   add_fields_dict, add_variables_dict,
                                                   user_uuid, team_uuid)

        if user_uuid:
            return redirect('/profile#/config')
        else:
            return redirect('/team/{}/#/configs'.format(team_uuid))

    return render_template('new_issue_template.html',
                           tab_name='New template',
                           errors=errors)


@routes.route('/download_issue_templates', methods=['POST'])
@requires_authorization
@check_session
def download_issue_templates(current_user):
    form = ExportIssueTemplates()

    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)
    if errors:
        return redirect('/projects/')

    result_arr = []
    for template_id in form.template_id.data:
        current_template = db.check_user_issue_template_access(template_id, current_user['id'], current_user['email'])
        if current_template:
            current_template = current_template[0]
            template_obj = {
                'tpl_name': current_template['tpl_name'],
                'name': current_template['name'],
                'description': current_template['description'],
                'url_path': current_template['url_path'],
                'cvss': current_template['cvss'],
                'cwe': current_template['cwe'],
                'cve': current_template['cve'],
                'status': current_template['status'],
                'type': current_template['type'],
                'fix': current_template['fix'],
                'param': current_template['param'],
                'fields': json.loads(current_template['fields']),  # { 'val1':{'type':'text','value':'1234'},... }
                'variables': json.loads(current_template['variables'])  # { 'val1':{'type':'text','value':'1234'},... }
            }

            result_arr.append(template_obj)

    json_file = jsonify(result_arr)
    json_file.headers['Content-Disposition'] = 'attachment;filename=IssueTemplates.json'
    return json_file


@routes.route('/delete_issue_templates', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def delete_issue_templates(current_user):
    form = DeleteIssueTemplates()

    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)
    if errors:
        return redirect('/projects/')

    result_arr = []
    for template_id in form.template_id.data:
        current_template = db.check_user_issue_template_access(template_id, current_user['id'], current_user['email'])
        if current_template:
            current_template = current_template[0]

            db.delete_issue_template(current_template['id'])

    referrer = request.headers.get("Referer")
    if referrer:
        return redirect(referrer + '#/configs')
    return redirect('/projects/')


@routes.route('/import_issue_templates', methods=['GET'])
@requires_authorization
@check_session
def import_issue_templates(current_user):
    return render_template('import_issue_templates.html',
                           tab_name='Import template')


@routes.route('/import_issue_templates', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def import_issue_templates_form(current_user):
    form = ImportIssueTemplates()

    form.validate()
    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)

    user_uuid = ''
    team_uuid = ''
    # check team access
    if form.team_id.data and is_valid_uuid(form.team_id.data):
        user_teams = db.select_user_teams(current_user['id'])
        current_team = {}
        for found_team in user_teams:
            if found_team['id'] == form.team_id.data:
                current_team = found_team
                team_uuid = current_team['id']
        if not current_team:
            errors.append('Team not found!')
    else:
        user_uuid = current_user['id']

    if not errors:
        for file in form.json_files.data:
            if file.filename:
                try:
                    file_content = file.read().decode('utf-8')
                    templates_arr = json.loads(file_content)
                    for template_obj in templates_arr:
                        template_tpl_name = str(template_obj['tpl_name'])
                        template_name = str(template_obj['name'])
                        template_description = str(template_obj['description'])
                        template_url_path = str(template_obj['url_path'])
                        template_cvss = float(template_obj['cvss']) if float(template_obj['cvss']) >= 0 and float(template_obj['cvss']) <= 10 else 0
                        template_cwe = int(template_obj['cwe']) if int(template_obj['cwe']) >= 0 else 0
                        template_cve = str(template_obj['cve'])
                        template_status = str(template_obj['status'])
                        template_type = str(template_obj['type'])
                        template_fix = str(template_obj['fix'])
                        template_param = str(template_obj['param'])
                        template_fields = template_obj['fields']
                        template_variables = template_obj['variables']

                        template_fields_checked = {}

                        # template_fields
                        for field_name in template_fields:
                            # first check
                            if type(template_fields[field_name]) == dict and \
                                    'type' in template_fields[field_name] and \
                                    'value' in template_fields[field_name]:
                                # second check
                                if template_fields[field_name]['type'] in ['text', 'number', 'float', 'boolean']:

                                    if template_fields[field_name]['type'] == "text":
                                        type_func = str
                                    elif template_fields[field_name]['type'] == "number":
                                        type_func = int
                                    elif template_fields[field_name]['type'] == "float":
                                        type_func = float
                                    elif template_fields[field_name]['type'] == "boolean":
                                        type_func = lambda x: bool(int(x))

                                    template_fields_checked[str(field_name)] = {
                                        'type': template_fields[field_name]['type'],
                                        'value': type_func(template_fields[field_name]['value'])
                                    }

                        template_variables_checked = {}

                        # template_fields
                        for variable_name in template_variables:
                            # first check
                            if type(template_variables[variable_name]) == dict and \
                                    'type' in template_variables[variable_name] and \
                                    'value' in template_variables[variable_name]:
                                # second check
                                if template_variables[variable_name]['type'] in ['text', 'number', 'float', 'boolean']:

                                    if template_variables[variable_name]['type'] == "text":
                                        type_func = str
                                    elif template_variables[variable_name]['type'] == "number":
                                        type_func = int
                                    elif template_variables[variable_name]['type'] == "float":
                                        type_func = float
                                    elif template_variables[variable_name]['type'] == "boolean":
                                        type_func = lambda x: bool(int(x))

                                    template_variables_checked[str(variable_name)] = {
                                        'type': template_variables[variable_name]['type'],
                                        'value': type_func(template_variables[variable_name]['value'])
                                    }
                        db.insert_new_issue_template(
                            form.prefix.data + template_tpl_name,
                            template_name,
                            template_description,
                            template_url_path,
                            template_cvss,
                            template_status,
                            template_cve,
                            template_cwe,
                            template_type,
                            template_fix,
                            template_param,
                            template_fields_checked,
                            template_variables_checked,
                            user_uuid,
                            team_uuid
                        )
                except Exception as e:
                    print(e)

    if not errors:
        if team_uuid:
            return redirect('/team/{}/#/configs'.format(team_uuid))
        else:
            return redirect('/profile#/config')

    return render_template('import_issue_templates.html',
                           tab_name='Import template',
                           errors=errors)


@routes.route('/issue_template/<uuid:template_id>/', methods=['GET'])
@requires_authorization
@check_session
@check_template_access
def edit_issue_template(current_user, template_id, current_template):
    return render_template('edit_issue_template.html',
                           tab_name='Edit template',
                           current_template=current_template)


@routes.route('/issue_template/<uuid:template_id>/', methods=['POST'])
@requires_authorization
@check_session
@check_template_access
@send_log_data
def edit_issue_template_form(current_user, template_id, current_template):
    form = EditIssueTemplate()

    form.validate()

    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)

    # delete & return
    if not errors and form.action.data == 'Delete':
        db.delete_issue_template(current_template['id'])
        if current_template['team_id']:
            return redirect('/team/{}/#/configs'.format(current_template['team_id']))
        else:
            return redirect('/profile#/config')

    if not (len(form.variable_value.data) == len(form.variable_type.data) == len(form.variable_name.data)):
        errors.append('Error with variables form!')

    if not (len(form.additional_field_name.data) == len(form.additional_field_type.data) == len(form.additional_field_value.data)):
        errors.append('Error with additional fields form!')

    user_uuid = ''
    team_uuid = ''
    # check team access
    if form.team_id.data and is_valid_uuid(form.team_id.data):
        user_teams = db.select_user_teams(current_user['id'])
        current_team = {}
        for found_team in user_teams:
            if found_team['id'] == form.team_id.data:
                current_team = found_team
                team_uuid = current_team['id']
        if not current_team:
            errors.append('Team not found!')
    else:
        user_uuid = current_user['id']

    if not errors:
        # add additional fields
        field_counter = 0
        add_fields_dict = {}
        for field_name in form.additional_field_name.data:
            field_type = form.additional_field_type.data[field_counter]
            field_value = form.additional_field_value.data[field_counter]
            if field_type in ["text", "number", "float", "boolean"]:
                # add text field
                try:
                    if field_type == "text":
                        type_func = str
                    elif field_type == "number":
                        type_func = int
                    elif field_type == "float":
                        type_func = float
                    elif field_type == "boolean":
                        type_func = lambda x: bool(int(x))
                    add_fields_dict[field_name] = {}
                    add_fields_dict[field_name]['value'] = type_func(field_value) if field_type == 'text' or field_value else type_func(0)
                    add_fields_dict[field_name]['type'] = field_type
                except:
                    pass
            field_counter += 1

        # add variables
        variables_counter = 0
        add_variables_dict = {}
        for variable_name in form.variable_name.data:
            variable_type = form.variable_type.data[variables_counter]
            variable_value = form.variable_value.data[variables_counter]
            if variable_type in ["text", "number", "float", "boolean"]:
                # add text field
                try:
                    if variable_type == "text":
                        type_func = str
                    elif variable_type == "number":
                        type_func = int
                    elif variable_type == "float":
                        type_func = float
                    elif variable_type == "boolean":
                        type_func = lambda x: bool(int(x))
                    add_variables_dict[variable_name] = {}
                    add_variables_dict[variable_name]['value'] = type_func(variable_value) if variable_type == 'text' or variable_value else type_func(0)
                    add_variables_dict[variable_name]['type'] = variable_type
                except:
                    pass
                variables_counter += 1

        # create IssueTemplate

        cvss = form.cvss.data
        criticality = form.criticality.data
        if 0 <= criticality <= 10:
            cvss = criticality

        db.edit_issue_template(current_template['id'],
                               form.tpl_name.data,
                               form.name.data,
                               form.description.data,
                               form.url.data, cvss, form.status.data,
                               form.cve.data, form.cwe.data, form.issue_type.data,
                               form.fix.data, form.param.data,
                               add_fields_dict, add_variables_dict,
                               user_uuid, team_uuid)

        return redirect('/issue_template/{}/'.format(current_template['id']))

    return render_template('edit_issue_template.html',
                           tab_name='Edit template',
                           current_template=current_template)


@routes.route('/new_template_from_issue', methods=['POST'])
@requires_authorization
@check_session
@send_log_data
def new_template_from_issue(current_user):
    form = NewTemplateFromIssue();

    errors = []
    if form.errors:
        for field in form.errors:
            for err in form.errors[field]:
                errors.append(err)
    if not errors:
        current_issue = db.select_issue(form.issue_id.data)
        if not current_issue:
            errors.append('Issue not found!')
        else:
            current_issue = current_issue[0]

            current_project = db.check_user_project_access(current_issue['project_id'], current_user['id'])
            if not current_project:
                errors.append('You do not have access to this project!')
            else:
                return render_template('new_issue_template_from_issue.html',
                                       tab_name='Edit template',
                                       current_issue=current_issue)

    return render_template('new_issue_template_from_issue.html',
                           tab_name='Edit template',
                           current_issue=current_issue,
                           errors=errors)
