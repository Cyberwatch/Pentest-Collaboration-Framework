import base64
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from flask import Flask, session, render_template, request
from flask import jsonify
from flask_apscheduler import APScheduler
from flask_session import Session
from flask_compress import Compress
from datetime import timedelta
from system.config_load import config_dict
from xml.sax.saxutils import escape
import json
import time
import string
import random
import logging
import urllib.parse
from os import remove
import glob
import secure
from functools import wraps
from pyngrok import ngrok

from system.db import Database

from routes.webdav.webdav import *

from flask_wtf.csrf import CSRFProtect, CSRFError

from system.forms import *

from os import environ, path
from shutil import copyfile

from flask_caching import Cache
from flask_swagger_ui import get_swaggerui_blueprint

from wsgidav.wsgidav_app import WsgiDAVApp

global db

csrf = CSRFProtect()
# disable csrf-protection for http sniffer
csrf.exempt("routes.ui.tools.http_sniffer_capture_page")
# disable csrf-protection for interactive search fields
csrf.exempt("routes.ui.project.filter_host_port_form")
# disable csrf-protection for notes edit
csrf.exempt("routes.ui.project.edit_note_form")
# disable csrf-protection for issue rule selection
csrf.exempt("routes.ui.project.project_issue_rules_ids")

config = config_dict()

compress = Compress()

db = Database(config)

app = Flask(__name__,
            static_folder=None,
            template_folder='templates')

app.config['DATABASE'] = db

app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=int(config['security']['session_lifetime']))
app.config['SECRET_KEY'] = config['main']['secret']
app.config['WTF_CSRF_TIME_LIMIT'] = 60 * 60 * int(config['security']['csrf_lifetime'])

# enable jsonify pretty output
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

if config['security']['sessions_type'] == 'filesystem':
    sess = Session()
    sess.init_app(app)
# else - standart session flask


csrf.init_app(app)

compress.init_app(app)

# webdav

webdav_config = {
    "http_authenticator": {"domain_controller": None},
    # anonymous
    # "simple_dc": {"user_mapping": {"*": True}},
    'simple_dc': {
        "user_mapping": {
            "*": {"test": {"password": "test", "description": "", "roles": []}}
        }
    },
    'provider_mapping': {
        "/": VirtualResourceProvider(db)
    },
    'provider': VirtualResourceProvider(db),
    "lock_storage": True,
    'http_authenticator': {
        "accept_basic": True,
        "accept_digest": False,
        "default_to_digest": False,
        "domain_controller": PAMDomainController,
        "db": db
    },
    'property_manager': True,
    'destrealm': '/',
    'verbose': 1
}

webdav_app = WsgiDAVApp(webdav_config)

dispatched_app = Flask(__name__)

if config['main']['webdav'] == "1":
    dispatched_app.wsgi_app = DispatcherMiddleware(app, {
        '/webdav': webdav_app
    })
else:
    dispatched_app.wsgi_app = DispatcherMiddleware(app)


# add swagger ui

SWAGGER_URL = '/api/docs'
API_JSON_URL = '/api/v1/swagger_v1.0.0.json'
swagger_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_JSON_URL,
)

app.register_blueprint(swagger_blueprint)

# secure headers
hsts = secure.StrictTransportSecurity().preload().max_age(2592000)
secure_headers = secure.Secure(hsts=hsts)


@app.after_request
def set_secure_headers(response):
    secure_headers.framework.flask(response)
    return response


cache = Cache(config={'CACHE_TYPE': 'simple', "CACHE_DEFAULT_TIMEOUT": 300})
cache.init_app(app)

if config['logs']['logging'] == '1':
    # output to log file
    logging.basicConfig(handlers=[
        logging.FileHandler(config['logs']['log_file']),
        logging.StreamHandler()
    ]
    )


def backup_database():
    # if timer is fast anough
    if environ['backup_status'] == '0':
        environ['backup_status'] = '1'
        file_dates = [int(file.split('backup_')[-1].split('.sqlite3')[0]) for
                      file in
                      glob.glob(config['backup']['db_backup_folder'] +
                                "backup_*.sqlite3")]

        file_dates.sort()

        while len(file_dates) >= int(config['backup']['db_backup_amount']):
            # delete old file
            old_date = file_dates[0]
            old_backup_path = path.join(config['backup']['db_backup_folder'],
                                        'backup_{}.sqlite3'.format(old_date))
            remove(old_backup_path)
            file_dates = [int(file.split('backup_')[-1].split('.sqlite3')[0])
                          for file in
                          glob.glob(config['backup']['db_backup_folder'] +
                                    "backup_*.sqlite3")]

        curr_time = int(time.time())

        new_backup_path = path.join(config['backup']['db_backup_folder'],
                                    'backup_{}.sqlite3'.format(curr_time))
        copyfile(config['database']['path'], new_backup_path)

        environ['backup_status'] = '0'


if config['backup']['db_backup'] == '1' and (not ('backup_loaded' in environ)):
    # fix of double loading scheduler
    environ['backup_loaded'] = '1'
    environ['backup_status'] = '0'
    hours = int(config['backup']['db_backup_hours'])
    if config['database']['type'] == 'sqlite3':
        scheduler = APScheduler()
        scheduler.init_app(app)
        scheduler.add_job(func=backup_database, trigger='interval',
                          id='backup_database',
                          weeks=int(config['backup']['db_backup_weeks']),
                          days=int(config['backup']['db_backup_days']),
                          hours=int(config['backup']['db_backup_hours']),
                          minutes=int(config['backup']['db_backup_minutes']),
                          seconds=int(config['backup']['db_backup_seconds']))
        scheduler.start()


def ok_user_and_password(username, password):
    return username == config['security']['basic_login'] and \
           password == config['security']['basic_password']


def authenticate():
    message = {'message': "Authenticate."}
    resp = jsonify(message)

    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Main"'

    return resp


def requires_authorization(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if config['security']['basic_auth'] == '0':
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not ok_user_and_password(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


@app.errorhandler(404)
@requires_authorization
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


@app.errorhandler(405)
@requires_authorization
def page_not_found(e):
    return render_template('405.html'), 405


@app.errorhandler(500)
@requires_authorization
def page_exception(e):
    return render_template('500.html'), 500


def redirect(redirect_path):
    response = jsonify()
    response.status_code = 302
    response.headers['location'] = redirect_path
    response.autocorrect_location_header = False
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf.html', reason=e.description), 400


def check_session(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        # if proxy auth
        if config['security']['proxy_auth'] == '1':
            auth_email = request.headers.get(config['security']['proxy_email_header'])
            if auth_email:
                current_user = db.select_user_by_email(auth_email)
                if not current_user:
                    # register user
                    user_id = db.insert_user(auth_email, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30)))
                    current_user = db.select_user_by_id(user_id)[0]
                else:
                    current_user = current_user[0]
                session['id'] = current_user['id']
                session['current_user'] = current_user
                kwargs['current_user'] = current_user
                return fn(*args, **kwargs)
            else:
                return redirect('/login')
        else:
            url = request.path
            if 'id' not in session:
                return redirect(
                    '/logout?redirect={}'.format(urllib.parse.quote_plus(url)))
            current_user = db.select_user_by_id(session['id'])
            if not current_user:
                return redirect('/logout')
            kwargs['current_user'] = current_user[0]
            session['current_user'] = current_user[0]
            return fn(*args, **kwargs)

    return decorated_view


def check_team_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        team_id = kwargs['team_id']
        user_teams = db.select_user_teams(session['id'])
        current_team = {}
        for found_team in user_teams:
            if found_team['id'] == str(team_id):
                current_team = found_team
        if not current_team:
            return redirect('/create_team')
        kwargs['current_team'] = current_team
        return fn(*args, **kwargs)

    return decorated_view


def send_log_data(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_team = {}
        current_project = {}
        if 'current_team' in kwargs:
            current_team = kwargs['current_team']
        if 'current_project' in kwargs:
            current_project = kwargs['current_project']
        db.config_update(kwargs['current_user'],
                         current_team=current_team,
                         current_project=current_project)
        return fn(*args, **kwargs)

    return decorated_view


# init some global variables
@app.context_processor
def add_template_vars():
    return dict(db=db,
                escape=lambda x: escape(str(x)),
                json_unpack=json.loads,
                json_pack=json.dumps,
                format_date=lambda unix_time,
                                   str_format: datetime.datetime.fromtimestamp(
                    int(unix_time)).strftime(str_format),
                b64decode=base64.b64decode,
                b64encode=base64.b64encode,
                urlencode=urllib.parse.quote,
                time=time.time,
                open=open,
                len=len,
                is_valid_uuid=is_valid_uuid,
                str=str,
                debug=(config['main']['debug'] == '1'),
                external_js=int(config['speedup']['external_js']),
                external_css=int(config['speedup']['external_css']),
                external_img=int(config['speedup']['external_img']),
                one_file_js=int(config['speedup']['one_file_js']),
                one_file_css=int(config['speedup']['one_file_css']),
                date_format_template=config['design']['date_format_template'],
                list_dict_value=lambda list_dict, key_name: [x[key_name] for x in list_dict],
                list=list,
                search_dict_list=lambda list_obj, key_name, key_val: key_val in [x[key_name] for x in list_obj],
                list_crossing=lambda list1, list2: list(set(list1) & set(list2))
                )


from routes.ui import routes as main_routes
from routes.api import api_bp

app.register_blueprint(api_bp)

app.register_blueprint(main_routes)

# disable CSRF for API
csrf.exempt(api_bp)


def config_prepare():
    port = config['network']['port']
    host = config['network']['host']
    debug = config['main']['debug'] == '1'
    ssl_context = None

    if config['network']['ngrok'] == '1':
        if not config['network']['ngrok_token']:
            print('Need NGROK token to use it!')
        ngrok_ip = config['network']['host'] if config['network']['host'] != '0.0.0.0' else '127.0.0.1'
        ngrok_tunnel = ngrok.connect(ngrok_ip + ':' + config['network']['port'],
                                     proto="http")
        ngrok.set_auth_token(config['network']['ngrok_token'])
        ngrok_url = ngrok_tunnel.public_url
        print('#' * (len(ngrok_url) + 11))
        print('# Ngrok: {} #'.format(ngrok_url))
        print('#' * (len(ngrok_url) + 11))
        print('All data duplicated')
        f = open(config['network']['ngrok_url_file'], 'w')
        f.write(ngrok_url)
        f.close()

    if config['ssl']['ssl'] == '1':
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(config['ssl']['cert'], config['ssl']['priv_key'])
        ssl_context = context
    return host, port, debug, ssl_context


if __name__ == '__main__':
    host, port, debug, ssl_context = config_prepare()

    if ssl_context:
        dispatched_app.run(
            ssl_context=ssl_context,
            host=host,
            port=port,
            debug=debug,
            threaded=True)
    else:
        dispatched_app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True)
else:
    application = dispatched_app
