import fastwsgi
import app


def start_server():
    host, port, debug, ssl_context = app.config_prepare()

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

    fastwsgi.run(wsgi_app=app.application, host=host, port=port)
