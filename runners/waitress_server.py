from waitress import serve
from flask import request
import app
import logging


def start_server():
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.DEBUG)
    host, port, debug, ssl_context = app.config_prepare()


    @app.app.before_request
    def log_request_info():
        base_url = request.base_url # 'http://...'
        method = request.method
        print('{} - {}\n'.format(method, base_url), flush=True)


    serve(app.application, host=host, port=port)
