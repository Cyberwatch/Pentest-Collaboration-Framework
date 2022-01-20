import app


def start_server():
    host, port, debug, ssl_context = app.config_prepare()
    if ssl_context:
        app.application.run(
            ssl_context=ssl_context,
            host=host,
            port=port,
            debug=debug,
            threaded=True)
    else:
        app.application.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True)
