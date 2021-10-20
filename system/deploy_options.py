from os import environ
import requests
import time


def deploy_heroku(config_change_func):
    # fix for heroku
    config_change_func('database', 'type', 'postgres')
    config_change_func('speedup', 'external_js', '1')
    config_change_func('speedup', 'external_img', '1')
    config_change_func('speedup', 'external_css', '1')
    config_change_func('files', 'files_storage', 'database')
    config_change_func('files', 'poc_storage', 'database')
    config_change_func('files', 'template_storage', 'database')

    if 'BASIC_AUTH_LOGIN' in environ and 'BASIC_AUTH_PASSWORD' in environ and \
            (environ['BASIC_AUTH_LOGIN'] or environ['BASIC_AUTH_PASSWORD']):
        config_change_func('security', 'basic_auth', '1')
        config_change_func('security', 'basic_login', environ['BASIC_AUTH_LOGIN'])
        config_change_func('security', 'basic_password', environ['BASIC_AUTH_PASSWORD'])

    if 'PORT' in environ:
        config_change_func('network', 'port', str(int(environ['PORT'])))


def deploy_aws(config_change_func):
    # wait for network interface creation
    time.sleep(15)
    instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id').text
    print('Your password was changed to' + instance_id)
    config_change_func('security', 'basic_auth', '1')
    config_change_func('security', 'basic_login', 'awsadmin')
    config_change_func('security', 'basic_password', instance_id)
