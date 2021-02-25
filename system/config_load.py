try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from system.crypto_functions import random_string

config_path = "./configuration/settings.ini"


def config_dict():
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    return config


def change_secret_key():
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    config.set('main', 'secret', random_string(20))
    with open("./configuration/settings.ini", 'w') as configfile:
        config.write(configfile)
    return


def change_basic_password():
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    config.set('security', 'basic_password', random_string(20))
    with open("./configuration/settings.ini", 'w') as configfile:
        config.write(configfile)
    return


def change_option(group: str, option_name: str, option_value: str):
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    config.set(group, option_name, option_value)
    with open("./configuration/settings.ini", 'w') as configfile:
        config.write(configfile)
    return


def change_db_type(database: str):
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    config.set('database', 'type', str(database))
    with open("./configuration/settings.ini", 'w') as configfile:
        config.write(configfile)
    return


def change_external_option(status: bool):
    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
    config.set('speedup', 'external_js', str(int(status)))
    config.set('speedup', 'external_css', str(int(status)))
    config.set('speedup', 'external_img', str(int(status)))
    with open("./configuration/settings.ini", 'w') as configfile:
        config.write(configfile)
    return


def recover_config():
    pass
    # TODO
