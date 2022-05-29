import runners.fastwsgi_server
from system.config_load import config_dict
from runners import fastwsgi_server, flask_server, waitress_server




print('''
##################################################################
#                                                                #
#   .----------------.  .----------------.  .----------------.   #
#  | .--------------. || .--------------. || .--------------. |  #
#  | |   ______     | || |     ______   | || |  _________   | |  #
#  | |  |_   __ \   | || |   .' ___  |  | || | |_   ___  |  | |  #
#  | |    | |__) |  | || |  / .'   \_|  | || |   | |_  \_|  | |  #
#  | |    |  ___/   | || |  | |         | || |   |  _|      | |  #
#  | |   _| |_      | || |  \ `.___.'\  | || |  _| |_       | |  #
#  | |  |_____|     | || |   `._____.'  | || | |_____|      | |  #
#  | |              | || |              | || |              | |  #
#  | '--------------' || '--------------' || '--------------' |  #
#   '----------------'  '----------------'  '----------------'   #
#                                                                #
#         https://gitlab.com/invuls/pentest-projects/pcf         #
#                                                                #
##################################################################''')

config = config_dict()
run_func = None
if config['main']['web_engine'] == 'flask':
    run_func = flask_server.start_server
elif config['main']['web_engine'] == 'waitress':
    run_func = waitress_server.start_server
elif config['main']['web_engine'] == 'fastwsgi':
    run_func = fastwsgi_server.start_server
else:
    print("Parameter 'web_engine' was not recognized!")
    exit(-1)

# starting server
run_func()
