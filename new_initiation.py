from system.db_initiation import create_db
from system.config_load import change_secret_key, change_option, change_basic_password
from system.cert_initiation import create_self_signed_cert
from system.deploy_options import deploy_heroku, deploy_aws
from os import mkdir, path
from sys import argv

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
##################################################################

This script will do following:
1. Renames database /configuration/database.sqlite3
2. Regenerates SSL certificates
3. Regenerates session key.
4. Creates new empty /configuration/database.sqlite3 database
5. Creates /tmp_storage/ folder 
''')

if len(argv) == 2:
    if argv[1] == 'heroku':
        print('Cloud deployment: "HEROKU"')
        deploy_heroku(change_option)
    elif argv[1] == 'aws':
        print('Cloud deployment: "AWS"')
        deploy_aws(change_option)
else:
    print('Are you sure running it? Write: DELETE_ALL')
    init_proof = input('Your input: ')
    if init_proof != 'DELETE_ALL':
        print('Error! String wasn\'t correct!')
        exit(1)
    change_basic_password()

create_db()

change_secret_key()

create_self_signed_cert()

if not path.exists('tmp_storage'):
    mkdir('tmp_storage')

print('Success!')
