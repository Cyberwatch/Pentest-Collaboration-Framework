from shutil import copyfile

from fix_scripts.val_problem import val_db_fixer
from fix_scripts.new_notes_type_field import note_type_add
from os import path
import time

print("This is a console app to fix your PCF instance!")

print("!!! Important !!! Better to turn off your PCF instance while fixing (or just don't do anything there)")

print("It will also create a database backup (only for SQLite3)!")

s = input("If you are ready for some fix scripts, write I_WILL_READ_THE_OUTPUT:")

if s not in ("I_WILL_READ_THE_OUTPUT", "I_WILL_READ_THE_OUTPUT:"):
    print("Wrong string :( Retry again!")
    exit()

print('## Reading the config file')
try:
    import configparser

    config = configparser.ConfigParser()
    config.read("./configuration/settings.ini")
except Exception as e:
    print("Exception:", e)
    print("Error reading config file: one of the following problems exist")
    print("1. configparser lib is not installed - you need to run "
          "`pip3 install -r requirements_linux.txt` or `pip3 install -r requirements_windows.txt`")
    print("2. Config settings.ini does not exist at ./configuration/ folder - "
          "you need to create it or copy from PCF GitLab repository")
    print("3. You run fixer.py script not from PCF repository (etc using full path to script). "
          "You need to be inside PCF folder to run it!")
    exit()

print('## Get access to database')
try:
    from system.db import Database

    db = Database(config)
except Exception as e:
    print("Exception:", e)
    print("Error connecting to Database: one of the following problems exist")
    print("1. If SQLite -> check for sqlite3 library")
    print("2. If PostgreSQL -> check for postgresql library")
    print("3. If PostgreSQL -> Wrong password/ip/port/username/database/no privileges")
    print("4. If SQLite -> wrong path to database file")
    exit(0)

print("######### Database backup SQLite3 START #########")

if config['database']['type'] == 'sqlite3':
    try:
        db_path = config['database']['path']
        curr_time = int(time.time())
        new_backup_path = path.join(config['backup']['db_backup_folder'],
                                    'fixer_backup_{}.sqlite3'.format(curr_time))
        copyfile(config['database']['path'], new_backup_path)
    except Exception as e:
        print("Problem during creating database backup!")
        print("Exception:", e)
        print("Possible solutions:")
        print("1. Check that config has `database` -> `path` field")
        print("2. Check that this path exists:", new_backup_path)
        print("3. Check that you have rights to write:", new_backup_path)
        exit()
    print("## Backup file path:", new_backup_path)
    print("Don't forget to delete it later!")

print("######### Database backup SQLite3 END #########")

print("######### Config fixes START #########")

print("######### Config fixes END #########")

print("######### Database fixes START #########")

print('## Fix all "value" -> "val" inside database')
val_db_fixer.val_db_fixer(config, db)

print('## Add new column to Notes - "type"')
note_type_add.note_type_add(config, db)

print("######### Database fixes END #########")
