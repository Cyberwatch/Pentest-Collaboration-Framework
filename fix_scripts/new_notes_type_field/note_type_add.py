import json
import sqlite3


def note_type_add(config, db):
    print("This script will add a new field to 'Notes' table - type. This field will be text, docs,...")
    print("More info: https://gitlab.com/invuls/pentest-projects/pcf/-/issues/156")
    print("Fixing Notes table")
    try:
        db.execute("ALTER TABLE Notes ADD type text default 'html';")
        db.conn.commit()
    except sqlite3.OperationalError as e:
        print("Don't need to add a new column!")
    except Exception as e:
        print("Unhandled exception during process of creating a new column - 'type' "
              "for Notes table. Please, create a bug ticket and attach the exception!")
        print("Exception:", e)
    print("Fixed Notes table!")
