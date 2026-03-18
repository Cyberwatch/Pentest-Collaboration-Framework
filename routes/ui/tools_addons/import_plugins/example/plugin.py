######## Imports #########
import logging

from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database

# For demonstration
import json

######## Description #############
route_name = "example"  # [a-zA-Z0-9_]

tools_description = [  # array with tools information (to join same tools process algorith, like Nmap and masscan)
    {
        "Icon file": "icon.png",
        "Icon URL": "https://cdn-icons-png.flaticon.com/512/5828/5828226.png",  # upload icon to IMG-BB etc
        "Official name": "Example tool I",
        "Short name": "example_tool",  # [a-zA-Z0-9_]
        "Description": "Test tool to show plugin functionality, more info <a href=''>here</a>",
        # can use HTML inside.
        "URL": "https://example.com/",
        "Plugin author": "@drakylar"  # Change as you want :)
    },
    {
        "Icon file": "icon.png",
        "Icon URL": "https://cdn-icons-png.flaticon.com/512/5828/5828226.png",
        "Official name": "Example tool II",
        "Short name": "example_tool2",
        "Description": "Second tool to show functionality of joining two tools page",
        "URL": "https://example2.com/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    # Example multiple file upload field
    # must not be "access_token"
    json_files = MultipleFileField(label='json_files',  # same as variable name
                                   description="JSON-report",  # short description
                                   default=None,
                                   validators=[],
                                   # Validate argument - https://wtforms.readthedocs.io/en/2.3.x/validators/
                                   _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml,.txt"})

    # Example text input field
    example_text = StringField(label='example_text',  # same as variable name
                               description="Text input",  # short description
                               default="example default value",  # this will also be in HTML-tag
                               validators=[
                                   DataRequired(message='This field is required!')
                               ],
                               _meta={"display_row": 1, "display_column": 2, "file_extensions": "", "multiline": False})

    example_required_text = StringField(label='example_text2',
                                        description="Required text",
                                        validators=[
                                            DataRequired(message='example_required_text field is required!')
                                        ],
                                        _meta={"display_row": 2, "display_column": 1, "file_extensions": ""})

    # Example number input field
    example_number = IntegerField(label='example_number',  # same as variable name
                                  description="Number input",  # short description
                                  default=1337,  # this will also be in HTML-tag
                                  # Validate argument - https://wtforms.readthedocs.io/en/2.3.x/validators/
                                  validators=[
                                      NumberRange(min=1, max=65535, message="Port 1..65535")
                                  ],
                                  _meta={"display_row": 2, "display_column": 2, "file_extensions": ""})

    # Example checkbox input field
    example_checkbox = BooleanField(label='example_checkbox',  # same as variable name
                                    description="Checkbox input",  # short description
                                    default=True,  # checked/not-checked
                                    # Validate argument - https://wtforms.readthedocs.io/en/2.3.x/validators/
                                    validators=[],
                                    _meta={"display_row": 3, "display_column": 1, "file_extensions": ""})


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # fields variables
    json_files = input_dict["json_files"]  # [b"1234", b"5678"]
    example_text = input_dict["example_text"]  # "example default value" (str)
    example_number = input_dict["example_number"]  # 1337 (int)
    example_checkbox = input_dict["example_checkbox"]  # True/False (Boolean)

    # example of files processing
    for binary_file_data in input_dict["json_files"]:
        text_file_data = binary_file_data.decode("charmap")
        json_object = json.loads(text_file_data)
        # do some data process

    # example of database requests
    # careful here - it does not have any input checks
    # Fields from database - https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/Settings#structure

    # GET-data
    hosts = db.select_project_hosts(project_id=current_project['id'])

    # INSERT-data
    new_host_uuid = db.insert_host(
        project_id=current_project['id'],
        ip="8.8.8.8",
        user_id=current_user['id'],
        comment="example comment",
        threats=[""]
    )

    # same input/get can be done with almost any data, database functions start with type of request
    # insert_..., select_..., update_..., delete_...

    # get data from config
    if global_config['files']['poc_storage'] == 'database':
        pass

    # return status
    success = True
    if success:
        return ""
    else:
        logging.error("This string will be in error log")
        return "There were some errors! (user will get this error string)"
