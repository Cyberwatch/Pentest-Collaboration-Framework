import io
import os
import re
from io import BytesIO
from urllib.parse import quote
import base64
from system.crypto_functions import is_valid_uuid, check_hash, gen_uuid
from system.config_load import config_dict

from wsgidav import util
from wsgidav.lock_man.lock_manager import LockManager
from wsgidav.lock_man.lock_storage import LockStorageDict
from wsgidav.dav_error import (
    HTTP_FORBIDDEN,
    DAVError,
    PRECONDITION_CODE_ProtectedProperty,
)
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider
from wsgidav.dc.base_dc import BaseDomainController
from wsgidav.util import join_uri

BUFFER_SIZE = 8192


def check_basic_auth(login: str, password: str, db: object) -> object:
    config = config_dict()
    if int(config['security']['basic_auth']) == 1:
        # check basic auth
        if ':::' not in login:
            return None
        if ':::' not in password:
            return None
        if config['security']['basic_login'] != login.split(':::')[0]:
            return None
        if config['security']['basic_password'] != login.split(':::')[1]:
            return None

        login = password.split(':::')[0]
        password = password.split(':::')[1]

    current_user = db.select_user_by_email(login)
    if not current_user:
        return None
    current_user = current_user[0]

    if not check_hash(current_user['password'], password):
        return False
    return current_user


class RootCollection(DAVCollection):
    """ Get projects of user - GET/ """
    db = None
    current_user = None

    def __init__(self, environ, db, current_user):
        self.db = db
        self.current_user = current_user
        DAVCollection.__init__(self, "/", environ)

    def get_member_names(self):
        projects = self.db.select_user_projects(self.current_user['id'])

        project_name_list = []
        for current_project in projects:
            project_name_list.append(
                re.sub('[^a-zA-Z0-9а-яА-Я]', '_', current_project['name']) + '_' + current_project['id']
            )
        return project_name_list

    def resolve(self, script_name, path_info):
        """Return a _DAVResource object for the path (None, if not found).

        `path_info`: is a URL relative to this object.
        """
        path_info = path_info.replace('/webdav/', '/')
        if path_info in ("", "/"):
            return self
        assert path_info.startswith("/")
        name, rest = util.pop_path(path_info)
        res = self.get_member(name)
        if res is None or rest in ("", "/"):
            return res
        return res.resolve(util.join_uri(script_name, name), rest)

    def get_member(self, name):
        """
        Get list of projects by name
        """
        projects = self.db.select_user_projects(self.current_user['id'])

        if name.split('_')[-1] in [x['id'] for x in projects] and is_valid_uuid(name.split('_')[-1]):
            p = join_uri(self.path, name)
            env = self.environ
            name = name.split('_')[-1]
            db = self.db
            return_obj = CategoryTypeCollection(p, env, name, db)
            return return_obj
        return None


class FileObject:
    """
    Need for creating a fake file stream object
    """

    def __init__(self, file_stream, buffer=0):
        config_pcf = config_dict()
        self.max_size = int(config_pcf["files"]["files_max_size"])
        self.current_size = 0
        self.file_stream = file_stream

    def write(self, data):
        if len(data) + self.current_size < self.max_size:
            self.file_stream.write(data)
        self.current_size += len(data)

    def close(self):
        pass


class CategoryTypeCollection(DAVCollection):
    """Get project folders, for example /test_project_c9fa3b92-53f4-4237-9fcc-e5b31b489c2a"""

    current_project = None
    db = None
    filename = None

    def __init__(self, path, environ, project_id, db):
        self.db = db
        self.current_username = self.db.select_user_by_email(environ['wsgidav.auth.user_name'])[0]
        self.current_project = self.db.select_projects(project_id)[0]
        DAVCollection.__init__(self, path, environ)

    def get_display_info(self):
        return {"type": "Category type"}

    def get_member_names(self):
        """Get project file names"""

        files = self.db.select_project_files(self.current_project['id'])
        names = [
            re.sub('[^a-zA-Z0-9\\.а-яА-Я]', '_', '.'.join(x['filename'].split('.')[:-1]))
            + '_'
            + x['id']
            + '.'
            + re.sub('[^a-zA-Z0-9\\.а-яА-Я]', '_', x['filename'].split('.')[-1])
            for x in files
        ]
        names.sort()
        return names

    def get_member(self, name):
        """ Get object of file in project by filename"""
        project_name = self.name
        project_id = project_name.split('_')[-1]
        if not is_valid_uuid(project_id):
            return None
        current_project = self.db.select_projects(project_id)[0]

        file_name = name
        file_id = file_name.split('.')[-2].split('_')[-1]

        if not is_valid_uuid(file_id):
            return None
        current_file = self.db.select_files(file_id)[0]

        if current_file['project_id'] != current_project['id']:
            return None

        # if subdirectory

        if self.path.strip('/').split('/') == 1:
            data = {
                "key": current_file['id'],
                "title": current_file['filename'],
                "orga": "Project: {}".format(self.current_project['name']),
                "tags": ["pcf", current_file['type']],
                "status": "published",
                "description": current_file['description'],
                "resPathList": [
                    os.path.join(self.current_project['name'] + '_' + current_project['id'], current_file['filename'])
                ]
            }
            return VirtualResource(join_uri(self.path, name), self.environ, data, self.db)
        else:
            return VirtualResFile(join_uri(self.path, name), self.environ, self.name, '', self.db)

    def create_empty_resource(self, filename):
        """ Create an empty file in project"""
        assert self.is_collection

        current_project = self.current_project
        current_username = self.current_username

        filetype = 'binary'

        if filename.lower().split('.')[-1] in ['png', 'jpg', 'jpeg', 'svg', 'bmp']:
            filetype = 'image'
        elif filename.lower().split('.')[-1] in ['txt', 'sql', 'html', 'py']:
            filetype = 'text'

        file_id = str(gen_uuid())
        config_pcf = config_dict()
        storage = config_pcf["files"]["files_storage"]
        if storage == 'filesystem':
            f = open('./static/files/code/' + file_id, 'wb')
            f.close()
        self.filename = filename + '_' + file_id
        if len(filename.split('.')) > 1:
            self.filename = '.'.join(filename.split('.'))[:-1] + '_' + file_id + '.' + filename.split('.')[-1]
        self.db.insert_new_file(file_id, current_project['id'], filename, 'Added from webdav',
                                {}, filetype, current_username['id'], storage, data=b'')
        return self

    def begin_write(self, *, content_type=None):
        """ Start writing into virtual file """
        filename = self.filename
        file_id = filename.split('.')[-2].split('_')[-1]
        if not is_valid_uuid(file_id):
            return None

        current_file = self.db.select_files(file_id)
        if not current_file:
            return None
        current_file = current_file[0]
        if current_file['project_id'] != self.current_project['id']:
            return None

        if self.current_project['status'] != 1:
            return None

        if current_file['storage'] == 'database':
            self.stream = io.BytesIO(base64.b64decode(current_file['base64']))
        elif current_file['storage'] == 'filesystem':
            self.stream = open('./static/files/code/' + file_id, 'wb')
        else:
            return None
        self.current_file = current_file
        self.file_obj = FileObject(self.stream)
        return self.file_obj

    def end_write(self, *, with_errors):
        """ End writing into virtual file - saving """
        if self.current_file['storage'] == 'filesystem':
            self.stream.close()
        elif self.current_file['storage'] == 'database':
            bytes_obj = self.stream.getvalue()
            self.stream.close()
            self.db.update_file_base64(bytes_obj)
        else:
            return False
        return True

    def copy_move_single(self, dest_path, *, is_move):
        pass

    def resolve(self, script_name, path_info):
        """
        Return a _DAVResource object for the path (None, if not found).

        `path_info`: is a URL relative to this object.
        """
        if path_info in ("", "/"):
            return self
        assert path_info.startswith("/")
        name, rest = util.pop_path(path_info)
        res = self.get_member(name)
        if res is None or rest in ("", "/"):
            return res
        return res.resolve(util.join_uri(script_name, name), rest)


# ============================================================================
# VirtualResource
# ============================================================================
class VirtualResource(DAVCollection):
    """A virtual 'resource', displayed as a collection of artifacts and files."""

    _supportedProps = [
        "{virtres:}key",
        "{virtres:}title",
        "{virtres:}status",
        "{virtres:}orga",
        "{virtres:}tags",
        "{virtres:}description",
    ]

    def __init__(self, path, environ, data, db):
        self.db = db
        DAVCollection.__init__(self, path, environ)
        self.data = data

    def get_display_info(self):
        return {"type": "Virtual Resource"}

    def get_member_names(self):
        names = []
        for f in self.data["resPathList"]:
            name = os.path.basename(f)
            names.append(name)
        return names

    def get_member(self, name):
        for file_path in self.data["resPathList"]:
            fname = os.path.basename(file_path)
            if fname == name:
                return VirtualResFile(
                    join_uri(self.path, name), self.environ, self.data, file_path, self.db
                )
        return None

    def handle_copy(self, dest_path, *, depth_infinity):
        """Change semantic of COPY to add resource tags."""
        # destPath must be '/by_tag/<tag>/<resname>'
        if "/by_tag/" not in dest_path:
            raise DAVError(HTTP_FORBIDDEN)
        catType, tag, _rest = util.save_split(dest_path.strip("/"), "/", 2)
        assert catType == "by_tag"
        if tag not in self.data["tags"]:
            self.data["tags"].append(tag)
        return True  # OK

    def handle_move(self, dest_path):
        """Change semantic of MOVE to change resource tags."""
        # path and destPath must be '/by_tag/<tag>/<resname>'
        if "/by_tag/" not in self.path:
            raise DAVError(HTTP_FORBIDDEN)
        if "/by_tag/" not in dest_path:
            raise DAVError(HTTP_FORBIDDEN)
        catType, tag, _rest = util.save_split(self.path.strip("/"), "/", 2)
        assert catType == "by_tag"
        assert tag in self.data["tags"]
        self.data["tags"].remove(tag)
        catType, tag, _rest = util.save_split(dest_path.strip("/"), "/", 2)
        assert catType == "by_tag"
        if tag not in self.data["tags"]:
            self.data["tags"].append(tag)
        return True  # OK

    def get_property_names(self, *, is_allprop):
        """Return list of supported property names in Clark Notation.
        See DAVResource.get_property_names()
        """
        # Let base class implementation add supported live and dead properties
        propNameList = super().get_property_names(is_allprop=is_allprop)
        # Add custom live properties (report on 'allprop' and 'propnames')
        propNameList.extend(VirtualResource._supportedProps)
        return propNameList

    def get_property_value(self, name):
        """Return the value of a property.
        See get_property_value()
        """
        # Supported custom live properties
        if name == "{virtres:}key":
            return self.data["key"]
        elif name == "{virtres:}title":
            return self.data["title"]
        elif name == "{virtres:}status":
            return self.data["status"]
        elif name == "{virtres:}orga":
            return self.data["orga"]
        elif name == "{virtres:}tags":
            # 'tags' is a string list
            return ",".join(self.data["tags"])
        elif name == "{virtres:}description":
            return self.data["description"]
        # Let base class implementation report live and dead properties
        return super().get_property_value(name)

    def set_property_value(self, name, value, dry_run=False):
        """Set or remove property value.
        See DAVResource.set_property_value()
        """
        if value is None:
            # We can never remove properties
            raise DAVError(HTTP_FORBIDDEN)
        if name == "{virtres:}tags":
            # value is of type etree.Element
            self.data["tags"] = value.text.split(",")
        elif name == "{virtres:}description":
            # value is of type etree.Element
            self.data["description"] = value.text
        elif name in VirtualResource._supportedProps:
            # Supported property, but read-only
            raise DAVError(
                HTTP_FORBIDDEN, err_condition=PRECONDITION_CODE_ProtectedProperty
            )
        else:
            # Unsupported property
            raise DAVError(HTTP_FORBIDDEN)
        # Write OK
        return

    def copy_move_single(self, dest_path, *, is_move):
        pass

    def resolve(self, script_name, path_info):
        """Return a _DAVResource object for the path (None, if not found).

        `path_info`: is a URL relative to this object.
        """
        if path_info in ("", "/"):
            return self
        assert path_info.startswith("/")
        name, rest = util.pop_path(path_info)
        res = self.get_member(name)
        if res is None or rest in ("", "/"):
            return res
        return res.resolve(util.join_uri(script_name, name), rest)


# ============================================================================
# _VirtualNonCollection classes
# ============================================================================
class VirtualNonCollection(DAVNonCollection):
    """Abstract base class for all non-collection resources."""

    def __init__(self, path, environ):
        self.db = environ["wsgidav.config"]["http_authenticator"]["db"]
        self.current_username = self.db.select_user_by_email(environ['wsgidav.auth.user_name'])[0]
        DAVNonCollection.__init__(self, path, environ)

    def get_content_length(self):
        return None

    def get_content_type(self):
        return None

    def get_creation_date(self):
        return None

    def get_display_name(self):
        return self.name

    def get_display_info(self):
        raise NotImplementedError

    def get_etag(self):
        return None

    def get_last_modified(self):
        return None

    def support_ranges(self):
        return False

    def handle_delete(self):
        current_file = self.current_file
        current_project = self.current_project
        current_username = self.current_username

        file_path = os.path.join('./static/files/code/', current_file['id'])
        if current_file['storage'] == 'filesystem':
            os.remove(file_path)
        self.db.delete_file(current_file['id'])
        return True

    def handle_move(self, destPath):
        current_file = self.current_file
        current_project = self.current_project
        current_username = self.current_username

        if current_project['status'] != 1:
            return False

        dest_project_name = destPath.strip('/').split('/')[0]
        dest_project_id = dest_project_name.split('_')[-1]
        dest_filename = destPath.strip('/').split('/')[1].replace('_' + current_file['id'], '')

        config_pcf = config_dict()

        if not is_valid_uuid(dest_project_id):
            return DAVError(HTTP_FORBIDDEN)

        dest_project = self.db.check_user_project_access(dest_project_id, current_username['id'])
        if not dest_project:
            return DAVError(HTTP_FORBIDDEN)

        if dest_project['status'] != 1:
            return False

        if dest_project['id'] == current_project['id']:

            without_id = dest_filename.replace('_' + current_file['id'], '')

            if without_id != current_file['filename']:
                self.db.update_file_filename(current_file['id'], without_id)
            return True

        # get content
        file_content = b''
        if current_file['storage'] == 'filesystem':
            f = open('./static/files/code/' + self.current_file['id'], 'rb')
            file_content = f.read()
            f.close()
        elif current_file['storage'] == 'database':
            file_content = base64.b64decode(current_file["base64"])

        # move content

        file_id = gen_uuid()
        file_size = len(file_content)
        if file_size > int(config_pcf['files']['files_max_size']):
            return False

        if config_pcf['files']['files_storage'] == 'filesystem':
            f = open('./static/files/code/' + file_id, 'wb')
            file_content = f.write(file_content)
            f.close()
            file_content = b''
        self.db.insert_new_file(file_id, dest_project['id'], dest_filename,
                                current_file['description'],
                                {}, current_file['type'], self.current_username['id'],
                                storage=config_pcf["files"]["files_storage"],
                                data=file_content)
        # delete old file
        self.handle_delete()

        return True


# ============================================================================
# VirtualResFile
# ============================================================================
class VirtualResFile(VirtualNonCollection):
    """Represents an existing file, that is a member of a VirtualResource."""

    def __init__(self, path, environ, data, file_path, db):
        self.db = db
        self.provider = environ["wsgidav.provider"]
        self.path = path
        self.is_collection = True
        self.environ = environ
        self.name = util.get_uri_name(self.path)

        self.current_username = self.db.select_user_by_email(environ['wsgidav.auth.user_name'])[0]

        p = path.strip('/').split('/')
        self.project_name = p[0]
        self.filename = p[1]
        project_id = self.project_name.split('_')[-1]
        file_id = self.filename.split('.')[-2].split('_')[-1]
        if not is_valid_uuid(project_id):
            return
        if not is_valid_uuid(file_id):
            return
        self.current_project = self.db.select_projects(project_id)[0]
        self.current_file = self.db.select_files(file_id)[0]
        VirtualNonCollection.__init__(self, path, environ)
        self.data = data
        self.file_path = file_path

    def is_collection(self, path, environ):
        """Return True, if path maps to an existing collection resource.

        This method should only be used, if no other information is queried
        for <path>. Otherwise a _DAVResource should be created first.
        """
        raise True

    def get_content_length(self):
        if self.current_file['storage'] == 'database':
            return len(base64.b64decode(self.current_file['base64']))
        elif self.current_file['storage'] == 'filesystem':
            return os.stat('./static/files/code/' + self.current_file['id']).st_size
        return None

    def support_etag(self):
        return False

    def get_content_type(self):
        if self.current_file['type'] == 'image':
            return "image/png"
        elif self.current_file['type'] == 'text':
            return "text/plain"
        else:
            return "application/octet-stream"

    def get_creation_date(self):
        return 0

    def get_display_info(self):
        return {"type": "Content file"}

    def get_last_modified(self):
        return 0

    def get_ref_url(self):
        refPath = "/webdav/%s/%s" % (self.project_name.replace('/', ''), self.filename)
        return quote(self.provider.share_path + refPath)

    def get_content(self):
        f = None
        if self.current_file['storage'] == 'filesystem':
            f = open('./static/files/code/' + self.current_file['id'], 'rb', BUFFER_SIZE)
            return f
        elif self.current_file['storage'] == 'database':
            f = BytesIO(base64.b64decode(self.current_file['base64']))
        return f

    def copy_move_single(self, dest_path, *, is_move):
        pass

    def begin_write(self, *, content_type=None):
        filename = self.filename
        file_id = filename.split('.')[-2].split('_')[-1]
        if not is_valid_uuid(file_id):
            return None

        current_file = self.db.select_files(file_id)
        if not current_file:
            return None
        current_file = current_file[0]
        if current_file['project_id'] != self.current_project['id']:
            return None

        if self.current_project['status'] != 1:
            return None

        if current_file['storage'] == 'database':
            self.stream = io.BytesIO(base64.b64decode(current_file['base64']))
        elif current_file['storage'] == 'filesystem':
            self.stream = open('./static/files/code/' + file_id, 'wb')
        else:
            return None
        self.current_file = current_file
        self.file_obj = FileObject(self.stream)
        return self.file_obj

    def end_write(self, *, with_errors):
        if self.current_file['storage'] == 'filesystem':
            self.stream.close()
        elif self.current_file['storage'] == 'database':
            bytes_obj = self.stream.getvalue()
            self.stream.close()
            self.db.update_file_base64(bytes_obj)
        else:
            return False
        return True


class Lock_manager(LockManager):
    """
    Disable locking at all
    """

    def check_write_permission(self, **kwargs):
        pass


# ============================================================================
# VirtualResourceProvider
# ============================================================================
class VirtualResourceProvider(DAVProvider):
    """
    DAV provider that serves a VirtualResource derived structure.
    """

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.current_user = None
        self.share_path = '/webdav'
        self.lock_manager = None

    def set_share_path(self, share_path):
        self.share_path = "/webdav"

    def get_resource_inst(self, path, environ):
        """Return _VirtualResource object for path.
        path is expected to be
            categoryType/category/name/artifact
        for example:
            'by_tag/cool/My doc 2/info.html'
        See DAVProvider.get_resource_inst()
        """
        self._count_get_resource_inst += 1
        self.current_user = environ['current_user']
        # check if it is a correct object
        self.current_user['id']
        root = RootCollection(environ, self.db, self.current_user)
        return_obj = root.resolve("", path)
        return return_obj

    def set_lock_manager(self, lock_manager):
        self.lock_manager = Lock_manager(LockStorageDict())


class PAMDomainController(BaseDomainController):
    def __init__(self, wsgidav_app, config):
        self.db = config['http_authenticator']['db']
        super().__init__(wsgidav_app, config)
        self.current_user = None

    def get_domain_realm(self, path_info, environ):
        return ""

    def require_authentication(self, realm, environ):
        return True

    def basic_auth_user(self, realm, user_name, password, environ):
        current_user = check_basic_auth(user_name, password, self.db)
        if not current_user:
            return False
        self.current_user = current_user
        environ['current_user'] = current_user
        return True

    def supports_http_digest_auth(self):
        # We don't have access to a plaintext password (or stored hash)
        return False
