from flask import Blueprint

routes = Blueprint('routes', __name__)

from .project import *
from .struct import *
from .tools import *
