import os
import importlib

__globals = globals()

modules = []

for file in os.listdir(os.path.dirname(__file__)):
    if '__' not in file:
        mod_name = file[:-3]   # strip .py at the end
        module_obj = importlib.import_module('.' + mod_name, package=__name__)
        modules.append(module_obj)