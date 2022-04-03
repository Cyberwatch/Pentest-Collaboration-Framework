import re

from func_timeout import func_timeout, FunctionTimedOut


def run_function_timeout(func_obj, timeout: float, *args, **kwargs):
    try:
        return_value = func_timeout(timeout, func_obj, args=args, kwargs=kwargs)
    except FunctionTimedOut:
        return_value = None
    return return_value


def latex_str_escape(s: str):
    change_dict = {'\\': '',  # TODO: fix later to $\\backslash$
                   '\n': '\\newline ',
                   '\r': '',
                   '{': '',
                   '}': '',
                   '$': '\\$',
                   '(': '$($',
                   ')': '$)$',
                   '_': '\\_',
                   '=': '$=$',
                   '#': '\\#',
                   '%': '\\%',
                   '&': '\\&',
                   '"': '$"$',
                   "'": "$'$",
                   "^": "\\^{}",
                   }
    result = s
    for change_char in change_dict:
        result = result.replace(change_char, change_dict[change_char])

    return result


def htmlspecialchars(s: str):
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def sql_to_regexp(s: str):
    '''
    "%test%" -> "[\s\S]*test[\s\S]*"
    '''
    m = s.split('%')
    new_regexp = re.escape(m[0])
    for x in m[1:]:
        new_regexp += r'[\s\S]*' + re.escape(x)
    return '^' + new_regexp + '$'


def extract_to_regexp(s: str):
    '''
    "%te<>st%" -> "[\s\S]*te([\s\S]*)st[\s\S]*"
    '''
    m = s.split('%')
    new_regexp = re.escape(m[0])
    not_found = True
    for x in m[1:]:
        if '<>' in x and not_found:
            new_regexp += r'[\s\S]*' + re.escape(x.split('<>')[0]) + r'([\s\S]*)' + re.escape(x.split('<>')[1])
            not_found = False
    return '^' + new_regexp + '$'
