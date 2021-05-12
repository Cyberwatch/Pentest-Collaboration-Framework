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
