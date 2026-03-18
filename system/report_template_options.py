def group_issues_by(issues_dict, field_name):
    additional_field = False
    if field_name.startswith("field_"):
        additional_field = True
        field_name = field_name[6:]
    result_arr = {}
    for issue_id in issues_dict:
        issue_obj = issues_dict[issue_id]
        if additional_field:
            group_val = issue_obj["fields"][field_name]["val"] if field_name in issue_obj["fields"] else ''
        else:
            group_val = issue_obj[field_name] if field_name in issue_obj else ''
        if group_val not in result_arr:
            result_arr[group_val] = []
        result_arr[group_val].append(issue_id)
    return result_arr


def csv_escape(s):
    return str(s).strip() \
        .replace('\\', '\\\\') \
        .replace('\r\n', '\n') \
        .replace('\r', '\n') \
        .replace('"', '""')


def issue_targets_list(issue_obj, hostnames, ports):
    result = []
    services_dict = issue_obj['services']
    for port_id in services_dict:
        port_obj = ports[port_id]
        postfix = ''
        if not port_obj['is_tcp']:
            postfix = '/udp'
        ip = services_dict[port_id]['ip']
        if services_dict[port_id]['is_ip']:
            s = ip + ':' + str(port_obj['port']) + postfix
            result.append(s)
        hostnames_list = services_dict[port_id]['hostnames']
        for hostname_id in hostnames_list:
            s = hostnames[hostname_id]['hostname'] + ':' + str(port_obj['port']) + postfix
            result.append(s)

    result = list(set(result))
    return result