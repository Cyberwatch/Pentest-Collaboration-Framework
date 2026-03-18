import json


def val_db_fixer(config, db):
    print("This script will fix database value -> val for: Issues, Issue templates, Issue rules")
    print("More info: https://gitlab.com/invuls/pentest-projects/pcf/-/issues/156")
    print(
        "It will replace all 'value' to 'val'. If there will be two fields like 'val' & 'value' -> it will remove 'value', so better to recheck backup later. ")
    print("Fixing Issues table")
    db.execute("SELECT id, fields FROM Issues")
    result = db.return_arr_dict()
    count = 0
    for issue_obj in result:
        need_to_fix = False
        j = json.loads(issue_obj["fields"])
        for var_name in j:
            if "value" in j[var_name]:
                need_to_fix = True
                count += 1
                if 'val' not in j[var_name]:
                    j[var_name]['val'] = j[var_name]['value']
                del j[var_name]['value']
        if need_to_fix:
            db.update_issue_fields(issue_obj["id"], j)

    print("Fixed {} Issues rows!".format(count))

    print("Fixing IssueRules table")
    db.execute("SELECT id, search_rules, extract_vars FROM IssueRules")
    result = db.return_arr_dict()
    count = 0
    for rule_obj in result:
        need_to_fix_search = False
        need_to_fix_extract = False
        j_search = json.loads(rule_obj["search_rules"])
        j_extract = json.loads(rule_obj["extract_vars"])

        j_search_new = []
        j_extract_new = []

        for search_obj in j_search:
            if "value" in search_obj:
                need_to_fix_search = True
                if "val" not in search_obj:
                    search_obj['val'] = search_obj['value']
                del search_obj['value']
            j_search_new.append(search_obj)

        for extract_obj in j_extract:
            if "value" in extract_obj:
                need_to_fix_extract = True
                if "val" not in extract_obj:
                    extract_obj['val'] = extract_obj['value']
                del extract_obj['value']
            j_extract_new.append(extract_obj)


        if need_to_fix_search:
            db.execute(
                '''UPDATE IssueRules set search_rules=? WHERE id=?''',
                (json.dumps(j_search_new), rule_obj['id'])
            )
        if need_to_fix_extract:
            db.execute(
                '''UPDATE IssueRules set extract_vars=? WHERE id=?''',
                (json.dumps(j_extract_new), rule_obj['id'])
            )
        if need_to_fix_search or need_to_fix_extract:
            count += 1
            db.conn.commit()
    print("Fixed {} IssueRules rows!".format(count))

    print("Fixing IssueTemplates table")
    db.execute("SELECT id, variables, fields FROM IssueTemplates")
    result = db.return_arr_dict()
    count = 0
    for template_obj in result:
        need_to_fix_vars = False
        need_to_fix_fields = False
        j_vars = json.loads(template_obj["variables"])
        j_fields = json.loads(template_obj["fields"])


        for var_name in j_vars:
            if "value" in j_vars[var_name]:
                need_to_fix_vars = True
                if "val" not in j_vars[var_name]:
                    j_vars[var_name]['val'] = j_vars[var_name]['value']
                del j_vars[var_name]['value']

        for field_name in j_fields:
            if "value" in j_fields[field_name]:
                need_to_fix_fields = True
                if "val" not in j_fields[field_name]:
                    j_fields[field_name]['val'] = j_fields[field_name]['value']
                del j_fields[field_name]['value']

        if need_to_fix_vars:
            db.execute(
                '''UPDATE IssueTemplates set variables=? WHERE id=?''',
                (json.dumps(j_vars), template_obj['id'])
            )
        if need_to_fix_fields:
            db.execute(
                '''UPDATE IssueTemplates set fields=? WHERE id=?''',
                (json.dumps(j_vars), template_obj['id'])
            )
        if need_to_fix_vars or need_to_fix_fields:
            count += 1
            db.conn.commit()
    print("Fixed {} IssueTemplates rows!".format(count))
