import sqlite3
# from supersqlite import sqlite3
from system.config_load import config_dict
from system.crypto_functions import *
import json
from os import remove, path, environ
import time
import ipaddress
import threading
import re
import psycopg2
from base64 import b64encode
import qmarkpg
from markdownify import markdownify


class Database:
    db_path = config_dict()['database']['path']
    cursor = None
    conn = None
    config = None
    db_type = None
    current_user = {}
    current_team = {}
    current_project = {}

    def __init__(self, config):
        self.db_type = config['database']['type']
        if config['database']['type'] == 'postgres':
            # fix for heroku
            if 'DATABASE_URL' in environ:
                DATABASE_URL = environ['DATABASE_URL']
                self.conn = qmarkpg.connect(DATABASE_URL, sslmode='require')
            else:
                self.conn = qmarkpg.connect(dbname=config['database']['name'], user=config['database']['login'],
                                            password=config['database']['password'], host=config['database']['host'], port=config['database']['port'])
                self.conn.autocommit = True
        elif config['database']['type'] == 'sqlite3':
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.create_function("REGEXP", 2, self.regexp)

        self.cursor = self.conn.cursor()
        self.config = config
        self.lock = threading.Lock()
        return

    def regexp(self, expr, item):
        reg = re.compile(expr)
        return reg.search(item) is not None

    def config_update(self, current_user, current_team={}, current_project={}):
        self.current_user = current_user
        self.current_team = current_team
        self.current_project = current_project

    def execute(self, sql, arg1=()):
        # TODO: if threads will be blocked
        if self.db_type == 'sqlite3':
            self.lock.acquire()
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.create_function("REGEXP", 2, self.regexp)
            self.cursor = self.conn.cursor()
            self.cursor.execute(sql, arg1)
            self.lock.release()
        else:
            self.cursor.execute(sql, arg1)

    def return_arr_dict(self):
        if self.db_type == 'sqlite3':
            # self.lock.acquire()
            try:
                ncols = len(self.cursor.description)
                colnames = [self.cursor.description[i][0] for i in range(ncols)]
                results = []
                for row in self.cursor.fetchall():
                    res = {}
                    for i in range(ncols):
                        res[colnames[i]] = row[i]
                    results.append(res)
            except:
                results = []
            finally:
                # self.cursor.close()
                # self.lock.release()
                pass
        else:
            try:
                ncols = len(self.cursor.description)
                colnames = [self.cursor.description[i][0] for i in range(ncols)]
                results = []
                for row in self.cursor.fetchall():
                    res = {}
                    for i in range(ncols):
                        res[colnames[i]] = row[i]
                    results.append(res)
            except:
                results = []
        return results

    def insert_user(self, email, password):
        user_id = gen_uuid()
        password_hash = hash_password(password)
        self.execute(
            "INSERT INTO Users(id,email,password) VALUES (?,?,?)",
            (user_id, email, password_hash)
        )
        self.conn.commit()
        return user_id

    def select_user_by_email(self, email):
        self.execute('SELECT * FROM Users WHERE email=?', (email,))
        result = self.return_arr_dict()
        return result

    def select_user_by_id(self, user_id):
        # TODO: fix threads
        self.execute('SELECT * FROM Users WHERE id=?', (user_id,))
        result = self.return_arr_dict()
        return result

    def update_user_info(self, user_id, fname, lname, email, company):
        self.execute('''UPDATE Users SET fname=?, 
                                                lname=?, 
                                                email=?, 
                                                company=? 
                               WHERE id=?''',
                     (fname, lname, email, company, user_id))
        self.conn.commit()
        return

    def update_user_password(self, id, password):
        password_hash = hash_password(password)
        self.execute('''UPDATE Users SET password=? WHERE id=?''',
                     (password_hash, id))
        self.conn.commit()
        return

    def insert_team(self, name, description, user_id):
        team_id = gen_uuid()
        self.execute(
            "INSERT INTO Teams(id,admin_id,name,description,admin_email,users) "
            "VALUES (?,?,?,?,(SELECT email FROM Users WHERE id=? LIMIT 1),?)",
            (team_id,
             user_id,
             name,
             description,
             user_id,
             '{{"{}":"admin"}}'.format(user_id))  # initiation of json dict
        )
        self.conn.commit()

        self.insert_log('Team "{}" was created!'.format(name), teams=[team_id])

        return str(team_id)

    def delete_team(self, team_id):
        self.execute("DELETE FROM Teams WHERE id=?", (team_id,))
        self.conn.commit()

        return

    def delete_team_safe(self, team_id):
        # unpin projects
        projects = self.select_team_projects(team_id)

        for project in projects:
            teams = json.loads(project['teams'])
            if team_id in teams:
                del teams[teams.index(team_id)]
                self.update_project_teams(project['id'], teams)

        # unpin logs

        # TODO: add to config availability to delete logs

        # unpin templates

        self.delete_team_report_templates(team_id)

        # unpin configs

        self.delete_team_configs(team_id)

        # unpin templates

        self.delete_team_issue_templates(team_id)

        # delete team

        self.delete_team(team_id)

        return True

    def update_team_info(self, team_id, name, admin_email, description,
                         user_id):
        self.execute(
            '''UPDATE Teams SET name=?,admin_email=?,description=? WHERE id=?''',
            (name, admin_email, description, team_id))
        self.conn.commit()
        self.insert_log('Team information was updated!')
        return

    def select_team_by_id(self, team_id):
        self.execute('SELECT * FROM Teams WHERE id=?', (team_id,))
        result = self.return_arr_dict()
        return result

    def update_new_team_user(self, team_id, user_email, role='tester'):
        curr_users_data = json.loads(
            self.select_team_by_id(team_id)[0]['users'])
        curr_user = self.select_user_by_email(user_email)[0]
        curr_users_data[curr_user['id']] = role
        self.execute(
            '''UPDATE Teams SET users=? WHERE id=?''',
            (json.dumps(curr_users_data), team_id))
        self.conn.commit()
        self.insert_log('User {} role was changed to {}!'.format(user_email,
                                                                 role))
        return

    def get_log_by_team_id(self, team_id, limit=10000000000000, offset=0):
        # TODO: need to optimise
        self.execute(
            '''SELECT * FROM Logs WHERE teams LIKE '%' || ? || '%' ORDER BY date DESC LIMIT ? OFFSET ?''',
            (team_id, limit, offset))
        result = self.return_arr_dict()
        return result

    def insert_log(self, description, user_id='', teams=[], project_id='',
                   date=-1):
        if date == -1:
            date = int(time.time())
        if not project_id and 'id' in self.current_project:
            project_id = self.current_project['id']

        if not teams and 'id' in self.current_team:
            teams = [self.current_team]

        if not user_id and 'id' in self.current_user:
            user_id = self.current_user['id']

        if project_id and project_id == self.current_project['id'] \
                and not teams:
            teams = json.dumps(self.current_project['teams'])
        self.execute(
            '''INSERT INTO Logs(id,teams,description,date,user_id,project) 
               VALUES (?,?,?,?,?,?)''',
            (gen_uuid(), json.dumps(teams), description, date, user_id,
             project_id)
        )
        self.conn.commit()
        return

    def select_user_teams(self, user_id):
        self.execute(
            "SELECT * FROM Teams WHERE admin_id=? or users like '%' || ? || '%' ",
            (user_id, user_id))
        result = self.return_arr_dict()
        return result

    def select_user_team_members(self, user_id):
        teams = self.select_user_teams(user_id)
        members = []
        for team in teams:
            current_team = self.select_team_by_id(team['id'])[0]
            users = json.loads(current_team['users'])
            members += [user for user in users]
        members = list(set(members))

        members_info = []
        for member in members:
            members_info += self.select_user_by_id(member)
        return members_info

    def insert_new_project(self, name, description, project_type, scope,
                           start_date, end_date, auto_archive, testers,
                           teams, admin_id, user_id):
        project_id = gen_uuid()
        self.execute(
            "INSERT INTO Projects(id,name,description,type,scope,start_date,"
            "end_date,auto_archive,status,testers,teams,admin_id) "
            "VALUES (?,?,?,?,?,?,?,?,1,?,?,?)",
            (project_id,
             name,
             description,
             project_type,
             scope,
             int(start_date),
             int(end_date),
             int(auto_archive),
             json.dumps(testers),
             json.dumps(teams),
             admin_id)  # initiation of json dict
        )
        self.conn.commit()
        self.insert_log('Project {} was created!'.format(name), teams=teams)
        return project_id

    def check_admin_team(self, team_id, user_id):
        team = self.select_team_by_id(team_id)
        if not team:
            return False
        team = team[0]
        users = json.loads(team['users'])
        return team['admin_id'] == user_id or (
                user_id in users and users[user_id] == 'admin')

    def delete_user_from_team(self, team_id, user_id_delete, user_id):
        self.execute('SELECT * FROM Teams WHERE id=?', (team_id,))
        team = self.return_arr_dict()
        if not team:
            return 'Team does not exist.'
        team = team[0]
        if team['admin_id'] == user_id_delete:
            return 'Can\'t kick team creator.'
        users = json.loads(team['users'])
        if user_id_delete not in users:
            return 'User is not in team'
        del users[user_id_delete]

        self.execute(
            "UPDATE Teams set users=? WHERE id=?",
            (json.dumps(users), team_id)
        )
        self.conn.commit()
        current_user = self.select_user_by_id(user_id_delete)[0]
        self.insert_log('User {} was removed from team!'.format(
            current_user['email']))

        return ''

    def devote_user_from_team(self, team_id, user_id_devote, user_id):

        self.execute('SELECT * FROM Teams WHERE id=?', (team_id,))
        team = self.return_arr_dict()
        if not team:
            return 'Team does not exist.'
        team = team[0]
        if team['admin_id'] == user_id_devote:
            return 'Can\'t devote team creator.'
        users = json.loads(team['users'])
        if user_id_devote not in users:
            return 'User is not in team'
        if users[user_id_devote] != 'admin':
            return 'User is not team administrator.'

        users[user_id_devote] = 'tester'

        self.execute(
            "UPDATE Teams set users=? WHERE id=?",
            (json.dumps(users), team_id)
        )
        self.conn.commit()
        current_user = self.select_user_by_id(user_id_devote)[0]
        self.insert_log(
            'User {} was devoted to tester!'.format(current_user['email']))

        return ''

    def set_admin_team_user(self, team_id, user_id_admin, user_id):

        self.execute('SELECT * FROM Teams WHERE id=?', (team_id,))
        team = self.return_arr_dict()
        if not team:
            return 'Team does not exist.'
        team = team[0]
        if team['admin_id'] == user_id_admin:
            return 'User is already admin.'
        users = json.loads(team['users'])
        if user_id_admin not in users:
            return 'User is not in team'
        if users[user_id_admin] != 'tester':
            return 'User is not team tester.'

        if users[user_id_admin] == 'admin':
            return 'User is already admin.'

        users[user_id_admin] = 'admin'

        self.execute(
            "UPDATE Teams set users=? WHERE id=?",
            (json.dumps(users), team_id)
        )
        self.conn.commit()
        current_user = self.select_user_by_id(user_id_admin)[0]
        self.insert_log(
            'User {} was promoted to admin!'.format(current_user['email']))
        return ''

    def select_team_projects(self, team_id):
        self.execute(
            '''SELECT * FROM Projects WHERE teams LIKE '%' || ? || '%' ''',
            (team_id,))
        result = self.return_arr_dict()
        return result

    def select_projects(self, project_id):
        self.execute(
            '''SELECT * FROM Projects WHERE id=? ''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_user_projects(self, user_id):
        projects = []
        user_teams = self.select_user_teams(user_id)
        for team in user_teams:
            team_projects = self.select_team_projects(team['id'])
            for team_project in team_projects:
                found = 0
                for added_project in projects:
                    if added_project['id'] == team_project['id']:
                        found = 1
                if not found:
                    projects.append(team_project)
        self.execute(
            '''SELECT * FROM Projects WHERE testers LIKE '%' || ? || '%' or admin_id=?''',
            (user_id, user_id))
        user_projects = self.return_arr_dict()
        for user_project in user_projects:
            found = 0
            for added_project in projects:
                if added_project['id'] == user_project['id']:
                    found = 1
            if not found:
                projects.append(user_project)
        return projects

    def check_user_project_access(self, project_id, user_id):
        user_projects = self.select_user_projects(user_id)
        for user_project in user_projects:
            if user_project['id'] == project_id:
                return user_project
        return None

    def select_project_hosts(self, project_id):
        self.execute(
            '''SELECT * FROM Hosts WHERE project_id=? ORDER BY ip ASC''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_ip_hostnames(self, host_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id=?''',
            (host_id,))
        result = self.return_arr_dict()
        return result

    def select_ip_from_project(self, project_id, ip):
        self.execute(
            '''SELECT * FROM Hosts WHERE project_id=? and ip=?''',
            (project_id, ip))
        result = self.return_arr_dict()
        return result

    def insert_host(self, project_id, ip, user_id,
                    comment='', threats=[], os=''):
        # todo refactor later - delete project_id and set current_project
        ip_id = gen_uuid()
        self.execute(
            '''INSERT INTO Hosts(id,project_id,ip,comment,user_id,threats,os) 
               VALUES (?,?,?,?,?,?,?)''',
            (ip_id, project_id, ip, comment, user_id, json.dumps(threats), os)
        )
        self.conn.commit()
        self.insert_log('Added ip {}'.format(ip))
        self.insert_host_port(str(ip_id), 0, 1, 'info',
                              'Information about whole host', user_id,
                              project_id)

        return str(ip_id)

    def select_host(self, host_id):
        self.execute(
            '''SELECT * FROM Hosts WHERE id=?''',
            (host_id,))
        result = self.return_arr_dict()
        return result

    def select_project_host(self, project_id, host_id):
        self.execute(
            '''SELECT * FROM Hosts WHERE id=? and project_id=?''',
            (host_id, project_id))
        result = self.return_arr_dict()
        return result

    def update_host_comment_threats(self, host_id, comment, threats, os):
        self.execute(
            '''UPDATE Hosts SET comment=?,threats=?,os=? WHERE id=?''',
            (comment, json.dumps(threats), os, host_id))
        self.conn.commit()
        self.insert_log('Updated ip {} description'.format(
            self.select_host(host_id)[0]['ip'])
        )
        return

    def update_host_os(self, host_id, os):
        self.execute(
            '''UPDATE Hosts SET os=? WHERE id=?''',
            (os, host_id))
        self.conn.commit()
        self.insert_log('Updated ip {} operating system'.format(
            self.select_host(host_id)[0]['ip'])
        )
        return

    def delete_host(self, host_id):
        current_host = self.select_host(host_id)
        if not current_host:
            return
        current_host = current_host[0]
        self.execute(
            '''DELETE FROM Hosts WHERE id=?''',
            (host_id,))
        self.conn.commit()
        self.insert_log('Deleted ip {}'.format(current_host['ip']))
        return

    def delete_host_safe(self, project_id, host_id):
        host = self.select_project_host(project_id, host_id)
        if not host:
            return
        current_host = host[0]
        # delete ports
        ports = self.select_host_ports(current_host['id'], full=True)
        for current_port in ports:
            self.delete_port_safe(current_port['id'])

        # delete hostnames
        hostnames = self.select_ip_hostnames(host_id)
        for hostname in hostnames:
            self.delete_hostname_safe(hostname['id'])

        # delete network paths
        self.delete_path_by_host(project_id=project_id,
                         host_id=current_host['id'])

        # delete host
        self.delete_host(host_id)
        return

    def delete_issue_safe(self, project_id, issue_id):
        # delete field files
        current_issue = self.select_issue(issue_id)
        if not current_issue or current_issue[0]['project_id'] != project_id:
            return
        current_issue = current_issue[0]
        fields = json.loads(current_issue['fields'])
        for field_name in fields:
            if fields[field_name]['type'] == 'file':
                self.delete_file(fields[field_name]['value'])

        # delete issue
        self.delete_issue(issue_id, project_id)
        return

    def delete_hostname_safe(self, hostname_id):

        current_hostname = self.select_hostname(hostname_id)
        if not current_hostname:
            return

        # delete issue & pocs connection

        self.delete_issues_with_hostname(hostname_id)

        # delete networks

        self.delete_network_with_hostname(hostname_id)

        # delete files

        self.update_files_services_hostnames(hostname_id)

        # delete creds
        self.update_creds_hostnames(hostname_id)

        # delete hostname

        self.delete_hostname(hostname_id)

    def insert_host_port(self, host_id, port, is_tcp, service, description,
                         user_id, project_id):
        # check port in host
        curr_port = self.select_ip_port(host_id, port, is_tcp)
        if curr_port:
            return 'exist'
        port_id = gen_uuid()
        self.execute(
            '''INSERT INTO Ports(
            id,host_id,port,is_tcp,service,description,user_id,project_id) 
               VALUES (?,?,?,?,?,?,?,?)''',
            (port_id, host_id, port, int(is_tcp), service, description, user_id,
             project_id)
        )
        self.conn.commit()
        if port != 0:
            self.insert_log('Added port {}({}) to ip {}'.format(
                port,
                'tcp' if is_tcp else 'udp',
                self.select_host(host_id)[0]['ip']))
        return port_id

    def select_host_ports(self, host_id, full=False):
        if not full:
            self.execute(
                '''SELECT * FROM Ports WHERE host_id=? and port != 0 ORDER BY port''',
                (host_id,))
        else:
            self.execute(
                '''SELECT * FROM Ports WHERE host_id=? ORDER BY port''',
                (host_id,))
        result = self.return_arr_dict()
        return result

    def select_host_port(self, host_id, port_num=0, is_tcp=True):
        self.execute(
            '''SELECT * FROM Ports WHERE host_id=? AND port=? and is_tcp=?''',
            (host_id, port_num, int(is_tcp)))
        result = self.return_arr_dict()
        return result

    def find_ip_hostname(self, host_id, hostname):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id=? AND hostname=?''',
            (host_id, hostname))
        result = self.return_arr_dict()
        return result

    def insert_hostname(self, host_id, hostname, description, user_id):
        hostname_id = gen_uuid()
        self.execute(
            '''INSERT INTO Hostnames(
            id,host_id,hostname,description,user_id) 
               VALUES (?,?,?,?,?)''',
            (hostname_id, host_id, hostname, description, user_id)
        )
        self.conn.commit()
        self.insert_log(
            'Added hostname {} to host {}'.format(
                hostname, self.select_host(host_id)[0]['ip']))
        return hostname_id

    def update_hostname(self, hostname_id, description):
        self.execute(
            '''UPDATE Hostnames SET description=? WHERE id=?''',
            (description, hostname_id))
        self.conn.commit()
        self.insert_log('Updated hostname {} description'.format(
            self.select_hostname(hostname_id)[0]['hostname'])
        )
        return

    def check_host_hostname_id(self, host_id, hostname_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id=? AND id=?''',
            (host_id, hostname_id))
        result = self.return_arr_dict()
        return result

    def delete_hostname(self, hostname_id):
        current_hostname = self.select_hostname(hostname_id)[0]
        self.execute(
            '''DELETE FROM Hostnames WHERE id=?''',
            (hostname_id,))
        self.conn.commit()
        self.insert_log(
            'Deleted hostname {}'.format(current_hostname['hostname']))
        return

    def check_port_in_project(self, project_id, port_id):
        self.execute(
            '''SELECT project_id FROM Hosts WHERE 
            id=(SELECT host_id FROM Ports WHERE id=? LIMIT 1) 
            and project_id=? ''',
            (port_id, project_id))
        result = self.return_arr_dict()
        return result

    def select_port(self, port_id):
        self.execute(
            '''SELECT * FROM Ports WHERE id=?''',
            (port_id,))
        result = self.return_arr_dict()
        return result

    def select_hostname(self, hostname_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE id=?''',
            (hostname_id,))
        result = self.return_arr_dict()
        return result

    def select_project_hostname(self, project_id, hostname_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE id=? and  host_id IN (select id from Hosts WHERE project_id=?)''',
            (hostname_id, project_id))
        result = self.return_arr_dict()
        return result

    def insert_new_issue(self, name, description, url_path, cvss, user_id,
                         services, status, project_id, cve='', cwe=0,
                         issue_type='custom', fix='', param='', fields={}):
        issue_id = gen_uuid()
        self.execute(
            '''INSERT INTO Issues(
            id,name,description,url_path,cvss,user_id,services,status, project_id, cve,cwe,type,fix,param,fields) 
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (issue_id, name, description, url_path, cvss, user_id,
             json.dumps(services), status, project_id, cve, cwe, issue_type,
             fix, param, json.dumps(fields))
        )
        self.conn.commit()
        self.insert_log('Added issue "{}"'.format(name))
        return issue_id

    def update_issue_text_fields(self, issue_id, fields: dict):
        self.execute(
            '''UPDATE Issues SET fields=? WHERE id=?''',
            (json.dumps(fields), issue_id))
        self.conn.commit()
        self.insert_log('Updated issue {} fields'.format(
            self.select_issue(issue_id)[0]['name'])
        )
        return

    def update_issue_cvss(self, issue_id, cvss):
        self.execute(
            '''UPDATE Issues SET cvss=? WHERE id=?''',
            (cvss, issue_id))
        self.conn.commit()
        self.insert_log('Updated issue {} cvss to {}'.format(
            self.select_issue(issue_id)[0]['name'], cvss)
        )
        return

    def update_issue_field(self, issue_id, field_name, field_type, field_value):
        if field_type in ["text", "number", "float", "boolean"]:
            current_issue = self.select_issue(issue_id)[0]

            if field_type == "text":
                type_func = str
            elif field_type == "number":
                type_func = int
            elif field_type == "float":
                type_func = float
            elif field_type == "boolean":
                type_func = lambda x: bool(int(x))
            field_value = type_func(field_value)

            fields_dict = json.loads(current_issue['fields'])
            fields_dict[field_name] = {}
            fields_dict[field_name]['value'] = field_value
            fields_dict[field_name]['type'] = field_type

            self.execute(
                '''UPDATE Issues SET fields=? WHERE id=?''',
                (json.dumps(fields_dict), issue_id))
            self.conn.commit()
            self.insert_log('Updated issue {} field "{}"'.format(
                self.select_issue(issue_id)[0]['name'], field_name)
            )
        return

    def search_issue_dublicates(self, name, description, url_path, cvss, status, project_id, cve='', cwe=0,
                                issue_type='custom', fix='', param=''):
        self.execute(
            '''SELECT * FROM Issues WHERE name=? AND description=? AND url_path=? AND cvss=? AND status=? 
            AND project_id=? AND cve=? AND cwe=? AND type=? AND fix=? AND param=?''',
            (name, description, url_path, cvss, status, project_id, cve, cwe, issue_type, fix, param))
        result = self.return_arr_dict()
        return result

    def search_hostname_hosts(self, project_id, hostname):
        self.execute(
            '''SELECT * FROM Hosts WHERE id in (SELECT host_id FROM Hostnames WHERE hostname = ?) and project_id=?''',
            (hostname, project_id))
        result = self.return_arr_dict()
        return result

    def update_hostnames_description(self, project_id, hostname, hostname_description):
        self.execute(
            '''UPDATE hostnames set description=? WHERE hostname=? AND host_id IN (SELECT id FROM hosts WHERE project_id=?)''',
            (hostname_description, hostname, project_id))
        self.conn.commit()
        self.insert_log('Updated whois hosts info')
        return

    def insert_new_issue_no_dublicate(self, name, description, url_path, cvss, user_id,
                                      services, status, project_id, cve='', cwe=0,
                                      issue_type='custom', fix='', param=''):

        issue_dublicates = self.search_issue_dublicates(name, description, url_path, cvss, status, project_id,
                                                        cve, cwe, issue_type, fix, param)

        if issue_dublicates:
            dublicate_id = issue_dublicates[0]['id']
            old_services = json.loads(issue_dublicates[0]['services'])
            for port_id in services:
                if port_id not in old_services:
                    old_services[port_id] = []
                for hostname_id in services[port_id]:
                    if hostname_id not in old_services[port_id]:
                        old_services[port_id].append(hostname_id)
            self.update_issue_services(dublicate_id, old_services)
            issue_id = dublicate_id
        else:
            # create new issue
            issue_id = self.insert_new_issue(name, description, url_path, cvss, user_id,
                                             services, status, project_id, cve, cwe, issue_type, fix, param)
        return issue_id

    def select_project_issues(self, project_id):
        self.execute(
            '''SELECT * FROM Issues WHERE project_id=? ORDER BY cvss DESC''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_port_issues(self, port_id):
        self.execute(
            '''SELECT * FROM Issues WHERE services LIKE '%' || ? || '%' ORDER BY cvss DESC''',
            (port_id,))
        result = self.return_arr_dict()
        return result

    def select_port_networks(self, port_id):
        self.execute(
            '''SELECT * FROM Networks WHERE access_from LIKE '%' || ? || '%' ''',
            (port_id,))
        result = self.return_arr_dict()
        return result

    def select_host_by_port_id(self, port_id):
        self.execute(
            '''SELECT * FROM Hosts WHERE 
            id=(SELECT host_id FROM Ports WHERE id=?)''',
            (port_id,))
        result = self.return_arr_dict()
        return result

    def select_issue(self, issue_id):
        self.execute(
            '''SELECT * FROM Issues WHERE id=?''',
            (issue_id,))
        result = self.return_arr_dict()
        return result

    def update_issue(self, issue_id, name, description, url_path, cvss,
                     services, status, cve, cwe, fix, issue_type, param):
        self.execute(
            '''UPDATE Issues SET name=?, description=?, url_path=?, cvss=?, 
            services=?, status=?, cve=?, cwe=?, fix=?, type=?, param=? WHERE id=?''',
            (name, description, url_path, cvss,
             json.dumps(services), status, cve, cwe, fix, issue_type,
             param, issue_id)
        )
        self.conn.commit()
        self.insert_log('Updated issue {}'.format(name))

    def check_hostname_port_in_issue(self, hostname_id, port_id, issue_id):
        current_issue = self.select_issue(issue_id)[0]
        services = json.loads(current_issue['services'])
        if port_id not in services:
            return False
        if hostname_id not in services[port_id]:
            return False
        return True

    def select_issue_flagged_pocs(self, issue_id):
        self.execute(
            '''SELECT * FROM PoC WHERE issue_id=? and priority=1''',
            (issue_id,))
        result = self.return_arr_dict()
        return result

    def insert_new_poc(self, port_id, description, file_type, filename,
                       issue_id,
                       user_id, hostname_id, poc_id='random', storage='filesystem', data=b''):
        if poc_id == 'random':
            poc_id = gen_uuid()

        priority = 1
        pocs = self.select_issue_flagged_pocs(issue_id)
        if pocs:
            priority = 0

        self.execute(
            '''INSERT INTO PoC(
            id,port_id,description,type,filename,
            issue_id,user_id,hostname_id,priority,storage, base64) 
               VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (poc_id, port_id, description, file_type, filename, issue_id,
             user_id, hostname_id, priority, storage, base64.b64encode(data).decode('charmap'))
        )
        self.conn.commit()
        current_issue = self.select_issue(issue_id)[0]
        self.insert_log('Added PoC {} to issue {}'.format(poc_id,
                                                          current_issue['name']))
        return str(poc_id)

    def select_issue_pocs(self, issue_id):
        self.execute(
            '''SELECT * FROM PoC WHERE issue_id=?''',
            (issue_id,))
        result = self.return_arr_dict()
        return result

    def select_poc(self, poc_id):
        self.execute(
            '''SELECT * FROM PoC WHERE id=?''',
            (poc_id,))
        result = self.return_arr_dict()
        return result

    def update_poc_priority(self, poc_id, priority=0):

        curr_poc = self.select_poc(poc_id)

        if not curr_poc:
            return

        self.execute(
            '''UPDATE PoC SET priority=? WHERE id=?''',
            (priority, poc_id))
        self.conn.commit()

        return

    def delete_poc(self, poc_id):
        removed_poc = self.select_poc(poc_id)[0]
        self.execute(
            '''DELETE FROM PoC WHERE id=?''',
            (poc_id,))
        self.conn.commit()
        if self.config['main']['auto_delete_poc'] == '1':
            poc_path = path.join('./static/files/poc/', poc_id)
            remove(poc_path)
            self.insert_log('Deleted PoC {} with file'.format(poc_id))
        self.insert_log('Deleted PoC {} without file.'.format(poc_id))
        if removed_poc['priority']:
            priority_pocs = self.select_issue_flagged_pocs(removed_poc['issue_id'])
            if not priority_pocs:
                pocs = self.select_issue_pocs(removed_poc['issue_id'])
                if pocs:
                    self.update_poc_priority(pocs[0]['id'], 1)
        return

    def delete_issue(self, issue_id, project_id):
        current_issue = self.select_issue(issue_id)[0]
        self.execute(
            '''DELETE FROM Issues WHERE id=? and project_id=?''',
            (issue_id, project_id))
        self.conn.commit()
        self.insert_log('Deleted Issue {}'.format(current_issue['name']))
        return

    def insert_new_network(self, ip, mask, asn, comment, project_id, user_id,
                           is_ipv6, internal_ip='', cmd='', services={}, name=''):
        network_id = gen_uuid()
        self.execute(
            '''INSERT INTO Networks(
            id,ip,mask,comment,project_id,user_id,is_ipv6,asn,internal_ip, cmd, access_from, name) 
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (network_id, ip, mask, comment, project_id, user_id, int(is_ipv6),
             int(asn or 0), internal_ip, cmd, json.dumps(services), name)
        )
        self.conn.commit()
        self.insert_log('Added new network {}/{}'.format(ip, mask))
        return network_id

    def update_network(self, network_id, project_id, ip, mask, asn, comment,
                       is_ipv6, internal_ip='', cmd='', services={}, name=''):
        self.execute(
            '''UPDATE Networks SET ip=?, mask=?, comment=?, is_ipv6=?, asn=?, internal_ip=?, cmd=?, access_from=?, name=?
            WHERE id=? and project_id=?''',
            (ip, mask, comment, int(is_ipv6), int(asn or 0), internal_ip, cmd,
             json.dumps(services),name, str(network_id), str(project_id))
        )
        self.conn.commit()
        self.insert_log('Updated network {}/{}'.format(ip, mask))
        return

    def select_project_networks(self, project_id):
        self.execute(
            '''SELECT * FROM Networks WHERE project_id=?''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_project_networks_by_id(self, project_id, network_id):
        self.execute(
            '''SELECT * FROM Networks WHERE project_id=? AND id=?''',
            (project_id, network_id))
        result = self.return_arr_dict()
        return result

    def select_project_network_by_ip(self, project_id, ip, mask):
        self.execute(
            '''SELECT * FROM Networks WHERE project_id=? AND ip=? AND mask=?''',
            (project_id, ip, int(mask)))
        result = self.return_arr_dict()
        return result

    def delete_network_safe(self, network_id):
        current_network = self.select_network(network_id)[0]

        if not current_network:
            return
        current_network = current_network[0]

        # delete network paths
        self.delete_path_by_network(project_id=current_network['project_id'],
                         network_id=current_network['id'])

        # delete network
        self.delete_network(network_id)
        return

    def delete_network(self, network_id):
        current_network = self.select_network(network_id)[0]
        self.execute(
            '''DELETE FROM Networks WHERE id=?''',
            (network_id,))
        self.conn.commit()
        self.insert_log('Deleted network {}/{}'.format(current_network['ip'],
                                                       current_network['mask']))
        return

    def select_network(self, network_id):
        self.execute(
            '''SELECT * FROM Networks WHERE id=?''',
            (network_id,))
        result = self.return_arr_dict()
        return result

    def select_network_by_ip(self, project_id, gateway, mask, ipv6=0):
        self.execute(
            '''SELECT * FROM Networks WHERE ip=? and mask=? and is_ipv6=? and project_id=?''',
            (gateway, int(mask), int(ipv6), project_id))
        result = self.return_arr_dict()
        return result

    def insert_new_cred(self, login, password_hash, hash_type,
                        cleartext_passwd, description, source,
                        services, user_id, project_id):
        cred_id = gen_uuid()
        self.execute(
            '''INSERT INTO Credentials(
            id,login,hash,hash_type,cleartext,
            description,source,services, user_id, project_id)
             VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (cred_id, login, password_hash, hash_type, cleartext_passwd,
             description, source, json.dumps(services), user_id, project_id)
        )
        self.conn.commit()
        self.insert_log('Added new credentials {}'.format(cred_id))
        return cred_id

    def select_project_creds(self, project_id):
        self.execute(
            '''SELECT * FROM Credentials WHERE project_id=?''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_creds(self, creds_id):
        self.execute(
            '''SELECT * FROM Credentials WHERE id=?''',
            (creds_id,))
        result = self.return_arr_dict()
        return result

    def select_creds_dublicates(self, project_id, login, hash_str, cleartext, comment, source, hash_type):
        self.execute(
            '''SELECT * FROM Credentials WHERE login=? AND hash=? AND cleartext=? 
            AND description=? AND source=? AND project_id=? AND hash_type=?''',
            (login, hash_str, cleartext, comment, source, str(project_id), hash_type))
        result = self.return_arr_dict()
        return result

    def delete_creds(self, creds_id):
        self.execute(
            '''DELETE FROM Credentials WHERE id=?''',
            (creds_id,))
        self.conn.commit()
        self.insert_log('Deleted credentials {}'.format(creds_id))
        return

    def delete_chat(self, chat_id):
        current_chat = self.select_chat(chat_id)
        if current_chat:
            self.execute(
                '''DELETE FROM Chats WHERE id=?''',
                (chat_id,))
            self.conn.commit()
            self.insert_log('Removed chat {}'.format(current_chat[0]['name']))
        return

    def update_chat_name(self, chat_id, new_name):
        current_chat = self.select_chat(chat_id)
        if current_chat:
            self.execute(
                '''UPDATE Chats SET name=? WHERE id=?''',
                (new_name, chat_id,))
            self.conn.commit()
            self.insert_log('Rename chat {} to {}'.format(current_chat[0]['name'], new_name))
        return

    def delete_chat_all_messages(self, chat_id):
        self.execute(
            '''DELETE FROM Messages WHERE chat_id=?''',
            (chat_id,))
        self.conn.commit()
        self.insert_log('Removed all chat {} messages'.format(chat_id))
        return

    def update_creds(self, creds_id, login, password_hash, hash_type,
                     cleartext_passwd, description, source,
                     services):
        self.execute(
            '''UPDATE Credentials SET login=?,hash=?,hash_type=?,cleartext=?,
            description=?,source=?,services=? WHERE id=?''',
            (login, password_hash, hash_type, cleartext_passwd,
             description, source, json.dumps(services), creds_id)
        )
        self.conn.commit()
        self.insert_log('Updated credentials {}'.format(creds_id))
        return

    def select_project_notes(self, project_id, host_id=''):
        self.execute(
            '''SELECT * FROM Notes WHERE project_id=? and host_id = ? ''',
            (project_id, host_id))
        result = self.return_arr_dict()
        return result

    def select_all_project_notes(self, project_id):
        self.execute(
            '''SELECT * FROM Notes WHERE project_id=?''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_project_note(self, project_id, note_id):
        self.execute(
            '''SELECT * FROM Notes WHERE project_id=? and id = ? ''',
            (project_id, note_id))
        result = self.return_arr_dict()
        return result

    def select_project_host_notes(self, project_id):
        self.execute(
            '''SELECT  * FROM Hosts WHERE project_id=? AND id IN (SELECT host_id FROM Notes WHERE project_id=?); ''',
            (project_id, project_id))
        result = self.return_arr_dict()
        return result

    def select_note(self, note_id):
        self.execute(
            '''SELECT * FROM Notes WHERE id=?''',
            (note_id,))
        result = self.return_arr_dict()
        return result

    def select_host_notes(self, host_id, project_id):
        self.execute(
            '''SELECT * FROM Notes WHERE host_id=? AND project_id=?''',
            (host_id, project_id))
        result = self.return_arr_dict()
        return result

    def insert_new_note(self, project_id, name, user_id, host_id='', text=''):
        note_id = gen_uuid()
        self.execute(
            '''INSERT INTO Notes(
            id,project_id,name,text,user_id,host_id) 
               VALUES (?,?,?,?,?,?)''',
            (note_id, project_id, name, text, user_id, host_id)
        )
        self.conn.commit()
        self.insert_log('Created new note "{}"'.format(name))
        return note_id

    def update_note(self, note_id, text_data, project_id):
        current_note = self.select_note(note_id)[0]
        self.execute(
            '''UPDATE Notes SET text=? WHERE id=? AND project_id=?''',
            (text_data, note_id, project_id)
        )
        self.conn.commit()
        self.insert_log('Edited note {}'.format(current_note['name']))
        return

    def update_note_name(self, note_id, name, project_id):
        self.execute(
            '''UPDATE Notes SET name=? WHERE id=? AND project_id=?''',
            (name, note_id, project_id)
        )
        self.conn.commit()
        self.insert_log('Renamed note {}'.format(name))
        return

    def delete_note(self, note_id, project_id):
        current_note = self.select_note(note_id)[0]
        self.execute(
            '''DELETE FROM Notes WHERE id=? AND project_id=?''',
            (note_id, project_id)
        )
        self.conn.commit()
        self.insert_log('Deleted note {}'.format(current_note['name']))
        return

    def insert_new_file(self, file_id, project_id, filename, description,
                        services, filetype, user_id, storage, data=b''):

        # todo: fix file_id param
        self.execute(
            '''INSERT INTO Files(
            id,project_id,filename,description,
            services,type,user_id,storage,base64) VALUES (?,?,?,?,?,?,?,?,?)''',
            (file_id, project_id, filename, description,
             json.dumps(services), filetype, user_id, storage, base64.b64encode(data).decode('charmap'))
        )
        self.conn.commit()
        self.insert_log('Added new file {}'.format(filename))
        return file_id

    def select_files(self, file_id):
        self.execute(
            '''SELECT * FROM Files WHERE id=?''',
            (file_id,))
        result = self.return_arr_dict()
        return result

    def select_host_files(self, host_id):
        ports = self.select_host_ports(host_id, full=True)
        file_ids = []
        result = []
        for port in ports:
            files = self.select_files_by_port(port['id'])
            for file in files:
                if file['id'] not in file_ids:
                    result.append(file)
                    file_ids.append(file['id'])
        return result

    def select_project_files(self, project_id):
        self.execute(
            '''SELECT * FROM Files WHERE project_id=? AND type != 'report' AND type != 'field' ''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_project_reports(self, project_id):
        self.execute(
            '''SELECT * FROM Files WHERE project_id=? AND type = 'report' ''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def delete_file(self, file_id):
        current_file = self.select_files(file_id)[0]
        self.execute(
            '''DELETE FROM Files WHERE id=?''',
            (file_id,))
        self.conn.commit()
        self.insert_log('Deleted file {}'.format(current_file['filename']))
        return

    def update_project_status(self, project_id, status):
        # TODO: add data types to functions status: int
        self.execute(
            '''UPDATE Projects SET status=? WHERE id=? ''',
            (status, project_id)
        )
        self.conn.commit()
        self.insert_log('Updated project status to {}'.format(int(status)))
        return

    def update_project_settings(self, project_id, name, description,
                                project_type, scope,
                                start_date, end_date, auto_archive, testers,
                                teams):
        self.execute(
            "UPDATE Projects set name=?,description=?,type=?,"
            "scope=?,start_date=?,"
            "end_date=?,auto_archive=?,"
            "testers=?,teams=? WHERE id=? ",
            (name,
             description,
             project_type,
             scope,
             int(start_date),
             int(end_date),
             int(auto_archive),
             json.dumps(testers),
             json.dumps(teams),
             project_id)
        )
        self.conn.commit()
        self.insert_log('Updated project settings ')
        return

    def update_project_teams(self, project_id, teams):
        self.execute(
            "UPDATE Projects set teams=? WHERE id=? ",
            (json.dumps(teams),
             project_id)
        )
        self.conn.commit()
        self.insert_log('Updated project teams.')
        return

    def update_project_autoarchive(self, project_id, autoarchive):
        self.execute(
            '''UPDATE Projects SET auto_archive=? WHERE id=? ''',
            (autoarchive, project_id)
        )
        self.conn.commit()
        self.insert_log(
            'Updated project autoarchive param to {}'.format(int(autoarchive)))
        return

    def select_project_host_by_ip(self, project_id, ip):
        self.execute(
            '''SELECT * FROM Hosts WHERE project_id=? and ip=?''',
            (project_id, ip))
        result = self.return_arr_dict()
        return result

    def select_ip_hostname(self, host_id, hostname):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id=? and hostname=?''',
            (host_id, hostname))
        result = self.return_arr_dict()
        return result

    def select_ip_hostnames(self, host_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id=?''',
            (host_id,))
        result = self.return_arr_dict()
        return result

    def select_ip_port(self, host_id, port, is_tcp=True):
        self.execute(
            '''SELECT * FROM Ports WHERE host_id=? and port=? and is_tcp=?''',
            (host_id, port, int(is_tcp)))
        result = self.return_arr_dict()
        return result

    def update_port_proto_description(self, port_id, service, description):
        current_port = self.select_port(port_id)[0]
        current_host = self.select_host(current_port['host_id'])[0]
        self.execute(
            '''UPDATE Ports SET service=?, description=? WHERE id=? ''',
            (service, description, port_id)
        )
        self.conn.commit()
        self.insert_log('Updated port {}:{}({}) info'.format(
            current_host['ip'],
            current_port['port'],
            'tcp' if current_port['is_tcp'] else 'udp')
        )
        return

    def update_port_service(self, port_id, service):
        current_port = self.select_port(port_id)[0]
        current_host = self.select_host(current_port['host_id'])[0]
        self.execute(
            '''UPDATE Ports SET service=? WHERE id=? ''',
            (service, port_id)
        )
        self.conn.commit()
        self.insert_log('Updated {}:{}({}) service info'.format(
            current_host['ip'],
            current_port['port'],
            'tcp' if current_port['is_tcp'] else 'udp'))
        return

    def select_host_issues(self, host_id):
        self.execute(
            '''SELECT * FROM Ports WHERE host_id=?''',
            (host_id,))
        ports = self.return_arr_dict()
        result = []
        for port in ports:
            issues = self.select_port_issues(port['id'])
            for issue in issues:
                if issue not in result:
                    result.append(issue)
        return result

    def select_port_issues_stats(self, port_id):
        port_issues = self.select_port_issues(port_id)
        criticality = {'info': [], 'low': [], 'medium': [], 'high': [],
                       'critical': []}
        for issue in port_issues:
            if issue['cvss'] == 0:
                criticality['info'].append(issue)
            elif issue['cvss'] <= 3.9:
                criticality['low'].append(issue)
            elif issue['cvss'] <= 6.9:
                criticality['medium'].append(issue)
            elif issue['cvss'] <= 8.9:
                criticality['high'].append(issue)
            else:
                criticality['critical'].append(issue)
        return criticality

    def update_issue_services(self, issue_id, services):
        current_issue = self.select_issue(issue_id)[0]
        self.execute(
            '''UPDATE Issues SET services=? WHERE id=? ''',
            (json.dumps(services), issue_id)
        )
        self.conn.commit()
        self.insert_log(
            'Updated issue {} services'.format(current_issue['name']))
        return

    def update_issue_fields(self, issue_id, fields: dict):
        current_issue = self.select_issue(issue_id)[0]
        self.execute(
            '''UPDATE Issues SET fields=? WHERE id=? ''',
            (json.dumps(fields), issue_id)
        )
        self.conn.commit()
        self.insert_log(
            'Updated issue {} fields'.format(current_issue['name']))
        return

    def delete_issue_host(self, issue_id, host_id):
        ports = self.select_host_ports(host_id, full=True)
        issue = self.select_issue(issue_id)
        if not issue:
            return
        issue = issue[0]
        issue_services = json.loads(issue['services'])
        old_services = issue_services.copy()
        for port in ports:
            if port['id'] in issue_services:
                del issue_services[port['id']]
        if old_services != issue_services:
            self.update_issue_services(issue_id, issue_services)
        current_issue = self.select_issue(issue_id)[0]
        self.insert_log('Updated issue {} hosts'.format(current_issue['name']))
        return

    def delete_issues_with_port(self, port_id):
        issues = self.select_port_issues(port_id)
        for issue in issues:
            services = json.loads(issue['services'])
            del services[port_id]
            self.execute(
                '''UPDATE Issues SET services=? WHERE id=? ''',
                (json.dumps(services), issue['id'])
            )
            self.conn.commit()

            self.insert_log('Updated issue {} ports'.format(issue['name']))

            pocs = self.select_issue_pocs(issue['id'])

            for poc in pocs:
                if poc['port_id'] == port_id:
                    self.delete_poc(poc['id'])
        return

    def delete_network_with_port(self, port_id):
        networks = self.select_port_networks(port_id)
        for network in networks:
            services = json.loads(network['access_from'])
            del services[port_id]
            self.execute(
                '''UPDATE Networks SET access_from=? WHERE id=? ''',
                (json.dumps(services), network['id'])
            )
            self.conn.commit()

            self.insert_log('Updated network {}/{} ports'.format(network['ip'], network['mask']))

        return

    def select_hostname_issues(self, hostname_id):
        self.execute(
            '''SELECT * FROM Issues WHERE services LIKE '%' || ? || '%' ORDER BY cvss DESC''',
            (hostname_id,))
        result = self.return_arr_dict()
        return result

    def select_hostname_networks(self, hostname_id):
        self.execute(
            '''SELECT * FROM Networks WHERE access_from LIKE '%' || ? || '%' ''',
            (hostname_id,))
        result = self.return_arr_dict()
        return result

    def delete_issues_with_hostname(self, hostname_id):
        if hostname_id == '0':
            return
        issues = self.select_hostname_issues(hostname_id)
        for issue in issues:
            services = json.loads(issue['services'])
            for port_id in services:
                if hostname_id in services[port_id]:
                    del services[port_id][services[port_id].index(hostname_id)]
            self.execute(
                '''UPDATE Issues SET services=? WHERE id=? ''',
                (json.dumps(services), issue['id'])
            )
            self.conn.commit()

            self.insert_log('Updated issue {} hosts'.format(issue['name']))

            pocs = self.select_issue_pocs(issue['id'])

            for poc in pocs:
                if poc['hostname_id'] == hostname_id:
                    self.delete_poc(poc['id'])
        return

    def delete_network_with_hostname(self, hostname_id):
        if hostname_id == '0':
            return
        networks = self.select_hostname_networks(hostname_id)
        for network in networks:
            services = json.loads(network['access_from'])
            for port_id in services:
                if hostname_id in services[port_id]:
                    del services[port_id][services[port_id].index(hostname_id)]
            self.execute(
                '''UPDATE Networks SET access_from=? WHERE id=? ''',
                (json.dumps(services), network['id'])
            )
            self.conn.commit()

            self.insert_log('Updated network {}/{} hosts'.format(network['ip'], network['mask']))

        return

    def select_files_by_port(self, port_id):
        self.execute(
            '''SELECT * FROM Files WHERE services LIKE '%' || ? || '%' ''',
            (port_id,))
        files = self.return_arr_dict()
        return files

    def select_files_by_hostname(self, hostname_id):
        self.execute(
            '''SELECT * FROM Files WHERE services LIKE '%' || ? || '%' ''',
            (hostname_id,))
        files = self.return_arr_dict()
        return files

    def update_files_services_ports(self, port_id):
        files = self.select_files_by_port(port_id)

        for file in files:
            file_services = json.loads(file['services'])
            del file_services[port_id]
            self.execute(
                '''UPDATE Files SET services=? WHERE id=? ''',
                (json.dumps(file_services), file['id'])
            )
            self.conn.commit()
            self.insert_log('Updated file {} services'.format(file['filename']))

        return

    def update_files_services_hostnames(self, hostname_id):
        if hostname_id == '0':
            return
        files = self.select_files_by_hostname(hostname_id)

        for file in files:
            file_services = json.loads(file['services'])
            for port_id in file_services:
                if hostname_id in file_services[port_id]:
                    del file_services[port_id][
                        file_services[port_id].index(hostname_id)]
            self.execute(
                '''UPDATE Files SET services=? WHERE id=? ''',
                (json.dumps(file_services), file['id'])
            )
            self.conn.commit()
            self.insert_log(
                'Updated file {} hostnames'.format(file['filename']))

        return

    def select_creds_by_port(self, port_id):
        self.execute(
            '''SELECT * FROM Credentials WHERE services LIKE '%' || ? || '%' ''',
            (port_id,))
        result = self.return_arr_dict()
        return result

    def select_creds_by_host(self, project_id, host_id):
        host_port_ids = [port['id'] for port in self.select_host_ports(host_id, full=True)]
        project_creds = self.select_project_creds(project_id)
        if not project_creds or not host_port_ids:
            return []
        creds_array = []

        for current_creds in project_creds:
            services = json.loads(current_creds['services'])
            found = 0
            for port_id in services:
                if port_id in host_port_ids:
                    found = 1
            if found:
                creds_array.append(current_creds)
        return creds_array

    def select_creds_by_hostname(self, hostname_id):
        self.execute(
            '''SELECT * FROM Credentials WHERE services LIKE '%' || ? || '%' ''',
            (hostname_id,))
        result = self.return_arr_dict()
        return result

    def update_creds_services(self, port_id):

        creds = self.select_creds_by_port(port_id)

        for cred in creds:
            cred_services = json.loads(cred['services'])
            del cred_services[port_id]
            self.execute(
                '''UPDATE Credentials SET services=? WHERE id=? ''',
                (json.dumps(cred_services), cred['id'])
            )
            self.conn.commit()
            self.insert_log('Updated credentials {} ports'.format(cred['id']))
        return

    def update_creds_hostnames(self, hostname_id):

        creds = self.select_creds_by_hostname(hostname_id)

        for cred in creds:
            cred_services = json.loads(cred['services'])
            for port_id in cred_services:
                if hostname_id in cred_services[port_id]:
                    del cred_services[port_id][
                        cred_services[port_id].index(hostname_id)]
            self.execute(
                '''UPDATE Credentials SET services=? WHERE id=? ''',
                (json.dumps(cred_services), cred['id'])
            )
            self.conn.commit()
            self.insert_log(
                'Updated credentials {} hostnames'.format(cred['id']))
        return

    def delete_port_safe(self, port_id):

        # delete port

        self.execute(
            '''DELETE FROM Ports WHERE id=? ''',
            (port_id,)
        )
        self.conn.commit()

        # delete issue & pocs connection

        self.delete_issues_with_port(port_id)

        # delete network connection

        self.delete_network_with_port(port_id)

        # delete files

        self.update_files_services_ports(port_id)

        # delete creds
        self.update_creds_services(port_id)

    def select_project_hosts_by_port(self, project_id, port):

        self.execute(
            '''SELECT * FROM Hosts WHERE id IN 
            (SELECT host_id FROM Ports WHERE port=? AND 
            host_id IN (SELECT id FROM Hosts WHERE project_id=? )) ''',
            (port, project_id))
        result = self.return_arr_dict()
        return result

    def select_project_hosts_by_subnet(self, project_id, subnet):

        # subnet = 127.0.0.1/2
        subnet_obj = ipaddress.ip_network(subnet, False)

        result = []
        hosts = self.select_project_hosts(project_id)
        for current_host in hosts:
            ip_obj = ipaddress.ip_address(current_host['ip'])
            if ip_obj in subnet_obj:
                result.append(current_host)
        return result

    def search_host(self, project_id, search_request):

        search_request = search_request.strip()

        all_hosts = self.select_project_hosts(project_id)

        if not search_request:
            return all_hosts

        # split by params

        params_dict = {}
        try:
            params_arr = search_request.split(' ')
            for param in params_arr:
                param_data = param.split('=')
                params_dict[param_data[0]] = param_data[1]
        except:
            pass

        if params_dict:
            if 'port' in params_dict:
                return self.select_project_hosts_by_port(project_id,
                                                         params_dict['port'])
            if 'subnet' in params_dict:
                return self.select_project_hosts_by_subnet(project_id,
                                                           params_dict[
                                                               'subnet'])

        # find by ip/comment

        self.execute(
            '''SELECT * FROM Hosts WHERE project_id=? and (ip LIKE '%' || ? || '%' or 
            comment LIKE '%' || ? || '%') ''',
            (project_id, search_request, search_request))
        hosts = self.return_arr_dict()

        # find by hostname

        for host in all_hosts:
            hostname = self.select_ip_hostnames(host['id'])
            if hostname and search_request in hostname[0]['hostname']:
                found = 0
                # check if host_id in hosts
                for check_host in hosts:
                    if check_host['id'] == hostname[0]['host_id']:
                        found = 1
                if not found:
                    hosts += self.select_project_host(project_id,
                                                      hostname[0]['host_id'])
        return hosts

    def search_hostlist(self, project_id=None, network='', ip_hostname='',
                        issue_name='', port='', service='', comment='',
                        threats=''):

        all_hosts = self.select_project_hosts(project_id)

        if not network and not ip_hostname and not issue_name and not port and \
                not service and not comment and not threats:
            return all_hosts

        # host filter
        if not ip_hostname:
            ip_hostname_result = all_hosts
        else:
            self.execute(
                '''SELECT * FROM Hosts WHERE ((ip LIKE '%' || ? || '%') and 
                (project_id = ?)) or id IN (SELECT host_id FROM Hostnames WHERE 
                project_id=? and lower(hostname) LIKE lower('%' || ? || '%'))''',
                (ip_hostname, project_id, project_id, ip_hostname))
            ip_hostname_result = self.return_arr_dict()

        # network filter
        if not network:
            network_result = all_hosts
        else:
            network_result = []
            for network_id in network.split(','):
                if is_valid_uuid(network_id):
                    network = self.select_network(network_id)[0]
                    ip = network['ip']
                    mask = network['mask']
                    subnet = '{}/{}'.format(ip, mask)
                    for host in all_hosts:
                        if ipaddress.ip_address(host['ip']) in \
                                ipaddress.ip_network(subnet, False):
                            network_result.append(host)

        # issue filter
        if not issue_name:
            issue_result = all_hosts
        else:
            self.execute(
                '''SELECT * FROM Issues WHERE (((lower(name) LIKE lower('%' || ? || '%')) or id=?) and 
                (project_id = ?))''',
                (issue_name, issue_name, project_id))
            issues = self.return_arr_dict()
            issue_result = []
            for issue in issues:
                services = [service for service in
                            json.loads(issue['services'])]
                for curr_service in services:
                    host_id = self.select_port(curr_service)[0]['host_id']
                    host = self.select_host(host_id)[0]
                    issue_result.append(host)

        # comment filter
        if not comment:
            comment_result = all_hosts
        else:
            comment_result = []
            for host in all_hosts:
                if comment.lower() in host['comment'].lower():
                    comment_result.append(host)

        # threats filter
        if not threats:
            threats_result = all_hosts
        else:
            threats_set = set(threats)
            threats_result = []
            for host in all_hosts:
                host_theats = set(json.loads(host['threats']))
                if host_theats & threats_set:
                    threats_result.append(host)

        # port_service
        if (not port) and (not service):
            port_service_result = all_hosts
        else:
            service = service.lower() if service else ''
            service_regex = '|'.join(service.split(','))
            if port:
                port_array = port.split(',')
                port_regexp = '|'.join(
                    ['^' + str(int(port.split('/')[0])) + '/' + \
                     str(int(port.split('/')[1] == 'tcp')) + '$' \
                     for port in port_array])
                if self.db_type == 'sqlite3':
                    self.execute(
                        '''SELECT * FROM Hosts WHERE project_id=? and id IN 
                        (SELECT host_id FROM Ports WHERE (port || '/' || is_tcp) REGEXP ? and 
                        LOWER(service) REGEXP ?)''',
                        (project_id, port_regexp, service_regex))
                elif self.db_type == 'postgres':
                    self.execute(
                        '''SELECT * FROM Hosts WHERE project_id=? and id IN 
                                                (SELECT host_id FROM Ports WHERE (port || '/' || is_tcp) ~ ? and 
                                                LOWER(service) ~ ?)''',
                        (project_id, port_regexp, service_regex))
                port_service_result = self.return_arr_dict()
            else:
                if self.db_type == 'sqlite3':
                    self.execute(
                        '''SELECT * FROM Hosts WHERE project_id=? and id IN 
                        (SELECT host_id FROM Ports WHERE 
                        service REGEXP ?)''',
                        (project_id, service_regex))
                elif self.db_type == 'postgres':
                    self.execute(
                        '''SELECT * FROM Hosts WHERE project_id=? and id IN 
                        (SELECT host_id FROM Ports WHERE 
                        service ~ ?)''',
                        (project_id, service_regex))
                port_service_result = self.return_arr_dict()

        # summary
        unique_results = []
        for host in all_hosts:
            if all(host in i for i in
                   (all_hosts, ip_hostname_result, network_result,
                    issue_result, comment_result, threats_result,
                    port_service_result)):
                unique_results.append(host)

        return unique_results

    def search_issues(self, project_id, search_request):
        all_issues = self.select_project_issues(project_id)
        if not search_request:
            return all_issues

        # find name, description, status

        self.execute(
            '''SELECT * FROM Issues WHERE project_id = ? and (
                name LIKE '%' || ? || '%' or 
                description LIKE '%' || ? || '%' or 
                url_path LIKE '%' || ? || '%' or 
                cve LIKE '%' || ? || '%' or 
                status LIKE '%' || ? || '%' or 
                type LIKE '%' || ? || '%' or 
                fix LIKE '%' || ? || '%' or
                param LIKE '%' || ? || '%') ORDER BY cvss DESC''',
            (project_id, search_request, search_request,
             search_request, search_request, search_request,
             search_request, search_request, search_request))
        issues = self.return_arr_dict()

        # find host issues

        self.execute(
            '''SELECT * FROM Hosts WHERE project_id=? and (ip LIKE '%' || ? || '%')  ''',
            (project_id, search_request))
        hosts = self.return_arr_dict()

        for host in hosts:
            host_issues = self.select_host_issues(host['id'])
            for current_issue in host_issues:
                found = 0
                for added_issue in issues:
                    if added_issue['id'] == current_issue['id']:
                        found = 1
                if not found:
                    issues.append(current_issue)
        return issues

    def search_issues_port_ids(self, project_id, issues_name):
        self.execute(
            '''SELECT * FROM Issues WHERE project_id = ? and 
                name LIKE '%' || ? || '%' ''',
            (project_id, issues_name))
        issues = self.return_arr_dict()

        ports_result = []

        for issue in issues:
            ports_result += [port for port in
                             json.loads(issue['services'])]

        return ports_result

    def select_project_ports(self, project_id):
        self.execute(
            '''SELECT * FROM Ports WHERE project_id=? ORDER BY port,is_tcp''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_project_port(self, project_id, port_id):
        self.execute(
            '''SELECT * FROM Ports WHERE project_id=? and id=? ORDER BY port,is_tcp''',
            (project_id, port_id))
        result = self.return_arr_dict()
        return result

    def select_project_ports_unique(self, project_id):
        results = self.select_project_ports(project_id)
        unique_results = []
        for port in results:
            found = 0
            for added_port in unique_results:
                if added_port['port'] == port['port'] and \
                        added_port['is_tcp'] == port['is_tcp']:
                    found = 1
            if not found and port['port'] != 0:
                unique_results.append(port)
        return unique_results

    def select_project_ports_grouped(self, project_id):
        all_ports = self.select_project_ports(project_id)
        # port, is_tcp, service, description, host_id:[]
        grouped_ports = []

        project_issues = self.select_project_issues(project_id)

        for port in all_ports:
            found = 0
            for added_port in grouped_ports:
                if added_port['port'] == port['port'] and \
                        added_port['is_tcp'] == port['is_tcp'] and \
                        added_port['service'] == port['service'] and \
                        added_port['description'] == port['description'] and \
                        port['host_id'] not in added_port['host_id']:
                    added_port['host_id'].append(port['host_id'])
                    for issue in project_issues:
                        if port['id'] in issue['services']:
                            if issue and 'cvss' in issue:
                                if issue['cvss'] == 0 and \
                                        'info' not in added_port['issues']:
                                    added_port['issues'].append('info')
                                elif issue['cvss'] <= 3.9 and \
                                        'low' not in added_port['issues']:
                                    added_port['issues'].append('low')
                                elif issue['cvss'] <= 6.9 and \
                                        'medium' not in added_port['issues']:
                                    added_port['issues'].append('medium')
                                elif issue['cvss'] <= 8.9 and \
                                        'high' not in added_port['issues']:
                                    added_port['issues'].append('high')
                                elif 'critical' not in added_port['issues']:
                                    added_port['issues'].append('critical')
                    found = 1
            if not found and port['port'] != 0:
                new_port = {}
                new_port['port'] = port['port']
                new_port['is_tcp'] = port['is_tcp']
                new_port['service'] = port['service']
                new_port['description'] = port['description']
                new_port['host_id'] = [port['host_id']]
                new_port['issues'] = []
                for issue in project_issues:
                    # strange bug, TODO later for better fix :)
                    if port['id'] in issue['services']:
                        if issue and 'cvss' in issue:
                            if issue['cvss'] == 0 and \
                                    'info' not in new_port['issues']:
                                new_port['issues'].append('info')
                            elif issue['cvss'] <= 3.9 and \
                                    'low' not in new_port['issues']:
                                new_port['issues'].append('low')
                            elif issue['cvss'] <= 6.9 and \
                                    'medium' not in new_port['issues']:
                                new_port['issues'].append('medium')
                            elif issue['cvss'] <= 8.9 and \
                                    'high' not in new_port['issues']:
                                new_port['issues'].append('medium')
                            elif 'critical' not in new_port['issues']:
                                new_port['issues'].append('critical')
                grouped_ports.append(new_port)
        return grouped_ports

    def update_host_description(self, host_id, comment):
        self.execute(
            '''UPDATE Hosts SET comment=? WHERE id=? ''',
            (comment, host_id)
        )
        self.conn.commit()
        current_host = self.select_host(host_id)[0]
        self.insert_log(
            'Updated host {} description'.format(current_host['ip']))
        return

    def update_host_description(self, host_id, comment):
        self.execute(
            '''UPDATE Hosts SET comment=? WHERE id=? ''',
            (comment, host_id)
        )
        self.conn.commit()
        current_host = self.select_host(host_id)[0]
        self.insert_log(
            'Updated host {} description'.format(current_host['ip']))
        return

    def select_project_chats(self, project_id, js=False):
        self.cursor.close()
        self.cursor = self.conn.cursor()
        self.execute(
            '''SELECT * FROM Chats WHERE project_id=? ''',
            (project_id,))
        result = self.return_arr_dict()
        if js:
            return [x['id'] for x in result]
        return result

    def select_project_chat(self, project_id, chat_id):
        self.execute(
            '''SELECT * FROM Chats WHERE project_id=? and id=? ''',
            (project_id, chat_id))
        result = self.return_arr_dict()
        return result

    def select_chat(self, chat_id):
        self.execute(
            '''SELECT * FROM Chats WHERE id=? ''',
            (chat_id,))
        result = self.return_arr_dict()
        return result

    def select_chat_messages(self, chat_id, date=-1):
        self.execute(
            '''SELECT * FROM Messages WHERE chat_id=? AND time>? ORDER BY time''',
            (chat_id, date))
        result = self.return_arr_dict()
        return result

    def insert_chat(self, project_id, name, user_id):
        chat_id = gen_uuid()
        self.execute(
            '''INSERT INTO Chats(
            id,project_id,name,user_id) 
               VALUES (?,?,?,?)''',
            (chat_id, project_id, name, user_id)
        )
        self.conn.commit()
        self.insert_log('Created new chat {}'.format(name))
        return chat_id

    def insert_new_message(self, chat_id, message, user_id):
        message_id = gen_uuid()
        message_time = int(time.time() * 1000)
        self.execute(
            '''INSERT INTO Messages(
            id,chat_id,message,user_id,time) 
               VALUES (?,?,?,?,?)''',
            (message_id, chat_id, message, user_id, message_time)
        )
        self.conn.commit()
        current_chat = self.select_chat(chat_id)
        self.insert_log('Wrote a message to chat "{}"'.format(
            current_chat[0]['name'])
        )
        return message_time

    def insert_new_http_sniffer(self, name, project_id):
        sniffer_id = gen_uuid()
        self.execute(
            '''INSERT INTO tool_sniffer_http_info(
            id,project_id,name,status,
            location,body) VALUES (?,?,?,?,?,?)''',
            (sniffer_id, project_id, name, 200, '', '')
        )
        self.conn.commit()
        self.insert_log('Added new HTTP-sniffer {}'.format(name))
        return

    def select_project_http_sniffers(self, project_id):
        self.execute(
            '''SELECT * FROM tool_sniffer_http_info WHERE project_id=?''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_http_sniffer_by_id(self, sniffer_id):
        self.execute(
            '''SELECT * FROM tool_sniffer_http_info WHERE id=?''',
            (sniffer_id,))
        result = self.return_arr_dict()
        return result

    def update_http_sniffer(self, sniffer_id, status, location, body, save_credentials):
        self.execute(
            '''UPDATE tool_sniffer_http_info SET status=?,
                  location=?,body=?,save_credentials=? WHERE id=? ''',
            (status, location, body, save_credentials, sniffer_id)
        )
        self.conn.commit()
        current_sniffer = self.select_http_sniffer_by_id(sniffer_id)[0]
        self.insert_log(
            'Updated HTTP-sniffer {} info'.format(current_sniffer['name']))
        return

    def insert_new_http_sniffer_package(self, sniffer_id, date, ip, request):
        package_id = gen_uuid()
        self.execute(
            '''INSERT INTO tool_sniffer_http_data(
            id,sniffer_id,date,ip,request) VALUES (?,?,?,?,?)''',
            (package_id, sniffer_id, date, ip, request)
        )
        self.conn.commit()
        self.insert_log('Captured HTTP-sniffer package')
        return

    def select_http_sniffer_requests(self, sniffer_id):
        self.execute(
            '''SELECT * FROM tool_sniffer_http_data WHERE sniffer_id=? ORDER BY date''',
            (sniffer_id,))
        result = self.return_arr_dict()
        return result

    def delete_http_sniffer_requests(self, sniffer_id):
        self.execute(
            '''DELETE FROM tool_sniffer_http_data WHERE sniffer_id=?''',
            (sniffer_id,))
        current_sniffer = self.select_http_sniffer_by_id(sniffer_id)[0]
        self.insert_log(
            'Cleared HTTP-sniffer {} requests'.format(current_sniffer['name']))

    def delete_http_sniffer(self, sniffer_id):
        current_sniffer = self.select_http_sniffer_by_id(sniffer_id)[0]
        self.execute(
            '''DELETE FROM tool_sniffer_http_info WHERE id=?''',
            (sniffer_id,))
        self.insert_log(
            'Removed HTTP-sniffer {}'.format(current_sniffer['name']))

    def safe_delete_http_sniffer(self, sniffer_id):
        self.delete_http_sniffer_requests(sniffer_id)
        self.delete_http_sniffer(sniffer_id)
        return

    def insert_config(self, team_id='0', user_id='0', name='', display_name='',
                      data='', visible=0):
        config_id = gen_uuid()
        self.execute(
            '''INSERT INTO Configs(
            id,team_id,user_id,name,display_name,
            data,visible) VALUES (?,?,?,?,?,?,?)''',
            (config_id, team_id, user_id, name, display_name, data, visible)
        )
        self.conn.commit()
        self.insert_log('Added "{}" config value'.format(display_name))
        return config_id

    def select_configs(self, team_id='0', user_id='0', name=''):
        self.execute(
            '''SELECT * FROM Configs WHERE team_id=? and user_id=? and 
            name LIKE '%' || ? || '%' ''',
            (team_id, user_id, name))
        result = self.return_arr_dict()
        return result

    def update_config(self, team_id='0', user_id='0', name='', value=''):
        self.execute(
            '''UPDATE Configs SET data = ? WHERE team_id=? and user_id=? and 
            name= ?  ''',
            (value, team_id, user_id, name))
        self.conn.commit()
        self.insert_log('Updated "{}" config value'.format(name))
        return

    def delete_config(self, team_id='0', user_id='0', name=''):
        self.execute(
            '''DELETE FROM Configs WHERE team_id=? and user_id=? and 
            name= ?  ''',
            (team_id, user_id, name))
        self.conn.commit()
        self.insert_log('Deleted "{}" config value'.format(name))
        return

    def insert_template(self, template_id='', team_id='0', user_id='0', name='',
                        filename='', storage='filesystem', data=b''):
        self.execute(
            '''INSERT INTO ReportTemplates(
            id,team_id,user_id,name,filename, storage, base64) VALUES (?,?,?,?,?,?,?)''',
            (template_id, team_id, user_id, name, filename, storage, base64.b64encode(data).decode('charmap'))
        )
        self.conn.commit()
        self.insert_log('Added "{}" report template.'.format(name))

    def select_report_templates(self, team_id='', user_id='', template_id=''):
        self.execute(
            '''SELECT * FROM ReportTemplates WHERE team_id LIKE '%' || ? || '%'
            and user_id LIKE '%' || ? || '%' and 
            id LIKE '%' || ? || '%' ''',
            (team_id, user_id, template_id))
        result = self.return_arr_dict()
        return result

    def delete_team_report_templates(self, team_id):
        self.execute('''DELETE FROM ReportTemplates WHERE team_id=?''',
                     (team_id,))
        self.conn.commit()
        self.insert_log('Removed all {} team templates.'.format(team_id))

    def delete_team_configs(self, team_id):
        self.execute('''DELETE FROM Configs WHERE team_id=?''',
                     (team_id,))
        self.conn.commit()
        self.insert_log('Removed all {} team configs.'.format(team_id))

    def delete_team_issue_templates(self, team_id):
        self.execute('''DELETE FROM IssueTemplates WHERE team_id=?''',
                     (team_id,))
        self.conn.commit()
        self.insert_log('Removed all {} issue templates.'.format(team_id))

    def delete_template_safe(self, template_id, team_id='0', user_id='0'):

        template = self.select_report_templates(template_id=template_id,
                                                team_id=team_id,
                                                user_id=user_id)
        if not template:
            return
        template = template[0]

        remove('./static/files/templates/{}'.format(template['id']))

        self.execute(
            '''DELETE FROM ReportTemplates WHERE id = ?  ''',
            (template['id'],))
        self.conn.commit()
        self.insert_log('Deleted "{}" template'.format(template['name']))
        return

    def select_project_users(self, project_id):
        current_project = self.select_projects(project_id)[0]

        all_user_ids = []

        all_user_ids = json.loads(current_project['testers'])
        teams_ids = json.loads(current_project['teams'])

        teams = [self.select_team_by_id(team_id)[0] for team_id in teams_ids]
        for team in teams:
            all_user_ids += json.loads(team['users'])

        all_user_ids = list(set(all_user_ids))

        all_users = [self.select_user_by_id(x)[0] for x in all_user_ids]

        return all_users

    def select_project_pocs(self, project_id):
        self.execute(
            '''SELECT * FROM PoC WHERE issue_id in 
            (SELECT id FROM Issues WHERE project_id=?)''',
            (project_id,))
        result = self.return_arr_dict()
        return result

    def select_report_info_sorted(self, project_id):

        result = {}
        tmp_result = {}

        # project

        tmp_sql_result = self.select_projects(project_id)
        current_project = tmp_sql_result[0]
        tmp_result['name'] = current_project['name']
        tmp_result['start_date'] = current_project['start_date']
        tmp_result['end_date'] = current_project['end_date']
        result['project'] = tmp_result
        result['project']['testers'] = {}
        tmp_sql_result = self.select_project_users(project_id)
        for user in tmp_sql_result:
            user_obj = {'email': user['email'],
                        'fname': user['fname'],
                        'lname': user['lname']}
            result['project']['testers'][user['id']] = user_obj

        # hostnames

        result['hostnames'] = {}

        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id in 
            (SELECT id FROM Hosts WHERE project_id=?)''',
            (project_id,))
        tmp_sql_result = self.return_arr_dict()
        for hostname in tmp_sql_result:
            hostname_obj = {
                'hostname': hostname['hostname'],
                'comment': hostname['description']
            }
            result['hostnames'][hostname['id']] = hostname_obj

        # port
        result['ports'] = {}
        project_ports = self.select_project_ports(project_id)
        for port in project_ports:
            port_obj = {
                'port': port['port'],
                'is_tcp': bool(port['port']),
                'comment': port['description'],
                'service': port['service']
            }
            result['ports'][port['id']] = port_obj

        # hosts
        result['hosts'] = {}
        project_hosts = self.select_project_hosts(project_id)
        for host in project_hosts:
            host_obj = {
                'hostnames': [x['id'] for x in
                              self.select_ip_hostnames(host['id'])],
                'ports': [x['id'] for x in self.select_host_ports(host['id'])],
                'comment': host['comment'],
                'issues': [x['id'] for x in self.select_host_issues(host['id'])]
            }
            result['hosts'][host['ip']] = host_obj

        # issues
        result['issues'] = {}
        project_issues = self.select_project_issues(project_id)
        for issue in project_issues:
            issue_obj = {
                'name': issue['name'],
                'description': issue['description'],
                'cve': issue['cve'],
                'cwe': issue['cwe'],
                'cvss': issue['cvss'],
                'url_path': issue['url_path'],
                'pocs': [x['id'] for x in self.select_issue_pocs(issue['id'])],
                'status': issue['status'],
                'fix': issue['fix'],
                'type': issue['type'],
                'param': issue['param'],
                'fields': json.loads(issue['fields'])
            }

            # criticality
            if issue['cvss'] == 0:
                issue_obj['criticality'] = 'info'
            elif issue['cvss'] <= 3.9:
                issue_obj['criticality'] = 'low'
            elif issue['cvss'] <= 6.9:
                issue_obj['criticality'] = 'medium'
            elif issue['cvss'] <= 8.9:
                issue_obj['criticality'] = 'high'
            else:
                issue_obj['criticality'] = 'critical'

            services = json.loads(issue['services'])

            issue_obj['services'] = {}

            for port_id in services:
                service_obj = {}
                host = self.select_host_by_port_id(port_id)[0]
                service_obj['ip'] = host['ip']
                service_obj['is_ip'] = '0' in services[port_id]
                service_obj['hostnames'] = [x for x in services[port_id]
                                            if x != '0']
                issue_obj['services'][port_id] = service_obj

            result['issues'][issue['id']] = issue_obj

        # pocs

        result['pocs'] = {}

        project_pocs = self.select_project_pocs(project_id)
        for curr_poc in project_pocs:
            poc_obj = {'filename': curr_poc['filename'],
                       'url': '/static/files/poc/' + curr_poc['id'],
                       'comment': curr_poc['description'],
                       'path': '',
                       'services': {},
                       'filetype': curr_poc['type'],
                       'priority': curr_poc['priority']}

            if curr_poc['port_id'] != '0':
                service_obj = {}
                host = self.select_host_by_port_id(curr_poc['port_id'])[0]
                service_obj['ip'] = host['ip']
                service_obj['is_ip'] = ('0' == curr_poc['hostname_id'])
                service_obj['hostnames'] = []
                if curr_poc['hostname_id'] != '0':
                    service_obj['hostnames'] = [curr_poc['hostname_id']]
                poc_obj['services'][curr_poc['port_id']] = service_obj

            f = open(path.join('./static/files/poc/', curr_poc['id']), 'rb')
            content_b = f.read().decode('charmap')
            f.close()
            poc_obj['content'] = content_b
            poc_obj['content_base64'] = b64encode(content_b.encode("charmap"))
            poc_obj['content_hex'] = content_b.encode("charmap").hex()
            result['pocs'][curr_poc['id']] = poc_obj

        # grouped_issues

        result['grouped_issues'] = {}

        for issue_id in result['issues']:
            if result['issues'][issue_id]['name'] not \
                    in result['grouped_issues']:
                result['grouped_issues'][result['issues'][issue_id]['name']] = \
                    [issue_id]
            else:
                result['grouped_issues'][
                    result['issues'][issue_id]['name']].append(issue_id)

        # notes
        result['notes'] = {}
        notes = self.select_all_project_notes(project_id)
        for note in notes:
            result['notes'][note['id']] = {
                'name': note['name'],
                'host_id': note['host_id'],
                'html': note['text'],
                'markdown': '',
                'base64': base64.b64encode(note['text'].encode('charmap')).decode('charmap')
            }
            try:
                result['notes'][note['id']]['markdown'] = markdownify(note['text'])
            except Exception as e:
                pass

        # paths
        result['paths'] = {}
        paths = self.select_project_paths(project_id)
        for current_path in paths:
            result['paths'][current_path['id']] = {
                'host_out': current_path['host_out'],
                'host_in': current_path['host_in'],
                'network_out': current_path['network_out'],
                'network_in': current_path['network_in'],
                'description': current_path['description'],
                'type': current_path['type'],
                'direction': current_path['direction']
            }

        # networks
        result['networks'] = {}
        networks = self.select_project_networks(project_id)
        for current_network in networks:
            result['networks'][current_network['id']] = {
                'name': current_network['name'],
                'ip': current_network['ip'],
                'mask': current_network['mask'],
                'comment': current_network['comment'],
                'is_ipv6': current_network['is_ipv6'],
                'asn': current_network['asn'],
                'internal_ip': current_network['internal_ip'],
                'cmd': current_network['cmd'],
            }

            result['networks'][current_network['id']]['access_from'] = {}

            access_obj = json.loads(current_network['access_from'])
            for port_id in access_obj:
                service_obj = {}
                host = self.select_host_by_port_id(port_id)[0]
                service_obj['ip'] = host['ip']
                service_obj['is_ip'] = '0' in access_obj[port_id]
                service_obj['hostnames'] = [x for x in access_obj[port_id]
                                            if x != '0']
                result['networks'][current_network['id']]['access_from'][port_id] = service_obj



        return result

    def insert_token(self, user_id, name='', create_date=0,
                     duration=60 * 60 * 24):
        token_id = gen_uuid()
        self.execute(
            '''INSERT INTO Tokens(
            id,user_id,name,create_date,duration) 
            VALUES (?,?,?,?,?)''',
            (token_id, user_id, name, create_date, duration)
        )
        self.conn.commit()
        self.insert_log('Added new token {}'.format(token_id))
        return token_id

    def select_token(self, token_id):
        self.execute(
            '''SELECT * FROM Tokens WHERE id=?''',
            (token_id,))
        result = self.return_arr_dict()
        return result

    def update_disable_token(self, token_id):
        self.execute(
            '''UPDATE Tokens SET duration=0 WHERE id=? ''',
            (token_id,)
        )
        self.conn.commit()
        self.insert_log(
            'Disabled token {}'.format(str(token_id)))
        return

    def select_hosts_json(self, project_id):
        hosts = self.select_project_hosts(project_id)
        # id, uuid, ip, description, threads
        result_hosts = []
        for host in hosts:
            host_obj = {
                "id": hosts.index(host) + 1,
                "ip": host["ip"],
                "description": host["comment"],
                "threads": json.loads(host["threats"]),
                "uuid": host["id"],
                "os": host["os"]
            }
            result_hosts.append(host_obj)
        networks = self.select_project_networks(project_id)
        result_networks = []
        for network in networks:
            network_obj = {
                "id": len(result_hosts) + networks.index(network) + 1,
                "network": network["ip"],
                "mask": int(network["mask"]),
                "description": network["comment"]
            }
            result_networks.append(network_obj)
        return [json.dumps(result_hosts), json.dumps(result_networks)]

    def select_project_hostnames(self, project_id):
        self.execute(
            '''SELECT * FROM Hostnames WHERE host_id IN (SELECT id FROM Hosts WHERE project_id=?)''',
            (project_id,)
        )
        result = self.return_arr_dict()
        return result

    def select_project_pair_host_port(self, project_id):
        self.execute(
            '''SELECT Ports.id as port_id,
                      Ports.port as port,
                       Ports.is_tcp as is_tcp,
                       Hosts.id as host_id,
                       Hosts.ip as ip
               FROM Ports LEFT JOIN Hosts ON Ports.host_id=Hosts.id WHERE Hosts.project_id=? ORDER by ip, port ;''',
            (project_id,)
        )
        result = self.return_arr_dict()
        return result

    def select_project_hosts_hostnames(self, project_id):
        self.execute(
            '''SELECT ip as host, id FROM Hosts WHERE project_id=?
               UNION
               SELECT hostname as host, id FROM Hostnames WHERE host_id IN (SELECT id FROM Hosts WHERE project_id=?)''',
            (project_id, project_id)
        )
        result = self.return_arr_dict()
        return result

    def select_project_pair_hostname_port(self, project_id):
        self.execute(
            '''SELECT  Ports.id as port_id,
                       Ports.port as port,
                       Ports.is_tcp as is_tcp,
                       Hosts.id as host_id,
                       Hosts.ip as ip,
                       Hostnames.hostname as hostname,
                       Hostnames.id as hostname_id
                FROM Ports LEFT JOIN Hosts ON Ports.host_id=Hosts.id JOIN Hostnames 
                ON Hosts.id=Hostnames.host_id WHERE Hosts.project_id=? ORDER BY hostname,port;''',
            (project_id,)
        )
        result = self.return_arr_dict()
        return result

    def project_stats(self, project_id):
        sql = '''
        SELECT 
        -- Credentials stats
        (SELECT count(*) FROM Credentials where project_id=? and cleartext != '') as creds_clr_pwd,
        (SELECT count(*) FROM Credentials where project_id=? and cleartext = '' and hash != '') as creds_hash_pwd,
        (SELECT count(*) FROM Credentials where project_id=? and cleartext != '' and hash != '') as creds_clr_hash,
        (SELECT count(*) FROM Credentials where project_id=? and cleartext = '' and hash = '' and 'login' != '') as creds_just_login,
        -- Time left
        (SELECT start_date FROM Projects where id=?) as start_date,
        (SELECT end_date FROM Projects where id=?) as end_date,
        -- Issues
        (SELECT count(*) FROM Issues where project_id=? and cvss>8.9) as issues_critical,
        (SELECT count(*) FROM Issues where project_id=? and cvss<=8.9 and cvss>6.9) as issues_high,
        (SELECT count(*) FROM Issues where project_id=? and cvss<=6.9 and cvss>3.9) as issues_medium,
        (SELECT count(*) FROM Issues where project_id=? and cvss<=3.9 and cvss>0) as issues_low,
        (SELECT count(*) FROM Issues where project_id=? and cvss=0) as issues_info,
        -- Hosts OS
        (SELECT count(*) FROM Hosts where project_id=? and lower(os) LIKE '%lin%' ) as stats_linux,
        (SELECT count(*) FROM Hosts where project_id=? and lower(os) LIKE '%win%' ) as stats_windows,
        (SELECT count(*) FROM Hosts where project_id=? and lower(os) LIKE '%mac%' ) as stats_mac,
        (SELECT count(*) FROM Hosts where project_id=? and lower(os) NOT LIKE '%mac%' and lower(os) NOT LIKE '%win%' and lower(os) NOT LIKE '%lin%' ) as stats_no_os
         '''
        self.execute(sql, [project_id for x in range(15)])
        result = self.return_arr_dict()

        max_count = max([
            int(result[0]['issues_critical']),
            int(result[0]['issues_high']),
            int(result[0]['issues_medium']),
            int(result[0]['issues_low']),
            int(result[0]['issues_info'])
        ])

        if max_count == 0:
            max_count = 1

        stats_dict = {
            'creds': {
                'clr_pwd': int(result[0]['creds_clr_pwd']),
                'hash_pwd': int(result[0]['creds_hash_pwd']),
                'clr_hash': int(result[0]['creds_clr_hash']),
                'just_login': int(result[0]['creds_just_login']),
            },
            'creds_array': [
                int(result[0]['creds_clr_pwd']),
                int(result[0]['creds_hash_pwd']),
                int(result[0]['creds_clr_hash']),
                int(result[0]['creds_just_login']),
            ],
            'os': {
                'linux': int(result[0]['stats_linux']),
                'windows': int(result[0]['stats_windows']),
                'macos': int(result[0]['stats_mac']),
                'other': int(result[0]['stats_no_os'])
            },
            'os_array': [
                int(result[0]['stats_windows']),
                int(result[0]['stats_linux']),
                int(result[0]['stats_mac']),
                int(result[0]['stats_no_os'])
            ],
            'issues': {
                'Critical': int(result[0]['issues_critical']),
                'High': int(result[0]['issues_high']),
                'Medium': int(result[0]['issues_medium']),
                'Low': int(result[0]['issues_low']),
                'Information': int(result[0]['issues_info']),
                'max_count': max_count
            },
            'issues_arr': [
                int(int(result[0]['issues_critical']) / max_count * 100),
                int(int(result[0]['issues_high']) / max_count * 100),
                int(int(result[0]['issues_medium']) / max_count * 100),
                int(int(result[0]['issues_low']) / max_count * 100),
                int(int(result[0]['issues_info']) / max_count * 100)
            ],
            'project': {
                'start_date': int(result[0]['start_date']),
                'end_date': int(result[0]['end_date']),
                'percents': 0
            }
        }
        curr_time = int(time.time())
        if curr_time > stats_dict['project']['end_date']:
            stats_dict['project']['percents'] = 100
        elif stats_dict['project']['start_date'] < curr_time < stats_dict['project']['end_date']:
            stats_dict['project']['percents'] = int(((curr_time - stats_dict['project']['start_date']) / (stats_dict['project']['end_date'] - stats_dict['project']['start_date'])) * 100)

        stats_dict['project']['percents'] = 100 - stats_dict['project']['percents']
        project_ports = self.select_project_ports(project_id)

        ports_dict = {}

        for port in project_ports:
            if port['port']:
                port_str = '{}/{}'.format(port['port'], 'tcp' if port['is_tcp'] else 'udp')
                if port_str not in ports_dict:
                    ports_dict[port_str] = 0
                ports_dict[port_str] += 1

        sorted_ports = list({k: v for k, v in sorted(ports_dict.items(), key=lambda item: item[1], reverse=True)}.items())
        top_ports_name = [x[0] for x in sorted_ports][:10]
        top_ports_count = [x[1] for x in sorted_ports][:10]

        stats_dict['ports'] = {
            'names': top_ports_name,
            'count': top_ports_count
        }

        return stats_dict

    def select_project_stats_divbar(self, project_id):
        sql = '''
                SELECT 
                -- Credentials stats
                (SELECT count(*) FROM Credentials where project_id=?) as creds_counter,
                (SELECT count(*) FROM Hosts where project_id=?) as hosts_counter,
                (SELECT count(*) FROM Issues where project_id=?) as issues_counter,
                (SELECT count(*) FROM Files where project_id=? and type != 'report' and type != 'field') as files_counter,
                (SELECT count(*) FROM Notes where project_id=? and host_id = '') as notes_counter,
                (SELECT count(*) FROM Chats where project_id=?) as chats_counter,
                (SELECT count(*) FROM Files where project_id=? and type='report') as reports_counter,
                (SELECT count(*) FROM Networks where project_id=?) as networks_counter
                                 '''
        self.execute(sql, [project_id for x in range(8)])
        result = self.return_arr_dict()

        services_counter = len(self.select_project_ports_grouped(project_id))

        # fix for strange bug with zero results
        if not result:
            result_obj = {
                'services_counter': 0,
                'creds_counter': 0,
                'hosts_counter': 0,
                'issues_counter': 0,
                'files_counter': 0,
                'notes_counter': 0,
                'chats_counter': 0,
                'networks_counter': 0,
                'reports_counter': 0,
            }
        else:
            result_obj = {
                'services_counter': services_counter,
                'creds_counter': int(result[0]['creds_counter']),
                'hosts_counter': int(result[0]['hosts_counter']),
                'issues_counter': int(result[0]['issues_counter']),
                'files_counter': int(result[0]['files_counter']),
                'notes_counter': int(result[0]['notes_counter']),
                'chats_counter': int(result[0]['chats_counter']),
                'networks_counter': int(result[0]['networks_counter']),
                'reports_counter': int(result[0]['reports_counter']),
            }

        return result_obj

    def select_ports_by_fields(self, project_id, port, is_tcp, service, description):
        self.execute(
            '''SELECT * FROM Ports WHERE project_id=? AND port=? AND is_tcp=? AND service=? AND description=?''',
            (project_id, port, int(is_tcp), service, description))
        result = self.return_arr_dict()
        return result

    def update_service_multiple_info(self, project_id,
                                     old_port, old_is_tcp, old_service, old_description,
                                     port, is_tcp, service, description, hosts,
                                     user_id):
        self.execute(
            '''UPDATE Ports SET port=?,is_tcp=?,service=?,description=? WHERE project_id=? AND port=? AND is_tcp=? AND service=? AND description=? ''',
            (port, int(is_tcp), service, description, project_id, old_port, old_is_tcp, old_service, old_description)
        )
        self.conn.commit()

        ports = self.select_ports_by_fields(project_id, port, is_tcp, service, description)

        existed_hosts = [x['host_id'] for x in ports]

        # ports which must be removed
        remove_ports = []
        for host_id in existed_hosts:
            if host_id not in hosts:
                remove_ports.append(host_id)

        # ports which must be added
        new_ports = []
        for host_id in hosts:
            if host_id not in existed_hosts:
                new_ports.append(host_id)

        for host_id in remove_ports:
            port_to_delete = self.select_host_port(host_id, int(port), is_tcp)
            if port_to_delete:
                self.delete_port_safe(port_to_delete[0]['id'])

        for host_id in new_ports:
            port_to_add = self.select_host_port(host_id, int(port), is_tcp)
            if not len(port_to_add):
                self.insert_host_port(host_id, port, is_tcp, service, description, user_id, project_id)
            else:
                self.update_port_proto_description(port_to_add[0]['id'], service, description)

        self.insert_log(
            'Updated service {}/'.format((port,
                                          'tcp' if int(is_tcp) else 'udp')))
        return

    def insert_new_issue_template(self, tpl_name, name, description, url_path, cvss, status, cve='', cwe=0,
                                  issue_type='custom', fix='', param='', fields={}, variables={}, user_id='', team_id=''):
        template_id = gen_uuid()
        self.execute(
            '''INSERT INTO IssueTemplates(
            id, tpl_name, name, description, url_path, cvss, cwe, cve, status, type, fix, param, fields, variables, user_id, team_id) VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (str(template_id), tpl_name, name, description, url_path,
             cvss, cwe, cve, status, issue_type, fix, param,
             json.dumps(fields), json.dumps(variables), user_id, team_id)
        )
        self.conn.commit()
        self.insert_log('Added issue template "{}"'.format(tpl_name))
        return str(template_id)

    def edit_issue_template(self, template_id, tpl_name, name, description, url_path, cvss, status, cve='', cwe=0,
                            issue_type='custom', fix='', param='', fields={}, variables={}, user_id='', team_id=''):

        current_template = self.select_issue_template(template_id)

        if not current_template:
            return

        current_template = current_template[0]

        self.execute(
            '''UPDATE IssueTemplates SET
            tpl_name=?, name=?, description=?, url_path=?, cvss=?, cwe=?, cve=?, status=?, type=?, fix=?, param=?, fields=?, variables=?, user_id=?, team_id=?
            WHERE id=?''',
            (tpl_name, name, description, url_path,
             cvss, cwe, cve, status, issue_type, fix, param,
             json.dumps(fields), json.dumps(variables), user_id,
             team_id, template_id)
        )
        self.conn.commit()
        teams = []
        if current_template['team_id']:
            teams.append(current_template['team_id'])

        if team_id and team_id != current_template['team_id']:
            teams.append(team_id)

        self.insert_log('Edited issue template "{}"'.format(tpl_name), teams=teams)
        return

    def select_issue_templates(self, user_id='', team_id=''):
        self.execute(
            '''SELECT * FROM IssueTemplates WHERE user_id=? AND team_id=?;''',
            (user_id, team_id)
        )
        result = self.return_arr_dict()
        return result

    def select_issue_template(self, template_id):
        self.execute(
            '''SELECT * FROM IssueTemplates WHERE id=?;''',
            (template_id,)
        )
        result = self.return_arr_dict()
        return result

    def check_user_issue_template_access(self, template_id, user_id, user_email):
        self.execute(
            '''SELECT * FROM IssueTemplates WHERE (id=? AND user_id=?) 
            OR (id=? AND team_id in (SELECT id FROM Teams WHERE admin_id=? OR admin_email=? OR users LIKE '%' || ? || '%'));''',
            (template_id, user_id, template_id, user_id, user_email, user_id)
        )
        result = self.return_arr_dict()
        return result

    def delete_issue_template(self, template_id: str):

        current_template = self.select_issue_template(template_id)

        if not current_template:
            return

        current_template = current_template[0]

        self.execute(
            '''DELETE FROM IssueTemplates WHERE id=? ''',
            (template_id,)
        )
        self.conn.commit()
        self.insert_log(
            'Removed issue template {}'.format(str(template_id)), teams=[current_template['team_id']] if current_template['team_id'] else [])
        return

    def select_user_issue_templates(self, user_id):
        # get user templates

        if self.current_user and self.current_user['id'] == user_id:
            current_user = self.current_user
        else:
            current_user = self.select_user_by_id(user_id)
            if current_user:
                current_user = current_user[0]
            else:
                return []

        self.execute('''
        SELECT * FROM IssueTemplates WHERE user_id=? or (team_id != '' AND team_id in (SELECT id from Teams WHERE admin_id=? or users like '%' || ? || '%' or admin_email=?))
        ''', (user_id, user_id, user_id, current_user['email']))

        result = self.return_arr_dict()

        return result

    def delete_project_safe(self, project_id):

        # TODO: create one line delete project SQL query

        # delete hosts
        all_hosts = self.select_project_hosts(project_id)
        for host in all_hosts:
            self.delete_host_safe(project_id, host['id'])

        # delete issues
        all_issues = self.select_project_issues(project_id)
        for issue in all_issues:
            self.delete_issue_safe(project_id, issue['id'])

        # delete files
        all_files = self.select_project_files(project_id)
        for file in all_files:
            self.delete_file(file['id'])

        # delete notes
        all_notes = self.select_project_notes(project_id)
        for note in all_notes:
            self.delete_note(note['id'], project_id)

        # delete networks
        all_networks = self.select_project_networks(project_id)
        for network in all_networks:
            self.delete_network_safe(network['id'])

        # delete credentials
        all_creds = self.select_project_creds(project_id)
        for cred in all_creds:
            self.delete_creds(cred['id'])

        # delete chats
        all_chats = self.select_project_chats(project_id)
        for chat in all_chats:
            self.delete_chat(chat['id'])

        # delete project
        self.execute("DELETE FROM Projects WHERE id=?", (project_id,))
        self.conn.commit()

    def insert_path(self, project_id='', out_host='', out_network='', in_host='', in_network='', description='', path_type='connection', direction='forward'):
        path_id = gen_uuid()
        self.execute(
            '''INSERT INTO NetworkPaths(
            id,host_out,network_out,host_in,network_in,description,project_id,type, direction) VALUES (?,?,?,?,?,?,?,?,?)''',
            (path_id, out_host, out_network, in_host, in_network, description, project_id,path_type, direction)
        )
        self.conn.commit()
        self.insert_log('Added "{}" network path.'.format(path_id))
        return path_id

    def delete_path_by_network(self, project_id='', network_id=''):
        self.execute(
            '''DELETE FROM NetworkPaths WHERE project_id=? AND (network_out=? OR network_in=?)''',
            (project_id, network_id, network_id)
        )

        self.conn.commit()
        self.insert_log('Removed network path.')

    def delete_path_by_host(self, project_id='', host_id=''):
        self.execute(
            '''DELETE FROM NetworkPaths WHERE project_id=? AND (host_out=? OR host_in=?)''',
            (project_id, host_id, host_id)
        )

        self.conn.commit()
        self.insert_log('Removed network path.')

    def search_path(self, project_id='', out_host='', out_network='', in_host='', in_network=''):
        self.execute(
            '''SELECT * FROM NetworkPaths WHERE project_id=? AND host_out=? AND network_out=?
            AND host_in=? AND network_in=?;''',
            (project_id, out_host, out_network, in_host, in_network)
        )
        result = self.return_arr_dict()
        return result

    def select_path(self, path_id='', project_id=''):
        self.execute(
            '''SELECT * FROM NetworkPaths WHERE id=? AND project_id LIKE '%' || ? || '%'  ''',
            (path_id, project_id)
        )
        result = self.return_arr_dict()
        return result

    def update_path_description_type(self, path_id='', description='', path_type='connection', direction='forward'):
        self.execute(
            '''UPDATE NetworkPaths SET description = ?,type = ?,direction = ? WHERE id = ?  ''',
            (description,path_type,direction, path_id))
        self.conn.commit()
        self.insert_log('Updated "{}" path description,type & direction'.format(path_id))
        return

    def delete_path(self, path_id='', project_id=''):
        self.execute(
            '''DELETE FROM NetworkPaths WHERE id=? AND project_id LIKE '%' || ? || '%'  ''',
            (path_id, project_id))
        self.conn.commit()
        self.insert_log('Trying to remove path_id "{}"'.format(path_id))
        return

    def select_project_paths(self, project_id=''):
        self.execute(
            '''SELECT * FROM NetworkPaths WHERE project_id=?;''',
            (project_id,)
        )
        result = self.return_arr_dict()
        return result
