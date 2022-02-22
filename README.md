# Pentest Collaboration Framework

<p align="center">
<a href="https://elements.heroku.com/buttons/drakylar/pcf_fork_check_gitlab"><img src="https://img.shields.io/badge/supports-Heroku-darkviolet" /></a>
<a href=""><img src="https://img.shields.io/badge/supports-Docker-blue" /></a>
<a href=""><img src="https://img.shields.io/badge/python-3.9-orange"/></a>
<a href=""><img src="https://img.shields.io/badge/lisence-MIT-red" /></a>
<a href = "https://t.me/PentestCollaborationFramework"><img src="https://img.shields.io/badge/chat-telegram-blue?logo=telegram" /></a>

<b>Pentest Collaboration Framework - an opensource, cross-platform and portable toolkit for automating routine processes when carrying out various works for testing!</b>
    <br />
    <a href="https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/home"><strong>Explore the docs »</strong></a>
    <br />
</p>  


## ‼️ Important Links

<table>
    <thead>
        <tr>
            <th>Links</th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan=1><a href="https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/Installation"><b>📖Installation Guide</b></a></td>
            <td rowspan=6><img src="https://i.ibb.co/CnctfrR/Webp-net-resizeimage.png"></td>
        </tr>
        <tr>
            <td rowspan=1><a href="https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/home"><b>🌐Wiki</b></a></td>
        </tr>
        <tr>
            <td rowspan=1><a href="https://gitlab.com/invuls/pentest-projects/pcf/-/releases"><b>🚀Releases</b></a></td>
        </tr>
        <tr>
            <td rowspan=1><a href="https://t.me/PentestCollaborationFramework"><b>💬Telegram</b></a></td>
        </tr>
        <tr>
            <td rowspan=1>
                <a href="https://dashboard.heroku.com/new-app?template=https://github.com/drakylar/pcf_FORK_CHECK_GITLAB"><img src="https://www.herokucdn.com/deploy/button.png"></a><br/>
                <a href="https://aws.amazon.com/marketplace/pp/B08XMGYCHR"><img src="https://i.ibb.co/jbwS6cP/Fotoram-io-1-2.png"></a>
            </td>
        </tr>
        <tr>
            <td rowspan=1><a href="http://testing-pcf.herokuapp.com/"><b>🕹️Demo</b></a></td>
        </tr>
    </tbody>
</table>

# ✨ Features

| Structure |                          |
| ---------------- | ---------------------- |
| <ul><li>:family_mmb: Teams<ul><li>Work team</li><li>Personal team</li></ul></li><li>⛑ Pentest projects<ul><li>🖥️ Hosts<ul><li>ip-address</li><li>hostnames</li><li>operation system</li><li>open ports</li><li>tester notes</li></ul></li><li>🐞 Issues<ul><li>Proof of concept</li></ul></li><li>🌐 Networks</li><li>🔑 Found credentials</li><li>📝 Notes</li><li>💬 Chats</li><li>📊 Report generation<ul><li>plaintext</li><li>docx</li><li>zip</li></ul></li><li>📁 Files</li><li>🛠 Tools</li></ul></li></ul> | ![image](https://i.ibb.co/v48y1py/2022-01-12-003906.png) |

* 🔬 You can create private or team projects!
* 💼 Team moderation.
* 🛠 Multiple tools integration support! Such as Nmap/Masscan, Nikto, Nessus and Acunetix!
* 🖥️ Cross-platform, opensource & free!
* ☁ Cloud deployment support.

## 📊 PCF vs analogues

| **Name**  | PCF | Lair | Dradis | Faraday | AttackForge | PenTest.WS | Hive
| -------------- | --- | ---- | ------ | ------- | ----------- | ---------- | -----
| Portable | ✅ | ❌ | ❌ | ❌ | ❌  | ✅💲 | ❌
| Cross-platform | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌
| Free | ✅ | ✅ | ❌✅ | ❌✅ | ❌✅  | ❌✅ | ❌✅
| NOT deprecated! | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅
| Data export | ✅ | ❌✅ | ✅ | ✅ | ✅ | ❌✅ | ✅
| Chat | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅
| Made for sec specialists, not managers | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌✅ 
| Report generation | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅
| API | ✅ | ❌✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅
| Issue templates | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅

## 🛠 Supported tools

| **Tool name**  | Integration type | Description
| ---------- | ---------------- | ---------------
| Nmap | Import | Import XML results (ip, port, service type, service version, hostnames, os). Supported plugins: vulners
| Nessus | Import | Import .nessus results (ip, port, service type, security issues, os)
| Qualys | Import | Import .xml results (ip, port, service type, security issues)
| Masscan | Import | Import XML results (ip, port)
| Nikto | Import | Import XML, CSV, JSON results (issue, ip, port)
| Acunetix | Import | Import XML results (ip, port, issue)
| Burp Suite Enterprise | Import | Import HTML results (ip, port, hostname, issue, poc)
| kube-hunter | Import | Import JSON result (ip, port, service, issue)
| Checkmarx SAST | Import | Import XML/CSV results (code info, issue)
| Dependency-check | Import | Import XML results (code issues)
| OpenVAS/GVM | Import | Import XML results (ip, port, hostname, issue)
| NetSparker | Import | Import XML results (ip, port, hostname, issue)
| [BurpSuite](https://gitlab.com/invuls/pentest-projects/pcf_tools/pcf-burpsuite-extention/-/tree/master/out/artifacts/burp_jar) | Import/Extention | Extention for fast issue send from burpsuite.
| ipwhois | Scan | Scan hosts(s)/network(s) and save whois data
| shodan | Scan | Scan hosts ang save info (ip, port, service).
| HTTP-Sniffer | Additional | Create multiple http-sniffers for any project.
| WPScan | Import | Import JSON results (ip, port, hostname, issue)
| DNSrecon | Import | Import JSON/CSV/XML results (ip, port, hostname)
| theHarvester | Import | Import XML results (ip, hostname)
| Metasploit | Import | Import XML project (ip, port, hostname, issue)
| Nuclei | Import | Import JSON results (ip, hostname, port, issue)
| PingCastle | Import | Import XML results (ip, issue)
| MaxPatrol | Import | Import XML results (ip, port, issue)

## 🙋 Table of Contents
* 📖 [Fast Installation Guide](https://gitlab.com/invuls/pentest-projects/pcf#-full-installation-guide)
    * 💻 [Standalone](https://gitlab.com/invuls/pentest-projects/pcf#-windows-linux-macos)
    * ☁️ [Heroku](https://gitlab.com/invuls/pentest-projects/pcf#%EF%B8%8F-heroku)
    * ☁️ [AWS](https://gitlab.com/invuls/pentest-projects/pcf#%EF%B8%8F-aws)
    * 🐋 [Docker Usage](https://gitlab.com/invuls/pentest-projects/pcf#whale-docker)
* 🦜 [Telegram](https://t.me/PentestCollaborationFramework)
* 🤸 [Usage](https://gitlab.com/invuls/pentest-projects/pcf#-usage)
* 🖼️ [Gallery](https://gitlab.com/invuls/pentest-projects/pcf#-gallery)
* ⚠️ [WARNING](https://gitlab.com/invuls/pentest-projects/pcf#-warning)
* 🎪 [Community](https://gitlab.com/invuls/pentest-projects/pcf#-community)
* 📝 [TODO](https://gitlab.com/invuls/pentest-projects/pcf#-todo)
* 🎁 [Presentations](https://gitlab.com/invuls/pentest-projects/pcf#-presentations)
* 🏢 [Companies](https://gitlab.com/invuls/pentest-projects/pcf#-companies)
* ❤️ [Contribute](https://gitlab.com/invuls/pentest-projects/pcf#%EF%B8%8F-contribute)


# 📖 Fast Installation Guide
**You need only Python3**. 

## 🖥️ Windows / Linux / MacOS

Download project:
```sh
git clone https://gitlab.com/invuls/pentest-projects/pcf.git
```

Go to folder:
```bash
cd pcf
```

Install deps (for unix-based systems):
```bash
pip3 install -r requirements_unix.txt

```
or windows:
```bash
pip.exe install -r requirements_windows.txt

```

Run initiation script:
```bash
python3 new_initiation.py
```
or windows
```bash
python.exe new_initiation.py
```

Edit configuration:
```bash
nano configuration/settings.ini
```

Run:
```bash
old version: python3 app.py
new version: python3 run.py
```
or windows
```bash
old version: python.exe app.py
new version: python.exe run.py
```

## ☁️ Heroku

### 👍 Easy way

Deploy from our github repository:

[![Deploy](https://www.herokucdn.com/deploy/button.png)](https://dashboard.heroku.com/new-app?template=https://github.com/drakylar/pcf_FORK_CHECK_GITLAB)

Careful: Check github repo last push version!

You can check 😓Harder and 💀Impossible ways at [🌐wiki page](https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/Heroku%20installation)!

## ☁️ AWS

You can just follow the link and install PCF from AWS marketplace:

[![Marketplace](https://i.ibb.co/jbwS6cP/Fotoram-io-1-2.png)](https://aws.amazon.com/marketplace/pp/B08XMGYCHR)


## :whale: Docker 

#### One line install

_Will be added later!_

#### Build by yourself

Clone repository
```bash
git clone https://gitlab.com/invuls/pentest-projects/pcf.git
```
Go to folder:
```bash
cd pcf
```
Run docker-compose:
```bash
docker-compose up
```
and go to URL
```bash
http://127.0.0.1:5000/
```
# 🤸 Usage

Default port (check config): 5000
Default ip (if run at localhost): 127.0.0.1 



1. Register at http(s)://\<ip\>:\<port\>/register

2. Login at http(s)://\<ip\>:\<port\>/login

3. Create team (if need) at http(s)://\<ip\>:\<port\>/create_team

4. Create project at http(s)://\<ip\>:\<port\>/new_project

5. Enjoy your hacking process! 

API information: https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/API%20documentation

## 🖼️ Gallery


|||
:-------------------------:|:-------------------------:
![image](https://i.ibb.co/2vxsVRh/image.png)|![image](https://i.ibb.co/SPDcNWH/image.png)
Team information|Projects list
![image](https://i.ibb.co/YB9pDbn/image.png)|![image](https://i.ibb.co/bvy13Vp/image.png)
Project: issues|Project: host page
![image](https://i.ibb.co/HrqC5tn/image.png)|![image](https://i.ibb.co/7RmVRN7/image.png)
Project: hosts|Project:services
![image](https://i.ibb.co/QcLJDkN/image.png)|![image](https://i.ibb.co/NpCS7MX/image.png)
Project: issue info|Project: issue info (PoC)
![image](https://i.ibb.co/Bw7X2dD/image.png)|![image](https://i.ibb.co/LP4Wk4D/image.png)
Project: networks|Project: files
![image](https://i.ibb.co/m05NQ2Q/image.png)|![image](https://i.ibb.co/kMG3q1b/image.png)
Project: tools (may be changed)|Project: found credentials
![image](https://i.ibb.co/Y0Nm98f/image.png)|![image](https://i.ibb.co/Kqf7Ffm/image.png)
Project: testing notes|Project: chats
![image](https://i.ibb.co/nskQJgq/image.png)|![image](https://i.ibb.co/TW67yq1/image.png)
Project: settings|Project: reports


# ⚠️ WARNING


#### 🚨 Default settings

This program, by default, uses 5000 port and allows everyone to register and use it, so you need to set correct firewall & network rules.

#### 🔌 Initiation logic

Careful with new_initiation script! It makes some important changes with filesystem:

1. Renames database /configuration/database.sqlite3 
2. Regenerates SSL certificates
3. Regenerates session key.
4. Creates new empty /configuration/database.sqlite3 database
5. Creates /tmp_storage/ folder


# 🎪 Community

If you have any feature suggestions or bugs, leave a GitLab issue. We welcome any and all support :D

We communicate over Telegram. [Click here](https://t.me/PentestCollaborationFramework) to join our Telegram community!


## 📝 TODO

#### General
* [x] Team config storage
* [x] Team report templates storage
* [x] Automatic database backup
* [x] Share Issues with non-registered users
* [x] Report generation
* [x] Fast popular password bruteforce check (top-10k)
* [x] REST-API
* [x] Network graph
* [x] Hash fast export/import
* [x] Add another databases
* [x] Add .doc report generation support
* [x] Issue templates
* [ ] Backup/Restore from backup projects/teams
    
#### Tools
* [x] HTTP-sniffer
* [ ] NetNTLM smb sniffer
* [x] Custom tool txt report upload support (added notes to hosts)
* [x] Hash fast check top-10k passwords
* [ ] Export projects from Faraday/Dradis
* [ ] Metasploit/Cobalt Strike integration

#### Version 2.0

* [ ] Vue.js
* [ ] Websockets
* [ ] Push messages (updates)
* [ ] Database rebuild (objects)
* [ ] hosts -> interfaces -> ports
* [ ] hosts -> hostnames
* [ ] Project file manager
* [ ] Port -> Protocol:Software:Version
* [ ] User-defined host marks (mark all hosts with open port)
* [ ] TODO marks button every page
* [ ] Dublicate hosts (join them?)
* [ ] host MAC/AD domain/Forest

# 🎁 Presentations

* Black Hat:
    * Asia ![](https://i.ibb.co/WfwyMKp/singapore.png):
        [2021](https://drive.google.com/file/d/1D_Y-oFqP4BAlFPeFzDeZukSp4RKGvrQU/view?usp=sharing)
    * Europe ![](https://i.ibb.co/J5JB7nX/68747470733a2f2f7261772e6769746875622e636f6d2f77696b692f696e666f627974652f666172616461792f696d616765.png)
        [2021](https://docs.google.com/presentation/d/1qn0ecorYNtSvm-uh9n62oTbUhqHqxp6698vh5Zg5ZTY/edit?usp=sharing)
      

* MIPHI ![](https://i.ibb.co/F0dGx5M/russia.png):
    [2021](https://docs.google.com/presentation/d/1MIioNG_ChvGH_Wcxcg_Cc3C68E3zGiKREU0oo7CdCZg/edit?usp=sharing)
   

* Defcon-NN ![](https://i.ibb.co/F0dGx5M/russia.png):
    [2021](https://docs.google.com/presentation/d/1eW19sIikp6DGju8YjfhJoPYqpIsCvupmQZfcmr39YQ4/edit?usp=sharing)
   
 
* DC7495 ![](https://i.ibb.co/F0dGx5M/russia.png):
    [2021](https://docs.google.com/presentation/d/1KQPvxGoPl6c954GyL9ugUCGNOvOa0uM1FtGMbn-vJHY/edit?usp=sharing)
    
* H@cktivityCon🌐:
    [2021](https://docs.google.com/presentation/d/1Zit2km6TAjwdiKJSLI1COKkM70q2aGqnDa7PWs1JTL4/edit?usp=sharing)
  
* Standoff ![](https://i.ibb.co/F0dGx5M/russia.png):
    [2021](https://docs.google.com/presentation/d/1Cp-a9cmvMnNf7pqHz3A7jEwx30UvRcvhZlCO1qwN6Jw/edit?usp=sharing)

# 🏢 Companies
There will be companies list which use Pentest Collaboration Framework.


If you want to add your company, then read next topic :)
# ❤️ Contribute

If you want to help to project or encourage PCF developers, you can do any of the following:

* Mention PCF at your presentations/research articles/forum topics/other information resources.
* Advise it to you friends/collegues.
* "Star" this repository
* Don't forget about PCF telegram chat 
https://t.me/PentestCollaborationFramework
* Create more feature/bug requests at gitlab issues page
https://gitlab.com/invuls/pentest-projects/pcf/-/issues
* If you use it at work, you can ask @drakylar (Telegram) to add your work icon + link at "Companies" topic at README.md
* You can create more template examples for PCF and send them to me (@drakylar Telegram), so I will add them to template examples folder at main repository
* Also you can create more nmap scripts plugins and also send them to @drakylar. More info here: 
https://gitlab.com/invuls/pentest-projects/pcf/-/issues/34
https://gitlab.com/invuls/pentest-projects/pcf/-/blob/master/routes/ui/tools_addons/nmap_scripts/nmap_example.py

**There was some frequent question:**
> How to donate money to the project?

No way. I do not guarantee that I will not abandon this project after a while, so the best "donation" will be a contribution to the development and distribution of the utility.

> How to make a merge requests to this repository?

Again, no way. To develop PCF faster, I need to know all of its code, so just create an issue at gitlab with bug/feature request and some code example, which I may use to fix it.

