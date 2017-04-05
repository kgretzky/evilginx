## Evilginx

![Evilginx](/img/evilginx-title.png?raw=true "Evilginx")

Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes `proxy_pass` and `sub_filter` to proxy and modify HTTP content, while intercepting traffic between client and server.

You can learn how it works and how to install everything yourself on my blog:

**The blog post will be available on Thursday (2017-04-06). At the moment the link is dead.**

[Evilginx - Advanced Phishing With Two-factor Authentication Bypass](https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/)

#### Usage

```
usage: evilginx_parser.py [-h] -i INPUT -o OUTDIR -c CREDS [-x]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input log file to parse.
  -o OUTDIR, --outdir OUTDIR
                        Directory where output files will be saved.
  -c CREDS, --creds CREDS
                        Credentials configuration file.
  -x, --truncate        Truncate log file after parsing.
```

**Example:**
```
python evilginx_parser.py -i /var/log/evilginx-google.log -o ./logs -c google.creds
```
