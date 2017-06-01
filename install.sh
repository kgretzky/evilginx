#!/bin/bash

# Evilginx Installation Script

## Config

OPENRESTY_VERSION='1.11.2.2'
OPENRESTY_SRC_URL="https://openresty.org/download/openresty-$OPENRESTY_VERSION.tar.gz"

## Installation

CUR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr()  { echo "[-] $1" >&2; exit 1; }
exiterr2() { echo "[-] 'apt-get install' failed." >&2; exit 1; }
iecho() { echo "[*] $1"; }
bigecho() { echo; echo "## $1"; echo; }

os_type="$(lsb_release -si 2>/dev/null)"
if [ -z "$os_type" ]; then
  [ -f /etc/os-release  ] && os_type="$(. /etc/os-release  && echo "$ID")"
  [ -f /etc/lsb-release ] && os_type="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
  [ "$os_type" = "debian" ] && os_type=Debian
  [ "$os_type" = "ubuntu" ] && os_type=Ubuntu
  [ "$os_type" = "kali" ] && os_type=Kali
fi
if [ "$os_type" != "Ubuntu" ] && [ "$os_type" != "Debian" ] && [ "$os_type" != "Raspbian" ] && [ "$os_type" != "Kali" ]; then
  exiterr "This script only supports Ubuntu/Debian."
fi

if [ "$(id -u)" != 0 ]; then
  exiterr "Script must be run as root. Try 'sudo sh $0'"
fi

# check if systemd is installed
if [ -z $(which systemctl) ]; then
  exiterr "Systemd must be installed. Install with 'apt-get install systemd-sysv' and reboot."
fi

# check if any daemon is listening on ports 80 and 443
if [[ $(netstat -lnt | awk '$6 == "LISTEN" && ($4 ~ ":80$" || $4 ~ ":443$")') ]]; then
  exiterr "Seems ports 80 and 443 are currently being used. Make sure to disable and uninstall any HTTP servers."
fi

bigecho "Evilginx installation in progress. Please wait."

# create and change working dir
mkdir -p /opt/src
cd /opt/src || exiterr "Cannot enter directory /opt/src."

iecho "Populating apt-get cache..."
apt-get -yq update || exiterr "'apt-get update' failed."

# make sure to use the 1.0.x package of openssl
LIBSSL_PKG='libssl-dev'
if [ ! -z $(apt-cache search libssl1.0-dev | sed 's/\s.*//') ]; then
  LIBSSL_PKG='libssl1.0-dev'
fi

iecho "Installing required packages..."
apt-get -yq install make gcc libpcre3-dev $LIBSSL_PKG wget || exiterr2

iecho "Downloading openresty source..."
openresty_src="openresty-$OPENRESTY_VERSION"
if ! { wget -t 3 -T 30 -nv -O "$openresty_src.tar.gz" "$OPENRESTY_SRC_URL"; }; then
  exiterr "Cannot download openresty source."
fi
/bin/rm -rf "/opt/src/$openresty_src"
tar xvf "$openresty_src.tar.gz" && /bin/rm -f "$openresty_src.tar.gz"
cd "$openresty_src" || exiterr "Cannot enter openresty source dir."
iecho "Configuring openresty..."
./configure --user=www-data --group=www-data --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock \
  --with-http_ssl_module --with-pcre --with-http_sub_module --with-luajit || exiterr "Failed to configure openresty installation."
iecho "Compiling openresty..."
make -s || exiterr "Failed to compile openresty."
make -s install || exiterr "Failed to install openresty."

# verify install and clean up
cd /opt/src || exiterr "Cannot enter directory /opt/src."
/bin/rm -rf "/opt/src/$openresty_src"
/bin/rm "/opt/src/$openresty_src.tar.gz"
if ! /usr/sbin/nginx -v 2>/dev/null; then
  exiterr "Openresty $OPENRESTY_VERSION failed to build."
fi

iecho "Downloading Certbot..."
cd $CUR_DIR
wget https://dl.eff.org/certbot-auto || exiterr "Certbot download failed."
chmod 700 certbot-auto

iecho "Installing Certbot..."
./certbot-auto -n --os-packages-only

bigecho "Installing Evilginx daemon..."
if [ ! -d "/etc/systemd/system/" ]; then exiterr "Cannot find /etc/systemd/system/ dir."; fi

cat <<EOF > /etc/systemd/system/nginx.service  
[Unit]
Description=The NGINX HTTP and reverse proxy server  
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking  
PIDFile=/run/nginx.pid  
ExecStartPre=/usr/sbin/nginx -t  
ExecStart=/usr/sbin/nginx  
ExecReload=/bin/kill -s HUP $MAINPID  
ExecStop=/bin/kill -s QUIT $MAINPID  
PrivateTmp=true

[Install]
WantedBy=multi-user.target  
EOF

grep -q -F 'include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ include \/etc\/nginx\/sites-enabled\/*;' /etc/nginx/nginx.conf
mkdir -p /etc/nginx/sites-available/ /etc/nginx/sites-enabled/

systemctl enable nginx.service || exiterr "Failed to enable Nginx daemon."
systemctl start nginx.service || exiterr "Failed to start Nginx daemon."

chmod 700 update.sh
./update.sh

bigecho "Evilginx successfully installed!"
