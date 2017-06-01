#!/bin/bash

# Evilginx Update Script (run this after every update from GitHub)

bigecho() { echo; echo "## $1"; echo; }

grep -q -F 'server_names_hash_bucket_size 128;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ server_names_hash_bucket_size 128;' /etc/nginx/nginx.conf
grep -q -F 'fastcgi_buffers 16 16k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ fastcgi_buffers 16 16k;' /etc/nginx/nginx.conf
grep -q -F 'fastcgi_buffer_size 32k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ fastcgi_buffer_size 32k;' /etc/nginx/nginx.conf
grep -q -F 'proxy_buffer_size 128k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_buffer_size 128k;' /etc/nginx/nginx.conf
grep -q -F 'proxy_buffers 4 256k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_buffers 4 256k;' /etc/nginx/nginx.conf
grep -q -F 'proxy_busy_buffers_size 256k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_busy_buffers_size 256k;' /etc/nginx/nginx.conf

systemctl restart nginx.service

bigecho "Nginx config files are up to date!"
