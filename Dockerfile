FROM debian:jessie

RUN apt-get update && apt-get install -y git python zlib1g-dev net-tools make gcc libpcre3-dev libssl-dev wget


ENV OPENRESTY_VERSION='1.11.2.2' 
ENV OPENRESTY_SRC_URL="https://openresty.org/download/openresty-$OPENRESTY_VERSION.tar.gz"
ENV openresty_src="openresty-$OPENRESTY_VERSION"

RUN export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" && \\
mkdir -p /opt/src && cd /opt/src


RUN wget -t 3 -T 30 -nv -O "$openresty_src.tar.gz" "$OPENRESTY_SRC_URL";

RUN rm -rf "/opt/src/$openresty_src"

RUN tar xvf "$openresty_src.tar.gz" && rm -f "$openresty_src.tar.gz" 

WORKDIR $openresty_src
RUN ./configure --user=www-data --group=www-data --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock \
  --with-http_ssl_module --with-pcre --with-http_sub_module --with-luajit 

RUN make -s && make -s install

WORKDIR /evilginx
RUN wget https://dl.eff.org/certbot-auto 
RUN chmod 700 certbot-auto

RUN ./certbot-auto -n --os-packages-only

RUN grep -q -F 'include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ include \/etc\/nginx\/sites-enabled\/*;' /etc/nginx/nginx.conf

RUN mkdir -p /etc/nginx/sites-available/ /etc/nginx/sites-enabled/


RUN grep -q -F 'server_names_hash_bucket_size 128;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ server_names_hash_bucket_size 128;' /etc/nginx/nginx.conf
RUN grep -q -F 'fastcgi_buffers 16 16k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ fastcgi_buffers 16 16k;' /etc/nginx/nginx.conf
RUN grep -q -F 'fastcgi_buffer_size 32k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ fastcgi_buffer_size 32k;' /etc/nginx/nginx.conf
RUN grep -q -F 'proxy_buffer_size 128k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_buffer_size 128k;' /etc/nginx/nginx.conf
RUN grep -q -F 'proxy_buffers 4 256k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_buffers 4 256k;' /etc/nginx/nginx.conf
RUN grep -q -F 'proxy_busy_buffers_size 256k;' /etc/nginx/nginx.conf || sed -i '/^http {/a\ \ \ \ proxy_busy_buffers_size 256k;' /etc/nginx/nginx.conf

ADD . .

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]