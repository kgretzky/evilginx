FROM debian

RUN apt-get update
RUN apt-get install -y git python
RUN git clone https://github.com/kgretzky/evilginx
RUN cd evilginx && chmod 700 install.sh && ./install.sh

CMD python evilginx/evilginx.py 
