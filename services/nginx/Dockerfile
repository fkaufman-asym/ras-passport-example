#FROM python:3-buster
FROM nginx:1.13-alpine

WORKDIR /root
ADD . /root

# install various things
RUN apk upgrade --update-cache --available && \
  apk add openssl && \
  rm -rf /var/cache/apk/*

# add web dir
RUN mkdir -p /var/www/html && \
  cp /root/index.html /var/www/html/

# make various self-signed certs
RUN cd /etc/ssl && \
  mkdir selfsigned && \
  cd selfsigned && \
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/C=US/ST=California/L=Los Angeles/O=.../OU=.../CN=.../emailAddress=..." && \
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout client.key -out client.crt -subj "/C=US/ST=California/L=Los Angeles/O=.../OU=.../CN=.../emailAddress=..." && \
  openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -passout pass:password && \
  cp client.pfx /var/www/html/

# now setup Nginx
RUN cd /etc/nginx/conf.d && \
    cp default.conf ../backup && \
    cp /root/default ./default.conf
