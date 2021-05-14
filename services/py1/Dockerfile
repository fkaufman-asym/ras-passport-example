FROM python:3-buster

# WORKDIR /root
# ADD . /root
RUN mkdir -p /var/keys
#COPY jwtRS256.key /var/keys/
#COPY jwtRS256.key.pub /var/keys/

# install various things
RUN apt-get update && apt-get install -y \
  vim less

# build the keys
RUN cd /var/keys && \
  ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key -N "" && \
  openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
