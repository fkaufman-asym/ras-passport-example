FROM python:3-buster

# WORKDIR /root
# ADD . /root
RUN mkdir -p /var/keys
COPY jwtRS256.key /var/keys/
COPY jwtRS256.key.pub /var/keys/

# install various things
RUN apt-get update && apt-get install -y \
  vim less
