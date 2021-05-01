# Repackaging NIH RAS GA4GH Passport into a Broad GA4GH Passport

A prototype to show how a client could repackage an NIH RAS passport into a Broad signed passport. Both the passport and the visas are encoded.

To run you'll need to update the config. You will need the following:
1. client_id and client_secret for getting the RAS access token.
2. Redirect uri known to RAS
3. RAS test user and password
4. For the repackaged passport, you can add an issuer and email or leave blank.
6. Copy config_template.py and rename to config.py

You will also need an RSA private key for encoding the new passport. Place in same directory as repack_passport.py. To create a key:
```
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
cat jwtRS256.key
cat jwtRS256.key.pub
```

## How to run:  
```
git clone git@github.com:broadinstitute/ras-passport-example.git
cd ras-passport-example
virtualenv -p python3.7 venv && . venv/bin/activate && pip install -r requirements.txt
python3 repack_passport.py
```
## Note:
You will be prompted to put the RAS authorize url into a browser and login with your RAS test user. After logging in take that new url and paste into the cmd line to proceed.

## Docker-Based

### Origin

This project is inspired by, and forked from, this blog post:

**🐳 Simplified guide to using Docker for local development environment**

_The blog link :_

[https://blog.atulr.com/docker-local-environment/](https://blog.atulr.com/docker-local-environment/)

### Launching Python Dev Environment

To run the example:

`docker-compose up` or `docker-compose up -d` if you want to avoid console output

Details about each service and how to run them is present in the individual services directories.

### Connecting to Python Dev Environment

Once you launch with `docker-compose up` you can login in to the Python service
container using:


    $> bash connect.sh
    # inside the Docker container
    #> cd ~/py-dev/scripts/repackage_python_script

### Executing the Python Script

    #> python repack_passport.py

### Python Server

The flask server is running on `http://localhost:9000` and just returns "Hello from py1"
