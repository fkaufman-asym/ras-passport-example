# NIH RAS GA4GH Passport Prototyping

This repo was created to prototype the following:

* Repackaging and signing a RAS GA4GH Passports, see [original repo](https://github.com/broadinstitute/ras-passport-example) by Nicole B
* Demonstrating how to POST a JWT passport to access a GA4GH DRS endpoint
* Demonstrating how a client/DRS server can be secured with mutual SSL Authentication

## Repackaging NIH RAS GA4GH Passport into a Broad GA4GH Passport

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

## Docker-Based: Repackaging NIH RAS GA4GH Passport into a Broad GA4GH Passport

### Origin

This project is inspired by, and forked from, this blog post:

**🐳 Simplified guide to using Docker for local development environment**

_The blog link :_

[https://blog.atulr.com/docker-local-environment/](https://blog.atulr.com/docker-local-environment/)

### Launching Python Dev Environment

To run the example:

`docker-compose up` or `docker-compose up -d` if you want to avoid console output

`docker-compose up --build` to force a rebuild

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


## Demonstrating POST'ing a Passport JWT to a Mock DRS Server

### Creating Token

Take the token from "Broad_encoded_passport.txt"

  % export token=`cat ./working/scripts/repackage_python_script/Broad_encoded_passport.txt`
  % curl -X POST -d "token=$token" 'http://localhost:9000/ga4gh/drs/v1/objects/12192312'

The return is a DRS response.  If you get a stacktrace then the verification of the signature was likely incorrect.
The service is referencing the file /root/py-dev/scripts/repackage_python_script/jwtRS256.key.pub in the
container so make sure you create that in the repackaging example above and
run through the whole login flow to generate the resigned JWT ("Broad_encoded_passport.txt").

## Example Client-Server Mutual Authentication with Nginx

This needs to be built into the Dockerfile for a second python based service.
But for now, I'm following the tutorial here:

https://levelup.gitconnected.com/certificate-based-mutual-tls-authentication-with-nginx-57c7e693759d

With one note, the following line should be:

  ssl_verify_client       on;

Not "yes" as it is in the tutorial.

I also connected to localhost:9000 for the proxy instead of localhost:5000 in the tutorial.

```
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        # SSL configuration
        #
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        ssl_certificate         /etc/ssl/selfsigned/server.crt;
        ssl_certificate_key     /etc/ssl/selfsigned/server.key;
        ssl_client_certificate  /etc/ssl/selfsigned/client.crt;
        ssl_verify_client       on;

...

location / {
        # First attempt to serve request as file, then
        # as directory, then fall back to displaying a 404.
        #####try_files $uri $uri/ =404;
        proxy_pass http://localhost:9000/;

}
```

LEFT OFF WITH: need to show an example of a curl using the client certificate.
