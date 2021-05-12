import server.config as config
from flask import Flask, request, render_template, redirect
import os
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import requests
import json
import urllib.parse as urlparse
from urllib.parse import parse_qs
import time
from pathlib import Path

app = Flask(__name__)

auth_code = ""


# Login endpoints
@app.route("/login")
def login():
    url = 'https://stsstg.nih.gov:443/auth/oauth/v2/authorize'
    params = {
          'client_id': config.auth['client_id'],
          'response_type': 'code',
          'scope': 'openid profile email ga4gh_passport_v1',
          'prompt': 'login consent',
          'redirect_uri': config.auth['redirect_uri'],
    }

    response = requests.get(url, params=params, allow_redirects=True, timeout=2)
    return redirect(response.url, code=302)

@app.route("/fence-callback")
def callback():
    # get the auth code from the callback
    auth_code = get_auth_code(request.full_path)

    # now get the access token
    access_token = get_access_token(auth_code)

    # use userinfo to get back the passport for this user
    ras_passport = get_passport(access_token)

    # extract the visas
    ras_visas = decode_passport(ras_passport)

    # create a new broad passport using the ras_visas
    broad_passport = create_broad_passport(ras_visas)

    public_key = Path('/var/keys/jwtRS256.key.pub').read_text()

    # put together a response
    return render_template("token.html", token=broad_passport, public_key=public_key)


def get_auth_code(callback_url):
    """ Parses the auth code from the url after login."""
    #callback_url = input("After logging in copy url here: ")
    # Example:
    # 'http://local.broadinstitute.org/fence-callback?code=356stringdb1& \
    # correlationID=nihgw-string0b632'

    print("callback URL: "+callback_url)
    p = urlparse.urlparse(callback_url)
    print(str(p))
    auth_code = parse_qs(p.query)['code'][0]
    #print("Auth code from RAS: ", auth_code)
    print("Auth code from RAS: ")
    return auth_code


def get_access_token(auth_code):
    """Gets access token from RAS"""
    url = 'https://stsstg.nih.gov:443/auth/oauth/v2/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    params = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': config.auth['redirect_uri'],
        'scope': 'ga4gh_passport_v1',
        'client_id': config.auth['client_id'],
        'client_secret': config.auth["client_secret"]

    }

    r = requests.post(url, params=params, headers=headers)
    # Example response:
    # {
    #   "access_token":"eyJ0eXAsomethingverylongD1g",
    #   "token_type":"Bearer",
    #   "expires_in":1800,
    #   "refresh_token":"551ca2e3-string-1e089ee4e2e9",
    #   "scope":"openid profile email ga4gh_passport_v1",
    #   "sub":"bCbsufBstringBHKap4",
    #   "id_token":"eyJ0eXAsomethingverylong40CxA",
    #   "id_token_type":"urn:ietf:params:oauth:grant-type:jwt-bearer"
    # }

    j = r.json()
    #print("RAS token response: ", j) #HHEHHHEHRHEH
    print("RAS token response: ") #HHEHHHEHRHEH
    print("RAS Access token: ", j['access_token'])
    #save("RAS token response", json.dumps(j))
    return j['access_token']


def get_passport(access_token):
    """Calls userinfo endpoint for RAS passport JSON."""
    url = 'https://stsstg.nih.gov/openid/connect/v1.1/userinfo'

    headers_auth = {
        'content-type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    r = requests.get(url, headers=headers_auth, allow_redirects=True)
    # Example response:
    # {'sub': 'bCbsufBstringBHKap4',
    # 'preferred_username': 'broadtestuser111@era.nih.gov',
    # 'userid': 'Broadtestuser111',
    # 'email': 'Broadtestuser111@ras.test.nih.gov',
    # 'txn': 'vRWstring054',
    # 'passport_jwt_v11': 'eyJ0eXAiOiverylongXrzUSwmw'}

    #print("RAS userinfo response: ", r.json())
    print("RAS userinfo response: ")
    #save("RAS userinfo response", json.dumps(r.json()))
    j = r.json()
    return j['passport_jwt_v11']


# TODO: note, we need to return the full array here an not just the single visa
def decode_passport(passport_jwt):
    """Decodes the passport JWT."""
    decoded_passport = jwt.decode(passport_jwt, verify=False)
    # Example decoded passport:
    # {'sub': 'bCbsufBstringBHKap4',
    # 'jti': 'b2fb39cc-string-d2f6483c896f',
    # 'scope': 'openid profile email ga4gh_passport_v1',
    # 'txn': 'vRWagEstring0c054',
    # 'iss': 'https://stsstg.nih.gov',
    # 'iat': 1617473120,
    # 'exp': 1617516320,
    # 'ga4gh_passport_v1': ['ew0KICAverylong4Jg']}

    #print("Decoded RAS passport: ", decoded_passport)
    print("Decoded RAS passport: ")
    #save("Decoded RAS passport", json.dumps(decoded_passport))
    coded_visas = decoded_passport['ga4gh_passport_v1'][0]
    return coded_visas


def decode_visas(encoded_visas):
    """Decodes the embedded visas JWT."""
    decoded_visas = jwt.decode(encoded_visas, verify=False)
    #print("RAS visas: ", decoded_visas)
    print("RAS visas: ")
    #save("RAS visas", json.dumps(decoded_visas))
    return decoded_visas


def create_broad_passport(encoded_visa):
    """Encode passport to make a signed Broad passport with RAS encoded Visas"""

    private_key = Path('/var/keys/jwtRS256.key').read_text()    # generated an RSA private key beforehand.
    #private_key = private_key.replace('\n', '')

    encoded_passport = jwt.encode(
        {
            'sub': 'some_subject_identifier',
            'jti': 'some_unique_token_identifier',
            'scope': 'email profile department idp member sac ga4gh_passport_v1 openid',
            'txn': 'some_transaction_claim',
            'iss': config.new_passport['iss'],
            'iat': time.time(),
            'exp': time.time() + 24 * 60 * 60,
            'ga4gh_passport_v1': encoded_visa
        },
        private_key,
        headers={
                 'typ': 'JWT',
                 'alg': 'RS256',
                 'kid': 'some_key_identifier'
        },
        algorithm="RS256"
    ).decode('UTF8')
    #print("Broad encoded passport: ", encoded_passport)
    print("Broad encoded passport: ")
    #save("Broad encoded passport", encoded_passport)

    # Used RAS userinfo endpoint format for Broad's here
    data = {
        'sub': 'some_subject_identifier',
        'preferred_username': config.new_passport['preferred_username'],
        'userid': config.ras_login['ras_username'],
        'email': config.new_passport['email'],
        'txn': 'some_transaction_claim',
        'passport_jwt_v11': encoded_passport
    }
    broad_userinfo_response = json.dumps(data)
    #print("Broad's userinfo json object response: ", broad_userinfo_response)
    print("Broad's userinfo json object response: ")
    #save("Broads userinfo json object response", broad_userinfo_response)
    return(encoded_passport)

# DRS endpoints

@app.route("/service-info")
def serviceinfo():
    return "Hello from drs!"

@app.route("/download-simulated-signed-url")
def signedurl():
    return redirect("http://genome.ucsc.edu/goldenPath/help/examples/cramExample.cram", code=302)

@app.route('/ga4gh/drs/v1/objects/<int:myId>', methods=['GET', 'POST'])
def object(myId):
    if request.method == 'GET':
        return render_template('object.json', myId=myId)
    else:
        return 'invalid, use GET, no auth required'

@app.route('/ga4gh/drs/v1/objects/<int:myId>/access/<accessId>', methods=['GET', 'POST'])
def access(myId, accessId):
    if request.method == 'POST':
        token = request.form['token']
        # Load the public key to run another test...
        with open("/var/keys/jwtRS256.key.pub", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )
        # this will throw an exception if the JWT doesn't verify, see https://stackoverflow.com/questions/29650495/how-to-verify-a-jwt-using-python-pyjwt-with-public-key/48916883
        message = jwt.decode(token, public_key, algorithms=['RS256'])
        return redirect("http://genome.ucsc.edu/goldenPath/help/examples/cramExample.cram", code=302)
    else:
        return 'invalid, use POST'



if __name__ == '__main__':
    port = os.environ['PORT']
    app.run(host='0.0.0.0', port=port, debug=True)
