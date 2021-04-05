#!/usr/bin/env python3

import requests
import json
import urllib.parse as urlparse
from urllib.parse import parse_qs
import jwt  # jwt requires ("PyJWT==1.7.1")
import time
from pathlib import Path

""" 
references used: 
https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md#ga4gh-jwt-format
https://auth.nih.gov/docs/RAS/serviceofferings.html#AppendixA
https://github.com/NIH-Auth-Services/CIT-IAM-RAS/blob/master/NIH_RAS_PartnerDevGuide-STG_v1.1.docx
"""

def get_auth_code_url():
    """Requests RAS login url."""
    url = 'https://stsstg.nih.gov:443/auth/oauth/v2/authorize'
    params = {
          'client_id': '16082a60-505e-4ac1-a82f-13710ff0cf39',
          'response_type': 'code',
          'scope': 'openid profile email ga4gh_passport_v1',
          'prompt': 'login consent',
          # 'redirect_uri': 'http://local.broadinstitute.org/fence-callback',
          'redirect_uri': 'http://local.broadinstitute.org/fence-callback',
    }

    response = requests.get(url, params=params, allow_redirects=True, timeout=2)
    login_url = response.url

    # RAS only accepts authentication codes so we need to take the authorize url
    # and put it into a browser to log in with our RAS test user on staging.
    # username: Broadtestuser111
    # password BGK{$BC\ht
    # You will get a site is not reached page but we can still get the auth code from the url.
    # This auth code can be used only once.

    print("Put the authorize url into a browser to log in.", login_url)
    print("RAS test username: Broadtestuser111   password: BGK{$BC\ht")
    print("If you have recently logged in, you might not have to login again")


def get_auth_code():
    """ Parses the auth code from the url after login."""
    callback_url = input("After logging in copy url here: ")
    # Example:
    # 'http://local.broadinstitute.org/fence-callback?code=356d02d5-5664-49dd-bba1-c2f6529bddb1& \
    # correlationID=nihgw-wfn7JmcZ2XY=.fabd97d17d20b632'

    p = urlparse.urlparse(callback_url)
    auth_code = parse_qs(p.query)['code'][0]
    print("Auth code from RAS: ", auth_code)
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
        'redirect_uri': 'http://local.broadinstitute.org/fence-callback',
        'scope': 'ga4gh_passport_v1',
        'client_id': '16082a60-505e-4ac1-a82f-13710ff0cf39',
        'client_secret': 'nullnullnull'
    }

    r = requests.post(url, params=params, headers=headers)
    # Example response:
    # {
    #   "access_token":"eyJ0eXAsomethingverylongD1g",
    #   "token_type":"Bearer",
    #   "expires_in":1800,
    #   "refresh_token":"551ca2e3-70d7-435e-b00d-1e089ee4e2e9",
    #   "scope":"openid profile email ga4gh_passport_v1",
    #   "sub":"bCbsufBJvApw6RKmMpv-2f-ZI2kkhhGFBEJMyBHKap4",
    #   "id_token":"eyJ0eXAsomethingverylong40CxA",
    #   "id_token_type":"urn:ietf:params:oauth:grant-type:jwt-bearer"
    # }

    j = r.json()
    print("RAS Access token: ", j['access_token'])
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
    # {'sub': 'bCbsufBJvApw6RKmMpv-2f-ZI2kkhhGFBEJMyBHKap4',
    # 'preferred_username': 'broadtestuser111@era.nih.gov',
    # 'userid': 'Broadtestuser111',
    # 'email': 'Broadtestuser111@ras.test.nih.gov',
    # 'txn': 'vRWagEEd+0Q=.fabd97d17d20c054',
    # 'passport_jwt_v11': 'eyJ0eXAiOiverylongXrzUSwmw'}

    print("RAS userinfo response: ", r.json())
    j = r.json()
    return j['passport_jwt_v11']


def decode_passport(passport_jwt):
    """Decodes the passport JWT."""
    decoded_passport = jwt.decode(passport_jwt, verify=False)
    # Example decoded passport:
    # {'sub': 'bCbsufBJvApw6RKmMpv-2f-ZI2kkhhGFBEJMyBHKap4',
    # 'jti': 'b2fb39cc-d536-419e-b3e0-d2f6483c896f',
    # 'scope': 'openid profile email ga4gh_passport_v1',
    # 'txn': 'vRWagEEd+0Q=.fabd97d17d20c054',
    # 'iss': 'https://stsstg.nih.gov',
    # 'iat': 1617473120,
    # 'exp': 1617516320,
    # 'ga4gh_passport_v1': ['ew0KICAverylong4Jg']}

    print("Decoded RAS passport: ", decoded_passport)
    coded_visas = decoded_passport['ga4gh_passport_v1'][0]
    return coded_visas


def decode_visas(encoded_visas):
    """Decodes the embedded visas JWT."""
    decoded_visas = jwt.decode(encoded_visas, verify=False)
    print("RAS visas: ", decoded_visas)
    return decoded_visas


def create_broad_passport(visas):
    """Encode visas and passport to make a signed Broad passport"""

    private_key = Path('jwtRS256.key').read_text()    # generated an RSA private key beforehand.
    private_key = private_key.replace('\n', '')

    encoded_visa = jwt.encode(
        visas,
        private_key
    ).decode('UTF8')

    print("Broad encoded visa : ", encoded_visa)

    encoded_passport = jwt.encode(
        {
            'sub': 'some_subject_identifier',
            'jti': 'some_unique_token_identifier',
            'scope': 'email profile department idp member sac ga4gh_passport_v1 openid',
            'txn': 'some_transaction_claim',
            'iss': 'https://app.terra.bio',
            'iat': time.time(),
            'exp': time.time() + 24 * 60 * 60,
            'ga4gh_passport_v1': encoded_visa
        },
        private_key,
        headers={
                 'typ': 'JWT',
                 'alg': 'RS256',
                 'kid': 'some_key_identifier'
        }
    ).decode('UTF8')
    print("Broad encoded passport: ", encoded_passport)

    # Used RAS userinfo endpoint format for Broad's here
    data = {
        'sub': 'some_subject_identifier',
        'preferred_username': 'broadtestuser111@era.nih.gov',
        'userid': 'Broadtestuser111',
        'email': 'Broadtestuser111@ras.test.nih.gov',
        'txn': 'some_transaction_claim',
        'passport_jwt_v11': encoded_passport
    }
    broad_userinfo_response = json.dumps(data)
    print("Broad's userinfo json object response: ", broad_userinfo_response)


def main():
    get_auth_code_url()
    auth_code = get_auth_code()
    access_token = get_access_token(auth_code)
    passport_jwt = get_passport(access_token)
    encoded_visas = decode_passport(passport_jwt)
    visas = decode_visas(encoded_visas)
    create_broad_passport(visas)


if __name__ == '__main__':
    main()

