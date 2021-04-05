# Repackaging NIH RAS GA4GH Passport into a Broad GA4GH Passport

This is a prototype to show how a client could repackage an NIH RAS passport into a Broad signed passport. Both the passport and the visas are encoded.

To run this you'll need:
1. Broad client_secret for getting the access token from RAS. Add to repack_passport.py. Config pending.
2. RSA private key for encoding Broad passports. Place in same directory as repack_passport.py
3. RAS test user and password

## How to run:  
```
git clone git@github.com:broadinstitute/ras-passport-example.git
cd ras-passport-example
virtualenv -p python3.7 venv && . venv/bin/activate && pip install -r requirements.txt
python3 repack_passport.py
```
## Note: 
You will be prompted to put the RAS authorize url into a browser and login with your RAS test user. After logging in take that new url and paste into the cmd line to proceed.
