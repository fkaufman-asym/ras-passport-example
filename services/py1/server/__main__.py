from flask import Flask, request, render_template
import os
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello from drs!"

@app.route('/ga4gh/drs/v1/objects/<int:myId>', methods=['GET', 'POST'])
def object(myId):
    if request.method == 'POST':
        token = request.form['token']
        # Load the public key to run another test...
        with open("/root/py-dev/scripts/repackage_python_script/jwtRS256.key.pub", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )
        # this will throw an exception if the JWT doesn't verify, see https://stackoverflow.com/questions/29650495/how-to-verify-a-jwt-using-python-pyjwt-with-public-key/48916883
        message = jwt.decode(token, public_key, algorithms=['RS256'])
        return render_template('object.json', myId=myId)
    else:
        return 'invalid, use POST'

if __name__ == '__main__':
    port = os.environ['PORT']
    app.run(host='0.0.0.0', port=port, debug=True)
