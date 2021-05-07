from flask import Flask, request
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
        message = jwt.decode(token, public_key, algorithms=['RS256'])
        return 'Hello POST from drs object id: %d token: %s decode message: %s' % (myId, token, str(message))
    else:
        return 'invalid, use POST'

if __name__ == '__main__':
    port = os.environ['PORT']
    app.run(host='0.0.0.0', port=port, debug=True)
