import os
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .base import BaseHandler

# Define the key
key = "thesecondbestsecretkeyintheentireworld"

nonce_bytes = os.urandom(16)

# Unsuccessful in getting encryption logic to work/attempted to use practical code with defined input values
chacha20_cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce_bytes),
                         mode=None)
chacha20_encryptor = chacha20_cipher.encryptor()
chacha20_decryptor = chacha20_cipher.decryptor()

input_value = f"{dispayName}{home_address}{disabilty}{D_O_B}{email}"

plaintext_bytes = bytes(input_value, "utf-8")

ciphertext_bytes = encryptor.update(plaintext_bytes)
ciphertext = ciphertext_bytes.hex()
print("Ciphertext: " + ciphertext)

plaintext_bytes_2 = chacha20_decryptor.update(ciphertext_bytes)
plaintext_2 = str(plaintext_bytes_2, "utf-8")
print("Original Plaintext: " + plaintext_2)


class RegistrationHandler(BaseHandler):

    # Following the preexisting code logic to expand the input fields
    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            disability = body.get('disability')
            if not isinstance(disability, str):
                raise Exception()
            home_address: object = body.get('home_address')
            if not isinstance(home_address, str):
                raise Exception()
            DOB = body.get('D_O_B')
            if not isinstance(D_O_B, str):
                raise Exception()

        except Exception as e:
            self.send_error(400, message='You must provide an additional details !')
            return

        if not email:
            self.send_error(400, message='Email address is invalid!')
            return

        if not password:
            self.send_error(400, message='Password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='Display name is invalid!')
            return

        if not disability:
            self.send_error(400, message='Disability description is invalid!')
            return

        if not D_O_B:
            self.send_error(400, message='DOB is invalid!')
            return

        if not home_address:
            self.send_error(400, message='Home address is invalid!')
            return

        user = yield self.db.users.find_one({
            'email': email
        }, {})

        if user is not None:
            self.send_error(406, message='A user with the given email address already exists!')
            return

        # Updated code to hash the password(taken from practical)
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        passphrase_bytes = bytes(password, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)

        # store in mongo.
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_passphrase,
            'salt': salt,
            'displayName': display_name,
            'disability': disability,
            'home_address': home_address,
            'DOB': DOB,
        })

        self.set_status(200)
        self.response['email'] = email
        self.response["displayName"] = display_name
        self.response['DOB'] = D_O_B
        self.response['home_address'] = home_address
        self.response['disability'] = disability

        self.write_json()
