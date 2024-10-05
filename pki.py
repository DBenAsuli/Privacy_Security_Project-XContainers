# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import random
import string
import datetime
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15


def generate_random_string(length):
    letters = string.ascii_letters + string.digits
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str


class CA:
    def __init__(self, name=None):
        if name == None:
            self.name = generate_random_string(4)

        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.certificates_dict = {}

    # Request from CA to sign the certificate using the entity's public key
    # Calculated a timestamp that makes the signature valid for 'hours_limit' hours.
    def sign_certificate(self, entity_public_key, entity_name, hours_limit=1, ca=None):
        # Calculates validity period
        valid_from = datetime.datetime.now()
        valid_to = valid_from + datetime.timedelta(hours=hours_limit)
        valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S')
        valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S')

        # Concatenate the key, the data and the valid timestamp to the signed string
        certificate_data = self.name.encode('utf-8') + entity_name.encode(
            'utf-8') + entity_public_key.export_key() + valid_from_str.encode('utf-8') + valid_to_str.encode(
            'utf-8')

        # Creates signature
        certificate_hash = SHA256.new(certificate_data)
        signature = pkcs1_15.new(self.key).sign(certificate_hash)

        # Add signature to dictionary of valid certificates
        if entity_name not in self.certificates_dict.keys():
            self.certificates_dict[entity_name] = []

        self.certificates_dict[entity_name].append(signature)

        return signature, valid_from_str, valid_to_str

    # Verify the signature was not revoked by CA and still considered valid
    def verify_signature_validity(self, entity_name, signature):
        print("dfgdsfgdfgs1")
        if entity_name in self.certificates_dict:
            print("dfgdsfgdfgs2")

            if signature in self.certificates_dict[entity_name]:
                print("dfgdsfgdfgs3")

                return True

        return False

    # Revoke a certificate granted to a given entity
    # by removing it from dictionary
    def revoke_certificate(self, entity_name, signature):
        if entity_name in self.certificates_dict:
            if signature in self.certificates_dict[entity_name]:
                self.certificates_dict[entity_name].remove(signature)

    def get_name(self):
        return self.name

    def get_public_key(self):
        return self.public_key
