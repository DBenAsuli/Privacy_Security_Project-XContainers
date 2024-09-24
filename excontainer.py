# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

from pki import *
from xcontainer import *
from colorama import Fore, Style


class EXContainer(XContainer):
    def __init__(self, name, root_dir, hypervisor):
        super().__init__(name, root_dir, hypervisor)
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.certificate = None
        self.valid_from = None
        self.valid_to = None

    # Requesting a certificate from CA.
    # The user can specify the validity period of the certificate, default is 1 hour.
    # User also specify which CA it requests the certificate from either an external
    # one or the entity itself.
    def request_certificate(self, ca, hours_limit=1):
        self.certificate, self.valid_from, self.valid_to = ca.sign_certificate(entity_public_key=self.public_key,
                                                                               entity_name=self.name,
                                                                               hours_limit=hours_limit, ca=ca)

    # The entity signs the data for authenticity
    def sign_data(self, data):
        # If it doesnt have a proper certificate, it will not be able to sign the data.
        if not self.certificate:
            raise ValueError("Entity does not have a valid certificate.")

        # If it has a certificate, it uses it's provate key to sign the data
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(data_hash)
        return base64.b64encode(signature).decode('utf-8')

    # The entity encrypts the data for verification of Data Integrity.
    def encrypt_data(self, data, recipient_public_key):
        cipher = PKCS1_OAEP.new(recipient_public_key)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted_data).decode('utf-8')

    # TODO Re-implement X-Containers methods using above methods

    def get_name(self):
        return self.name

    def get_public_key(self):
        return self.public_key

    def get_certificate(self):
        return self.certificate

    def get_valid_from(self):
        return self.valid_from

    def get_valid_to(self):
        return self.valid_to


# Secured Hypervisor Simulation
# Serves as the Relying Party in PKI Protocol
class RelyingHypervisor:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def verify_container(self, entity_public_key, entity_name, valid_from, valid_to, ca, data, signature):

        # First verify the validity of the Entity's certificate
        if not self.verify_certificate(entity_public_key=entity_public_key, entity_name=entity_name, ca=ca,
                                       signature=signature, valid_from=valid_from, valid_to=valid_to):
            return False

        # If it has a valid certificate,
        # Check authenticity of the data signed by the entity
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        try:
            pkcs1_15.new(entity.get_public_key()).verify(data_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    # Verify the validity of the Entity's certificate
    def verify_certificate(self, entity_public_key, entity_name, ca, signature, valid_from,
                           valid_to):

        # Verify the signature was not revoked by CA
        if not ca.verify_signature_validity(entity_name=entity_name, signature=signature):
            return False

        # Concatenate the key, the data and the valid timestamp to the signed string
        certificate_data = ca.get_name().encode('utf-8') + entity_name.encode(
            'utf-8') + entity_public_key.export_key() + valid_from.encode('utf-8') + valid_to.encode('utf-8')
        certificate_hash = SHA256.new(certificate_data)
        try:
            # Verify the certificate itself based on the string's hash
            pkcs1_15.new(ca.get_public_key()).verify(certificate_hash, signature)

            # Verify timestamp validity
            current_datetime = datetime.datetime.now()
            valid_from_dt = datetime.datetime.strptime(valid_from, '%Y-%m-%d %H:%M:%S')
            valid_to_dt = datetime.datetime.strptime(valid_to, '%Y-%m-%d %H:%M:%S')
            if valid_from_dt <= current_datetime <= valid_to_dt:
                return True
            else:
                return False

        except (ValueError, TypeError):
            # Some error occured during verification, the certificate is not valid
            print("Verification failed")
            return False

    # The party decrypts the data for verification of Data Integrity.
    def decrypt_data(self, encrypted_data):
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
        return decrypted_data.decode('utf-8')

    def request_certificate_revokation(self, ca, entity_name, signature):
        ca.revoke_certificate(entity_name=entity_name, signature=signature)

    # TODO Implement "challenge" flow
    def challenge(self):
        pass

    def handle_task(self, task_type, data, entity_public_key, entity_name, signature, valid_from, valid_to, ca, ):

        if not self.verify_container(data=data, entity_public_key=entity_public_key, entity_name=entity_name,
                                     signature=signature, valid_from=valid_from, valid_to=valid_to, ca=ca):
            return "Failed to authenticate EX-Container"

        print(Fore.GREEN + f"Authentication for EX-Container PASSED successfully" + Style.RESET_ALL)

        decrypted_data = self.decrypt_data(encrypted_data=data)

        if task_type == "file_io":
            print(f"Hypervisor handling file I/O for container: {decrypted_data}")
            return f"Handled file I/O: {decrypted_data}"
        elif task_type == "network_io":
            print(f"Hypervisor handling network I/O for container: {decrypted_data}")
            return f"Handled network I/O: {decrypted_data}"
        else:
            return "Unsupported task type"

    def get_public_key(self):
        return self.public_key
