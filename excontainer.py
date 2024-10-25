# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour                                           207527680
# The Hebrew University of Jerusalem                      October 2024

from colorama import Fore, Style

from pki import *
from xcontainer import *


class EXContainer(XContainer):
    def __init__(self, name, root_dir, hypervisor, ca):
        super().__init__(name, root_dir, hypervisor)
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.ca = ca
        self.certificate = None
        self.valid_from = None
        self.valid_to = None
        self.recipient_public_key = hypervisor.public_key

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
        data_hash = SHA256.new(data)
        signature = pkcs1_15.new(self.key).sign(data_hash)
        return base64.b64encode(signature)

    # The entity encrypts the data for verification of Data Integrity.
    def encrypt_data(self, data, recipient_public_key):
        cipher = PKCS1_OAEP.new(recipient_public_key)
        encrypted_data = cipher.encrypt(data)
        return base64.b64encode(encrypted_data)

    def encrypt_command(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.encrypt_data(data, self.recipient_public_key)

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = self.encrypt_data(file_data, self.recipient_public_key)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

    def offload_to_hypervisor(self, task_type, data):
        encrypted_command = self.encrypt_command(data)
        self.signature = self.sign_data(data=encrypted_command)

        return self.hypervisor.handle_task(task_type=task_type, data=encrypted_command, entity_name=self.name,
                                           entity_public_key=self.public_key, signature=self.certificate,
                                           valid_from=self.valid_from, valid_to=self.valid_to, ca=self.ca,
                                           data_signature=self.signature)

    # Run a command securely inside the x-container (Linux Version)
    def run_secure_command(self, command):
        print(f"Running secure command in container {self.name}: {command}")

        try:
            encrypted_command = self.encrypt_command(command)
            decrypted_command = self.hypervisor.decrypt_command(encrypted_command)

            result = subprocess.run(decrypted_command, shell=True, cwd=self.root_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            if ">" in command:
                file_path = command.split(">")[-1].strip()
                file_path = f"{self.root_dir}/{file_path}"
                self.encrypt_file(file_path)  # Encrypt the file after creation

            if command.startswith("cat "):
                file_name = command.split("cat ", 1)[1].strip()
                return self.read_secure_file(file_name)

            encrypted_output = self.encrypt_command(result.stdout.strip())

            output = self.hypervisor.decrypt_command(encrypted_output)
            return output

        except Exception as e:
            print(f"Error in EXContainer {self.name}: {e}")
            return str(e)

    # Run a command securely inside the x-container (MacOS Version)
    def run_secure_command_mac(self, command):
        print(f"Running secure command in container {self.name}: {command}")
        try:

            encrypted_command = self.encrypt_command(command)
            decrypted_command = self.hypervisor.decrypt_command(encrypted_command)

            result = subprocess.run(decrypted_command, shell=True, cwd=self.root_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            if ">" in command:
                file_path = command.split(">")[-1].strip()
                file_path = f"{self.root_dir}/{file_path}"
                self.encrypt_file(file_path)  # Encrypt the file after creation

            if command.startswith("cat "):
                file_name = command.split("cat ", 1)[1].strip()
                return self.read_secure_file(file_name)

            encrypted_output = self.encrypt_command(result.stdout.strip())
            output = self.hypervisor.decrypt_command(encrypted_output)
            return output
        except Exception as e:
            print(f"Error in XContainer {self.name}: {e}")
            return str(e)

    # Send a message securely to another EXContainer
    def send_secure_message(self, recipient_container, message):
        signed_message = self.key.sign(message.encode('utf-8'))
        return recipient_container.receive_secure_message(signed_message, self.public_key)

    # Receive a message securely from another EXContainer
    def receive_secure_message(self, signed_message, sender_public_key=None):
        try:
            sender_public_key.verify(signed_message)  # Verification of signature
            message = signed_message.decode('utf-8')  # Assuming signature contains the original message
            print(f"{self.name} EXContainer -received a secure message: {message}")
            return message
        except InvalidSignature:
            raise Exception(f"EXContainer - Message signature verification failed for {self.name}")

    def read_secure_file(self, file_path):
        return self.hypervisor.decrypt_file(f"{self.root_dir}/{file_path}")

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

    def verify_container(self, entity_public_key, entity_name, valid_from, valid_to, ca, data, signature,
                         data_signature):

        # First verify the validity of the Entity's certificate
        if not self.verify_certificate(entity_public_key=entity_public_key, entity_name=entity_name, ca=ca,
                                       signature=signature, valid_from=valid_from, valid_to=valid_to,
                                       data_signature=data_signature):
            print(Fore.RED + f"Authentication for EX-Container's certificate FAILED " + Style.RESET_ALL)
            return False

        # If it has a valid certificate,
        # Check authenticity of the data signed by the entity
        data_hash = SHA256.new(data)
        signature = base64.b64decode(data_signature)

        try:
            pkcs1_15.new(entity_public_key).verify(data_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    # Verify the validity of the Entity's certificate
    def verify_certificate(self, entity_public_key, entity_name, ca, signature, valid_from,
                           valid_to, data_signature):

        # Verify the signature was not revoked by CA
        if not ca.verify_signature_validity(entity_name=entity_name, signature=signature):
            print(Fore.RED + f"Authentication for EX-Container's signature validity FAILED " + Style.RESET_ALL)
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
            print(Fore.RED + "Verification FAILED" + Style.RESET_ALL)
            return False

    # The party decrypts the data for verification of Data Integrity.
    def decrypt_data(self, encrypted_data):
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = self.decrypt_data(encrypted_data)
        return decrypted_data.decode()

    def decrypt_command(self, encrypted_data):
        return self.decrypt_data(encrypted_data).decode()

    def request_certificate_revokation(self, ca, entity_name, signature):
        ca.revoke_certificate(entity_name=entity_name, signature=signature)

    def challenge(self):
        # TODO Siwar Implement "challenge" flow
        pass

    def verify_signed_data(self, entity_public_key, entity_name, signature, valid_from, valid_to, ca, data,
                           data_signature):

        if not self.verify_certificate(entity_public_key=entity_public_key, entity_name=entity_name, ca=ca,
                                       signature=signature, valid_from=valid_from, valid_to=valid_to,
                                       data_signature=data_signature):
            print(Fore.RED + f"Authentication for EX-Container's certificate FAILED " + Style.RESET_ALL)
            return False

        # If it has a valid certificate,
        # Check authenticity of the data signed by the entity
        data_hash = SHA256.new(data)
        signature = base64.b64decode(data_signature)
        try:
            pkcs1_15.new(entity_public_key).verify(data_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    def handle_task(self, task_type, data, entity_public_key, entity_name, signature, data_signature, valid_from,
                    valid_to, ca):

        decrypted_data = self.decrypt_data(encrypted_data=data)
        if not self.verify_container(data=data, entity_public_key=entity_public_key, entity_name=entity_name,
                                     signature=signature, valid_from=valid_from, valid_to=valid_to, ca=ca,
                                     data_signature=data_signature):
            print(Fore.RED + f"Authentication for EX-Container FAILED " + Style.RESET_ALL)
            return "Failed to authenticate EX-Container"

        print(Fore.GREEN + f"Authentication for EX-Container PASSED successfully" + Style.RESET_ALL)

        is_verified = self.verify_signed_data(entity_public_key=entity_public_key, entity_name=entity_name,
                                              signature=signature, valid_from=valid_from, valid_to=valid_to, ca=ca,
                                              data=data, data_signature=data_signature)

        if not is_verified:
            print(Fore.RED + "\nVerification of signed data failed\n" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "\nVerification of signed data succeeded\n" + Style.RESET_ALL)

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
