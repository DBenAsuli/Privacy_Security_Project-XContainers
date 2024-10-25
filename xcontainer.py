# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour                                           207527680
# The Hebrew University of Jerusalem                      October 2024

from cryptography.fernet import Fernet

from container import *


class XContainer(Container):
    def __init__(self, name, root_dir, hypervisor):
        super().__init__(name, root_dir)
        self.hypervisor = hypervisor
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

    def encrypt_command(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt_command(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = self.cipher.encrypt(file_data)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

    def offload_to_hypervisor(self, task_type, data):
        return self.hypervisor.handle_task(task_type, data)

    # Run a command securely inside the x-container (Linux Version)
    def run_secure_command(self, command):
        print(f"Running secure command in container {self.name}: {command}")

        try:
            # Encrypt command before running
            encrypted_command = self.encrypt_command(command)
            decrypted_command = self.decrypt_command(encrypted_command)

            # Execute decrypted command in the container's root directory
            result = subprocess.run(decrypted_command, shell=True, cwd=self.root_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # Check if command involves file output redirection and encrypt file content
            if ">" in command:
                file_path = command.split(">")[-1].strip()
                file_path = f"{self.root_dir}/{file_path}"
                self.encrypt_file(file_path)  # Encrypt file after creation

            # Handle `cat` command to read and decrypt file content for secure output
            if command.startswith("cat "):
                file_name = command.split("cat ", 1)[1].strip()
                return self.read_secure_file(file_name)

            # Encrypt the command output
            encrypted_output = self.encrypt_command(result.stdout.decode("utf-8").strip())

            # Decrypt output for display or further processing
            output = self.decrypt_command(encrypted_output)
            return output

        except Exception as e:
            print(f"Error in XContainer {self.name}: {e}")
            return str(e)


    # Run a command securely inside the x-container (MacOS Version)
    def run_secure_command_mac(self, command):
        print(f"Running secure command in container {self.name}: {command}")
        try:
            # Encrypt memory before running the command
            encrypted_command = self.encrypt_command(command)

            # Decrypt before execution
            decrypted_command = self.decrypt_command(encrypted_command)
            result = subprocess.run(decrypted_command, shell=True, cwd=self.root_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # Check if any file is created, and encrypt the file content
            if ">" in command:
                file_path = command.split(">")[-1].strip()
                file_path = f"{self.root_dir}/{file_path}"
                self.encrypt_file(file_path)  # Encrypt the file after creation

            # If it's a `cat` command, decrypt the file content before returning the result
            if command.startswith("cat "):
                file_name = command.split("cat ", 1)[1].strip()
                return self.read_secure_file(file_name)

            # Encrypt the output
            encrypted_output = self.encrypt_command(result.stdout.decode("utf-8").strip())

            # Decrypt the output for external use
            output = self.decrypt_command(encrypted_output)
            return output
        except Exception as e:
            print(f"Error in XContainer {self.name}: {e}")
            return str(e)

    def read_secure_file(self, file_path):
        return self.decrypt_file(f"{self.root_dir}/{file_path}")

    # Sending a message securely to another X-Container
    def send_secure_message(self, recipient_container, message):
        encrypted_message = self.encryption_key.encrypt(message.encode('utf-8'))
        return recipient_container.receive_secure_message(encrypted_message)

    # Receive a message securely from another X-Container
    def receive_secure_message(self, encrypted_message, sender_public_key=None):
        message = self.encryption_key.decrypt(encrypted_message).decode('utf-8')
        print(f"{self.name} received a message: {message}")
        return message


# Hypervisor Simulation
class Hypervisor:
    def handle_task(self, task_type, data):
        if task_type == "file_io":
            print(f"Hypervisor handling file I/O for container: {data}")
            return f"Handled file I/O: {data}"
        elif task_type == "network_io":
            print(f"Hypervisor handling network I/O for container: {data}")
            return f"Handled network I/O: {data}"
        else:
            return "Unsupported task type"
