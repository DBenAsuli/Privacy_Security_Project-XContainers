# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

from cryptography.fernet import Fernet

from container import *

class XContainer(Container):
    def __init__(self, name, root_dir, hypervisor_service):
        super().__init__(name, root_dir)
        self.hypervisor_service = hypervisor_service
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

    def encrypt_memory(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt_memory(self, encrypted_data):
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
        return self.hypervisor_service.handle_task(task_type, data)

    def run_secure_command(self, command):
        print(f"Running secure command in container {self.name}: {command}")
        try:
            # Encrypt memory before running the command
            encrypted_command = self.encrypt_memory(command)
            print(f"Encrypted command: {encrypted_command}")

            # Decrypt before execution (in a real scenario, this happens inside an enclave)
            decrypted_command = self.decrypt_memory(encrypted_command)
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
                return self.read_file_securely(file_name)

            # Encrypt the output
            encrypted_output = self.encrypt_memory(result.stdout.decode("utf-8").strip())
            print(f"Encrypted output: {encrypted_output}")

            # Decrypt the output for external use
            output = self.decrypt_memory(encrypted_output)
            return output
        except Exception as e:
            print(f"Error in XContainer {self.name}: {e}")
            return str(e)

    def read_file_securely(self, file_path):
        return self.decrypt_file(f"{self.root_dir}/{file_path}")


# Hypervisor Service Simulation
class HypervisorService:
    def handle_task(self, task_type, data):
        if task_type == "file_io":
            print(f"Hypervisor handling file I/O for container: {data}")
            return f"Handled file I/O: {data}"
        elif task_type == "network_io":
            print(f"Hypervisor handling network I/O for container: {data}")
            return f"Handled network I/O: {data}"
        else:
            return "Unsupported task type"