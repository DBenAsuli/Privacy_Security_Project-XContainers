# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import subprocess
from container import *
from cryptography.fernet import Fernet

class XContainer(Container):
    def __init__(self, name, root_dir, hypervisor_service):
        super().__init__(name, root_dir)
        self.hypervisor_service = hypervisor_service
        self.encryption_key = Fernet.generate_key()  # Generate a unique encryption key for the container
        self.cipher = Fernet(self.encryption_key)

    def encrypt_memory(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt_memory(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()

    def offload_to_hypervisor(self, task_type, data):
        return self.hypervisor_service.handle_task(task_type, data)

    def run_secure_command(self, command):
        print(f"Running secure command in our x-container {self.name}: {command}")
        try:
            # Encrypt memory before running the command
            encrypted_command = self.encrypt_memory(command)
            print(f"Encrypted command: {encrypted_command}")

            # Decrypt before execution (in a real scenario, this happens inside an enclave)
            decrypted_command = self.decrypt_memory(encrypted_command)
            result = subprocess.run(decrypted_command, shell=True, cwd=self.root_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # Encrypt the output (as if the enclave protects the result)
            encrypted_output = self.encrypt_memory(result.stdout.decode("utf-8").strip())
            print(f"Encrypted output: {encrypted_output}")

            # Decrypt the output for external use
            output = self.decrypt_memory(encrypted_output)
            return output
        except Exception as e:
            print(f"Error in XContainer {self.name}: {e}")
            return str(e)


# Hypervisor Service Simulation
class HypervisorService:
    def handle_task(self, task_type, data):
        if task_type == "file_io":
            print(f"Hypervisor handling file I/O for container: {data}")
            # Simulate file I/O handling in a secure, isolated environment
            return f"Handled file I/O: {data}"
        elif task_type == "network_io":
            print(f"Hypervisor handling network I/O for container: {data}")
            return f"Handled network I/O: {data}"
        else:
            return "Unsupported task type"

def test_xcontainer_mac():
    # Simulate a hypervisor service
    hypervisor = HypervisorService()

    # Create an XContainer
    xcontainer = XContainer("XContainer_1", "./root_dir_x", hypervisor)

    test_results = []

    # Test secure command execution with encryption and decryption
    try:
        print("\n--- Testing Command Encryption and Decryption ---")
        command = "echo 'Hello from XContainer 1' > testfile_x1.txt"
        output_1 = xcontainer.run_secure_command(command)
        assert output_1 == "", "Expected no output after command execution"
        test_results.append(("Command Encryption and Decryption", True))
    except Exception as e:
        test_results.append(("Command Encryption and Decryption", False, str(e)))

    # Verify that the file content is encrypted and decrypted properly
    try:
        print("\n--- Testing File Content After Encryption ---")
        output_2 = xcontainer.run_secure_command("cat testfile_x1.txt")
        assert output_2 == "Hello from XContainer 1", "File content mismatch"
        test_results.append(("File Content After Encryption", True))
    except Exception as e:
        test_results.append(("File Content After Encryption", False, str(e)))

    # Check if the file I/O is offloaded to the hypervisor
    try:
        print("\n--- Testing Task Offloading to Hypervisor ---")
        hypervisor_output = xcontainer.offload_to_hypervisor("file_io", "testfile_x1.txt")
        assert "Handled" in hypervisor_output, "Hypervisor did not handle the task correctly"
        test_results.append(("Task Offloading to Hypervisor", True))
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor", False, str(e)))

    # Testing encryption specifically in memory (advantage over regular containers)
    try:
        print("\n--- Testing Memory Encryption ---")
        sensitive_data = "Sensitive Data"
        encrypted_data = xcontainer.encrypt_memory(sensitive_data)
        decrypted_data = xcontainer.decrypt_memory(encrypted_data)
        assert decrypted_data == sensitive_data, "Decrypted data does not match original"
        test_results.append(("Memory Encryption", True))
    except Exception as e:
        test_results.append(("Memory Encryption", False, str(e)))

    # Additional tests for X-Container-specific security features
    try:
        print("\n--- Testing Encryption of Multiple Commands ---")
        commands = [
            "echo 'Confidential info 1' > secret_file1.txt",
            "echo 'Confidential info 2' > secret_file2.txt",
            "cat secret_file1.txt",
            "cat secret_file2.txt"
        ]

        for cmd in commands:
            result = xcontainer.run_secure_command(cmd)
            assert result == "" or "no such file" in result.lower(), f"Unexpected output for command: {cmd}"

        test_results.append(("Encryption of Multiple Commands", True))
    except Exception as e:
        test_results.append(("Encryption of Multiple Commands", False, str(e)))

    # Verifying that offloading to the hypervisor simulates additional security for IO-heavy tasks
    try:
        print("\n--- Testing Hypervisor Offloading for Sensitive I/O ---")
        for cmd in ["secret_file1.txt", "secret_file2.txt"]:
            hypervisor_result = xcontainer.offload_to_hypervisor("file_io", cmd)
            assert "Handled" in hypervisor_result, "Hypervisor did not handle I/O correctly"

        test_results.append(("Hypervisor Offloading for Sensitive I/O", True))
    except Exception as e:
        test_results.append(("Hypervisor Offloading for Sensitive I/O", False, str(e)))

    # Summarize test results
    print("\n--- Test Results ---")
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(f"{test}: {status}{reason_message}")

    if all(result[1] for result in test_results):
        print("All tests completed successfully!")
    else:
        print("Some tests failed. Check the output for details.")

# Run the test
if __name__ == "__main__":
    test_xcontainer_mac()