# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour                                           207527680
# The Hebrew University of Jerusalem                      October 2024

import shutil
from excontainer import *
from multiprocessing import Process, Queue


# Run a command on Container (Linux)
def run_container_test(container_name, root_dir, command, result_queue):
    container = Container(container_name, root_dir)
    container.run(command, result_queue)
    print(f"{container_name} finished running {command}")


# Run a command on Container (MacOS)
def run_container_test_mac(container_name, root_dir, command, result_queue):
    container = Container(container_name, root_dir)
    print(f"Running command in container {container_name}: {command}")
    container.run_mac(command, result_queue)
    print(f"{container_name} finished running {command}")


def clear_root_dir(root_dir):
    protected_dirs = {"bin", "lib", "usr"}

    if os.path.exists(root_dir):
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if item in protected_dirs:
                continue
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        print(f"Cleared contents of {root_dir} (excluding protected directories)")
    else:
        os.makedirs(root_dir)
        print(f"Created root_dir directory at {root_dir}")


def compare_output(actual_output, expected_output):
    return actual_output.strip() == expected_output.strip()


# Run tests for Container class (Linux)
def verify_container(root_dir="./root_dir"):
    processes = []
    test_results = []
    result_queue = Queue()

    clear_root_dir(root_dir)

    # For Linux
    commands = [
        ("echo Bonjourno from Container 1", "Bonjourno from Container 1"),
        ("echo Bonjourno from Container 2", "Bonjourno from Container 2"),
        ("echo 'This is Container 1' > /testfile1.txt && cat /testfile1.txt", "This is Container 1"),
        ("mkdir /testdir && echo 'Creating a directory in Container 2'", "Creating a directory in Container 2"),
        ("/bin/bash -c 'echo Bash from Container 3 && sleep 2 && echo Finished sleeping'",
         "Bash from Container 3\nFinished sleeping"),
        ("touch /tempfile && echo 'Touched tempfile in Container 4'", "Touched tempfile in Container 4"),
        ("/bin/bash -c 'for i in {1..5}; do echo Looping $i in Container 5; sleep 1; done'",
         "Looping 1 in Container 5\nLooping 2 in Container 5\nLooping 3 in Container 5\nLooping 4 in Container 5\nLooping 5 in Container 5")
    ]

    process = Process(target=run_container_test,
                      args=(f"Container_{1}", root_dir, "/bin/ls -l", "total 0", result_queue))
    processes.append(process)
    process.start()

    for i, (command, expected_output) in enumerate(commands):
        process = Process(target=run_container_test, args=(f"Container_{i + 1}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        command = commands[int(container_name.split("_")[1]) - 1][0]
        expected_output = commands[int(container_name.split("_")[1]) - 2][1]
        if not compare_output(actual_output, expected_output):
            test_results.append((container_name, command, False))
            print(
                Fore.RED + f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}" + Style.RESET_ALL)
        else:
            test_results.append((container_name, command, True))
            print(Fore.GREEN + f"Test passed for {container_name}." + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results - Containers ---" + Style.RESET_ALL)
    for container_name, test, passed in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        print(color + f"{container_name}: {test}: {status}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run tests for Container class (MacOS)
def verify_container_mac(root_dir="./root_dir"):
    processes = []
    test_results = []
    result_queue = Queue()
    clear_root_dir(root_dir)

    commands = [
        ("echo 'This is Container 1' > testfile1.txt && cat testfile1.txt", "This is Container 1"),
        ("mkdir testdir && echo 'Creating a directory in Container 2'", "Creating a directory in Container 2"),
        ("/bin/bash -c 'echo Bash from Container 3 && sleep 2 && echo Finished sleeping'",
         "Bash from Container 3\nFinished sleeping"),
        ("touch tempfile && echo 'Touched tempfile in Container 4'", "Touched tempfile in Container 4"),
        ("/bin/bash -c 'for i in {1..5}; do echo Looping $i in Container 5; sleep 1; done'",
         "Looping 1 in Container 5\nLooping 2 in Container 5\nLooping 3 in Container 5\nLooping 4 in Container 5\nLooping 5 in Container 5"),
    ]

    for i, (command, expected_output) in enumerate(commands):
        process = Process(target=run_container_test_mac, args=(f"Container_{i + 1}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        command = commands[int(container_name.split("_")[1]) - 1][0]
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not compare_output(actual_output, expected_output):
            test_results.append((container_name, command, False))
            print(
                Fore.RED + f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}" + Style.RESET_ALL)
        else:
            test_results.append((container_name, command, True))
            print(Fore.GREEN + f"Test passed for {container_name}." + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results ---" + Style.RESET_ALL)
    for container_name, test, passed in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        print(color + f"{container_name}: {test}: {status}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run Isolation tests for Container class (Linux)
def test_container_isolation(root_dir="./root_dir"):
    processes = []
    test_results = []
    result_queue = Queue()
    clear_root_dir(root_dir)

    commands = [
        ("echo 'Bonjourno from Container 1' > testfile1.txt", ""),  # Container 1 creates a file
        ("cat testfile1.txt", "cat: testfile1.txt: No such file or directory"),
        ("mkdir testdir_container_3 && ls -l", "testdir_container_3"),  # Container 3 creates a directory and lists it
        ("echo 'More data from Container 1' >> testfile1.txt && cat testfile1.txt", "More data from Container 1"),
        ("touch temp_file_container_4 && ls temp_file_container_4", "temp_file_container_4"),
        ("echo 'Attempting to read from container 3 directory' && ls testdir_container_3",
         "ls: cannot access 'testdir_container_3': No such file or directory"),
    ]

    for i, (command, expected_output) in enumerate(commands):
        process = Process(target=run_container_test, args=(f"Container_{i + 1}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        command = commands[int(container_name.split("_")[1]) - 1][0]
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not compare_output(actual_output, expected_output):
            test_results.append((container_name, command, False))
            print(
                Fore.RED + f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}" + Style.RESET_ALL)
        else:
            test_results.append((container_name, command, True))
            print(Fore.GREEN + f"Test passed for {container_name}." + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results ---" + Style.RESET_ALL)
    for container_name, test, passed in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        print(color + f"{container_name}: {test}: {status}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run Isolation tests for Container class (MacOS)
# NOT STABLE #
def test_container_isolation_mac(root_dir="./root_dir"):
    processes = []
    test_results = []
    result_queue = Queue()
    clear_root_dir(root_dir)

    commands = [
        ("echo 'Bonjourno from Container 1' > testfile1.txt", ""),
        ("cat testfile1.txt", "cat: testfile1.txt: No such file or directory"),
        ("mkdir testdir_container_3 && ls", "testdir_container_3"),
        ("echo 'More data from Container 1' >> testfile1.txt && cat testfile1.txt", "More data from Container 1"),
        ("touch temp_file_container_4 && ls temp_file_container_4", "temp_file_container_4"),
        ("echo 'Attempting to read from container 3 directory' && ls testdir_container_3",
         "Attempting to read from container 3 directoryls: testdir_container_3: No such file or directory"),
    ]

    for i, (command, expected_output) in enumerate(commands):
        process = Process(target=run_container_test_mac, args=(f"Container_{i + 1}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        command = commands[int(container_name.split("_")[1]) - 1][0]
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not compare_output(actual_output, expected_output):
            test_results.append((container_name, command, False))
            print(
                Fore.RED + f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}" + Style.RESET_ALL)
        else:
            test_results.append((container_name, command, True))
            print(Fore.GREEN + f"Test passed for {container_name}." + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results ---" + Style.RESET_ALL)
    for container_name, test, passed in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        print(color + f"{container_name}: {test}: {status}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run tests for X-Container class (Linux)
def verify_xcontainer(root_dir="./root_dir_x"):
    hypervisor_1 = Hypervisor()
    xcontainer_1 = XContainer("XContainer_1", root_dir, hypervisor_1)

    hypervisor_2 = Hypervisor()
    xcontainer_2 = XContainer("XContainer_2", root_dir, hypervisor_2)

    test_results = []
    clear_root_dir(root_dir)

    # Test secure command execution with encryption and decryption for both containers
    try:
        print(Fore.BLUE + "--- Testing Command Encryption and Decryption for XContainer 1 ---" + Style.RESET_ALL)
        command_1 = "echo 'Hello from XContainer 1' > testfile_x1.txt"
        output_1 = xcontainer_1.run_secure_command(command_1)
        assert output_1 == "", "Expected no output after command execution in XContainer 1"
        test_results.append(("Command Encryption and Decryption - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Command Encryption and Decryption for XContainer 2 ---" + Style.RESET_ALL)
        command_2 = "echo 'Hello from XContainer 2' > testfile_x2.txt"
        output_2 = xcontainer_2.run_secure_command(command_2)
        assert output_2 == "", "Expected no output after command execution in XContainer 2"
        test_results.append(("Command Encryption and Decryption - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for XContainer 1 ---" + Style.RESET_ALL)
        output_1 = xcontainer_1.run_secure_command("cat testfile_x1.txt")
        assert output_1.strip().lower() == "hello from xcontainer 1".strip().lower(), "File content mismatch in XContainer 1"
        test_results.append(("File Content After Encryption - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for XContainer 2 ---" + Style.RESET_ALL)
        output_2 = xcontainer_2.run_secure_command("cat testfile_x2.txt")
        assert output_2.strip().lower() == "hello from xcontainer 2".strip().lower(), "File content mismatch in XContainer 2"
        test_results.append(("File Content After Encryption - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for XContainer 1 ---" + Style.RESET_ALL)
        hypervisor_output_1 = xcontainer_1.offload_to_hypervisor("file_io", "testfile_x1.txt")
        assert "Handled" in hypervisor_output_1, "Hypervisor did not handle the task correctly for XContainer 1"
        test_results.append(("Task Offloading to Hypervisor - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for XContainer 2 ---" + Style.RESET_ALL)
        hypervisor_output_2 = xcontainer_2.offload_to_hypervisor("file_io", "testfile_x2.txt")
        assert "Handled" in hypervisor_output_2, "Hypervisor did not handle the task correctly for XContainer 2"
        test_results.append(("Task Offloading to Hypervisor - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results - X-Containers ---" + Style.RESET_ALL)
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll X-Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some X-Containers tests failed. Check the output for details." + Style)


# Run tests for X-Container class (MacOS)
def verify_xcontainer_mac(root_dir="./root_dir_x"):
    hypervisor_1 = Hypervisor()
    xcontainer_1 = XContainer("XContainer_1", root_dir, hypervisor_1)

    hypervisor_2 = Hypervisor()
    xcontainer_2 = XContainer("XContainer_2", root_dir, hypervisor_2)

    test_results = []
    clear_root_dir(root_dir)

    # Test secure command execution with encryption and decryption for both containers
    try:
        print(Fore.BLUE + "--- Testing Command Encryption and Decryption for XContainer 1 ---" + Style.RESET_ALL)
        command_1 = "echo 'Bonjourno from XContainer 1' > testfile_x1.txt"
        output_1 = xcontainer_1.run_secure_command_mac(command_1)
        assert output_1 == "", "Expected no output after command execution in XContainer 1"
        test_results.append(("Command Encryption and Decryption - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Command Encryption and Decryption for XContainer 2 ---" + Style.RESET_ALL)
        command_2 = "echo 'Bonjourno from XContainer 2' > testfile_x2.txt"
        output_2 = xcontainer_2.run_secure_command_mac(command_2)
        assert output_2 == "", "Expected no output after command execution in XContainer 2"
        test_results.append(("Command Encryption and Decryption - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for XContainer 1 ---" + Style.RESET_ALL)
        output_1 = xcontainer_1.run_secure_command_mac("cat testfile_x1.txt")
        assert output_1.strip().lower() == "Bonjourno from XContainer 1".strip().lower(), "File content mismatch in XContainer 1"
        test_results.append(("File Content After Encryption - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for XContainer 2 ---" + Style.RESET_ALL)
        output_2 = xcontainer_2.run_secure_command_mac("cat testfile_x2.txt")
        assert output_2.strip().lower() == "Bonjourno from XContainer 2".strip().lower(), "File content mismatch in XContainer 2"
        test_results.append(("File Content After Encryption - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for XContainer 1 ---" + Style.RESET_ALL)
        hypervisor_output_1 = xcontainer_1.offload_to_hypervisor("file_io", "testfile_x1.txt")
        assert "Handled" in hypervisor_output_1, "Hypervisor did not handle the task correctly for XContainer 1"
        test_results.append(("Task Offloading to Hypervisor - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for XContainer 2 ---" + Style.RESET_ALL)
        hypervisor_output_2 = xcontainer_2.offload_to_hypervisor("file_io", "testfile_x2.txt")
        assert "Handled" in hypervisor_output_2, "Hypervisor did not handle the task correctly for XContainer 2"
        test_results.append(("Task Offloading to Hypervisor - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for XContainer 1 ---" + Style.RESET_ALL)
        sensitive_data_1 = "Sensitive Data 1"
        encrypted_data_1 = xcontainer_1.encrypt_command(sensitive_data_1)
        decrypted_data_1 = xcontainer_1.decrypt_command(encrypted_data_1)
        assert decrypted_data_1 == sensitive_data_1, "Decrypted data does not match original in XContainer 1"
        test_results.append(("Memory Encryption - XContainer 1", True))
        print(Fore.GREEN + f"Test passed for XContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - XContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for XContainer 2 ---" + Style.RESET_ALL)
        sensitive_data_2 = "Sensitive Data 2"
        encrypted_data_2 = xcontainer_2.encrypt_command(sensitive_data_2)
        decrypted_data_2 = xcontainer_2.decrypt_command(encrypted_data_2)
        assert decrypted_data_2 == sensitive_data_2, "Decrypted data does not match original in XContainer 2"
        test_results.append(("Memory Encryption - XContainer 2", True))
        print(Fore.GREEN + f"Test passed for XContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - XContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for XContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Encryption of Multiple Commands ---" + Style.RESET_ALL)

        commands = [
            ("echo 'Confidential info 1' > secret_file1.txt", ""),  # echo doesn't produce output
            ("echo 'Confidential info 2' > secret_file2.txt", ""),  # echo doesn't produce output
            ("cat secret_file1.txt", "Confidential info 1"),  # Expect decrypted content
            ("cat secret_file2.txt", "Confidential info 2")  # Expect decrypted content
        ]

        for cmd, expected_output in commands:
            result = xcontainer_1.run_secure_command_mac(cmd)
            assert result.strip().lower() == expected_output.strip().lower(), f"Unexpected output for command: {cmd}\nExpected: {expected_output}\nGot: {result}"

        test_results.append(("Encryption of Multiple Commands", True))
        print(Fore.GREEN + "Encryption of Multiple Commands: PASSED" + Style.RESET_ALL)

        # Simulate an adversary trying to directly access the files without using the XContainer
        print(Fore.BLUE + "\n   --- Testing Adversary Access to Encrypted Files ---" + Style.RESET_ALL)

        # Simulate adversary trying to access the file directly without decryption
        adversary_command = "cat secret_file1.txt"

        # Run the command as the adversary directly
        try:
            result_adversary = subprocess.run(adversary_command, shell=True, cwd="./root_dir_x", stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
            adversary_output = result_adversary.stdout.decode("utf-8").strip() or result_adversary.stderr.decode(
                "utf-8").strip()

            assert "Confidential info 1" not in adversary_output, "Adversary was able to read confidential information!"
            assert "no such file" in adversary_output.lower() or adversary_output.strip() != "", "Adversary got unexpected readable output!"

            test_results.append(("Adversary Access Prevention", True))  # Test passed
            print(Fore.GREEN + "    Adversary access prevention: PASSED" + Style.RESET_ALL)

        except Exception as e:
            print(f"    Adversary access test failed: {e}")
            test_results.append(("Adversary Access Prevention", False))  # Test failed
            print(Fore.RED + "  Adversary access prevention: FAILED" + Style.RESET_ALL)

    except AssertionError as e:
        print(e)
        test_results.append(("  Encryption of Multiple Commands", False))  # Test failed
        print(Fore.RED + "Encryption of Multiple Commands: PASSED" + Style.RESET_ALL)
        test_results.append(("Adversary Access Prevention", False))

    try:
        print(Fore.BLUE + "\n--- Testing Hypervisor Offloading for Sensitive I/O ---" + Style.RESET_ALL)
        for cmd in ["secret_file1.txt", "secret_file2.txt"]:
            hypervisor_result = xcontainer_1.offload_to_hypervisor("file_io", cmd)
            assert "Handled" in hypervisor_result, "Hypervisor did not handle I/O correctly"

        test_results.append(("Hypervisor Offloading for Sensitive I/O", True))
        print(Fore.GREEN + "Hypervisor Offloading for Sensitive I/O: PASSED" + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Hypervisor Offloading for Sensitive I/O", False, str(e)))
        print(Fore.RED + "Hypervisor Offloading for Sensitive I/O: FAILED" + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Cross-Container Encryption Isolation ---" + Style.RESET_ALL)

        # XContainer 1 encrypts some data
        xcontainer_1.run_secure_command_mac("echo 'Private data from XContainer 1' > cross_test_file.txt")

        # XContainer 2 tries to read and decrypt the file
        cross_container_output = xcontainer_2.run_secure_command_mac("cat cross_test_file.txt")

        # The output should not match the original text, since XContainer 2's decryption should fail
        assert cross_container_output.strip() != "Private data from XContainer 1".strip(), "XContainer 2 was able to decrypt XContainer 1's file!"

        test_results.append(("Cross-Container Encryption Isolation", True))
        print(Fore.GREEN + "Cross-Container Encryption Isolation: PASSED" + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Cross-Container Encryption Isolation", False, str(e)))
        print(Fore.RED + "Cross-Container Encryption Isolation: FAILED" + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results - X-Containers ---" + Style.RESET_ALL)
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll X-Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some X-Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run tests for Enhanced X-Container class (Linux)
def verify_excontainer(root_dir="./root_dir_ex"):
    ca = CA()
    hypervisor_1 = RelyingHypervisor()
    excontainer_1 = EXContainer(name="EXContainer_1", root_dir=root_dir, hypervisor=hypervisor_1, ca=ca)
    excontainer_1.request_certificate(ca=ca)

    hypervisor_2 = RelyingHypervisor()
    excontainer_2 = EXContainer(name="EXContainer_2", root_dir=root_dir, hypervisor=hypervisor_2, ca=ca)
    excontainer_2.request_certificate(ca=ca)

    test_results = []
    clear_root_dir(root_dir)

    # Test secure command execution with encryption and decryption for both containers
    try:
        print(Fore.BLUE + "--- Testing Command Encryption and Decryption for EXContainer 1 ---" + Style.RESET_ALL)
        command_1 = "echo 'Bonjourno from EXContainer 1' > testfile_x1.txt"
        output_1 = excontainer_1.run_secure_command(command_1)
        assert output_1 == "", "Expected no output after command execution in EXContainer 1"
        test_results.append(("Command Encryption and Decryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Command Encryption and Decryption for EXContainer 2 ---" + Style.RESET_ALL)
        command_2 = "echo 'Bonjourno from EXContainer 2' > testfile_x2.txt"
        output_2 = excontainer_2.run_secure_command(command_2)
        assert output_2 == "", "Expected no output after command execution in EXContainer 2"
        test_results.append(("Command Encryption and Decryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for EXContainer 1 ---" + Style.RESET_ALL)
        output_1 = excontainer_1.run_secure_command("cat testfile_x1.txt")
        assert output_1.strip().lower() == "Bonjourno from EXContainer 1".strip().lower(), "File content mismatch in EXContainer 1"
        test_results.append(("File Content After Encryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for EXContainer 2 ---" + Style.RESET_ALL)
        output_2 = excontainer_2.run_secure_command("cat testfile_x2.txt")
        assert output_2.strip().lower() == "Bonjourno from EXContainer 2".strip().lower(), "File content mismatch in EXContainer 2"
        test_results.append(("File Content After Encryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for EXContainer 1 ---" + Style.RESET_ALL)
        hypervisor_output_1 = excontainer_1.offload_to_hypervisor("file_io", "testfile_x1.txt")
        assert "Handled" in hypervisor_output_1, "Hypervisor did not handle the task correctly for EXContainer 1"
        test_results.append(("Task Offloading to Hypervisor - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for EXContainer 2 ---" + Style.RESET_ALL)
        hypervisor_output_2 = excontainer_2.offload_to_hypervisor("file_io", "testfile_x2.txt")
        assert "Handled" in hypervisor_output_2, "Hypervisor did not handle the task correctly for EXContainer 2"
        test_results.append(("Task Offloading to Hypervisor - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for EXContainer 1 ---" + Style.RESET_ALL)
        sensitive_data_1 = "Sensitive Data 1"
        encrypted_data_1 = excontainer_1.encrypt_command(sensitive_data_1)
        decrypted_data_1 = excontainer_1.hypervisor.decrypt_command(encrypted_data_1)
        assert decrypted_data_1 == sensitive_data_1, "Decrypted data does not match original in EXContainer 1"
        test_results.append(("Memory Encryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for EXContainer 2 ---" + Style.RESET_ALL)
        sensitive_data_2 = "Sensitive Data 2"
        encrypted_data_2 = excontainer_2.encrypt_command(sensitive_data_2)
        decrypted_data_2 = excontainer_2.hypervisor.decrypt_command(encrypted_data_2)
        assert decrypted_data_2 == sensitive_data_2, "Decrypted data does not match original in EXContainer 2"
        test_results.append(("Memory Encryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Encryption of Multiple Commands ---" + Style.RESET_ALL)
        commands = [
            ("echo 'Confidential info 1' > secret_file1.txt", ""),
            ("echo 'Confidential info 2' > secret_file2.txt", ""),
            ("cat secret_file1.txt", "Confidential info 1"),
            ("cat secret_file2.txt", "Confidential info 2")
        ]

        for cmd, expected_output in commands:
            result = excontainer_1.run_secure_command(cmd)
            assert result.strip().lower() == expected_output.strip().lower(), f"Unexpected output for command: {cmd}\nExpected: {expected_output}\nGot: {result}"

        test_results.append(("Encryption of Multiple Commands", True))
        print(Fore.GREEN + "Encryption of Multiple Commands: PASSED" + Style.RESET_ALL)

        # Simulate adversary trying to access file directly
        print(Fore.BLUE + "\n--- Testing Adversary Access to Encrypted Files ---" + Style.RESET_ALL)
        adversary_command = "cat secret_file1.txt"
        result_adversary = subprocess.run(adversary_command, shell=True, cwd=root_dir, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        adversary_output = result_adversary.stdout.decode("utf-8").strip() or result_adversary.stderr.decode(
            "utf-8").strip()
        assert "Confidential info 1" not in adversary_output, "Adversary was able to read confidential information!"
        assert "no such file" in adversary_output.lower() or adversary_output.strip() != "", "Adversary got unexpected readable output!"

        test_results.append(("Adversary Access to Encrypted Files", True))
        print(Fore.GREEN + "Adversary Access to Encrypted Files: PASSED" + Style.RESET_ALL)

    except Exception as e:
        test_results.append(("Encryption of Multiple Commands or Adversary Access", False, str(e)))
        print(Fore.RED + f"Encryption of Multiple Commands or Adversary Access: FAILED" + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results - Enhanced X-Containers ---" + Style.RESET_ALL)
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll X-Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some X-Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run tests for Enhanced X-Container class (MacOS)
def verify_excontainer_mac(root_dir="./root_dir_ex"):
    ca = CA()
    hypervisor_1 = RelyingHypervisor()
    excontainer_1 = EXContainer(name="EXContainer_1", root_dir=root_dir, hypervisor=hypervisor_1, ca=ca)
    excontainer_1.request_certificate(ca=ca)

    hypervisor_2 = RelyingHypervisor()
    excontainer_2 = EXContainer(name="EXContainer_2", root_dir=root_dir, hypervisor=hypervisor_2, ca=ca)
    excontainer_2.request_certificate(ca=ca)

    test_results = []
    clear_root_dir(root_dir)

    # Test secure command execution with encryption and decryption for both containers
    try:
        print(Fore.BLUE + "--- Testing Command Encryption and Decryption for EXContainer 1 ---" + Style.RESET_ALL)
        command_1 = "echo 'Bonjourno from EXContainer 1' > testfile_x1.txt"
        output_1 = excontainer_1.run_secure_command_mac(command_1)
        assert output_1 == "", "Expected no output after command execution in EXContainer 1"
        test_results.append(("Command Encryption and Decryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Command Encryption and Decryption for EXContainer 2 ---" + Style.RESET_ALL)
        command_2 = "echo 'Bonjourno from EXContainer 2' > testfile_x2.txt"
        output_2 = excontainer_2.run_secure_command_mac(command_2)
        assert output_2 == "", "Expected no output after command execution in EXContainer 2"
        test_results.append(("Command Encryption and Decryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Command Encryption and Decryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for EXContainer 1 ---" + Style.RESET_ALL)
        output_1 = excontainer_1.run_secure_command_mac("cat testfile_x1.txt")
        assert output_1.strip().lower() == "Bonjourno from EXContainer 1".strip().lower(), "File content mismatch in EXContainer 1"
        test_results.append(("File Content After Encryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing File Content After Encryption for EXContainer 2 ---" + Style.RESET_ALL)
        output_2 = excontainer_2.run_secure_command_mac("cat testfile_x2.txt")
        assert output_2.strip().lower() == "Bonjourno from EXContainer 2".strip().lower(), "File content mismatch in EXContainer 2"
        test_results.append(("File Content After Encryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("File Content After Encryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for EXContainer 1 ---" + Style.RESET_ALL)
        hypervisor_output_1 = excontainer_1.offload_to_hypervisor("file_io", "testfile_x1.txt")
        assert "Handled" in hypervisor_output_1, "Hypervisor did not handle the task correctly for EXContainer 1"
        test_results.append(("Task Offloading to Hypervisor - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Task Offloading to Hypervisor for EXContainer 2 ---" + Style.RESET_ALL)
        hypervisor_output_2 = excontainer_2.offload_to_hypervisor("file_io", "testfile_x2.txt")
        assert "Handled" in hypervisor_output_2, "Hypervisor did not handle the task correctly for EXContainer 2"
        test_results.append(("Task Offloading to Hypervisor - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Task Offloading to Hypervisor - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for EXContainer 1 ---" + Style.RESET_ALL)
        sensitive_data_1 = "Sensitive Data 1"
        encrypted_data_1 = excontainer_1.encrypt_command(sensitive_data_1)
        decrypted_data_1 = excontainer_1.hypervisor.decrypt_command(encrypted_data_1)
        assert decrypted_data_1 == sensitive_data_1, "Decrypted data does not match original in EXContainer 1"
        test_results.append(("Memory Encryption - EXContainer 1", True))
        print(Fore.GREEN + f"Test passed for EXContainer 1." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - EXContainer 1", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 1." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Memory Encryption for EXContainer 2 ---" + Style.RESET_ALL)
        sensitive_data_2 = "Sensitive Data 2"
        encrypted_data_2 = excontainer_2.encrypt_command(sensitive_data_2)
        decrypted_data_2 = excontainer_2.hypervisor.decrypt_command(encrypted_data_2)
        assert decrypted_data_2 == sensitive_data_2, "Decrypted data does not match original in EXContainer 2"
        test_results.append(("Memory Encryption - EXContainer 2", True))
        print(Fore.GREEN + f"Test passed for EXContainer 2." + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Memory Encryption - EXContainer 2", False, str(e)))
        print(Fore.RED + f"Test failed for EXContainer 2." + Style.RESET_ALL)

    try:
        print(Fore.BLUE + "\n--- Testing Encryption of Multiple Commands ---" + Style.RESET_ALL)

        commands = [
            ("echo 'Confidential info 1' > secret_file1.txt", ""),  # echo doesn't produce output
            ("echo 'Confidential info 2' > secret_file2.txt", ""),  # echo doesn't produce output
            ("cat secret_file1.txt", "Confidential info 1"),  # Expect decrypted content
            ("cat secret_file2.txt", "Confidential info 2")  # Expect decrypted content
        ]

        for cmd, expected_output in commands:
            result = excontainer_1.run_secure_command_mac(cmd)
            assert result.strip().lower() == expected_output.strip().lower(), f"Unexpected output for command: {cmd}\nExpected: {expected_output}\nGot: {result}"

        test_results.append(("Encryption of Multiple Commands", True))
        print(Fore.GREEN + "Encryption of Multiple Commands: PASSED" + Style.RESET_ALL)

        # Simulate an adversary trying to directly access the files without using the EXContainer
        print(Fore.BLUE + "\n   --- Testing Adversary Access to Encrypted Files ---" + Style.RESET_ALL)

        # Simulate adversary trying to access the file directly without decryption
        adversary_command = "cat secret_file1.txt"

        # Run the command as the adversary directly
        try:
            result_adversary = subprocess.run(adversary_command, shell=True, cwd="./root_dir_x", stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
            adversary_output = result_adversary.stdout.decode("utf-8").strip() or result_adversary.stderr.decode(
                "utf-8").strip()

            assert "Confidential info 1" not in adversary_output, "Adversary was able to read confidential information!"
            assert "no such file" in adversary_output.lower() or adversary_output.strip() != "", "Adversary got unexpected readable output!"

            test_results.append(("Adversary Access Prevention", True))  # Test passed
            print(Fore.GREEN + "    Adversary access prevention: PASSED" + Style.RESET_ALL)

        except Exception as e:
            print(f"    Adversary access test failed: {e}")
            test_results.append(("Adversary Access Prevention", False))  # Test failed
            print(Fore.RED + "  Adversary access prevention: FAILED" + Style.RESET_ALL)

    except AssertionError as e:
        print(e)
        test_results.append(("  Encryption of Multiple Commands", False))  # Test failed
        print(Fore.RED + "Encryption of Multiple Commands: PASSED" + Style.RESET_ALL)
        test_results.append(("Adversary Access Prevention", False))

    try:
        print(Fore.BLUE + "\n--- Testing Hypervisor Offloading for Sensitive I/O ---" + Style.RESET_ALL)
        for cmd in ["secret_file1.txt", "secret_file2.txt"]:
            hypervisor_result = excontainer_1.offload_to_hypervisor("file_io", cmd)
            assert "Handled" in hypervisor_result, "Hypervisor did not handle I/O correctly"

        test_results.append(("Hypervisor Offloading for Sensitive I/O", True))
        print(Fore.GREEN + "Hypervisor Offloading for Sensitive I/O: PASSED" + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Hypervisor Offloading for Sensitive I/O", False, str(e)))
        print(Fore.RED + "Hypervisor Offloading for Sensitive I/O: FAILED" + Style.RESET_ALL)

    # Verify that EXContainer 2 cannot decrypt EXContainer 1's data
    try:
        print(Fore.BLUE + "\n--- Testing Cross-Container Encryption Isolation ---" + Style.RESET_ALL)

        excontainer_1.run_secure_command_mac("echo 'Private data from EXContainer 1' > cross_test_file.txt")
        cross_container_output = excontainer_2.run_secure_command_mac("cat cross_test_file.txt")
        assert cross_container_output.strip() != "Private data from EXContainer 1".strip(), "EXContainer 2 was able to decrypt EXContainer 1's file!"

        test_results.append(("Cross-Container Encryption Isolation", True))
        print(Fore.GREEN + "Cross-Container Encryption Isolation: PASSED" + Style.RESET_ALL)
    except Exception as e:
        test_results.append(("Cross-Container Encryption Isolation", False, str(e)))
        print(Fore.RED + "Cross-Container Encryption Isolation: FAILED" + Style.RESET_ALL)

    print(Fore.GREEN + "\n--- Test Results - Enhanced X-Containers ---" + Style.RESET_ALL)
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll X-Containers tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "Some X-Containers tests failed. Check the output for details." + Style.RESET_ALL)
        return False


# Run unique tests for Enhanced X-Container class (Linux)
def unique_verify_excontainer(root_dir="./root_dir_ex"):
    ca = CA()
    hypervisor_1 = RelyingHypervisor()
    excontainer_1 = EXContainer(name="EXContainer_1", root_dir=root_dir, hypervisor=hypervisor_1, ca=ca)
    excontainer_1.request_certificate(ca=ca)

    hypervisor_2 = RelyingHypervisor()
    excontainer_2 = EXContainer(name="EXContainer_2", root_dir=root_dir, hypervisor=hypervisor_2, ca=ca)
    excontainer_2.request_certificate(ca=ca)

    hypervisor_3 = Hypervisor()
    xcontainer_1 = XContainer(name="XContainer_1", root_dir=root_dir, hypervisor=hypervisor_3)

    hypervisor_4 = Hypervisor()
    xcontainer_2 = XContainer(name="XContainer_2", root_dir=root_dir, hypervisor=hypervisor_4)

    test_results = []
    clear_root_dir(root_dir)

    # TODO Siwar

    # Test results
    print("\n--- Test Results ---")
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll EXContainer tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "\nSome tests failed. Check the results above." + Style.RESET_ALL)
        return False


# Run unique tests for Enhanced X-Container class (MacOS)
def unique_verify_excontainer_mac(root_dir="./root_dir_ex"):
    ca = CA()  # Certificate Authority for EXContainers
    hypervisor_1 = RelyingHypervisor()  # Hypervisor for Enhanced X-Containers
    hypervisor_2 = Hypervisor()  # Hypervisor for 'regular'' X-Containers

    # Create an enhanced X-Containers with PKI
    excontainer_1 = EXContainer(name="EXContainer_1", root_dir=root_dir, hypervisor=hypervisor_1, ca=ca)
    excontainer_1.request_certificate(ca=ca)
    excontainer_2 = EXContainer(name="EXContainer_2", root_dir=root_dir, hypervisor=hypervisor_1, ca=ca)
    excontainer_2.request_certificate(ca=ca)

    # Create a regular X-Containers
    xcontainer_1 = XContainer(name="XContainer_1", root_dir=root_dir, hypervisor=hypervisor_2)
    xcontainer_2 = XContainer(name="XContainer_2", root_dir=root_dir, hypervisor=hypervisor_2)

    test_results = []
    clear_root_dir(root_dir)

    # TODO Siwar

    # Test results
    print("\n--- Test Results ---")
    for test, passed, *reason in test_results:
        status = "PASSED" if passed else "FAILED"
        color = Fore.GREEN if passed else Fore.RED
        reason_message = f" - Reason: {reason[0]}" if reason else ""
        print(color + f"{test}: {status}{reason_message}" + Style.RESET_ALL)

    if all(result[1] for result in test_results):
        print(Fore.GREEN + "\nAll EXContainer tests completed successfully!" + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + "\nSome tests failed. Check the results above." + Style.RESET_ALL)
        return False


# Run 'regular' Containers tests
def run_containers_tests(SYSTEM='LINUX'):
    res = True
    if SYSTEM == 'LINUX':
        print(Fore.CYAN + "Running verify_container:\n" + Style.RESET_ALL)
        res &= verify_container()
        print(Fore.CYAN + "\n\nRunning test_container_isolation:\n" + Style.RESET_ALL)
        res &= test_container_isolation()
    elif SYSTEM == 'MACOS':
        print(Fore.CYAN + "Running verify_container_mac:\n" + Style.RESET_ALL)
        res &= verify_container_mac()

    return res


# Run 'Traditional' X-Containers tests
def run_xcontainer_tests(SYSTEM='LINUX'):
    res = True
    if SYSTEM == 'LINUX':
        print(Fore.CYAN + "Running verify_xcontainer:\n" + Style.RESET_ALL)
        res &= verify_xcontainer()
    elif SYSTEM == 'MACOS':
        print(Fore.CYAN + "Running verify_xcontainer_mac:\n" + Style.RESET_ALL)
        res &= verify_xcontainer_mac()

    return res


# Run our enhanced X-Containers tests
def run_enhanced_xcontainer_tests(SYSTEM='LINUX'):
    res = True
    if SYSTEM == 'LINUX':
        print(Fore.CYAN + "\nRunning verify_excontainer:\n" + Style.RESET_ALL)
        res &= verify_excontainer()
        print(Fore.CYAN + "\nRunning unique_verify_excontainer:\n" + Style.RESET_ALL)
        res &= unique_verify_excontainer()
    elif SYSTEM == 'MACOS':
        print(Fore.CYAN + "\nRunning verify_excontainer_mac:\n" + Style.RESET_ALL)
        res &= verify_excontainer_mac()
        print(Fore.CYAN + "\nRunning unique_verify_excontainer_mac:\n" + Style.RESET_ALL)
        res &= unique_verify_excontainer_mac()

    return res


# Run all the tests
if __name__ == "__main__":
    os_name = input("Enter 'L' for Linux and 'M' for Mac OS: ")
    if os_name.upper() == "L":
        SYSTEM = 'LINUX'
    elif os_name.upper() == "M":
        SYSTEM = 'MACOS'
    else:
        SYSTEM = 'LINUX'
        print("Non-valid OS name. Choosing Linux.")

    if SYSTEM == 'LINUX':
        print(Fore.CYAN + "Running verify_container:\n" + Style.RESET_ALL)
        verify_container()
        print(Fore.CYAN + "\nRunning test_container_isolation:\n" + Style.RESET_ALL)
        test_container_isolation()
        print(Fore.CYAN + "\nRunning verify_xcontainer:\n" + Style.RESET_ALL)
        verify_xcontainer()
        print(Fore.CYAN + "\nRunning verify_excontainer:\n" + Style.RESET_ALL)
        verify_excontainer()
        print(Fore.CYAN + "\nRunning unique_verify_excontainer:\n" + Style.RESET_ALL)
        unique_verify_excontainer()
    elif SYSTEM == 'MACOS':
        print(Fore.CYAN + "Running verify_container_mac:\n" + Style.RESET_ALL)
        verify_container_mac()
        print(Fore.CYAN + "\nRunning verify_xcontainer_mac:\n" + Style.RESET_ALL)
        verify_xcontainer_mac()
        print(Fore.CYAN + "\nRunning verify_excontainer_mac:\n" + Style.RESET_ALL)
        verify_excontainer_mac()
        print(Fore.CYAN + "\nRunning unique_verify_excontainer_mac:\n" + Style.RESET_ALL)
        unique_verify_excontainer_mac()
