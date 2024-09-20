# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import os
import shutil
import subprocess
from container import *
from multiprocessing import Process, Queue

def run_container_test(container_name, root_dir, command, result_queue, xcontainer= False):
    if xcontainer:
        pass
    else:
        container = Container(container_name, root_dir)
    container.run(command, result_queue)
    print(f"{container_name} finished running {command}")

def run_container_test_mac(container_name, root_dir, command, result_queue, xcontainer= False):
    container = Container(container_name, root_dir)
    print(f"Running command in container {container_name}: {command}")
    container.run(command, result_queue)
    print(f"{container_name} finished running {command}")


def run_container_test_mac(container_name, root_dir, command, result_queue, xcontainer=False):
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
                print(f"Skipping protected directory: {item_path}")
                continue
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        print(f"Cleared contents of {root_dir} (excluding protected directories)")
    else:
        os.makedirs(root_dir)
        print(f"Created root_dir directory at {root_dir}")


def check_output(actual_output, expected_output):
    return actual_output.strip() == expected_output.strip()


def verify_containers(root_dir="./root_dir"):
    processes = []
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
        process = Process(target=run_container_test, args=(f"Container_{i + 2}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    passed = True
    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        expected_output = commands[int(container_name.split("_")[1]) - 2][1]
        if not check_output(actual_output, expected_output):
            passed = False
            print(f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}")
        else:
            print(f"Test passed for {container_name}.")

    if passed:
        print("All container tests passed successfully!")
    else:
        print("Some container tests failed.")

def verify_containers_mac(root_dir="./root_dir"):
    processes = []
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

    passed = True
    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not check_output(actual_output, expected_output):
            passed = False
            print(f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}")
        else:
            print(f"Test passed for {container_name}.")

    if passed:
        print("All container tests passed successfully!")
    else:
        print("Some container tests failed.")

def test_container_isolation(root_dir="./root_dir"):
    processes = []
    result_queue = Queue()
    clear_root_dir(root_dir)

    commands = [
        ("echo 'Hello from Container 1' > testfile1.txt", ""),  # Container 1 creates a file
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

    passed = True
    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not check_output(actual_output, expected_output):
            passed = False
            print(f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}")
        else:
            print(f"Test passed for {container_name}.")

    if passed:
        print("All container isolation tests passed successfully!")
    else:
        print("Some container isolation tests failed.")

def test_container_isolation_mac(root_dir="./root_dir"):
    processes = []
    result_queue = Queue()
    clear_root_dir(root_dir)

    commands = [
        ("echo 'Hello from Container 1' > testfile1.txt", ""),
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

    passed = True
    while not result_queue.empty():
        container_name, actual_output = result_queue.get()
        expected_output = commands[int(container_name.split("_")[1]) - 1][1]
        if not check_output(actual_output, expected_output):
            passed = False
            print(f"Test failed for {container_name}.\nExpected:\n{expected_output}\nGot:\n{actual_output}")
        else:
            print(f"Test passed for {container_name}.")

    if passed:
        print("All container isolation tests passed successfully!")
    else:
        print("Some container isolation tests failed.")


# Run the tests
if __name__ == "__main__":
    os_name = input("Enter 'L' for Linux and 'M' for Mac OS:")
    if os_name.upper() == "L":
        SYSTEM = 'LINUX'
    elif os_name.upper() == "M":
        SYSTEM = 'MACOS'
    else:
        SYSTEM = 'LINUX'
        print("Non-valid OS name. Choosing Linux.")

    if SYSTEM == 'LINUX':
        print("Running verify_containers:\n")
        verify_containers()
        print("\n\nRunning test_container_isolation:\n")
        test_container_isolation()
    elif SYSTEM == 'MACOS':
        print("Running verify_containers_mac:\n")
        verify_containers_mac()
