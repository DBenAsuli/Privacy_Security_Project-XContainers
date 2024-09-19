# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import os
import shutil
import subprocess
from multiprocessing import Process, Queue

class Container:
    def __init__(self, name, root_dir):
        self.name = name
        self.root_dir = root_dir

    def run(self, command, result_queue):
        """Runs a command in the container (simulates process isolation) and returns output."""
        print(f"Running command in container {self.name}: {command}")
        try:
            # Simulate changing the root directory to the container's root_dir (like chroot)
            os.chroot(self.root_dir)

            # After chroot, set the working directory to the root ("/") of the new root filesystem
            os.chdir("/")

            # Capture the output of the command execution
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8").strip() + result.stderr.decode("utf-8").strip()

            result_queue.put((self.name, output))  # Put the result in the queue for processing
        except Exception as e:
            result_queue.put((self.name, str(e)))  # Capture errors and put them in the queue
        finally:
            os.chdir("/")  # Reset the working directory


def run_container_test(container_name, root_dir, command, result_queue):
    container = Container(container_name, root_dir)
    container.run(command, result_queue)
    print(f"{container_name} finished running {command}")

def clear_root_dir(root_dir):
    protected_dirs = {"bin", "lib", "usr"}

    if os.path.exists(root_dir):
        # Remove all contents of the root_dir directory, skipping protected directories
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if item in protected_dirs:
                print(f"Skipping protected directory: {item_path}")
                continue  # Skip protected directories
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)  # Remove files or symbolic links
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)  # Remove directories
        print(f"Cleared contents of {root_dir} (excluding protected directories)")
    else:
        os.makedirs(root_dir)  # Create the directory if it doesn't exist
        print(f"Created root_dir directory at {root_dir}")

def check_output(actual_output, expected_output):
    return actual_output.strip() == expected_output.strip()

def test_containers(root_dir_path="./root_dir"):
    processes = []
    root_dir = root_dir_path
    result_queue = Queue()

    clear_root_dir(root_dir)

    commands = [
        "/bin/ls -l",
        "echo Bonjourno from Container 1",
        "echo Bonjourno from Container 2",
        "/bin/bash -c 'echo Bash from Container 3'",
        "echo 'This is Container 1' > /testfile1.txt && cat /testfile1.txt",
        "mkdir /testdir && echo 'Creating a directory in Container 2'",
        "/bin/bash -c 'echo Bash from Container 3 && sleep 2 && echo Finished sleeping'",
        "touch /tempfile && echo 'Touched tempfile in Container 4'",
        "/bin/bash -c 'for i in {1..5}; do echo Looping $i in Container 5; sleep 1; done'"
    ]

    for i, command in enumerate(commands):
        process = Process(target=run_container_test, args=(f"Container_{i+1}", root_dir, command, result_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    print("All containers finished running.")

def verify_containers(root_dir_path="./root_dir"):
    root_dir = root_dir_path
    processes = []
    result_queue = Queue()

    clear_root_dir(root_dir)

    commands = [
        ("echo Bonjourno from Container 1", "Bonjourno from Container 1"),
        ("echo Bonjourno from Container 2", "Bonjourno from Container 2"),
        ("echo 'This is Container 1' > /testfile1.txt && cat /testfile1.txt", "This is Container 1"),
        ("mkdir /testdir && echo 'Creating a directory in Container 2'", "Creating a directory in Container 2"),
        ("/bin/bash -c 'echo Bash from Container 3 && sleep 2 && echo Finished sleeping'", "Bash from Container 3\nFinished sleeping"),
        ("touch /tempfile && echo 'Touched tempfile in Container 4'", "Touched tempfile in Container 4"),
        ("/bin/bash -c 'for i in {1..5}; do echo Looping $i in Container 5; sleep 1; done'", "Looping 1 in Container 5\nLooping 2 in Container 5\nLooping 3 in Container 5\nLooping 4 in Container 5\nLooping 5 in Container 5")
    ]

    process = Process(target=run_container_test, args=(f"Container_{1}", root_dir, "/bin/ls -l", "total 0", result_queue))
    processes.append(process)
    process.start()

    for i, (command, expected_output) in enumerate(commands):
        process = Process(target=run_container_test, args=(f"Container_{i+2}", root_dir, command, result_queue))
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


# Run the test
if __name__ == "__main__":
  #  test_containers()
    verify_containers()
