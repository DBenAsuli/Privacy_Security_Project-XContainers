# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import os
import subprocess
import sys

# Create a new namespace
CLONE_NEWNS = 0x00020000  # New mount namespace
CLONE_NEWPID = 0x20000000  # New PID namespace
CLONE_NEWUTS = 0x04000000  # New UTS namespace
CLONE_NEWIPC = 0x08000000  # New IPC namespace
CLONE_NEWUSER = 0x10000000  # New user namespace
CLONE_NEWNET = 0x40000000  # New network namespace


def run_container(command):
    def child():
        print("Inside the container!")
        subprocess.call(command)

    print("Running container with command:", command)
    pid = os.fork()

    if pid == 0:
        # Child process
        os.unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWNET)
        child()
    else:
        # Parent process
        os.waitpid(pid, 0)


#if __name__ == "__main__":
#    if len(sys.argv) < 2:
#        print("Usage: python container.py <command>")
#        sys.exit(1)
#
#    run_container(sys.argv[1:])

def test_container():
    # Define a series of commands to test different aspects of the container
    commands = [
        ["hostname"],  # Check the isolated hostname
        ["echo", "Hello from the container!"],  # Simple output to test execution
        ["ls", "/"],  # List root directory to check filesystem isolation
        ["ps", "aux"],  # List processes to see isolation in PID namespace
        ["ip", "addr"],  # Check network interfaces for network namespace isolation
    ]

    for command in commands:
        pid = os.fork()
        if pid == 0:
            # Child process: run the container code
            os.execvp("python3", ["python3", "container.py"] + command)
        else:
            # Parent process: wait for child to finish
            os.waitpid(pid, 0)

if __name__ == "__main__":
    test_container()
