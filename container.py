# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

import os
import subprocess


class Container:
    def __init__(self, name, root_dir):
        self.name = name
        self.root_dir = root_dir

    def run(self, command, result_queue):
        print(f"Running command in container {self.name}: {command}")
        try:
            os.chroot(self.root_dir)
            os.chdir("/")

            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8").strip() + result.stderr.decode("utf-8").strip()

            result_queue.put((self.name, output))
        except Exception as e:
            result_queue.put((self.name, str(e)))
        finally:
            os.chdir("/")
