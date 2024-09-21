# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      Septmeber 2024

from tests import *

if __name__ == '__main__':
    os_name = input("Enter 'L' for Linux and 'M' for Mac OS:")
    if os_name.upper() == "L":
        SYSTEM = 'LINUX'
    elif os_name.upper() == "M":
        SYSTEM = 'MACOS'
    else:
        SYSTEM = 'LINUX'
        print("Non-valid OS name. Choosing Linux.")

    print("\nTesting Containers\n")
    run_containers_tests(SYSTEM)

    print("\nTesting X-Containers\n")
    run_xcontainers_tests(SYSTEM)

    print("\nTesting Enhanced X-Containers\n")
    run_enhanced_xcontainers_tests(SYSTEM)
