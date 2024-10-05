# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour
# The Hebrew University of Jerusalem                      September 2024

from tests import *

if __name__ == '__main__':
    os_name = input("Enter 'L' for Linux and 'M' for Mac OS: ")
    if os_name.upper() == "L":
        SYSTEM = 'LINUX'
    elif os_name.upper() == "M":
        SYSTEM = 'MACOS'
    else:
        SYSTEM = 'LINUX'
        print("Non-valid OS name. Choosing Linux.")

    print(Fore.MAGENTA + "\nTesting Containers\n" + Style.RESET_ALL)
    #run_containers_tests(SYSTEM)

    print(Fore.MAGENTA + "\nTesting X-Containers\n" + Style.RESET_ALL)
    #run_xcontainer_tests(SYSTEM)

    print(Fore.MAGENTA + "\nTesting Enhanced X-Containers\n" + Style.RESET_ALL)
    run_enhanced_xcontainer_tests(SYSTEM)
