# Advanced Topics in Online Privacy and Cybersecurity     Project
# Dvir Ben Asuli                                          318208816
# Siwar Mansour                                           207527680
# The Hebrew University of Jerusalem                      October 2024

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

    res = True
    print(Fore.MAGENTA + "\nTesting Containers\n" + Style.RESET_ALL)
    res &= run_containers_tests(SYSTEM)

    print(Fore.MAGENTA + "\nTesting X-Containers\n" + Style.RESET_ALL)
    res &= run_xcontainer_tests(SYSTEM)

    print(Fore.MAGENTA + "\nTesting Enhanced X-Containers\n" + Style.RESET_ALL)
    res &= run_enhanced_xcontainer_tests(SYSTEM)

    if res == True:
        print(Fore.GREEN + "\033[1m\nALL TESTS PASSED :) \n\033[0m" + Style.RESET_ALL)
    else:
        print(Fore.RED + "\033[1m\nSOME TESTS FAILED :( \n\033[0m" + Style.RESET_ALL)
