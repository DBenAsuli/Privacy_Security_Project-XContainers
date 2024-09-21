# Privacy_Security_Project-XContainers
## Enhancing X-Containers Methodology
### Final Project in Advanced Topics in Online Privacy and Cybersecurity Course at HUJI, 2024 
### Dvir Ben Asuli & Siwar Mansour

#### Our code includes the following files:
1. container.py – Basic implementation of the traditional Containers methodology.
2. xcontainer.py - Basic implementation of the X-Containers methodology. Also includes implementation of a Hypervisor class.
3. excontainer.py – Implementation of our Enhanced X-Containers methodology.
4. tests.py – Several test flows to verify the functionality of all above classes.
5. main.py – Code that runs all tests for all above classes.

#### Important Notes:
1. The code requires directories inside run directory to run the containers in. The default names are: "root_dir", "root_dir_x" and "root_dir_ex" for Containers, X-Containers and Enhanced X-Containers respectively.
2. In order for the containers to be able to run inside these directories, they need to include /bin and /usr and /lib directories from the OS in order to work properly. It may differ between computers and OS's.
3. The tests have the option to run on Linux (Default) or MacOS. When running the code, you will be asked to type "L" for Linux usage or "M" for MacOS usage. When typing invalid input, Linux will be chosen.



