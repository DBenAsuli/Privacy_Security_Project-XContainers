# Privacy_Security_Project-XContainers
## Enhancing X-Containers Methodology Using PKI
### Final Project in Advanced Topics in Online Privacy and Cybersecurity Course at HUJI, 2024 
### Dvir Ben Asuli & Siwar Mansour

In our project, we shall try to integrate Public Key Infrastructure (PKI) protocol into the X-Container methodology, in order to enhance its security features. Introducing PKI into the traditional X-Container methodology can address many attack scenarios where a malicious attacker might exploit X-Containers' faults using different methods.
Since X-Containers is a rather-new approach, it’s hard to find license-free full implementation of it. So first of all, one of the main challenges of our project will be to try and implement a simplified version of such system. Later, we will introduce the PKI-Based Enhanced X-Container implementation.
The code also includes many tests to verify the behaviour of all the classes and methodologies.

#### Our code includes the following files:
1. container.py – Basic implementation of the traditional Containers methodology.
2. xcontainer.py - Basic implementation of the X-Containers methodology. Also includes implementation of a Hypervisor class.
3. excontainer.py – Implementation of our Enhanced PKI-Based X-Containers methodology.
4. pki.py – Implementation of utilities for PKI Protocol.
5. tests.py – Several test flows to verify the functionality of all above classes.
6. main.py – Code that runs all tests for all above classes.

#### Important Notes:
1. The code requires directories inside the main run directory to run the containers inside. The default names for such directories are: "root_dir", "root_dir_x" and "root_dir_ex" for Containers, X-Containers and Enhanced X-Containers respectively. Other names can be provided as input to the run fucntions.
2. In order for the containers to be able to run inside these directories, they need to include /bin and /usr and /lib directories from the OS in order to work properly. It may differ between computers and OS's.
3. The tests have the option to run on Linux (Default) or MacOS. When running the code, you will be asked to type "L" for Linux usage or "M" for MacOS usage. When typing invalid input, Linux will be chosen.

After all conditions are satisfied, just run main.py in the main directory in order to test all the different classes and execute all the tests we implemented.



