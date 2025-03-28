# My Zombies C2 Framework

## Overview

Welcome to the My Zombies C2 Framework repository! This project is designed to provide a comprehensive command and control (C2) solution for both Windows and Linux clients. Built primarily using HTML, CSS, JavaScript, and Python, this framework offers a user-friendly web interface and a variety of powerful modules, including persistence, information gathering, and remote code execution.

## Features

- **Cross-Platform Support**: Compatible with both Windows and Linux clients.
- **Modular Architecture**: Easily extendable with various modules for different functionalities.
  - **Persistence Modules**: Ensure that your agents remain active and connected.
  - **Information Gathering**: Collect valuable data from target systems.
  - **Remote Code Execution**: Execute commands and scripts on remote machines.
- **Web-Based Interface**: Access and control the framework through a simple and intuitive web interface hosted on localhost.

## Installation

To set up the My Zombies C2 Framework on your local machine, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/elofinky/My_Zombies_C2.git
   cd My_Zombies_C2
   ```

2. **Install Dependencies**:
   Ensure you have Python installed. Then, install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Framework**:
   Start the web server:
   ```bash
   cd Server/
   python3 server.py
   ```
   <i>make sure to create a py-venv first</i> <br>
   Open your web browser and navigate to `http://localhost:5000` to access the interface.

## Usage

Once the framework is running, you can:

- Use the "Client/client.py" however you want it is the main initialized payload.
- Deploy persistence modules to maintain access **not set to any preconfigured script**.
- Gather information from connected clients.
- Execute commands remotely on any client.

Refer to the documentation within the repository for detailed instructions on using each module.

## Contributing

Contributions are welcome! Pleas use this code in any way "Its opensource dude".

## Contact

If anyone wants to conact myself that's here: bytekiss@mailfence.com. <br>
This was made from scratch by "Nullkiss" "Elofinky" *all me diferaint account names.

---

Thank you for your interest in the My Zombies C2 Framework! We hope you find it useful for your projects. Happy coding!

## Images of the UI and some other things

![image](https://github.com/user-attachments/assets/ba5afada-4e1b-461f-9d91-228ea247e834)
![image](https://github.com/user-attachments/assets/8f33999a-19f4-451d-ae01-47064e98c282)
![image](https://github.com/user-attachments/assets/c9e13bf6-0345-4436-b464-f6cc8a165725)
![image](https://github.com/user-attachments/assets/4bc5b49f-413c-4be8-b6e0-681636747bde)


