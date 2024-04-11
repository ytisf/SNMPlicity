# SNMPlicity

[<img src="https://github.com/ytisf/SNMPlicity/raw/gh-pages/SNMPlicityLogoThumb.png">](https://github.com/ytisf/SNMPlicity)

# DISCLAIMER !!!!
**The SNMPlicity tool is developed for educational and ethical security auditing purposes only. It should only be used on networks and systems where explicit authorization has been obtained. Remember, with great power comes great responsibility: unauthorized use of this tool against any network or system without prior consent is illegal and strictly prohibited.**

By using SNMPlicity, you agree to use it responsibly and ethically. The developers and contributors of SNMPlicity are not responsible for misuse, damages, or any consequences arising from improper or illegal use. It is the user's responsibility to comply with all applicable local, state, national, and international laws and regulations.

Use SNMPlicity wisely and ethically to enhance your understanding of network security and to contribute positively to the cybersecurity community.

## Introduction

SNMPlicity: the Swiss Army Knife of the SNMP world, but, it's coded in Python, not made of stainless steel. Designed with the over-caffeinated engines and with the sleep-deprived cybersecurity practitioner in mind, this tool turns SNMP, the so-called "Simple" Network Management Protocol (we know, "simple" is quite the overstatement), into your very own remote control. Execute commands, snoop on system info, and perform digital magic from the comfort of your command line. It's like giving network management and security assessment a caffeine shot, but legally and without the jittery side effects.

## Features

- **Remote Command Execution**: Utilize SNMP to execute commands across networked devices, streamlining management tasks and response times.
- **Information Gathering**: Collect essential system information, such as current directory, user details, and hostname.
- **Logging Capabilities**: Automatically generate detailed logs of activities and findings, aiding in documentation and analysis.
- **Extensible Framework**: Designed with modularity in mind, allowing for easy extension and customization.

## Getting Started

These instructions will guide you through the setup and operation of SNMPlicity.

### Prerequisites

Ensure that Python 3 and pip are installed on your system. SNMPlicity requires the following Python packages:

- colorama

### Installation

1. Clone the SNMPlicity repository to your local machine:

```bash
git clone https://github.com/ytisf/SNMPlicity.git
```

Navigate into the SNMPlicity directory and install the required Python packages:
```bash
cd SNMPlicity
pip install -r requirements.txt
```

### Usage
To start using SNMPlicity, execute the script with the necessary arguments:

```bash
./SNMPlicity.py --community-string [COMMUNITY_STRING] --target [TARGET_IP] [--port [PORT]]
```
For a complete list of options and their descriptions, use the help command:

```bash
./SNMPlicity.py -h
```

### Contributing

Your contributions are what make the community great. Any contributions you make are greatly appreciated.

Fork the Project
1. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
2. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
3. Push to the Branch (`git push origin feature/AmazingFeature`)
4. Open a Pull Request

## License
Distributed under the MIT License. See LICENSE for more information.

## Contact
Project Link: https://github.com/ytisf/SNMPlicity
