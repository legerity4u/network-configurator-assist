# Network Configurator Assistant

Network Configurator Assistant is an yet another scripts for automating wired network adapter reconfiguration when switching between networks. It's used PowerShell 7.* under Microsft Windows 10, 11

## Description

This tool allows flexible network adapter configuration, switching between dynamic IP address assignment via DHCP server and using static network parameters from an encrypted configuration file.

## Features

- Configure adapter to obtain address from DHCP
- Apply static network parameters from encrypted configuration file
- Encryption and decryption of configuration files

## Usage

1. Prepare a JSON configuration file using the provided example
2. Run the configuration encryption script as
   ```bash
   .\EncryptConfig.ps1 -JsonFilePath <path_to_json_file>
   ```
3. Use the main script to configure the network as
   ```bash
   .\NetworkConfig.ps1 -EncryptedFilePath <path_to_encrypted_file> [-Help]
   ```

Applying static parameters requires entering the password used during configuration encryption.

## Requirements

- PowerShell 7
- Administrator rights for network settings modification

## Installation

```bash
git clone https://github.com/legerity4u/network-configurator-assist.git
cd network-configurator-assist
```
## Security
Configuration files are encrypted to protect sensitive information. Store the decryption password in a secure location.

## License
This project is distributed under the MIT License. See the LICENSE file for details.

## Contributing
You are welcome to contribut to the project. Please create issues or pull requests to suggest changes.

