[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTOPENVAS

Penterep OpenVAS/GVM Automation Tool

## Installation

```
pip install ptopenvas
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptopenvas -T www.example.com -P 80,443
ptopenvas -T 23.192.228.84 -P 80,443 -sc 'Base'
```

## Options
```
-T   --target       <target>           Set Target
-P   --port         <port>             Set Port(s)
-sc  --scan-config                     Select scan config type (default Full and fast):
                     Full and fast      Most NVT's; optimized by using previously collected information
                     Base               Basic config with a minimum set of NVTs
                     Discovery          Network Discovery
                     System Discovery   Network System Discovery
                     Host Discovery     Network Host Discovery
                     Log4Shell          Checks for Log4j and CVE-2021-44228

-v   --version                         Show script version and exit
-h   --help                            Show this help message and exit
-j   --json                            Output in JSON format
```

## Dependencies
```
ptlibs
```

## License

Copyright (c) 2025 Penterep Security s.r.o.

ptopenvas is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptopenvas is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptopenvas. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!