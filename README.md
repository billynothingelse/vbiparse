# vbiparse
vbiparse is a python script to handle the Xbox One VBI file format.

# Usage
```
usage: vbi.py [-h] [--info] [--type {host,sra,era}] [--extract] [--csb CSB] [--directory DIRECTORY] filename

Parse an Xbox VBI

positional arguments:
  filename              *.vbi filename

optional arguments:
  -h, --help            show this help message and exit
  --info                print VBI information
  --type {host,sra,era}
                        the os target type of VBI
  --extract             extract modules from VBI
  --csb CSB             code section begin offset
  --directory DIRECTORY
                        directory to store extracted files
```
