# WinDefReleaser
Small python tool to decrypt files quarantined by windows defender. This has been written for python3 using only the standard python library. 

### Credits

**Standing on the shoulders of giants** - This script is a fork of an [OALabs Gist](https://gist.github.com/OALabs/30346d78a1fccf59d6bfafab42fbee5e), which itself is a fork of [quarantine.py](https://raw.githubusercontent.com/brad-accuvant/cuckoo-modified/00ad13c94cc7453c40ed6152d16009ca1c8ed6f2/lib/cuckoo/common/quarantine.py) from the cuckoosandbox project.

**Credit** to KillerInstinct, Optiv, Inc and OALabs for the work this script builds upon.

---

### Usage

```
 _ _ _ _     ____      ___ _____     _
| | | |_|___|    \ ___|  _| __  |___| |___ ___ ___ ___ ___
| | | | |   |  |  | -_|  _|    -| -_| | -_| .'|_ -| -_|  _|
|_____|_|_|_|____/|___|_| |__|__|___|_|___|__,|___|___|_|


usage: 1windef.py [-h] [-o OUTPUT] path

Windows Defender Releaser

positional arguments:
  path                  Input filepath, the quarantined file you want to decrypt

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output folder path

Example:
python WinDefReleaser.py /path/to/quarantinedfile
```

### Example

```
User@User: python WinDefReleaser.py ENCRYPTEDFILE50

 _ _ _ _     ____      ___ _____     _
| | | |_|___|    \ ___|  _| __  |___| |___ ___ ___ ___ ___
| | | | |   |  |  | -_|  _|    -| -_| | -_| .'|_ -| -_|  _|
|_____|_|_|_|____/|___|_| |__|__|___|_|___|__,|___|___|_|


Selected File: 'ENCRYPTEDFILE50'
Selected Output Folder: '/home/user/Documents/windef/'

[+] Decrypted file (+ Metadata) saved to: '/home/user/Documents/ENCRYPTEDFILE50_decrypted_meta.bin'
[I] Aproximitely 250 bytes of defender metadata has been prepended to the original file. Look for magic bytes around 250 bytes in to see the start of the quarantined file.

[+] Quitting...
```
