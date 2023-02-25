# WinDefReleaser
Python tool to parse and decrypt files quarantined by windows defender. Useful for security analysts looking to review the original file windows defender alerted on.

### Credits

**Standing on the shoulders of giants** - This tool builds upon the amazing work of @knez and their [defender-dump](https://github.com/knez/defender-dump) tool. Now functional against any target path, hashing entries in memory and optionally outputting to an encrypted .ZIP. RC4 decryption routine also forked from [quarantine.py](https://raw.githubusercontent.com/brad-accuvant/cuckoo-modified/00ad13c94cc7453c40ed6152d16009ca1c8ed6f2/lib/cuckoo/common/quarantine.py) from the cuckoosandbox project.

**Credit** to knez, KillerInstinct, Optiv, Inc and OALabs for the work this script builds upon.

---

### Usage

```
usage: WinDefReleaser.py [-h] [-d] [-o OUTPUT] [-m MODE] path

Windows Defender Releaser

positional arguments:
  path                  input filepath, the 'Quarantine' folder you want to parse

optional arguments:
  -h, --help            show this help message and exit
  -d, --dump            decrypt and dump all entries into a pw protected .ZIP (pw: infected)
  -o OUTPUT, --output OUTPUT
                        output folder path
  -m MODE, --mode MODE  hashing mode: md5/sha1/sha256, default is sha1


Example:
python WinDefReleaser.py /path/to/Quarantine
```

### Example

```
User@User: python WinDefReleaser.py ENCRYPTEDFILE50

 _ _ _ _     ____      ___ _____     _
| | | |_|___|    \ ___|  _| __  |___| |___ ___ ___ ___ ___
| | | | |   |  |  | -_|  _|    -| -_| | -_| .'|_ -| -_|  _|
|_____|_|_|_|____/|___|_| |__|__|___|_|___|__,|___|___|_|


Selected File: 'ENCRYPTEDFILE50'
Selected Output Folder: '/home/user/Documents/'

[+] Decrypted file (+ Metadata) saved to: '/home/user/Documents/ENCRYPTEDFILE50_decrypted_meta.bin'
[I] Aproximitely 250 bytes of defender metadata has been prepended to the original file. Look for magic bytes around 250 bytes in to see the start of the quarantined file.

[+] Quitting...
```
