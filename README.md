# WinDefReleaser
Python tool to parse and decrypt files quarantined by windows defender. Useful for security analysts and incident responders looking to review the original file(s) windows defender alerted on.

### Credits

**Standing on the shoulders of giants** - This tool builds upon the amazing work of @knez and their [defender-dump](https://github.com/knez/defender-dump) tool. Now functional against any target path, hashing entries in memory and optionally outputting to an encrypted .ZIP. RC4 decryption routine also forked from [quarantine.py](https://raw.githubusercontent.com/brad-accuvant/cuckoo-modified/00ad13c94cc7453c40ed6152d16009ca1c8ed6f2/lib/cuckoo/common/quarantine.py) from the cuckoosandbox project.

**Credit** to knez, KillerInstinct, Optiv, Inc and OALabs for the work this tool builds upon.

---

### Usage

After detection, a file is moved to the following path for quarantine:
```
C:\ProgramData\Microsoft\Windows Defender\Quarantine
```
- Detection metadata is stored in the 'Entries' subfolder
- The original file is encrypted and stored in the 'ResourceData' subfolder

Defender uses a hardcoded key to RC4 encrypt each file thus the operation can easily be reversed. To make use of this tool please retrieve the entire `\Quarantine` folder.

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

![Example use of the tool.](/image/windef.png "Example use of the tool.")
