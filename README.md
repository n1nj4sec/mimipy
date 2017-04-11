# Mimipy
This is a port in python of @huntergregal's [mimipenguin.sh](https://github.com/huntergregal/mimipenguin) bash script with some improvments :
- no memory dump written on disk
- possibility to mitigate the attack by overwriting passwords found in memory (you might want to add a cron)
- possibility to search for any trace of your password in all your processes
- possibility to scan a process by pid
- add some additional processes to scan like lightDM

## Install
```bash
pip install -r requirements.txt
```

## Usage
```bash
usage: mimipy.py [-h] [--clean] [-v] [-p PID] [--search-password]

optional arguments:
    -h, --help         show this help message and exit
    --clean            @blueteams protect yourself and clean found passwords from memory ! You might want to regularly run this on your workstation/servers
    -v, --verbose      be more verbose !
    -p PID, --pid PID  choose the process's pid to scan instead of automatic selection
    --search-password  prompt for your password and search it in all your processes !.
```

## Contact
by mail: contact@n1nj4.eu  
on Twitter: [Follow me on twitter](https://twitter.com/n1nj4sec)

## Special thanks
Special thanks to @huntergregal for releasing his mimipenguin.sh idea and @gentilwiki for the awesome mimikatz tool

