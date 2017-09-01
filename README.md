# pam_honeyword
👻 PAM module that checks for "dictionary" passwords

### Why?
This is just me playing with PAM and trying to understand how it works (**hella fun**) and an idea I had while I was reading a paper about honeywords ([Honeywords: Making Password-Cracking Detectable](https://people.csail.mit.edu/rivest/pubs/JR13.pdf)).

## Arguments
There's two arguments you can use (one is mandatory and the other optional):
* **wordlist**: This will be the path to the dictionary passwords to use.
* **exec (optional)**: Path to an executable to be used if we find a matching password. Two args will be passed to the executable: the username and remote IP address.

## How to use it:
Compile:
```bash
$ make
```
In my case, I used this module (and only tested it) for sshd. You should append this to the pam.d/sshd configuration:
```bash
$ grep honeyword /etc/pam.d/sshd
auth  required  /PATH/TO/pam_honeyword.so wordlist=/tmp/wordlist exec=/tmp/exec.sh
```
Messages from the module are displayed using pam_syslog:
```bash
$ journalctl -S today | grep pam_honeyword
Aug 31 03:41:08 dev sshd[12377]: pam_honeyword(sshd:auth): Matching passwords (user: cedric;rhost: 127.0.0.1).
```

### Note
This is just a test and should not be used on a production server (or any kind of server _unless you improve it 'cause I'm not a great programmer_).
