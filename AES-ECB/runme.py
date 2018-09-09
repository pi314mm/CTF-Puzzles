from pwn import *
from Crypto.Cipher import AES
import os

key = os.urandom(16)
e = AES.new(key, AES.MODE_ECB)
flag = "FLAG"

def encrypt(message):
    m = message+flag
    while not len(m)%16==0:
        m=m+"\x00"
    return e.encrypt(m)


s = server(1234)

while True:
    c = s.next_connection()
    try:
        c.sendline("Welcome to the encryption service!")
        c.sendline("This program will encrypt any message for you")
        c.sendline("We use AES with ECB to encrypt the message you send appended by our secret text")
        c.sendline("print hex(encrypt(message+flag+\\x00 padding))")
        c.sendline("give an empty string to close the connection")
        message="hi"
        while len(message)>0:
            c.sendline("Please input your message:")
            message = c.recvline().strip()
            c.sendline("encrypted: "+encrypt(message).encode('hex'))
        c.close()
    except:
        c.close()
