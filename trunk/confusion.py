#!/usr/bin/python

# confusion - cross platform authentication with duress

from amnesia import Hyperblock, Superblock
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def main():
    pw = "toomanysecrets"
    duress = "youvegotnothing"
    
    # open and set up the blockfile
    hyperblock = Hyperblock(open("lulz", "r+"))
    hyper_instance.merge(Superblock(SHA256.new(pw)))
    hyper_instance.merge(Superblock(SHA256.new(duress)))

if __name__ == "__main__":
    main()
