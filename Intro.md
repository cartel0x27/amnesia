## Introduction ##
Release 0.1 of a deniable file system.

Amnesia is the only file system designed to destroy your files. Please don't use it for anything other than what you are better off deleting.

## Acquiring Amnesia ##

Amnesia is only available from googlecode.com SVN.

```
svn checkout http://amnesia.googlecode.com/svn/trunk/ amnesia
```


## Contents ##
```
 amnesia.py - library
 amnesiafs.py - fuse bindings
 amnesiacmd.py - simple tool to make out of band changes to the fs
```
## Example usage ##
```
cartel@manticore:~/code/amnesia/mounted$ dd if=/dev/urandom of=/tmp/lulz bs=4096 count=8192
8192+0 records in
8192+0 records out
33554432 bytes (34 MB) copied, 10.5016 seconds, 3.2 MB/s

cartel@manticore:~/code/amnesia$ ./amnesiafs.py -o root=/tmp/lulz ./mounted/
enter key [none to continue]:
enter key [none to continue]:
enter key [none to continue]:
mounting amnesiaFS from /tmp/lulz
total size: 33554432 (8192 blocks)
hyperblock has 0 entries.
2 keys known
33554432 bytes free
cartel@manticore:~/code/amnesia$ cd mounted/
cartel@manticore:~/code/amnesia/mounted$ cp ../amnesia.py .
cartel@manticore:~/code/amnesia/mounted$ ../amnesiacmd.py -s 0
setting working superblock to index 0
cartel@manticore:~/code/amnesia/mounted$ cp ../amnesiafs.py .
cartel@manticore:~/code/amnesia/mounted$ ls -l
total 38
-rw-r--r-- 1 cartel cartel 11864 2007-11-15 17:15 amnesiafs.py
-rw-r--r-- 1 cartel cartel 25813 2007-11-15 17:14 amnesia.py
cartel@manticore:~/code/amnesia/mounted$ ../amnesiacmd.py -d 1
deleting keyindex 1
cartel@manticore:~/code/amnesia/mounted$ ls
amnesia.py
cartel@manticore:~/code/amnesia/mounted$ head -n 7 amnesia.py
#!/usr/bin/python2.5
"""
The Amnesia file system library.

Cartel Research Laboratories 2007.

"""
cartel@manticore:~/code/amnesia/mounted$ ../amnesiacmd.py -a
enter key:
adding key [not echoed]
cartel@manticore:~/code/amnesia/mounted$ ls
amnesiafs.py  amnesia.py
cartel@manticore:~/code/amnesia/mounted$ head amnesiafs.py -n 7
#!/usr/bin/python2.5

"""
amnesia fuse bindings

(c) 2007 cartel research laboratories
"""
```

## todo ##
```
fix symbolic links 
Free space calculation - amnesia doesnt test if you actually have space to allocate
fix invalid literal bug - seems to be fixed
test suite - started
```

## contact ##

[mailto:cartel@cypherpunk.org.nz](mailto:cartel@cypherpunk.org.nz)