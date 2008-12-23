#!/usr/bin/python2.5
"""
The Amnesia file system library.

Cartel Research Laboratories 2007.

"""

import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import stat
from math import log10
from copy import copy as copier
import pickle
import random
import zlib
import time
import fuse


blocksize = 4096

class Hyperblock():
    """The hyperblock is a virtual object that combines all the superblocks.
    It is never written to disk and exists only in memory.
    It exports methods for interacting with directories."""
    def __init__(self, backend, superblocks=[]):
        assert isinstance(backend, file)
        global hyper_instance
        try:
            if hyper_instance:
                print "hyperblock already instanced"
                raise ConcurrencyError
        except:
            hyper_instance = self
        self.backend = backend
        self._superblocks = []
        self.reserved_bytes = {}
        self.reservedblocks = set()
        self.keys = set()
        self.blocksize = 4096
        self.stat = os.fstat(self.backend.fileno())
        self.size = self.stat[6]
        self.numblocks = self.stat.st_size / self.blocksize
        for i in superblocks:
            self.merge(i)
    def __flatten__(self):
        """Flatten the directory structure into a single list."""
        d = self.path("/")
        x = Directory()
        for i in d.entries:
            x.append(i)
        return x.entries
    def allocated_blocks(self, showowner=False):
        """iterate over all entries in the hyperblock, and return the summed
        blocklists."""
        b = []
        for i in list(self._superblocks) + list(self.__flatten__()):
            for j in i.blocklist:
                if showowner:
                    b.append((j, i))
                else:
                    b.append(j)
        return b

    def reallocate(self, n):
        for check, owner in self.allocated_blocks(showowner=True):
            if check[0] == n[0] and (check[1] <= n[1] or check[2] >= n[2]):
                if isinstance(owner, Superblock):
                    # theoretically we could reallocate a superblock's block,
                    # but for now we wont.
                    raise ValueError
                else:
                    ciphertext = owner.reference.readblocks(blocklist=[n])
                    newblock = hyper_instance.allocate()
                    allocated = owner.reference.writeblocks(ciphertext, blocklist=[newblock])
                    count = owner.blocklist.index(n)
                    for i in allocated:
                        owner.reference.blocklist.pop(count)
                        owner.reference.blocklist.insert(count, i)
                        count += 1

    def __len__(self):
        """Total number of entries across all superblocks."""
        return len(self.__flatten__())

    def merge(self, s):
        """Merge a superblock."""
        try:
            if self._superblocks.index(s):
                raise ValueError
        except:
            self._superblocks.append(s)
            self.keys.add(s.key)
            self.reservedblocks.add(s.entryblock)

    def unmerge(self, s):
        """Unmerge a superblock."""
        try:
            self._superblocks.remove(s)
            self.keys.remove(s.key)
            self.reservedblocks.remove(s.entryblock)
        except:
            raise ValueError

    def path(self, p="/"):
        """Return a Directory object with all FileEntries in all superblocks
        matching that path."""
        d = Directory(entries=[])
        resolved = False
        if p == '':
            p = "/"
        for i in self._superblocks:
            # dont cry if path does not exist
            try:
                for j in i.path(p).entries:
                    d.append(j.__modify__(superblock=i, reference=i.path(p)))
                d.superblock = i
                resolved = True
            except IOError:
                pass
        # cry if path doesnt exist in ANY superblock
        if resolved == False:
            path,terminus = os.path.split(p)
            if path == "/" and terminus == '':
                return d
            else:
                raise IOError(2, "no such file or directory")
        else:
            #print d.entries
            return d

    def allocate(self, blocklist=[], byoffset=None, super=False):
        """
        The purpose of this function s to find an empty block.
        We'll do this by selecting a random block after
        ranging all the blocks in the fs into a set and
        subtracting the set of the allocated blocks.
        Mmm.. set.
        Allocate from the given blocklist first, even if its currently occupied.
        """
        def NextBlock(blocklist=[]):
            #print "nextblock fired"
            for i in blocklist:
                print "got i: %s"%[i]
                yield i
            while True:
                yield None
        
            #print "allocated_blocks: %s"%self.allocated_blocks()
        #print "super: %s"%super
        def updateAdict():
            f = []
            adict = {}

            for i in self.allocated_blocks():
                # handling multiple frags in a block is hard
                #print "checking fdict for: %s"%[i]
                if adict.has_key(i[0]):
                    low = self.adict[i[0]][1] if adict[i[0]][0] < i[1] else i[1]
                    high = self.adict[i[0]][2] if adict[i[0]][2] > i[2] else i[2]
                    adict[i[0]] = (i[0], low, high)
                else:
                    adict[i[0]] = i
                    f.append(i[0])
            #print "adict has %s entries."%len(adict.keys())
            self.space = set(range(0, self.numblocks)) - set(f)
        #print "byoffset, bs: %s, %s"%(byoffset, blocksize)
        #print "allocating block from %s possibilities"%len(self.space)
            return adict
        
        self.adict = updateAdict()
        
        if byoffset != None:
            b = int(byoffset / self.blocksize)
            bentry = byoffset - (b * self.blocksize)
            # lol!
            n = (int(byoffset / self.blocksize), bentry, self.blocksize)
        else:
            if blocklist != []:
                n = NextBlock(blocklist).next()
            else:
                n = (random.choice(list(self.space)), 0, self.blocksize)
        #print "choice: %s"%[n]

        #print "selecton: %s"%n
        if self.adict.has_key(n[0]):
                #print "possible collision detected"
                if super != False:
                    if n != super.entryblock:
                        print "allocating a super entrypoint."
                        # check to see if this range isnt in hyperblocks reservedbytes
                        for check in hyper_instance.reservedblocks:
                            if check[0] == n[0] and (check[1] >= n[1] or check[2] <= n[2]):
                                print "super entrypoint collides with another superblock. you'd best \
                                use another key."
                                raise ValueError
                            else:
                                print n
                                hyper_instance.reallocate(n)
                        low = self.adict[n[0]][2] + 1 if self.adict[n[0]][1] != 0 else 0
                        high = self.blocksize if self.adict[n[0]][2] != self.blocksize else self.adict[n[0]][1] -1
                        return n (self.adict[n[0]][0], low, high)
        return n


    def SuperEntrypoint(self, super):
        a = self.allocate(byoffset=frunge(int(super.key.hexdigest(), 16), self.stat.st_size), super=super)
        return a

    def freespace(self):
        """ returns the total free bytes """
        free = 0
        for i in self.space:
            if isinstance(i, list):
                free += i[2] - i[1]
            else:
                free += self.blocksize
        return free
    def resolve(self, query):
        """ resolve query by path and return the object """
        #print "resolving %s"%query
        searchpath, terminus = os.path.split(query)
        d = self.path(searchpath)
        if terminus == '':
            return d
        for i in d.entries:
            if i.name == terminus:
                return i
        raise IOError(2, "no such file or directory")
    def unlink(self, e):
        """ resolve query by path and unlink the object """
        x = self.resolve(e)
        x.reference.remove(x)
        x.superblock.flush()
        x.superblock.reload()
    def ls(self, path="/"):
        """ return a list of all the file objects by name in the given path."""
        thisdir, terminus = os.path.split("path")
        parent = os.path.split(thisdir)[0]
        yield self.path(thisdir).__modify__(copy=True, name=".")
        yield self.path(parent).__modify__(copy=True, name="..")
        try:
            for i in self.path(path).entries:
                yield i
        except IOError:
            pass


class Stat(fuse.Stat):
    """
    abstract subclass of stub class: fuse.Stat
    """
    def __init__(self):
        self.st_uid = os.getuid()
        self.st_gid = os.getgid()
        self.st_atime = self.st_mtime = self.st_ctime = int(time.time())

    def __str__(self):
        return "(%d, %d, %d, %d, %d, %d, %d, %d, %d, %d)" % \
               (self.st_mode, self.st_ino, self.st_dev, self.st_nlink,
                self.st_uid, self.st_gid, self.st_size, self.st_atime,
                self.st_mtime, self.st_ctime)

class DirStat(Stat):
    def __init__(self):
        Stat.__init__(self)
        self.st_mode = stat.S_IFDIR | 0755
        self.st_nlink = 2
        self.st_ino = 0
        self.st_dev = 0
        self.st_size = 0

class FileStat(Stat):
    def __init__(self):
        Stat.__init__(self)
        self.st_mode = 33188
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 1
        self.st_size = 0

class FileEntry(object):
    """A file on the filesystem"""
    # Overload the pickle methods so the entire object isnt serialised.
    # We want name, size, stat, and blocklist. An attribute for parent key
    # should be defined when the object is unserialised.
    def __init__(self, name, stat=None, blocklist=[]):
        self.name = name
        #self.stat.st_size = size
        if stat == None:
            self.stat = FileStat()
        else:
            self.stat = stat
        self.blocklist = blocklist
    def __reduce__(self):
        return (FileEntry, (self.name, self.stat, self.blocklist))
    def __str__(self):
        return self.name
    def __modify__(self, copy=False, superblock=None, reference=None):
        # superblock and reference are the parent or directory
        if copy == True:
            i = copier(self)
        else:
            i = self
        i.superblock = superblock
        i.reference = reference
        return i
    def writeblocks(self, ciphertext, blocklist=None):
        """Write blocks using the given blocklist first. If exhausted start
        allocating new blocks."""
        allocated = []
        remaining = len(ciphertext)
        lastwrite = 0
        
        if blocklist != None:
            bl = blocklist
        else:
            bl = self.blocklist
        
        def block():
            for i in bl:
                yield i
            while True:
                yield hyper_instance.allocate()
        
        blocks = block()
        while remaining != 0:
            n = blocks.next()
            #print "using block %s"%[n]
            hyper_instance.backend.seek((n[0] * hyper_instance.blocksize) + n[1])
            blockfree = n[2] - n[1]
            if remaining >= blockfree:
                thiswrite = blockfree
            else:
                thiswrite = remaining
                n = (n[0], n[1], n[1] + thiswrite)
            thisrange = slice(lastwrite, lastwrite + thiswrite)
            hyper_instance.backend.write(ciphertext[thisrange])
            lastwrite = lastwrite + thiswrite
            allocated.append(n)
            remaining -= thiswrite
        hyper_instance.backend.flush()
        if blocklist != None:
            return allocated
        else:
            self.blocklist = allocated


    def readblocks(self, blocklist=[]):
        """Read file blocks from blocklist. Return the ciphertext."""
        ciphertext = ""
        if blocklist == []:
            blocklist = self.blocklist
            remaining = self.stat.st_size
        else:
            blocklist = blocklist
            remaining = sum([i[2] - i[1] for i in blocklist])
        for n in blocklist:
            hyper_instance.backend.seek((n[0] * hyper_instance.blocksize) + n[1])
            blockread = n[2] - n[1]
            thisread = blockread
            #thisread = blockread if remaining >= blockread else remaining
            ciphertext += hyper_instance.backend.read(thisread)
            remaining -= thisread
        print "should always be 0: %s"% remaining
        return ciphertext

    def writeplain(self, k, plaintext):
        """Encrypt plaintext with k and writeblocks"""
        a = AES.new(k.digest())
        ciphertext = a.encrypt(pad(plaintext,16))
        self.writeblocks(ciphertext)
        self.stat.st_size = len(plaintext)
    def readplain(self, k):
        """readblocks, decrypt with k and return"""
        a = AES.new(k.digest())
        ciphertext = self.readblocks()
        print "Got %s bytes of ciphertext for file %s. Superblock says %s bytes"%(len(ciphertext),self.name, self.stat.st_size)
        print "Decrypting using key: %s"%self.superblock.key.hexdigest()
        return a.decrypt(ciphertext)[:self.stat.st_size]
    def store(self, plaintext):
        self.writeplain(self.superblock.key, plaintext)
        self.superblock.update(self)
    def retr(self):
        return self.readplain(self.superblock.key)

class CommandFileEntry(FileEntry):
    def store(self, plaintext):
        # plaintext contains a structured command of the form
        # CMD arg1 arg2
        print "got plaintext %s"%plaintext
        cmd, arg1, arg2 = plaintext.split(" ")
        if cmd == "TRANSPOSE":
            print "transposing %s to superblock %s"%(arg1, arg2)
            transpose(arg1, hyper_instance._superblocks[int(arg2)])
        if cmd == "DELSUPERBLOCK":
            print "deleting superblock at index %s"%arg1
            hyper_instance.unmerge(hyper_instance._superblocks[int(arg1)])
        if cmd == "ADDSUPERBLOCK":
            print "adding given superblock to list"
            hyper_instance.merge(Superblock(SHA256.new(arg1)))
        if cmd == "SETWORKINGSUPERBLOCK":
            print "setting working superblock to %s"%arg1
            t = hyper_instance._superblocks.pop(int(arg1))
            hyper_instance.merge(t)
        hyper_instance.unlink(self.name)


class Link():
    """
    A symbolic or hard link to another file or directory object.
    """
    def __init__(self, name, link=(), stat=None):
        self.name = name
        #self.link = (type, ref)
        #ref can be a FileEntry reference or an absolute path
        if stat == None:
            self.stat = Stat()
        else:
            self.stat = stat
        self.link = reference



class Directory():
    """
    Directories can and do exist in more than one superblock.
    It's the hyperblocks job to join them.
    """
    def __init__(self, name="/", stat=None, blocklist=[], entries=[]):
        self.name = name
        self.blocklist = blocklist
        if stat == None or {}:
            self.stat = DirStat()
        else:
            self.stat = stat
        self.entries = entries
    def __modify__(self, copy=False, **kwargs):
        if copy == True:
            i = copier(self)
        else:
            i = self
        for attr, value in kwargs.items():
            setattr(i, attr, value)
        return i
    def __reduce__(self):
        return (Directory, (self.name, self.stat, self.blocklist, self.entries))
    def __getstate__(self):
        return {"name": self.name, "stat": self.stat, "blocklist": self.blocklist, "entries": self.entries}

    def append(self, e, overwrite=True):
        # cant have two entries with the same name. note this doesnt unlink from disk.
        x = self.entries
        exists = False
        for i in x:
            if i.name == e.name:
                if overwrite:
                    self.remove(i)
                else:
                    exists = True
        if not exists:
            self.entries.append(e)
        
    def remove(self, e):
        self.entries.remove(e)

class Superblock():
    def __init__(self, key, root=Directory("/"), blocklist=[]):
        self.root = root
        self.key = key
        self.blocklist = blocklist
        try:
            self.root, self.blocklist = self.reload()
        except (IOError, ValueError):
            # superblock structure does not exist in block, flush and reload.
            self.flush()
            self.root, self.blocklist = self.reload()
    def mkdir(self, name):
        """Create a Directory object and append to the relevant object"""
        x, y = os.path.split(name)
        self.path(x).append(Directory(y, entries=[]), overwrite=False)
        self.flush()
    def path(self, p="/"):
        """Resolve Directory entry for path"""
        searchpath, terminus = os.path.split(p)
        #first traverse and return the last directory before the terminus
        target = self.root
        items = target.entries
        searchelements = searchpath.split("/")
        for i in searchelements:
            if i == "":
                continue
            for j in items:
                if j.name == i:
                    target = j
                    items = target.entries
                    break
            raise IOError(2,"file or directory not found")
        # now check the final items against terminus
        if terminus != "":            
            for j in items:
                if j.name == terminus:
                    return j
            raise IOError(2, "file or directory not found")
        else:
            return target
            
    def update(self, e, p="/"):
        #if isinstance(e, HyperFile):
        #    del e.superblock
        #    e.__class__ = FileEntry
        try:
            self.remove(e, p=p)
        except IOError:
           pass
        finally:
            self.path(p).append(e)
            self.flush()
    def create(self, e, plaintext=None, p="/"):
        """create an object e and append to path object corresponding with p"""
        if plaintext:
            if isinstance(plaintext, file):
                plaintext = plaintext.read()
            e.writeplain(self.key, plaintext)
        self.path(p).append(e)
        self.flush()

    def remove(self, e=None, f=None, p="/"):
        if e==None:
            if f==None:
                raise ValueError
            else:
                name = f
        else:
            name = e.name
        #print "attempting to remove %s"%name
        for i in self.path(p).entries:
            if i.name == name:
                #print "removing: %s"%name
                self.path(p).entries.remove(i)
                self.flush()
                return
        raise IOError(-2, "no such file or directory")

    def flush(self):
        # Write the superblock out to disk.
        k = self.key
        #print "--- flush --- %s"%k.hexdigest()
        a = AES.new(k.digest())
        # this is gonna change. overload the pickle/unpickle functionality
        # so the entire object is not serialised.
        # then rebuild at runtime to include references etc.
        plaintext = pickle.dumps(self.root)
        allocated = []
        ciphertext = a.encrypt(pad(plaintext, 16))
        #print "lengths: %s cipher %s plain"%(len(ciphertext), len(plaintext))
        remaining = len(ciphertext)
        thisblock = hyper_instance.SuperEntrypoint(self)
        hyper_instance.reserved_bytes[k] = thisblock
        offset = (thisblock[0] * hyper_instance.blocksize) + thisblock[1]
        #print "seeking to: %s"%offset
        hyper_instance.backend.seek(offset)
        hyper_instance.backend.write(a.encrypt(pad(str(remaining), 16)))
        #print "new tell: %s"%hyper_instance.backend.tell()
        lastwrite = 0
        reserved = 48
        #print " -- begin loop"
        while remaining > 0:
        #    print "loop entry tell: %s"%hyper_instance.backend.tell()
        #    print "remaining: %s"%remaining
            thisblockremaining = thisblock[2] - thisblock[1]
            thiswrite =  remaining if thisblockremaining - reserved >= remaining else thisblockremaining - reserved
            reserved = 32
        #    print "thiswrite: %s"%thiswrite
            hyper_instance.backend.write(a.encrypt(pad(str(thiswrite), 16)))
            thisrange = slice(lastwrite, thiswrite+lastwrite)
        #    print "thisrange: %s"%thisrange
            hyper_instance.backend.write(ciphertext[thisrange])
            thisblock = (thisblock[0], thisblock[1], thisblock[1] + thiswrite)
            allocated.append(thisblock)
            remaining -= thiswrite
            lastwrite = thiswrite
            if remaining == 0:
                break
            try:
                thisblock = hyper_instance.allocate(byoffset=int(a.decrypt(hyper_instance.backend.read(16))))
            except:
                thisblock = hyper_instance.allocate()
        #    print "allocated: %s"%str(thisblock)
        #    print "tell: %s"%hyper_instance.backend.tell()
            hyper_instance.backend.write(a.encrypt(pad(str((thisblock[0] * hyper_instance.blocksize) + thisblock[1]), 16)))
            hyper_instance.backend.seek((thisblock[0] * hyper_instance.blocksize) + thisblock[1])
        #    print "new tell: %s"%hyper_instance.backend.tell()
        #print "final tell: %s"%hyper_instance.backend.tell()
        self.blocklist = allocated
        #print "flushed superblock for key %s"%self.key.hexdigest()
        hyper_instance.backend.flush()

    def reload(self):
        # Reload the superblock from disk.
        k = self.key
        #print "--- reload --- %s"%k.hexdigest()
        self.entryblock = hyper_instance.SuperEntrypoint(self)
        a = AES.new(k.digest())
        #print "seeking superblock at %s"%[self.entryblock]
        ciphertext = ""
        allocated = []
        thisblock = hyper_instance.SuperEntrypoint(self)
        #print "entrypoint: %s,%s,%s"%thisblock
        hyper_instance.reserved_bytes[k] = thisblock
        offset = (thisblock[0] * hyper_instance.blocksize) + thisblock[1]
        #print("seeking to: %s"%offset)
        hyper_instance.backend.seek(offset)
        remaining =  int(a.decrypt(hyper_instance.backend.read(16)))
        #print "new tell: %s"%hyper_instance.backend.tell()
        lastread = 0
        #print " -- begin loop"
        while remaining >= 0:
        #    print "loop entry tell: %s"%hyper_instance.backend.tell()
        #    print "remaining: %s"%remaining
            thisread =  int(a.decrypt(hyper_instance.backend.read(16)))
        #    print "thisread: %s"%thisread
            ciphertext += hyper_instance.backend.read(thisread)
            allocated.append(thisblock)
            remaining -= thisread
        #    print "tell: %s"%hyper_instance.backend.tell()
            dump = hyper_instance.backend.read(16)
        #    print "dump: %s"%dump
            if remaining == 0:
                break
            thisblock = hyper_instance.allocate(byoffset=int(a.decrypt(hyper_instance.backend.read(16))))
        #    print "allocated: %s"%str(thisblock)
            hyper_instance.backend.seek((thisblock[0] * hyper_instance.blocksize) + thisblock[1])
        #    print "offset: %s"%str((thisblock[0] * hyper_instance.blocksize) + thisblock[1])
        #print "final tell: %s"%hyper_instance.backend.tell()
        plaintext = a.decrypt(ciphertext)
        self.blocklist = allocated
        return pickle.loads(plaintext), allocated


def pad(a, b):
    return  '%-*s' % (b*((len(a)-1)//b+1), a)

def munge(x):
    for i in [128, 64]:
        x = ((x & (((2**i)-1)<<i)) >> i) ^ (x & ((2**i) -1))
    return x

def frunge(x, y):
    """Frunge x into smaller numbers until it fits in y."""
    x = x % y
    print "frunging to: %s"%x
    return x

def padlength(i):
    return (int(i / 16) +1) * 16

def transpose(path, s):
    """transpose an object from path into superblock s"""
    sourcepath, terminus = os.path.split(path)
    sourceobj = hyper_instance.resolve(path)
    # ensure that the target superblock has the right leading directories, if not
    # create them
    try:
        dest = s.path(sourcepath)
    except OSError:
        # traverse sourcepath and mkdir as required
        thispath = ""
        for i in sourcepath.split("/"):
            thispath = thispath + "/" + i
            s.mkdir(thispath)
        dest = s.path(sourcepath)
    # set up the FileEntry
    t = FileEntry(terminus)
    t.superblock = s
    t.reference = dest
    t.stat = sourceobj.stat
    p = sourceobj.retr()
    t.store(p)
    #print "removing from these entries:"
    #print sourceobj.reference.entries
    hyper_instance.unlink(path)
    dest.append(t)
    s.flush()


if __name__ == "__main__":
    plaintext_keys = ["foo", "bar"]
    hyperblock = Hyperblock(open("lulz", "r+"))
    superblocks = hyper_instance._superblocks
    #reserved_bytes = {}
    #blocksize = 4096
    for k in plaintext_keys:
        hyper_instance.merge(Superblock(SHA256.new(k)))
    del plaintext_keys
    del k
    print "total size: %s (%s blocks)"%(hyper_instance.size, hyper_instance.numblocks)

    # we have all the known superblocks now, merge them into the hyperblock
    print "hyperblock has %s entries." %len(hyper_instance)
    print "%s keys known"%len(hyper_instance.keys)
    print "%s bytes free"%hyper_instance.freespace()

    #superblocks[0].mkdir("/keke")
    print "hyper: %s"%hyper_instance
    
    #
    superblocks[1].create(FileEntry("amnesia.py"), plaintext=open("./amnesia.py"))
    
    #transpose("/amnesia.py", superblocks[0])
    #print "new super: %s"%hyper_instance.resolve("/amnesia.py").superblock.key.hexdigest()
    #print "retr: %s"%hyper_instance.resolve("/amnesia.py").retr()
    
    #print [j for j in superblocks[0].root.entries][0].retr()
    

    #print superblocks[0].path("/lulz/wow").entries
    #list(hyper_instance.path("/"))[0].superblock
