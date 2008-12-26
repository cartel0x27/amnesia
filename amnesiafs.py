#!/usr/bin/python2.5

"""
amnesia fuse bindings

(c) 2007 cartel research laboratories
"""

import os, sys
from errno import *
from stat import *
import fcntl
try:
    import _find_fuse_parts
except ImportError:
    pass
import fuse
from fuse import Fuse
from StringIO import StringIO
from amnesia import *
from getpass import getpass
import smtplib
import email
import base64


if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

fuse.feature_assert('stateful_files', 'has_init')


def flag2mode(flags): 
    md = {os.O_RDONLY: 'r', os.O_WRONLY: 'w', os.O_RDWR: 'w+'}
    m = md[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]

    if flags | os.O_APPEND:
        m = m.replace('w', 'a', 1)

    return m


class amnesiaFS(Fuse):

    def __init__(self, *args, **kw):

        Fuse.__init__(self, *args, **kw)
    
    def begin(self, plaintext_keys):
        global hyper_instance
        print "mounting amnesiaFS from %s"%self.root
        self.hyperblock = Hyperblock(open(self.root, "r+"))
        hyper_instance = self.hyperblock
        self.superblocks = self.hyperblock._superblocks
        if len(plaintext_keys) == 0:
            print "need at least one key"
            raise SystemExit
        for k in plaintext_keys:
            self.hyperblock.merge(Superblock(SHA256.new(k)))
        del plaintext_keys
        del k
        print "total size: %s (%s blocks)"%(self.hyperblock.size, self.hyperblock.numblocks)
        
        print "hyperblock has %s entries." %len(self.hyperblock)
        print "%s keys known"%len(self.hyperblock.keys)
        print "%s bytes free"%self.hyperblock.freespace()
        # do stuff to set up your filesystem here, if you want
        #import thread
        #thread.start_new_thread(self.mythread, ())
        #self.root = '/'

#    def mythread(self):
#
#        """
#        The beauty of the FUSE python implementation is that with the python interp
#        running in foreground, you can have threads
#        """
#        print "mythread: started"
#        while 1:
#            time.sleep(120)
#            print "mythread: ticking"

    def getattr(self, path):
        print "getattr: %s"%path
        print "stat: %s"%str(self.hyperblock.resolve(path).stat)
        return self.hyperblock.resolve(path).stat
        #return os.stat(".")

    def readlink(self, path):
        return self.hyperblock.resolve(path).reference

    def readdir(self, path, offset):
        print "readdir %s"%path
        for e in self.hyperblock.ls(path):
            print "got entry: %s"%e.name
            yield fuse.Direntry(e.name)

    def unlink(self, path):
        self.hyperblock.unlink(path)

    def rmdir(self, path):
        self.hyperblock.unlink(path)

    def symlink(self, path, path1):
        tpath, terminus = os.path.split(path)
        target = self.hyperblock.resolve(tpath)
        target.append(Link(terminus, link=(0, path1)))

    def rename(self, path, path1):
        s = self.hyperblock.resolve(path)
        tpath, terminus = os.path.split(path1)
        s.name = terminus

    def link(self, path, path1):
        s = self.hyperblock.resolve(path)
        tpath, terminus = os.path.split(path1)
        target = self.hyperblock.resolve(tpath)
        target.create(Link(terminus, link=(1, s)))

    def chmod(self, path, mode):
        print "changing mode: %s"%mode
        self.hyperblock.resolve(path).stat.st_mode = mode
        self.hyperblock.resolve(path).superblock.flush()

    def chown(self, path, user, group):
        s = self.hyperblock.resolve(path)
        s.stat.st_uid = user
        s.stat.st_gid = group

    def truncate(self, path, len):
        self.hyperblock.resolve(path).size  = len

    def mknod(self, path, mode, dev):
        #os.mknod("." + path, mode, dev)
        pass

    def mkdir(self, path, mode):
        searchpath, terminus = os.path.split(path)
        print "parent resolved as: %s"%searchpath
        t = self.hyperblock.resolve(searchpath)
        t.superblock.mkdir(path)
        t = self.hyperblock.resolve(path)
        t.stat.st_mode = S_IFDIR | mode
        t.superblock.flush()
        

    def utime(self, path, times):
        t = self.hyperblock.resolve(path)
        print "setting time: %s, %s"%times
        if times == None:
            times = (time.time(), time.time())
        t.stat.st_utime = times[0]
        t.stat.st_mtime = times[1]

#    The following utimens method would do the same as the above utime method.
#    We can't make it better though as the Python stdlib doesn't know of
#    subsecond preciseness in acces/modify times.
#  
#    def utimens(self, path, ts_acc, ts_mod):
#      os.utime("." + path, (ts_acc.tv_sec, ts_mod.tv_sec))

    def access(self, path, mode):
        #if not os.access("." + path, mode):
        #    return -EACCES
        pass

#    This is how we could add stub extended attribute handlers...
#    (We can't have ones which aptly delegate requests to the underlying fs
#    because Python lacks a standard xattr interface.)
#
#    def getxattr(self, path, name, size):
#        val = name.swapcase() + '@' + path
#        if size == 0:
#            # We are asked for size of the value.
#            return len(val)
#        return val
#
#    def listxattr(self, path, size):
#        # We use the "user" namespace to please XFS utils
#        aa = ["user." + a for a in ("foo", "bar")]
#        if size == 0:
#            # We are asked for size of the attr list, ie. joint size of attrs
#            # plus null separators.
#            return len("".join(aa)) + len(aa)
#        return aa

    def statfs(self):
        """
        Should return an object with statvfs attributes (f_bsize, f_frsize...).
        Eg., the return value of os.statvfs() is such a thing (since py 2.2).
        If you are not reusing an existing statvfs object, start with
        fuse.StatVFS(), and define the attributes.

        To provide usable information (ie., you want sensible df(1)
        output, you are suggested to specify the following attributes:

            - f_bsize - preferred size of file blocks, in bytes
            - f_frsize - fundamental size of file blcoks, in bytes
                [if you have no idea, use the same as blocksize]
            - f_blocks - total number of blocks in the filesystem
            - f_bfree - number of free blocks
            - f_files - total number of file inodes
            - f_ffree - nunber of free file inodes
        """

        return os.statvfs(".")

    def fsinit(self):
        #os.chdir(self.root)
        pass

    class AmnesiaFSFile(object):

        def __init__(self, path, flags, *mode):
            try:
                self.File = hyper_instance.resolve(path)
                self.file = StringIO(self.File.retr())
            except IOError:
                #print "flags, realmode: %s, %s, %s"%(flags, mode, flag2mode(flags))
                if flag2mode(flags) in ["w", "w+", "a"]:
                    path, name = os.path.split(path)
                    if name == ".amnesiacmd":
                        self.File = CommandFileEntry(name)
                    else:
                        self.File = FileEntry(name)
                    #self.File.stat.st_mode = flags
                    hyper_instance.resolve(path).entries.append(self.File)
                    self.File.superblock = hyper_instance.resolve(path).superblock
                    self.File.parent = hyper_instance.resolve(path)
                    self.file = StringIO("")
                else:
                    raise IOError(-2)
                
            #self.fd = self.file.fileno()

        def read(self, length, offset):
            self.file.seek(offset)
            return self.file.read(length)

        def write(self, buf, offset):
            self.file.seek(offset)
            self.file.write(buf)
            return len(buf)

        def release(self, flags):
            #self.File.writeplain(self.file.getvalue())
            self.file.close()

        def _fflush(self):
            try:
                self.file.flush()
            except:
                print "ohnoes"
                pass

        def fsync(self, isfsyncfile):
            self._fflush()
            #if isfsyncfile and hasattr(os, 'fdatasync'):
            #    os.fdatasync(self.fd)
            #else:
            print "key:%s"%self.File.superblock.key
            self.File.store(self.file.getvalue())

        def flush(self):
            self._fflush()
            # cf. xmp_flush() in fusexmp_fh.c
            self.File.store(self.file.getvalue())

        def fgetattr(self):
            return self.File.stat

        def ftruncate(self, len):
            self.file.truncate(len)

        def lock(self, cmd, owner, **kw):
            # The code here is much rather just a demonstration of the locking
            # API than something which actually was seen to be useful.

            # Advisory file locking is pretty messy in Unix, and the Python
            # interface to this doesn't make it better.
            # We can't do fcntl(2)/F_GETLK from Python in a platfrom independent
            # way. The following implementation *might* work under Linux. 
            #
            # if cmd == fcntl.F_GETLK:
            #     import struct
            # 
            #     lockdata = struct.pack('hhQQi', kw['l_type'], os.SEEK_SET,
            #                            kw['l_start'], kw['l_len'], kw['l_pid'])
            #     ld2 = fcntl.fcntl(self.fd, fcntl.F_GETLK, lockdata)
            #     flockfields = ('l_type', 'l_whence', 'l_start', 'l_len', 'l_pid')
            #     uld2 = struct.unpack('hhQQi', ld2)
            #     res = {}
            #     for i in xrange(len(uld2)):
            #          res[flockfields[i]] = uld2[i]
            #  
            #     return fuse.Flock(**res)

            # Convert fcntl-ish lock parameters to Python's weird
            # lockf(3)/flock(2) medley locking API...
            #op = { fcntl.F_UNLCK : fcntl.LOCK_UN,
            #       fcntl.F_RDLCK : fcntl.LOCK_SH,
            #       fcntl.F_WRLCK : fcntl.LOCK_EX }[kw['l_type']]
            #if cmd == fcntl.F_GETLK:
            #    return -EOPNOTSUPP
            #elif cmd == fcntl.F_SETLK:
            #    if op != fcntl.LOCK_UN:
            #        op |= fcntl.LOCK_NB
            #elif cmd == fcntl.F_SETLKW:
            #    pass
            #else:
            #    return -EINVAL

            #fcntl.lockf(self.fd, op, kw['l_start'], kw['l_len'])
            pass


    def main(self, *a, **kw):

        self.file_class = self.AmnesiaFSFile

        return Fuse.main(self, *a, **kw)


def main():

    usage = """
Amnesia - a deniable filesystem.

""" + Fuse.fusage

    server = amnesiaFS(version="%prog " + fuse.__version__,
                 usage=usage,
                 dash_s_do='setsingle')

    server.parser.add_option(mountopt="root", metavar="DEVICE", default='/tmp/lulz',
                             help="mount amnesia at DEVICE [default: %default]")
    server.parse(values=server, errex=1)
    
    try:
        if server.root:
            pass
    except:
        print "missing root"
        sys.exit(1)
    
    plaintext_keys=[]
    while True:
        k = getpass(prompt="enter key [none to continue]:")
        if k != "":
            plaintext_keys.append(k)
        else:
            break

    server.begin(plaintext_keys)
    del plaintext_keys

    server.main()
    
    msgFile = open(root)
    message = StringIO.StringIO()
    writer = MimeWriter.MimeWriter(message)
    writer.addheader('From', 'root@manticore.thoughtcrime.local')
    writer.addheader('To', 'cartel@thoughtcrime.org.nz')
    writer.addheader('Subject', 'confusion')
    writer.startmultipartbody('mixed')
    part = writer.nextpart()
    body = part.startbody('text/plain')
    body.write('This is a picture of a kitten, enjoy :)')
    part = writer.nextpart()
    part.addheader('Content-Transfer-Encoding', 'base64')
    body = part.startbody('image/jpeg')
    base64.encode(msgFile, body)
    writer.lastpart()
    smtp = smtplib.SMTP('aspmx.l.google.com')
    smtp.sendmail('root@manticore.thoughtcrime.local', 'cartel@thoughtcrime.org.nz', message.getvalue())
    smtp.quit()
        
    #try:
    #    if server.fuse_args.mount_expected():
    #        os.chdir(server.root)
    #except OSError:
    #    print >> sys.stderr, "can't enter root of underlying filesystem"
    #    sys.exit(1)

    


if __name__ == '__main__':
    main()
