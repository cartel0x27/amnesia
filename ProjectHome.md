**Amnesia** is a destructive deniable file system. By destructive, we mean it makes no attempt to safeguard your data. It is implemented in Python-FUSE.

Amnesia maintains multiple superblocks - one for each key that has been presented. If you present an entirely new key, an entirely new superblock will be allocated. This can overwrite existing data.

Amnesia was released in proof of concept form at Kiwicon 2007. Since then there have been a few major revisions.

See the wiki intro page for a quickstart.
