# kp
Go code capable of opening files encrypted with KeePass 2.x's kdbx file format.

This is not a complete library; it's some test code that works on some example files I created with the newest version of the official KeePass application, but I haven't tested it on a wider range of clients or with different versions of the official app. It is very likely that there are some file configurations which will not work. It can decrypt the container given the correct credentials, but it doesn't do any parsing of the XML inside the container. I'm not planning to continue work on this as I switched to a different password manager.

Resources used:
  * http://blog.sharedmemory.fr/en/2014/04/30/keepass-file-format-explained/
  * https://gist.github.com/msmuenchen/9318327
  * Perl's File::KeePass library
