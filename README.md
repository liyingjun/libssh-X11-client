libssh-X11-client
=================

This is a simple example of SSH X11 client using libssh.

Features:

- Support local display (e.g. :0)
- Support remote display (e.g. localhost:10.0).
- Using callbacks and event polling to significantly reduce CPU utilization.
- Use X11 forwarding with authentication spoofing (like openssh)

Note:

- Part of this code was inspired by openssh's one.

Dependencies
------------

- gcc >= 7.5.0
- libssh >= 0.8.0
- libssh-dev >= 0.8.0

To Build
--------

```
gcc -o ssh ssh.c -lssh -g
```

Authors
-------

[Marco Fortina](https://gitlab.com/marco.fortina)

Donations
---------

If you liked this work and wish to support the developer please donate to:

- Bitcoin: 1N2rQimKbeUQA8N2LU5vGopYQJmZsBM2d6

