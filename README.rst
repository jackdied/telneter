telneter
===

A pure-python library for parsing telnet streams.

Work In Progress, that aims to be `sansio <https://github.com/brettcannon/sans-io>`_
compatible. That is, it does all the parsing and state keeping needed for compliance
with RFC 854 (and beyond!) but doesn't even know what a file or socket is -- that's your job.

History: I wrote a telnet layer for `Lyntin <http://lyntin.sourceforge.net/>`_ (Will Khan-Green's client) in the early 2000s. Some of the tests for that ended up in the python stdlib but the python stdlib module 'telnetlib' is so complicated and patched and people who actually do use it rely on so many of those quirks that I never tried to replace it wholesale. A previous version of that [dead] work is still on the web for the `Leanlyn <http://bit.ly/leanlyn` client [which is also dead].

For a full list of RFCs involved with telnet and the python stdlib see an old blogpost of mine from 2009 `fixing telnetlib <http://jackdied.blogspot.com/2009/04/fixing-telnetlib.html>`_
