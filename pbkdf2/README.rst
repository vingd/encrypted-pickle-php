=================
`PBKDF2 For PHP`_
=================

PBKDF2 (Password-Based Key Derivation Function) is a `key stretching`_ algorithm.
It can be used to hash passwords in a computationally intensive manner, so that
dictionary and brute-force attacks are less effective. See `CrackStation's
Hashing Security Article`_ for instructions on implementing salted password
hashing.

The following code is a PBKDF2 implementation in PHP. It is in the public
domain, so feel free to use it for any purpose whatsoever. It complies with the
`PBKDF2 test vectors in RFC 6070`_. Performance improvements to the original code
were provided by `variations-of-shadow.com`_.


.. _`PBKDF2 For PHP`: https://defuse.ca/php-pbkdf2.htm
.. _`key stretching`: http://en.wikipedia.org/wiki/Key_stretching
.. _`CrackStation's Hashing Security Article`: http://crackstation.net/hashing-security.htm
.. _`PBKDF2 test vectors in RFC 6070`: https://www.ietf.org/rfc/rfc6070.txt
.. _`variations-of-shadow.com`: http://www.variations-of-shadow.com/
