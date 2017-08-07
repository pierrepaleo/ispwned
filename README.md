# ispwned

## About

Many online password checkers give advice on how to generate a "strong password". 
However, regardless of measurements (entropy or other metrics), a good start is to check if your password has not been used before and released in the wild after a data breach. 

This is an off-line utility to determine if a password is in the "pwned passwords list" of the [Have I been pwned?](https://haveibeenpwned.com/Passwords) website. 
It can check among 320 millions password in less than a second.

To check your passwords, you should use off-line tools instead of web-based services, as any password you input might be logged !

## Usage

The checker is in the form of a Python script and can be run as

```python
python ispwned.py mypassword
```

Alternatively, you can provide another database file

```python
python ispwned.py --filename pwned-passwords-update-1.txt mypassword
```

## How does it work

The data provided by the [Have I been pwned?](https://haveibeenpwned.com/Passwords) website 
contains lists of SHA1 hashed passwords. 
The digests are sorted in ascending order.

   * The script first detects if the password is a SHA1 digest. If not, the password is SHA1 hashed.
   * A bisection search is performed to roughly estimate where the hash is in the database file.
   * Once the approximate location of the hash is found, a bunch of lines is read from the database. A hash table is built from this bunch of lines. The  final step checks whether the (hashed) password is in this hash table.

