# Vulnerabilities to add

## Sign in with Apple

<https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/>

## JWT expiry

Have an app not checking the expiry or valid after times.

## Cracking JWTs with Hashcat

Check hash mode 16500

<https://hashcat.net/wiki/doku.php?id=example_hashes>


All these use the following dictionary:

```
fish
test
robin
hello
abc
Ironman
```

Dictionary attack, key is "hello"

```
sudo hashcat -m 16500 -a 0 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ElsKKULlzGtesThefMuj2_a6KIY9L5i2zDrBLHV-e0M" /tmp/words
```

This uses a hybrid attack, key is "Ironman2020"

```
hashcat -m 16500 -a 6 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.4lEYUHUv5hb1wGS4VyfM-9jLlDQK9D1gMT-od8dj1VE" /tmp/words ?d?d?d?d
```

Dictionary with rules, key is "Hello"

```
hashcat -m 16500 -a 0 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ElsKKULlzGtesThefMuj2_a6KIY9L5i2zDrBLHV-e0M" /tmp/words -r /usr/share/hashcat/rules/d3ad0ne.rule
```
