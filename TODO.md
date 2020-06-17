# Vulnerabilities to add

## Sign in with Apple

<https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/>

## JWT expiry

Have an app not checking the expiry or valid after times.

## Cracking JWTs with Hashcat

Check hash mode 16500

<https://hashcat.net/wiki/doku.php?id=example_hashes>

Secret key here is "hello"

```
sudo hashcat -m 16500  -a 0   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ElsKKULlzGtesThefMuj2_a6KIY9L5i2zDrBLHV-e0M" /tmp/words
```
