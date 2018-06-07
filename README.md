# pass-man

This is a project for me to tinker with various exploits.  It's a faux-password manger, which may one day evolve into a real one.

Please don't use this for real passswords right now.  pass-man is under rapid change, and I cannot guarantee anything about its real-world defenses against bad guys.

The scheme for passwords is based around PBKDF2 using SHA-512.  All passwords will be encrypted using AES-GCM-256 with the AEAD.
