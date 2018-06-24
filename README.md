# pass-man

This is a project for me to tinker with various exploits.  It's a faux-password manger, which may one day evolve into a real one.

Please don't use this for real passswords right now.  pass-man is under rapid change, and I cannot guarantee anything about its real-world defenses against bad guys.

Each user has a 256bit secret which is encrypted using a key derived using PBKDF2-SHA512.  This secret is used into an HKDF-SHA256 with a unique salt, and additional info.

The secret, and passwords for each entry are stored encrypted using AES-256-GCM using the keys which are derived from the description above.
