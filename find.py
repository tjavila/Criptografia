from Crypto.PublicKey import RSA
keyencode = '''-----BEGIN PUBLIC KEY-----
MEwwDQYJKoZIhvcNAQEBBQADOwAwOAIxAL4dl00g/JEIYNa7xH9ItZSweBCmT7hn
p8Se/wY9P+lqZyoqpTqjNLEKJScjiKuIzwIDAQAB
-----END PUBLIC KEY-----'''
key = RSA.importKey(keyencode)
print (key.n) #displays n
print (key.e) #displays e
