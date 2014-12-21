import MillerRabin as mr
import SHA as sha
import random
import time

N = 640
K0 = K1 = 256
p = 0
q = 0
e = 0
n = 0
phiN = 0

def generateKey():
    global p, q, n, e, d, phiN
    start = time.time()
    p = mr.generateLargePrime(548)
    q = mr.generateLargePrime(548)

    n = p * q
    phiN = (p-1) * (q-1)
    e = random.randrange(3, phiN-1)
    while (gcd(e, phiN) != 1):
        e = random.randrange(2, phiN-1)
    d = modinv(e, phiN)
        
def gcd(x, y):
    while y!=0:
        (x,y) = (y, x % y)
    return x

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)
 
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
    	raise Exception("exception")
    return x % m

def encryptRSAWithOAEP(message):
    global K0,K1,N,e,n
    valueMessage = long(message, 16)
    r = random.randrange(1 << (K0-1), (1 << K0) - 1)
    keccak = sha.sha3_384(hex(r))
    Gr = long(keccak.hexdigest(), 16) # 384 bits
    X = (valueMessage << K1) ^ Gr
    keccak = sha.sha3_256(hex(X))
    Hx = long(keccak.hexdigest(), 16) # 256 bits
    Y = r ^ Hx
    res = (X << K0) + Y
    # RSA encryption
    encrypt = pow(res, e, n)
    return encrypt

def decryptRSAWithOAEP(encrypt):
    global K0,K1,N,d,n
    # RSA decryption
    encryptValue = pow(encrypt, d, n)
    
    Y = encryptValue % (1 << K0)
    X = encryptValue >> K0
    keccak = sha.sha3_256(hex(X))
    Hx = long(keccak.hexdigest(), 16) # 256 bits
    r = Y ^ Hx
    keccak = sha.sha3_384(hex(r))
    Gr = long(keccak.hexdigest(), 16) # 384 bits
    message = X ^ Gr
    message >>= K1
    return hex(message)

#Main

start = time.time()
generateKey()
message = "0x592fa743889fc7f92ac2a37bb1f5ba1dL"
encrypt = encryptOAEP(message)
decrypt = decryptOAEP(encrypt)
if (long(decrypt, 16) == long(message, 16)):
    print "Decrypt successful!!"
else:
    print "Error decryption!!"
print time.time()-start
