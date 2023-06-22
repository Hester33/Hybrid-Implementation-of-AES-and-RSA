import secrets
import random
import sys
from Crypto.Cipher import AES
from Crypto import Random

#Public Key: e
#Private Key: d

#This is the Euclidean's extended algorithm
def multiplicativeInverse(a,b):
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a
    ob = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob
    if ly < 0:
        ly += oa
    return lx

#Eucclid's algorithm:
def gcd(a,b):
    while b != 0:
        temp = a%b
        a=b
        b=temp
    return a

#Miller Rabin Algo:
def millerRabin(n, k = 7):
    if n < 6:
        return[False,False,True,True,False,True][n]
    elif n & 1 == 0:
        return False
    else:
        s, d = 0,n - 1
        while d & 1 == 0:
            s, d= s+1, d>>1
        for a in random.sample(range(2,min(n-2,sys.maxsize), min(n-4,k))):
            x = pow(a,d,n)
            if x != 1 and x + 1 != n:
                for r in range(1,s):
                    x = pow(x,2,n)
                    if x == 1:
                        return False
                    elif x == n - 1:
                        a=0
                        break
                if a:
                    return False
            return True

#This function is used to check if a number is a prime number
def isPrime(n):
    low = [2,3, 5, 7, 11, 13, 17, 19, 23 ,29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
           97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
           193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
           307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
           421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
           547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653,
           659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 743, 751, 757, 761, 769, 773,
           787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
           919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if n in low:
        return True
    if (n < 2):
        return False
    for prime in low:
        if (n % prime == 0):
            return False
    return millerRabin()

#Generates a random prime number
def generatePrime(keysize): 
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num

#Creates two keys, private and public. The private key is used to encrypt the public key which is used to encrypt the plaintext.
def KeyGeneration(s=8):
    #Generate 2 large random primes p,q of the same size
    p = generatePrime(s)
    q = generatePrime(s)
    # Ensure p and q are distinct
    while p == q:
        q = generatePrime(s)

    #This should only happen if the generatePrime function fails:
    if not (isPrime(p) and isPrime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #Compute n=pq and phi=(p-1)(q-1)
    n=p*q
    phi=(p-1)*(q-1)
    #Select e: such that (1<e<phi) and gcd(e,phi)=1
    e = random.randrange(1, phi)
    g = gcd(e,phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    #Generate d: such that (1<d<phi) and e.d=1(mod phi)
    d = multiplicativeInverse(e, phi)
    #Return public and private keys
    #(e, n) = public key
    #(d, n) = private key
    return ((e,n), (d,n))

#Encryption function using public key
def encrypt(publicKey, plaintext):
    #Get (e, n)
    e,n = publicKey
    cipher =[(ord(char)**e)%n for char in plaintext]
    return cipher

#Decryption function using private key
def decrypt(privatekey, ciphertext):
    d,n = privatekey
    m = [chr((char**d)%n) for char in ciphertext]
    return m

# We are using PyCryptodome Library for AES Encrytion and Decryption Algorithms
def encryptAES(cipherAES, plainText):
    return cipherAES.encrypt(plainText.encode("utf-8"))

def decryptAES(cipherAES, cipherText):
    return cipherAES.decrypt(cipherText).decode("utf-8")

def main():
    '''Encryption: '''
    print('==============================================================')
    print('==============================================================')
    print('Encryption and Decrytion by using both AES and RSA.')
    print('==============================================================')
    print('==============================================================')
    
    #First, generate the public and private keys:
    print('Creating Keys using KeyGeneration()... ')
    publicKey, privateKey = KeyGeneration()
    print('\nPublic key (e, n) = ', publicKey)
    print('Private key (d, n) = ', privateKey)
    print('==============================================================')
    
    #Create a new symmetric key
    print("Creating random new symmetric key using PyCryptodome...")
    key = secrets.token_hex(16)
    print("AES Symmetric Key")
    print(key)
    AESKey=key.encode('utf-8')


    #Encrypt the message using the symmetric key:
    print("==============================================================")
    plainText = input("\nEnter the plaintext message to be encrypted here: ")

    cipherAES = AES.new(AESKey,AES.MODE_GCM)
    nonce = cipherAES.nonce
    print("\n==============================================================")

    print("\nEncrypting the message with AES...")
    cipherText=encryptAES(cipherAES,plainText)
    print("AES cipher text: ")
    print(cipherText)

    #Next we encrypt the AES symmetric key, using RSA
    cipherKey=encrypt(publicKey,key)
    print("\nEncrypting the AES symmetric key using RSA...")
    print("Encrypted AES symmetric key: ", cipherKey)

    #Both the public and private key are saved and needed for encryption.
    print("===============================================================")
    print("Encryption Complete. \nDecryption Starting now...")
    print("===============================================================")

    '''Decryption: '''
    #The first step to decrypt the text is to first decrypt the symmetric key using the private key.
    decryptedKey=''.join(decrypt(privateKey, cipherKey))
    print("Decrypting the AES Symmetric Key using the cipherKey and private key...")
    print("AES Symmetric Key: ", decryptedKey)

    #We can then use this decrypted key in order to decrypt the ciphertext messsage.
    decryptedK=decryptedKey.encode('utf-8')
    cipherAESd=AES.new(decryptedK, AES.MODE_GCM, nonce=nonce)
    FinalMessage=decryptAES(cipherAESd, cipherText)
    print('Decrypting the message using the AES symmetric key...... ')
    print('Original Plaintext message', FinalMessage)


if __name__ == "__main__":
    main()
    
