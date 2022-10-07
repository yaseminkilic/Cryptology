
import sys

if sys.version_info >= (3, 0):
    def xrange(*args, **kwargs):
        return iter(range(*args, **kwargs))

Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]

SBoxSize = 4

Sbox_inv = [Sbox.index(x) for x in xrange(16)]

PBox = [0,  16,   32,  48,    1,  17,  33,  49,   2,  18,  34,  50,  3,   19,  35,  51,
        4,  20,   36,  52,    5,  21,  37,  53,   6,  22,  38,  54,  7,   23,  39,  55,
        8,  24,   40,  56,    9,  25,  41,  57,  10,  26,  42,  58, 11,   27,  43,  59,
        12, 28,   44,  60,    13, 29,  45,  61,  14,  30,  46,  62, 15,   31,  47,  63]
        
PBox_inv = [PBox.index(x) for x in xrange(len(PBox))]

class Present:
    def __init__(self, key, round):
        self.key = key
        self.rounds = 31
        self.roundkeys = self.GenerateRoundKeys(key, round)

    def GenerateRoundKeys(self, key, round): 
        roundKeyValues = []
        for i in range(1, round + 1): # for 1 ≤ i ≤ 31
            roundKeyValues.append((key & 0xFFFFFFFFFFFFFFFF0000) >> 16)
            artikKey = 0x7FFFF & key
            key = key >> 19
            key = key ^ (artikKey << 61)
            
            sonDortBit = key >> 76 & 0xF
            sonDortBit = self.GetSbox(sonDortBit)
            key  = key & 0x0FFFFFFFFFFFFFFFFFFF
            key = key ^ (sonDortBit << 76)
            key = key  ^ ((i) << 15)

        roundKeyValues.append((key & 0xFFFFFFFFFFFFFFFF0000) >> 16) 
        print("RoundKeyValues After GenerateRoundKeys: ", (roundKeyValues))
        return roundKeyValues 

    def GetSbox(self, index):
        return Sbox[index]

    def GetInverseSbox(self, index):
        return Sbox_inv[index]

    def GetPbox(self, index):
        return PBox[index]

    def GetInversePbox(self, index):
        return PBox_inv[index]

    def GetBlockSize(self):
        return 8

    def AddRoundKey(self, stateth, roundkey):
         # bj → bj ⊕ κi =>  round key Ki = κi=63..κ0 for 1 ≤ i ≤ 32, state b63...b0 for 0 ≤ j ≤ 63
        key = stateth ^ roundkey 
        print("Key After AddRoundKey: ", hex(key))
        return key

    def PermLayer(self, state):  #
        permutation = 0
        for i in xrange(64):
            permutation += ((state >> i) & 0x01) << self.GetPbox(i)
        print("Permutation After PermLayer: ", hex(permutation))
        return permutation

    def InvPermLayer(self, state):
        permutation = 0
        for i in xrange(64):
            permutation += ((state >> i) & 0x01) << self.GetInversePbox(i)
        print("Permutation After InvPermLayer: ", hex(permutation))
        return permutation

    def SBoxLayer(self, state):  
        # sixteen 4-bit words w15 ...w0 where wi = b4∗i+3||b4∗i+2||b4∗i+1||b4∗i for 0 ≤ i ≤ 15
        output = 0
        for i in xrange(16):
            sbox = self.GetSbox((state >> (i * 4)) & 0xF)
            output += sbox << (i * 4)
        print("State After SBoxLayer: ", hex(output))
        return output

    def InvSBoxLayer(self, state):
        output = 0
        for i in xrange(16):
            invSbox = self.GetInverseSbox(( state >> (i * 4)) & 0xF)
            output += invSbox << (i * 4)
        print("State After InvSBoxLayer: ", hex(output))
        return output

    def Encrypt(self, plaintext):
        state = plaintext
        i = 0
        
        print("------- Encrypt -------")
        print("Plaintext before Encrypt", hex(plaintext))
        print("\n")

        for i in xrange(self.rounds):
            currentRound = self.roundkeys[i]
            print("-> Round: ", i)
            state = self.AddRoundKey(state, currentRound)
            state = self.SBoxLayer(state)
            state = self.PermLayer(state)
            print("\n")

        subkey32 = self.roundkeys[-1]
        state = self.AddRoundKey(state, subkey32)
        print("\nCipherText after Encrypt", hex(state))
        return state

    def Decrypt(self, encryptedText):
        state = encryptedText

        print("\n------- Decrypt -------")
        print("CipherText before Decrypt", hex(encryptedText))
        print("\n")

        decipherRoundKey = self.roundkeys[-1]
        state = self.AddRoundKey(state, decipherRoundKey)

        for i in range(self.rounds-1,-1,-1):
            currentRound = self.roundkeys[i]
            print("-> Round: ", i)
            state = self.InvPermLayer(state)
            state = self.InvSBoxLayer(state)
            state = self.AddRoundKey(state, currentRound)
            print("\n")

        print("CipherText after Decrypt", hex(state))
        return state

if __name__ == '__main__':

    # key: 0x00000000000000000000 & plain: 0x0000000000000000 => ciphertext: 0x5579c1387b228445
    # key: 0x00000000000000000000 & plain: 0xFFFFFFFFFFFFFFFF => ciphertext: 0xa112ffc72f68417b
    # key: 0xFFFFFFFFFFFFFFFFFFFF & plain: 0x0000000000000000 => ciphertext: 0xe72c46c0f5945049
    # key: 0xFFFFFFFFFFFFFFFFFFFF & plain: 0xFFFFFFFFFFFFFFFF => ciphertext: 0x3333dcd3213210d2

    key = 0x00000000000000000000
    plain = 0x0000000000000000

    cipher = Present(key, 31)

    encryptedText = cipher.Encrypt(plain)
    decrypted = cipher.Decrypt(encryptedText)

    print ('\nPlaintext: ', hex(plain))
    print ('Key: ', hex(key))
    print("CipherText: " , hex(encryptedText))