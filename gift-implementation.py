
"""RC = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28, 0x10, 0x20]"""

Sbox = [1, 10, 4,12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14]
Sbox_inv = [13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5]

PBox = [
    0, 17, 34, 51, 48,  1, 18, 35, 32, 49,  2, 19, 16, 33, 50,  3,
    4, 21, 38, 55, 52,  5, 22, 39, 36, 53,  6, 23, 20, 37, 54,  7,
    8, 25, 42, 59, 56,  9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
    12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
]

PBox_inv = [
    0,  5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
    12,  1,  6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
    8, 13,  2,  7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
    4,  9, 14,  3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51
]

class Gift:

    def __init__(self, plain,blockSize, key, round, sboxSize):
        self.PlainState = self.Plain = plain
        self.KeyState = self.Key = key

        self.Round = round
        self.SboxSize = sboxSize
        self.BlockSize = blockSize

        # round constants
        self.RCONSTANT = 0X000000
        self.RConstants = [0 for rc in range(round)]

    def GetSbox(self, index):
        return Sbox[index]

    def GetInverseSbox(self, index):
        return Sbox_inv[index]

    def GetPBox(self, index):
        return PBox[index]

    def GetInversePbox(self, index):
        return PBox_inv[index]

    def GetSboxCount(self):  
        return int(self.BlockSize / self.SboxSize)

    def GetU(self, sboxIndex, keyState):
        return ((keyState >> (32*sboxIndex+16)) &0xFFFF)

    def GetV(self, sboxIndex, keyState):
        return ((keyState >> (32*sboxIndex)) &0xFFFF)

    def RotateLeft(self, x, n):
        return int(f"{x:016b}"[n:] + f"{x:016b}"[:n], 2)

    def RotateRight(self, x, n):
        return int(f"{x:016b}"[-n:] + f"{x:016b}"[:-n], 2)

    def SubCells(self):  
        output = 0  
        SboxCount  = self.GetSboxCount()
        for SboxIndex in range(SboxCount):
            output ^=  self.GetSbox((self.PlainState >> (self.SboxSize * SboxIndex)) & 0xF) << (self.SboxSize * SboxIndex)
        self.PlainState = output
        print("After SubCells: ", hex(output))
        return 

    def InvSubCells(self): 
        output = 0  
        SboxCount  = self.GetSboxCount()
        for SboxIndex in range(SboxCount):
            output ^=  self.GetInverseSbox((self.CipherState >> (self.SboxSize * SboxIndex)) & 0xF) << (self.SboxSize * SboxIndex)
        self.CipherState = output
        print("After InvSubCells: ", hex(output))
        return 

    def PermBits(self):    
        output = 0 
        for bit in range(blockSize):
            output ^=  (self.PlainState >> bit & 0x1) << self.GetPBox(bit)
        self.PlainState = output
        print("After PermBits: ", hex(output))
        return 

    def InvPermBits(self):  
        output = 0     
        for bit in range(blockSize):
            output ^=  (self.CipherState >> bit & 0x1) << self.GetInversePbox(bit)
        self.CipherState = output
        print("After InvPermBits: ", hex(output))
        return 

    def AddRoundKey(self, cState, keyState, round):
        state = cState
        SboxCount  = self.GetSboxCount()
        v = self.GetV(0, keyState)
        u = self.GetU(0, keyState)
        for sboxIndex in range(SboxCount):
            index4i = (self.SboxSize * sboxIndex)
            current = (((v>>sboxIndex)&0x1)<<index4i) 
            current ^= (((u>>sboxIndex)&0x1)<<(index4i+1))
            state ^= current
        cState = self.AddConstants(state, round)
        return cState
        
    def AddConstants(self, state, round):
        constantUpdated = 0
        constantUpdated ^= ((self.RConstants[round] & 0x1) << 3)
        constantUpdated ^= (((self.RConstants[round]>>1) & 0x1) << 7)
        constantUpdated ^= (((self.RConstants[round]>>2) & 0x1) << 11)
        constantUpdated ^= (((self.RConstants[round]>>3) & 0x1) << 15)
        constantUpdated ^= (((self.RConstants[round]>>4) & 0x1) << 19)
        constantUpdated ^= (((self.RConstants[round]>>5) & 0x1) << 23)
        constantUpdated ^= (1 << 63)
        state ^= constantUpdated
        return state

    def UpdateConstants(self, round):
        C5 = (self.RCONSTANT>>5) &0X1
        C4 = (self.RCONSTANT>>4) &0X1
        self.RCONSTANT = (self.RCONSTANT<<1) ^ (C5 ^ C4 ^ 1)
        self.RConstants[round] = self.RCONSTANT
        return

    def KeyScheduleRC(self, round):
        other = (self.KeyState>>32)&0x00000000FFFFFFFFFFFFFFFFFFFFFFFF
        
        u4bit =((self.KeyState>>16)&0xFFFF)
        u = self.RotateRight(u4bit, 2)<<16

        v4bit =(self.KeyState&0xFFFF)
        v = self.RotateRight(v4bit, 12)

        self.KeyState = ((u^v)<<(128-32)) ^ other
        print("Updated Round: ", round, " Key: ", hex(self.KeyState))
        return
    
    def InvKeyScheduleRC(self):
        roundKeyState = [0 for r in range(self.Round)]
        self.KeyState = self.Key
        for r in range(0, self.Round, 1):
            roundKeyState[r] = self.KeyState
            self.KeyScheduleRC(r)
        return roundKeyState

    def encrypt(self):
        print("\n--------------> Encrypt <--------------")
        for r in range(0, self.Round, 1):
            self.UpdateConstants(r)
            print("\n", r, ") Round:")
            self.SubCells()
            self.PermBits()
            self.PlainState = self.AddRoundKey(self.PlainState, self.KeyState, r)
            print("After AddRoundKey: ", hex(self.PlainState))
            self.KeyScheduleRC(r)

        print("Output text after encrypt: ", hex(self.PlainState))
        return self.PlainState
    
    def decrypt(self, encryptedtext):
        self.CipherState = encryptedtext

        print("\n--------------> Decrypt <--------------\n")
        roundKeyState = self.InvKeyScheduleRC()

        for r in range(self.Round-1, -1, -1):
            print("\n", r, ") Round:")
            self.CipherState = self.AddRoundKey(self.CipherState, roundKeyState[r], r)
            print("After InvAddRoundKey: ", hex(self.CipherState), " With KeyState: ", hex(roundKeyState[r]))
            self.InvPermBits()
            self.InvSubCells()
            
        print("Output text after decrypt: ", hex(self.CipherState))
        return self.CipherState

if __name__ == '__main__':

    # plaintext: 0X0000000000000000  => ciphertext: 0xf62bc3ef34f775ac
    # plaintext: 0Xfedcba9876543210  => ciphertext: 0xc1b71f66160ff587
    # plaintext: 0Xc450c7727a9b8a7d  => ciphertext: 0xe3272885fa94ba8b
    plaintext = 0X0000000000000000

    # key: 0X00000000000000000000000000000000 => plaintext: 0X0000000000000000
    # key: 0Xfedcba9876543210fedcba9876543210 => plaintext: 0Xfedcba9876543210
    # key: 0Xbd91731eb6bc2713a1f9f6ffc75044e7 => plaintext: 0Xc450c7727a9b8a7d
    key = 0X00000000000000000000000000000000 

    round = 28
    sboxSize = 4
    blockSize = 64
    
    print ('PlaintextInput: ', hex(plaintext))
    print ('KeyInput: ', hex(key))

    cipher = Gift(plaintext, blockSize, key, round, sboxSize)

    encryptedtext = cipher.encrypt()
    decrypted = cipher.decrypt(encryptedtext)

    print ('\nCiphertext: ', hex(encryptedtext))
    print ('Plaintext: ', hex(decrypted))
    print ('Key: ', hex(key))