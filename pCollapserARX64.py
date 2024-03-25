#
# Trivial implementation of pCollapserARX64-8x2
#
# Key features of the algorithm:
# block size: 64-bits (in 4 16-bits words)
# word size: 16-bits
# nr. of rounds: 4
# nr. of words: 4
# nr. of rows: 4
# key size: 64-bits
# control state: 256-bits
#
# Written by Vadim Prudnikov (2024)
# Release under the terms of the MIT license

def expandedKey(self, MKaSV):  # Master-Key and state vector [64 + 256 bit]
    # [0 - 3] [m0, m1, m2, m3] -- from past round or original message or master key
    # [4 - 7] [s00, s01, s02, s03] -- in first round gXX equal sXX
    # [8 - 11] [s10, s11, s12, s13]
    # [12 - 15] [s20, s21, s22, s23]
    # [16 - 19] [s30, s31, s32, s33]

    # temp_MKaSV = [0x0000, 0x0000, 0x0000, 0x0000,  # [0 - 3] [m0, m1, m2, m3] -- from past round or original message or master key
    #              0x0000, 0x0000, 0x0000, 0x0000,  # [4 - 7] [s00, s01, s02, s03] -- in first round gXX equal sXX
    #              0x0000, 0x0000, 0x0000, 0x0000,  # [8 - 11] [s10, s11, s12, s13]
    #              0x0000, 0x0000, 0x0000, 0x0000,  # [12 - 15] [s20, s21, s22, s23]
    #              0x0000, 0x0000, 0x0000, 0x0000]  # [16 - 19] [s30, s31, s32, s33]

    temp_MKaSV = round_pCollapserARX64(MKaSV)  # 1 round
    temp_MKaSV = round_pCollapserARX64(temp_MKaSV)  # 2 round
    temp_MKaSV = round_pCollapserARX64(temp_MKaSV)  # 3 round
    temp_IV = temp_MKaSV[0:4]  # temp_IV = [0x0000, 0x0000, 0x0000, 0x0000] # Right part of IV, in the future ^_^
    temp_MKaSV = round_pCollapserARX64(temp_MKaSV)  # 4 round

    IV = temp_MKaSV[0:4]  # IV = [0x0000, 0x0000, 0x0000, 0x0000] # Ready expanded-key 64 + 64 bit <- in the future ^_^

    IV = IV + temp_IV  # Very ready expanded-key

    return IV

def encrypt_pCollapserARX64(self, m64bit):  # m64bit = [0x0000, 0x0000, 0x0000, 0x0000] 64 bit # masterKey = [0x0000, 0x0000, 0x0000, 0x0000] 64 bit

    global IV_generated
    global temp_masterKey
    global masterKey

    # temp_masterKey[0:4] = masterKey

    # IV_generated = self.expandedKey(temp_masterKey) # Expanded-key generated [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]

    # temp_masterKey[0:4] = m64bit ^ IV_generated[4:8] # -- non-realized
    temp_masterKey[0] = m64bit[0] ^ IV_generated[4]
    temp_masterKey[1] = m64bit[1] ^ IV_generated[5]
    temp_masterKey[2] = m64bit[2] ^ IV_generated[6]
    temp_masterKey[3] = m64bit[3] ^ IV_generated[7]

    temp_masterKey = round_pCollapserARX64(temp_masterKey)  # 1 round

    temp_masterKey[4] = temp_masterKey[4] ^ m64bit[0]  # Mixing states with message, s00 ^ m0
    temp_masterKey[8] = temp_masterKey[8] ^ m64bit[1]  # Mixing states with message, s10 ^ m0
    temp_masterKey[12] = temp_masterKey[12] ^ m64bit[2]  # Mixing states with message, s20 ^ m0
    temp_masterKey[16] = temp_masterKey[16] ^ m64bit[3]  # Mixing states with message, s30 ^ m0

    temp_masterKey[5] = temp_masterKey[5] ^ IV_generated[0]  # Mixing states with left part of expanded-key, s01 ^ iv0
    temp_masterKey[9] = temp_masterKey[9] ^ IV_generated[1]  # Mixing states with left part of expanded-key, s11 ^ iv1
    temp_masterKey[13] = temp_masterKey[13] ^ IV_generated[2]  # Mixing states with left part of expanded-key, s21 ^ iv2
    temp_masterKey[17] = temp_masterKey[17] ^ IV_generated[3]  # Mixing states with left part of expanded-key, s31 ^ iv3

    temp_masterKey = round_pCollapserARX64(temp_masterKey)  # 2 round
    temp_masterKey = round_pCollapserARX64(temp_masterKey)  # 3 round
    temp_masterKey = round_pCollapserARX64(temp_masterKey)  # 4 round

    cipherText64bit = temp_masterKey[0:4]  # Ready ciphertext #cipherText64bit = [0x0000, 0x0000, 0x0000, 0x0000]

    return cipherText64bit

def adapted_pCollapserARX64(self, in_plainText):

    temp_in_words = [0x0000, 0x0000, 0x0000, 0x0000]
    temp_masterKey = [0x0000, 0x0000, 0x0000, 0x0000]
    out_cipherText = [0x00000000, 0x00000000]

    # Rebuilding two 32-bit words in four 16-bit
    temp_in_words[0] = (in_plainText[0] & 0xffff0000) >> 16  # Reverse concatenation
    temp_in_words[1] = in_plainText[0] & 0x0000ffff
    temp_in_words[2] = (in_plainText[1] & 0xffff0000) >> 16  # Reverse concatenation
    temp_in_words[3] = in_plainText[1] & 0x0000ffff

    # Тут может быть (ваш)мой криптоалгоритм
    temp_out_words = self.encrypt_pCollapserARX64(temp_in_words)

    # Rebuilding four 16-bit words in two 32-bit
    out_cipherText[0] = (temp_out_words[0] << 16) + temp_out_words[1]
    out_cipherText[1] = (temp_out_words[2] << 16) + temp_out_words[3]

    return out_cipherText
