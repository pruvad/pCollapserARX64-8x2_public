cpdef int Rotate(int x, int r):  # Right rotate
    cdef int tmp
    tmp = (x << abs(8 - r)) & 0x00ff
    return (((x >> r) | tmp) & 0x00ff)

cpdef int funcARX(int t0, int t1, int t2, int t3, int t4, int t5, int t6, int t7, int temp_pdsboxArx, int internal_constARX):
    cdef int value_a1, value_b1, const_0, const_1, value_a2, value_b2, value_a3, value_b3, temp_pdsbox_After_ARX

    value_a1 = (temp_pdsboxArx & 0xff00) >> 8  # Reverse concatenation temp_pdsboxArx in value_a1
    value_b1 = temp_pdsboxArx & 0x00ff  # value_b1

    const_0 = (internal_constARX & 0xff00) >> 8  # Reverse concatenation internal_constARX in const_0
    const_1 = internal_constARX & 0x00ff  # const_1

    value_a2 = Rotate(int((((Rotate(value_a1, t0) ^ value_b1) + value_a1) % 255)), t2) ^ const_0
    value_b2 = Rotate(int((((Rotate(value_b1, t1) ^ value_a1) + value_b1) % 255)), t3) ^ const_1
    value_a3 = Rotate(int((((Rotate(value_a2, t4) ^ value_b2) + value_a2) % 255)), t6)
    value_b3 = Rotate(int((((Rotate(value_b2, t5) ^ value_a2) + value_b2) % 255)), t7)

    temp_pdsbox_After_ARX = (value_a3 << 8) + value_b3

    return temp_pdsbox_After_ARX

cpdef PDsboxARX64(int message, list state):  # state, gate_0v, cipher_v -- vectors [X0, X1, X2, X3] # return Unite output vector (UOV), [c0, gX0, gX1, gX2, gX3]

    # Unite output vector, [c0, gX0, gX1, gX2, gX3]
    cdef list UOV = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000]

    # Parameters of ARX-functions
    cdef list funcARX0 = [4, 8, 8, 4, 4, 8, 0, 0]  # [t0, t1, ..., t7] rotate operations
    cdef list funcARX1 = [4, 8, 4, 8, 8, 4, 4, 4]
    cdef list funcARX2 = [8, 4, 4, 8, 4, 8, 8, 8]
    cdef list funcARX3 = [8, 4, 8, 4, 8, 4, 12, 12]

    # Vector of constant for one PDsboxARX (16 bits)
    cdef list constARX = [0x00dd, 0x8e8a, 0x50cc, 0x2b05]  # const00...03 random generated

    # Vector of temporal value after XORing message and state[x]
    cdef list temp_pdsboxArx_v = [0x0000, 0x0000, 0x0000, 0x0000]  # temp_pdsboxArx0, temp_pdsboxArx1, # temp_pdsboxArx2, temp_pdsboxArx3

    # Vector of PDsboxARX output message (16 bits)
    cdef list y_v = [0x0000, 0x0000, 0x0000, 0x0000]  # y0, y1, y2, y3

    # XORing input message and statement
    temp_pdsboxArx_v[0] = message ^ state[0]
    temp_pdsboxArx_v[1] = message ^ state[1]
    temp_pdsboxArx_v[2] = message ^ state[2]
    temp_pdsboxArx_v[3] = message ^ state[3]

    y_v[0] = funcARX(funcARX0[0], funcARX0[1], funcARX0[2], funcARX0[3], funcARX0[4], funcARX0[5], funcARX0[6],
                          funcARX0[7], temp_pdsboxArx_v[0], constARX[0])
    y_v[1] = funcARX(funcARX1[0], funcARX1[1], funcARX1[2], funcARX1[3], funcARX1[4], funcARX1[5], funcARX1[6],
                          funcARX1[7], temp_pdsboxArx_v[1], constARX[1])
    y_v[2] = funcARX(funcARX2[0], funcARX2[1], funcARX2[2], funcARX2[3], funcARX2[4], funcARX2[5], funcARX2[6],
                          funcARX2[7], temp_pdsboxArx_v[2], constARX[2])
    y_v[3] = funcARX(funcARX3[0], funcARX3[1], funcARX3[2], funcARX3[3], funcARX3[4], funcARX3[5], funcARX3[6],
                          funcARX3[7], temp_pdsboxArx_v[3], constARX[3])

    UOV[0] = y_v[0] ^ y_v[1] ^ y_v[2] ^ y_v[3]  # Cipher-text, c0
    UOV[1] = y_v[0] ^ UOV[0]  # gX0
    UOV[2] = y_v[1] ^ UOV[0]  # gX1
    UOV[3] = y_v[2] ^ UOV[0]  # gX2
    UOV[4] = y_v[3] ^ UOV[0]  # gX3

    return UOV

cpdef round_pCollapserARX64(list URIV):  # URIV -- Unite round input vector
     # URIV = [0x0000, 0x0000, 0x0000, 0x0000,  # [0 - 3] [c0, c1, c2, c3] -- from past round or original message
     #        0x0000, 0x0000, 0x0000, 0x0000,  # [4 - 7] [g00, g01, g02, g03] -- in first round gXX equal sXX
     #        0x0000, 0x0000, 0x0000, 0x0000,  # [8 - 11] [g10, g11, g12, g13]
     #        0x0000, 0x0000, 0x0000, 0x0000,  # [12 - 15] [g20, g21, g22, g23]
     #        0x0000, 0x0000, 0x0000, 0x0000]  # [16 - 19] [g30, g31, g32, g33]

     cdef list TOV = [0x0000, 0x0000, 0x0000, 0x0000,  # [0 - 3] [c0, c1, c2, c3] -- from past round or original message
                      0x0000, 0x0000, 0x0000, 0x0000,  # [4 - 7] [g00, g01, g02, g03] -- in first round gXX equal sXX
                      0x0000, 0x0000, 0x0000, 0x0000,  # [8 - 11] [g10, g11, g12, g13]
                      0x0000, 0x0000, 0x0000, 0x0000,  # [12 - 15] [g20, g21, g22, g23]
                      0x0000, 0x0000, 0x0000, 0x0000]  # [16 - 19] [g30, g31, g32, g33]

     # Decollision vector(UROV): (256 bit) internal value for state building
     cdef list DV = [0x58eb, 0x9be5, 0x3f0d, 0x184e,  # [0 - 3] [d00, d01, d02, d03]
                     0x15db, 0x5e75, 0xf5ba, 0x3d0b,  # [4 - 7] [d10, d11, d12, d13]
                     0x673b, 0x2f2d, 0xa657, 0x2ba2,  # [8 - 11] [d20, d21, d22, d23]
                     0x8a4e, 0x675d, 0x248e, 0x3726]  # [12 - 15] [d30, d31, d32, d33]

     # Generation s00, ..., s33 PDsboxARX states for this round
     cdef list sXXstates = [0x0000, 0x0000, 0x0000, 0x0000,  # [0 - 3] [s00, s01, s02, s03]
                            0x0000, 0x0000, 0x0000, 0x0000,  # [4 - 7] [s10, s11, s12, s13]
                            0x0000, 0x0000, 0x0000, 0x0000,  # [8 - 11] [s20, s21, s22, s23]
                            0x0000, 0x0000, 0x0000, 0x0000]  # [12 - 15] [s30, s31, s32, s33]

     # for PDsboxARX64_0
     sXXstates[0] = ((URIV[4] ^ URIV[9] ^ URIV[14] ^ URIV[19]) ^ URIV[4]) ^ DV[0]  # s00 = ((g00 ^ g11 ^ g22 ^ g33) ^ g00) ^ d00
     sXXstates[1] = ((URIV[5] ^ URIV[10] ^ URIV[15] ^ URIV[16]) ^ URIV[5]) ^ DV[1]  # s01 = ((g01 ^ g12 ^ g23 ^ g30) ^ g01) ^ d01
     sXXstates[2] = ((URIV[6] ^ URIV[11] ^ URIV[12] ^ URIV[17]) ^ URIV[6]) ^ DV[2]  # s02 = ((g02 ^ g13 ^ g20 ^ g31) ^ g02) ^ d02
     sXXstates[3] = ((URIV[7] ^ URIV[8] ^ URIV[13] ^ URIV[18]) ^ URIV[7]) ^ DV[3]  # s03 = ((g03 ^ g10 ^ g21 ^ g32) ^ g03) ^ d03

     # for PDsboxARX64_1
     sXXstates[4] = ((URIV[4] ^ URIV[9] ^ URIV[14] ^ URIV[19]) ^ URIV[14]) ^ DV[4]  # s10 = ((g00 ^ g11 ^ g22 ^ g33) ^ g22) ^ d10
     sXXstates[5] = ((URIV[5] ^ URIV[10] ^ URIV[15] ^ URIV[16]) ^ URIV[15]) ^ DV[5]  # s11 = ((g01 ^ g12 ^ g23 ^ g30) ^ g23) ^ d11
     sXXstates[6] = ((URIV[6] ^ URIV[11] ^ URIV[12] ^ URIV[17]) ^ URIV[12]) ^ DV[6]  # s12 = ((g02 ^ g13 ^ g20 ^ g31) ^ g20) ^ d12
     sXXstates[7] = ((URIV[7] ^ URIV[8] ^ URIV[13] ^ URIV[18]) ^ URIV[13]) ^ DV[7]  # s13 = ((g03 ^ g10 ^ g21 ^ g32) ^ g21) ^ d13

     # for PDsboxARX64_2
     sXXstates[8] = ((URIV[4] ^ URIV[9] ^ URIV[14] ^ URIV[19]) ^ URIV[9]) ^ DV[8]  # s20 = ((g00 ^ g11 ^ g22 ^ g33) ^ g11) ^ d20
     sXXstates[9] = ((URIV[5] ^ URIV[10] ^ URIV[15] ^ URIV[16]) ^ URIV[10]) ^ DV[9]  # s21 = ((g01 ^ g12 ^ g23 ^ g30) ^ g12) ^ d21
     sXXstates[10] = ((URIV[6] ^ URIV[11] ^ URIV[12] ^ URIV[17]) ^ URIV[11]) ^ DV[10]  # s22 = ((g02 ^ g13 ^ g20 ^ g31) ^ g13) ^ d22
     sXXstates[11] = ((URIV[7] ^ URIV[8] ^ URIV[13] ^ URIV[18]) ^ URIV[8]) ^ DV[11]  # s23 = ((g03 ^ g10 ^ g21 ^ g32) ^ g10) ^ d23

     # for PDsboxARX64_3
     sXXstates[12] = ((URIV[4] ^ URIV[9] ^ URIV[14] ^ URIV[19]) ^ URIV[19]) ^ DV[12]  # s30 = ((g00 ^ g11 ^ g22 ^ g33) ^ g33) ^ d30
     sXXstates[13] = ((URIV[5] ^ URIV[10] ^ URIV[15] ^ URIV[16]) ^ URIV[16]) ^ DV[13]  # s31 = ((g01 ^ g12 ^ g23 ^ g30) ^ g30) ^ d31
     sXXstates[14] = ((URIV[6] ^ URIV[11] ^ URIV[12] ^ URIV[17]) ^ URIV[17]) ^ DV[14]  # s32 = ((g02 ^ g13 ^ g20 ^ g31) ^ g31) ^ d32
     sXXstates[15] = ((URIV[7] ^ URIV[8] ^ URIV[13] ^ URIV[18]) ^ URIV[18]) ^ DV[15]  # s33 = ((g03 ^ g10 ^ g21 ^ g32) ^ g32) ^ d33

     # Unite round output vector(UROV): [c0, c1, c2, c3, g00 ... g33]
     cdef list UROV = [0x0000, 0x0000, 0x0000, 0x0000,  # [0 - 3] [c0, c1, c2, c3]
                       0x0000, 0x0000, 0x0000, 0x0000,  # [4 - 7] [g00, g01, g02, g03]
                       0x0000, 0x0000, 0x0000, 0x0000,  # [8 - 11] [g10, g11, g12, g13]
                       0x0000, 0x0000, 0x0000, 0x0000,  # [12 - 15] [g20, g21, g22, g23]
                       0x0000, 0x0000, 0x0000, 0x0000]  # [16 - 19] [g30, g31, g32, g33]

     # First PDsboxARX64
     TOV = PDsboxARX64(URIV[0], sXXstates[0:4])  # Slicing start : stop-1 #TOV = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000] # Temporal output vector [cX, gX0, gX1, gX2, gX3]
     UROV[0] = TOV[0]  # c0
     UROV[4:8] = TOV[1:5]  # g00, g01, g02, g03

     # Second PDsboxARX64
     TOV = PDsboxARX64(URIV[1], sXXstates[4:8])
     UROV[1] = TOV[0]  # c1
     UROV[8:12] = TOV[1:5]  # g10, g11, g12, g13

     # Third PDsboxARX64
     TOV = PDsboxARX64(URIV[2], sXXstates[8:12])
     UROV[2] = TOV[0]  # c2
     UROV[12:16] = TOV[1:5]  # g20, g21, g22, g23

     # Fourth PDsboxARX64
     TOV = PDsboxARX64(URIV[3], sXXstates[12:16])
     UROV[3] = TOV[0]  # c2
     UROV[16:20] = TOV[1:5]  # g20, g21, g22, g23

     return UROV
