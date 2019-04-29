def plus(x, y):
    return (x + y) & 0xffffffff


def lrotate(x, n):
    l = (x << n) & 0xffffffff
    r = (x >> (32-n)) & 0xffffffff
    return l + r


def QuarterRound(a, b, c, d):
    a = plus(a, b); d ^= a; d = lrotate(d, 16)
    c = plus(c, d); b ^= c; b = lrotate(b, 12)
    a = plus(a, b); d ^= a; d = lrotate(d, 8)
    c = plus(c, d); b ^= c; b = lrotate(b, 7)
    return a, b, c, d


def chacha20(key, nonce, cnt=0):
    """
        const : 4 [byte] * 4 [block]
        key   : 4 [byte] * 8 [block]
        nonce : 4 [byte] * 3 [block]
        count : 4 [byte] * 1 [block]

        TOTAL : 4 [byte] * 16 [block]
    """

    '''
    The ChaCha20 state is initialized as follows:

   o  The first four words (0-3) are constants: 0x61707865, 0x3320646e,
      0x79622d32, 0x6b206574.

   o  The next eight words (4-11) are taken from the 256-bit key by
      reading the bytes in little-endian order, in 4-byte chunks.

   o  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
      word is enough for 256 gigabytes of data.

   o  Words 13-15 are a nonce, which MUST not be repeated for the same
      key.  The 13th word is the first 32 bits of the input nonce taken
      as a little-endian integer, while the 15th word is the last 32
      bits.

       cccccccc  cccccccc  cccccccc  cccccccc
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

   c=constant k=key b=blockcount n=nonce

   ChaCha20 runs 20 rounds, alternating between "column rounds" and
   "diagonal rounds".  Each round consists of four quarter-rounds, and
   they are run as follows.  Quarter rounds 1-4 are part of a "column"
   round, while 5-8 are part of a "diagonal" round:

      QUARTERROUND(0, 4, 8, 12)
      QUARTERROUND(1, 5, 9, 13)
      QUARTERROUND(2, 6, 10, 14)
      QUARTERROUND(3, 7, 11, 15)
      QUARTERROUND(0, 5, 10, 15)
      QUARTERROUND(1, 6, 11, 12)
      QUARTERROUND(2, 7, 8, 13)
      QUARTERROUND(3, 4, 9, 14)

   At the end of 20 rounds (or 10 iterations of the above list), we add
   the original input words to the output words, and serialize the
   result by sequencing the words one-by-one in little-endian order.

   Note: "addition" in the above paragraph is done modulo 2^32.  In some
   machine languages, this is called carryless addition on a 32-bit
   word.
    '''
    ## initialize ##
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    count = [0 + cnt]
    state = const + key + count + nonce
    state_orig = list(state)

    for _ in range(10):
        # Columns
        state[0], state[4], state[8], state[12] = QuarterRound(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = QuarterRound(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = QuarterRound(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = QuarterRound(state[3], state[7], state[11], state[15])

        # Diagonal
        state[0], state[5], state[10], state[15] = QuarterRound(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = QuarterRound(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = QuarterRound(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = QuarterRound(state[3], state[4], state[9], state[14])

    state = list(map(lambda x: plus(x[0], x[1]), zip(state, state_orig)))
    return state