# Electrum Mnemonic V2

Technically there is no recorded name for this algorithm, it is just known
that this has replaced the prior mnemonic implementation in Electrum.

The algorithm is derived based on inspection of the Electrum source code.

# Generation

Inputs:

 * number of bits for entropy: int (default 128)
 * prefix: bits[] (default to standard electrum seed prefix)
 * custom entropy: bigint (default 1)

Steps:
 0. Calculate number of bits that the custom entropy will take to store.
     * n = ceil(log2(custom_entropy))
 0. Calculate the number of bits that will be used by the prefix.
     * k = num_bits(prefix)
 0. Calculate the number of additional random bits required to have the expected total (but at least 16 bits).
     * n_added = max(16, k + entropy bits - n)
 0. Generate the additional random bits required as a value between 1 and 2^random-bits.
     * generated entropy = random bigint with n_added bits
 0. Set a nonce value at 0.
     * nonce = 0
 0. while the requirements have not been met:
     0. increment nonce value by 1.
         * nonce = nonce + 1
     0. calculate the final random value by multiplying in the custom entropy by the random bits+nonce
         * i = custom_entropy * (generated entropy + nonce)
     0. encode the value to a mnemonic sequence
         * seed = encode(i)
     0. check that the value is not a valid "legacy" one - if so, continue trying
         * if is_old_seed(seed) - fail
     0. check that the value has the requisite prefix
         * if is_new_seed(seed, prefix) return seed
