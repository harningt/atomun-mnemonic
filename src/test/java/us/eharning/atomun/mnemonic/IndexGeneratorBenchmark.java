/*
 * Copyright 2014, 2015 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.eharning.atomun.mnemonic;

import com.google.common.base.Preconditions;
import com.tomgibara.crinch.bits.BitReader;
import com.tomgibara.crinch.bits.ByteArrayBitReader;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Random;

/**
 * Benchmark tool for mnemonic index generation methods (aligned 11-bit reading).
 */
class IndexGeneratorBenchmark {
    private static final byte[] INPUT = new byte[128 / 8];
    private static final byte[] CHECKSUM = new byte[256 / 8];
    static {
        Random RNG = new Random(0x1234);
        RNG.nextBytes(INPUT);
        RNG.nextBytes(CHECKSUM);        
    }
    
    public int bigIntegerMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            byte[] entropy = INPUT;
            byte[] checksum = Arrays.copyOf(CHECKSUM, CHECKSUM.length);
            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int mnemonicSentenceLength = (entropyBitCount + checksumBitCount) / 11;

            BigInteger entropyBytes = new BigInteger(1, entropy);
            BigInteger checksumBytes = new BigInteger(1, checksum);

            /* We need only 'first' checksumBitCount from the full checksumBytes,
             * so we need to shift to the right checksum.length * 8 - bits
             */

            checksumBytes = checksumBytes.shiftRight(checksum.length * 8 - checksumBitCount);

            /* We need to 'tack on' the checksumBitCount to the right of the entropyBytes.
             * Shift the entropyBytes to the left checksumBitCount and 'or' the values.
             */

            BigInteger sentenceSource = entropyBytes.shiftLeft(checksumBitCount).or(checksumBytes);

            int[] indexValues = new int[mnemonicSentenceLength];
            for (int i = 0; i < mnemonicSentenceLength; i++) {
                /* Extract the 11-bit chunks out (in reverse order due to shifting optimization) */
                int index = sentenceSource.intValue() & ((1 << 11) - 1);
                indexValues[mnemonicSentenceLength - i - 1] = index;
                sentenceSource = sentenceSource.shiftRight(11);
            }
            dummy += indexValues[0];
        }
        return dummy;
    }

    /* Very very specialized, could use array input, but nope */
    private static BitSet bytesToBitSet(int totalBits, byte[] entropy, byte[] checksum) {
        Preconditions.checkNotNull(entropy);
        Preconditions.checkNotNull(checksum);
        Preconditions.checkArgument(totalBits > 0 && totalBits <= (entropy.length * 8 + checksum.length * 8));

        BitSet bits = new BitSet(totalBits);
        int checksumOffset = entropy.length * 8;
        int checksumLength = totalBits - checksumOffset;
        for (int i = 0; i < entropy.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                if ((entropy[i] & (1 << (7 - j))) != 0) {
                    bits.set((i * 8) + j);
                }
            }
        }

        for (int i = 0; i < checksum.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                int index = i * 8 + j;
                if (index >= checksumLength) {
                    return bits;
                }
                if ((checksum[i] & (1 << (7 - j))) != 0) {
                    bits.set(index + checksumOffset);
                }
            }
        }
        return bits;
    }

    public int bitsetMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            byte[] entropy = INPUT;
            byte[] checksum = Arrays.copyOf(CHECKSUM, CHECKSUM.length);
            
            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int mnemonicSentenceLength = (entropyBitCount + checksumBitCount) / 11;

            BitSet entropyBits = bytesToBitSet(entropyBitCount + checksumBitCount, entropy, checksum);

            /* Take each group of 11 bits and convert to an integer
             * that will be used to index into the word list.
             */

            int[] indexValues = new int[mnemonicSentenceLength];
            for (int i = 0; i < mnemonicSentenceLength; ++i) {
                int index = 0;
                for (int j = 0; j < 11; ++j) {
                    index <<= 1;
                    if (entropyBits.get((i * 11) + j)) {
                        index |= 0x1;
                    }
                }
                indexValues[i] = index;
            }
            dummy += indexValues[0];
        }
        return dummy;
    }

    private static boolean[] bytesToBits(byte[] data) {
        Preconditions.checkNotNull(data);
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
            }
        }
        return bits;
    }
    @Nonnull
    private static boolean[] bytesToBits(int totalBits, @Nonnull byte[] data) {
        Preconditions.checkNotNull(data);
        Preconditions.checkArgument(totalBits > 0 && totalBits <= data.length * 8);
        boolean[] bits = new boolean[totalBits];
        int offset = 0;
        for (int i = 0; i < data.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                bits[offset] = (data[i] & (1 << (7 - j))) != 0;
                offset++;
                if (offset >= totalBits) {
                    return bits;
                }
            }
        }
        return bits;
    }

    int joinedBooleanMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            byte[] entropy = INPUT;
            byte[] joined = new byte[entropy.length + 256 / 8];
            System.arraycopy(entropy, 0, joined, 0, entropy.length);
            System.arraycopy(CHECKSUM, 0, joined, entropy.length, CHECKSUM.length);

            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int mnemonicSentenceLength = (entropyBitCount + checksumBitCount) / 11;

            boolean[] concatBits = bytesToBits(entropyBitCount + checksumBitCount, joined);

            /* Take each group of 11 bits and convert to an integer
             * that will be used to index into the word list.
             */

            int[] indexValues = new int[mnemonicSentenceLength];
            for (int i = 0; i < mnemonicSentenceLength; ++i) {
                int index = 0;
                for (int j = 0; j < 11; ++j) {
                    index <<= 1;
                    if (concatBits[(i * 11) + j]) {
                        index |= 0x1;
                    }
                }
                indexValues[i] = index;
            }
            dummy += indexValues[0];
        }
        return dummy;
    }

    public int crinchBitReaderMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            byte[] entropy = INPUT;
            byte[] joined = new byte[entropy.length + 256 / 8];
            System.arraycopy(entropy, 0, joined, 0, entropy.length);
            System.arraycopy(CHECKSUM, 0, joined, entropy.length, CHECKSUM.length);

            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int totalBitCount = entropyBitCount + checksumBitCount;
            int mnemonicSentenceLength = totalBitCount / 11;

            BitReader bitReader = new ByteArrayBitReader(joined);

            int[] indexValues = new int[mnemonicSentenceLength];
            for (int i = 0; i < mnemonicSentenceLength; i++) {
                int index = bitReader.read(11);
                indexValues[i] = index;
            }
            
            dummy += indexValues[0];
        }
        return dummy;
    }

    public static void main(String[] args) {
        new IndexGeneratorBenchmark().run();
    }

    private void run() {
        long start, elapsed;
        int ret;
        int COUNT = 1000000;
        ret = bigIntegerMethod(COUNT);
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();

        start = System.currentTimeMillis();
        ret = bigIntegerMethod(COUNT);
        elapsed = System.currentTimeMillis() - start;
        System.out.println("bigIntegerMethod" + " Took " + elapsed + " -- " + ret);

        ret = bitsetMethod(COUNT);
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();

        start = System.currentTimeMillis();
        ret = bitsetMethod(COUNT);
        elapsed = System.currentTimeMillis() - start;
        System.out.println("bitsetMethod" + " Took " + elapsed + " -- " + ret);

        ret = joinedBooleanMethod(COUNT);
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();

        start = System.currentTimeMillis();
        ret = joinedBooleanMethod(COUNT);
        elapsed = System.currentTimeMillis() - start;
        System.out.println("joinedBooleanMethod" + " Took " + elapsed + " -- " + ret);

        ret = crinchBitReaderMethod(COUNT);
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();

        start = System.currentTimeMillis();
        ret = crinchBitReaderMethod(COUNT);
        elapsed = System.currentTimeMillis() - start;
        System.out.println("crinchBitReaderMethod" + " Took " + elapsed + " -- " + ret);
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();
    }
}
