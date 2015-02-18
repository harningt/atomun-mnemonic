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
package us.eharning.atomun.mnemonic.spi.bip0039;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteSource;
import com.google.common.primitives.UnsignedInteger;
import com.tomgibara.crinch.bits.BitReader;
import com.tomgibara.crinch.bits.BitVector;
import com.tomgibara.crinch.bits.ByteArrayBitReader;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Set;

/**
 * Collection of tested mnemonic index generator implementations to use.
 *
 * Thanks to the BitcoinJ project for inspiration of the boolean-array based encoder.
 */
class BIP0039MnemonicIndexGenerators {
    final static BIP0039MnemonicIndexGenerator OPTIMAL_GENERATOR = new JoinedBooleanGenerator();
    @SuppressWarnings("unused")
    final static Set<BIP0039MnemonicIndexGenerator> GENERATORS = ImmutableSet.<BIP0039MnemonicIndexGenerator>of(
            new BigIntegerProcessor(),
            new BitSetGenerator(),
            new BooleanGenerator(),
            new JoinedBooleanGenerator(),
            new JoinedDigestBooleanGenerator(),
            new CrinchBitReaderProcessor()
    );
    public static void main(String[] params) {
        byte[] entropy = BIP0039MnemonicUtility.sha256digest(new byte[0]);
        Iterable<BIP0039MnemonicIndexGenerator> generators = BIP0039MnemonicIndexGenerators.GENERATORS;

        /* SAN CHECK */
        for (BIP0039MnemonicIndexGenerator generator: generators) {
            int[] result = generator.generateIndices(entropy);
            System.out.printf("%s: %s\n", generator.getClass().getSimpleName(), Arrays.toString(result));
        }
        long start, elapsed;
        int COUNT = 1000000;

        /* WARMUP */
        for (BIP0039MnemonicIndexGenerator generator: generators) {
            for (int i = 0; i < COUNT; i++) {
                generator.generateIndices(entropy);
            }
            Runtime.getRuntime().gc();
            Runtime.getRuntime().gc();
        }
        for (BIP0039MnemonicIndexGenerator generator: generators) {
            start = System.currentTimeMillis();
            for (int i = 0; i < COUNT; i++) {
                generator.generateIndices(entropy);
            }
            elapsed = System.currentTimeMillis() - start;
            System.out.println(generator.getClass().getSimpleName() + " Took " + elapsed);
            Runtime.getRuntime().gc();
            Runtime.getRuntime().gc();
        }
    }

    private final static class BigIntegerProcessor extends BIP0039MnemonicIndexGenerator {

        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         * @return array of integer indices into dictionary.
         */
        @Override
        public int[] generateIndices(byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] checksum = BIP0039MnemonicUtility.sha256digest(entropy);

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
            return indexValues;
        }
    }

    private final static class BitSetGenerator extends BIP0039MnemonicIndexGenerator {

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

        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         * @return array of integer indices into dictionary.
         */
        @Override
        public int[] generateIndices(byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] checksum = BIP0039MnemonicUtility.sha256digest(entropy);

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
            return indexValues;
        }
    }

    private final static class BooleanGenerator extends BIP0039MnemonicIndexGenerator {

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

        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         * @return array of integer indices into dictionary.
         */
        @Override
        public int[] generateIndices(byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] checksum = BIP0039MnemonicUtility.sha256digest(entropy);

            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int mnemonicSentenceLength = (entropyBitCount + checksumBitCount) / 11;

            boolean[] hashBits = bytesToBits(checksum);
            boolean[] entropyBits = bytesToBits(entropy);

            /* Merge the bits */
            boolean[] concatBits = new boolean[entropyBits.length + checksumBitCount];
            System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
            System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumBitCount);

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
            return indexValues;
        }
    }

    /**
     * Generator based on treating an array of booleans as joined entropy+checksum storage.
     */
    @Immutable
    private final static class JoinedBooleanGenerator extends BIP0039MnemonicIndexGenerator {

        /**
         * Utility method to take the entropy and checksum byte arrays and merge them into a
         * boolean-based "bit" array.
         *
         * @param totalBits number of total bits to convert.
         * @param entropy   data
         * @param checksum  data
         *
         * @return array of booleans representing each bit
         */
        @Nonnull
        private static boolean[] bytesToBits(int totalBits, @Nonnull byte[] entropy, @Nonnull byte[] checksum) {
            Preconditions.checkNotNull(entropy);
            Preconditions.checkNotNull(checksum);
            Preconditions.checkArgument(totalBits > 0 && totalBits <= (entropy.length * 8 + checksum.length * 8));
            boolean[] bits = new boolean[totalBits];
            int offset = 0;
            for (int i = 0; i < entropy.length; ++i) {
                for (int j = 0; j < 8; ++j) {
                    bits[offset] = (entropy[i] & (1 << (7 - j))) != 0;
                    offset++;
                }
            }

            for (int i = 0; i < checksum.length; ++i) {
                for (int j = 0; j < 8; ++j) {
                    bits[offset] = (checksum[i] & (1 << (7 - j))) != 0;
                    offset++;
                    if (offset >= totalBits) {
                        return bits;
                    }
                }
            }
            return bits;
        }

        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         *
         * @return array of integer indices into dictionary.
         */
        @Nonnull
        @Override
        public int[] generateIndices(@Nonnull byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] checksum = BIP0039MnemonicUtility.sha256digest(entropy);

            /* Convert the length to bits for purpose of BIP0039 specification match-up */
            int entropyBitCount = entropy.length * 8;
            int checksumBitCount = entropyBitCount / 32;
            int mnemonicSentenceLength = (entropyBitCount + checksumBitCount) / 11;

            boolean[] concatBits = bytesToBits(entropyBitCount + checksumBitCount, entropy, checksum);

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
            int j = 0;
            for (int i = 0; i < 8; i++) {
                j |= (concatBits[i * 11] ? 0x1 : 0x0) << i;
            }
            return indexValues;
        }
    }

    /**
     * Generator based on treating an array of booleans as joined entropy+checksum storage,
     * and storing the original entropy+checksum together.
     */
    @Immutable
    private final static class JoinedDigestBooleanGenerator extends BIP0039MnemonicIndexGenerator {

        /**
         * Utility method to take the entropy and checksum byte arrays and merge them into a
         * boolean-based "bit" array.
         *
         * @param totalBits number of total bits to convert.
         * @param data   data
         *
         * @return array of booleans representing each bit
         */
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

        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         *
         * @return array of integer indices into dictionary.
         */
        @Nonnull
        @Override
        public int[] generateIndices(@Nonnull byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] joined = new byte[entropy.length + 256 / 8];
            System.arraycopy(entropy, 0, joined, 0, entropy.length);
            BIP0039MnemonicUtility.sha256digest(joined, 0, entropy.length, joined, entropy.length);

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
            int j = 0;
            for (int i = 0; i < 8; i++) {
                j |= (concatBits[i * 11] ? 0x1 : 0x0) << i;
            }
            return indexValues;
        }
    }

    private final static class CrinchBitReaderProcessor extends BIP0039MnemonicIndexGenerator {
        /**
         * Take the input entropy and output an array of word indices.
         *
         * @param entropy generated entropy to process.
         * @return array of integer indices into dictionary.
         */
        @Override
        public int[] generateIndices(byte[] entropy) {
            Preconditions.checkNotNull(entropy);
            byte[] joined = new byte[entropy.length + 256 / 8];
            
            System.arraycopy(entropy, 0, joined, 0, entropy.length);
            BIP0039MnemonicUtility.sha256digest(joined, 0, entropy.length, joined, entropy.length);

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
            return indexValues;

        }
    }
}
