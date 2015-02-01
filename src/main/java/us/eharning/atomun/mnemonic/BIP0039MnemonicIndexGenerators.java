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
import com.google.common.collect.ImmutableSet;

import java.util.Set;

/**
 * Collection of tested mnemonic index generator implementations to use.
 */
class BIP0039MnemonicIndexGenerators {
    final static BIP0039MnemonicIndexGenerator OPTIMAL_GENERATOR = new JoinedBooleanGenerator();
    final static Set<BIP0039MnemonicIndexGenerator> GENERATORS = ImmutableSet.<BIP0039MnemonicIndexGenerator>of(
            new JoinedBooleanGenerator()
    );

    private final static class JoinedBooleanGenerator extends BIP0039MnemonicIndexGenerator {

        /**
         * Utility method to take the entropy and checksum byte arrays and merge them into a
         * boolean-based "bit" array.
         *
         * @param totalBits number of total bits to convert.
         * @param entropy   data
         * @param checksum  data
         * @return array of booleans representing each bit
         */
        private static boolean[] bytesToBits(int totalBits, byte[] entropy, byte[] checksum) {
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
            return indexValues;
        }
    }
}
