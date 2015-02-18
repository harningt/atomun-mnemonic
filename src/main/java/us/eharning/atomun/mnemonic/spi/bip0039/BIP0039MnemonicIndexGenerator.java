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
import com.tomgibara.crinch.bits.BitReader;
import com.tomgibara.crinch.bits.ByteArrayBitReader;

import javax.annotation.Nonnull;

/**
 * Utility class for BIP0039 index generators.
 */
class BIP0039MnemonicIndexGenerator {
    /**
     * Take the input entropy and output an array of word indices.
     *
     * @param entropy generated entropy to process.
     * @return array of integer indices into dictionary.
     */
    @Nonnull
    public static int[] generateIndices(@Nonnull byte[] entropy) {
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
