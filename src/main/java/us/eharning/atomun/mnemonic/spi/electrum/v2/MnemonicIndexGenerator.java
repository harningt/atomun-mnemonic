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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import com.google.common.base.Preconditions;
import com.google.common.primitives.Ints;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;

import java.math.BigInteger;
import java.util.ArrayList;
import javax.annotation.Nonnull;

/**
 * Utility class for electrum v2 wrapping different types of index generators.
 */
class MnemonicIndexGenerator {
    /**
     * Take the input entropy and output an array of word indices.
     *
     * @param entropy
     *         generated entropy to process.
     * @param wordList
     *         word list to generate indices for.
     *
     * @return array of integer indices into dictionary.
     */
    @Nonnull
    public static int[] generateIndices(@Nonnull BigInteger entropy, BidirectionalDictionary wordList) {
        Preconditions.checkNotNull(entropy);

        /*
         * Cannot use the nice 11-bit stride trick for two reasons:
         *  * Not all supported word lists are 2048 words, Portuguese is less.
         *  * Entropy data is not guaranteed to be evenly divisible into 11-bit chunks.
         */
        ArrayList<Integer> indexList = new ArrayList<>();
        BigInteger wordListSize = BigInteger.valueOf(wordList.getSize());
        while (!entropy.equals(BigInteger.ZERO)) {
            BigInteger[] results = entropy.divideAndRemainder(wordListSize);
            entropy = results[0];
            indexList.add(results[1].intValue());
        }
        return Ints.toArray(indexList);
    }
}
