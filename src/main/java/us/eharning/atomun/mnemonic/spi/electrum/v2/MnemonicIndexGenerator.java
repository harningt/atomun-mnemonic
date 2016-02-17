/*
 * Copyright 2014, 2015, 2016 Thomas Harning Jr. <harningt@gmail.com>
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
import com.tomgibara.crinch.bits.ByteArrayBitReader;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
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
    public static int[] generateIndices(@Nonnull BigInteger entropy, Dictionary wordList) {
        Preconditions.checkNotNull(entropy);

        /* If the word list is a power of 2, we can use bit-shifting for the math */
        if (fast_is_pow2(wordList.getSize())) {
            int[] result = generateIndicesWithBitShift(entropy, wordList);
            /* SANITY CHECK */
            int[] checkResult = generateIndicesWithDivision(entropy, wordList);
            if (!Arrays.equals(result, checkResult)) {
                throw new Error("Mismatched results!" + Arrays.toString(result) + " != " + Arrays.toString(checkResult));
            }
            return result;
        } else {
            /* else we have to use manual division using big-integers */
            return generateIndicesWithDivision(entropy, wordList);
        }
    }

    /**
     * Take the input entropy and output an array of word indices.
     * This mechanism uses BigInteger division due to inability to use bitshift tricks.
     *
     * @param entropy
     *         generated entropy to process.
     * @param wordList
     *         word list to generate indices for.
     *
     * @return array of integer indices into dictionary.
     */
    @Nonnull
    public static int[] generateIndicesWithDivision(@Nonnull BigInteger entropy, Dictionary wordList) {
        Preconditions.checkNotNull(entropy);

        /*
         * Cannot use the nice x-bit due to the word list not being evenly
         * divisible by a power of 2for two reasons:
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

    /**
     * Take the input entropy and output an array of word indices.
     * This mechanism takes advantage of the fact that division by a power of 2 is bit-shift.
     *
     * @param entropy
     *         generated entropy to process.
     * @param wordList
     *         word list to generate indices for.
     *
     * @return array of integer indices into dictionary.
     */
    @Nonnull
    public static int[] generateIndicesWithBitShift(@Nonnull BigInteger entropy, Dictionary wordList) {
        Preconditions.checkNotNull(entropy);

        final int wordListSize = wordList.getSize();
        final int unitSize = fast_log2(wordListSize);

        byte[] entropyByteArray = entropy.toByteArray();
        ByteArrayBitReader reader = new ByteArrayBitReader(entropyByteArray);
        int totalBytes = entropyByteArray.length;

        /* Value is positive, skip the useless 00 positive marker */
        if (entropyByteArray[0] == 0) {
            reader.skipBits(8);
            totalBytes--;
        }
        final int totalBits = totalBytes << 3;
        int firstBits = totalBits % unitSize;
        if (firstBits == 0) {
            firstBits = unitSize;
        }

        //System.out.println("First bits:" + firstBits + " totalBytes " + totalBytes);
        int[] result = new int[(totalBits + (unitSize - 1)) / unitSize];
        result[result.length - 1] = reader.read(firstBits);
        for (int i = result.length - 2; i >= 0; i--) {
            result[i] = reader.read(unitSize);
        }
        int finalSize = result.length;
        /* Chop of trailing zeroes due to original division algorithm stopping at zero */
        while (result[finalSize - 1] == 0) {
            finalSize--;
        }
        if (result.length != finalSize) {
            result = Arrays.copyOf(result, finalSize);
        }
        //System.out.println(Arrays.toString(result));
        return result;
    }

    /**
     * Perform fast determination if positive integer is power of 2.
     *
     * @param value
     *         integer to check if power of 2.
     *
     * @return true if value power of 2.
     */
    private static boolean fast_is_pow2(int value) {
        return value != 0 && 0 == (value & (value - 1));
    }

    /**
     * Perform a fast log2 calculation on an integer known as a positive power of 2.
     *
     * @param value
     *         integer to calculate log2 of
     *
     * @return log2
     */
    private static int fast_log2(int value) {
        int[] bitMask = {
                0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0,
                0xFF00FF00, 0xFFFF0000
        };
        int result = (value & bitMask[0]) != 0 ? 1 : 0;
        for (int i = 4; i > 0; i--) { // unroll for speed...
            result |= ((value & bitMask[i]) != 0 ? 1 : 0) << i;
        }
        return result;
    }
}
