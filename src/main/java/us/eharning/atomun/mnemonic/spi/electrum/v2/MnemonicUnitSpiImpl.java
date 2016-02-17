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

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.tomgibara.crinch.bits.BitWriter;
import com.tomgibara.crinch.bits.ByteArrayBitWriter;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.spi.MnemonicUnitSpi;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;

import java.math.BigInteger;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Internal class to implement the electrum v2 mnemonic details.
 */
@Immutable
class MnemonicUnitSpiImpl extends MnemonicUnitSpi {
    private final Dictionary dictionary;

    /**
     * Construct a electrum v2 decoder SPI instance for the given dictionary.
     *
     * @param dictionary
     *         instance to match mnemonic words against.
     */
    public MnemonicUnitSpiImpl(@Nonnull Dictionary dictionary) {
        super(MnemonicAlgorithm.ElectrumV2);
        this.dictionary = dictionary;
    }

    /**
     * Convert a sequence of mnemonic word into a byte array for validation and usage.
     *
     * @param dictionary
     *         instance to check for the presence of all words.
     * @param mnemonicWordList
     *         sequence of mnemonic words to map against a dictionary for bit values.
     *
     * @return sequence of bytes based on word list.
     */
    @Nonnull
    private static byte[] mnemonicToBytes(@Nonnull Dictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        if (fast_is_pow2(dictionary.getSize())) {
            byte[] result = mnemonicToBytesWithBitshift(dictionary, mnemonicWordList);
            byte[] checkResult = mnemonicToBytesWithMultiplication(dictionary, mnemonicWordList);
            if (!Arrays.equals(result, checkResult)) {
                throw new Error("Mismatched results!" + Arrays.toString(result) + " != " + Arrays.toString(checkResult));
            }
            return result;
        } else {
            return mnemonicToBytesWithMultiplication(dictionary, mnemonicWordList);
        }
    }

    /**
     * Convert a sequence of mnemonic word into a byte array for validation and usage.
     *
     * @param dictionary
     *         instance to check for the presence of all words.
     * @param mnemonicWordList
     *         sequence of mnemonic words to map against a dictionary for bit values.
     *
     * @return sequence of bytes based on word list.
     */
    @Nonnull
    private static byte[] mnemonicToBytesWithBitshift(@Nonnull Dictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        Converter<String, Integer> reverseConverter = dictionary.reverse();

        final int wordListSize = dictionary.getSize();
        final int unitSize = fast_log2(wordListSize);

        final int totalBits = mnemonicWordList.size() * unitSize;
        final int totalBytes = totalBits >> 3;
        int firstBits = (totalBytes << 3) % unitSize;
        if (firstBits == 0) {
            firstBits = unitSize;
        }

        byte[] result = new byte[(totalBits + 7) >> 3];
        BitWriter bw = new ByteArrayBitWriter(result);

        boolean modified = false;
        int bitsToWrite = firstBits;
        for (int i = mnemonicWordList.size() - 1; i >= 0; i--) {
            String word = mnemonicWordList.get(i);
            /* Find the word index in the wordList. */
            /* Warning suppressed due to word guaranteed non-null */
            //noinspection ConstantConditions
            int index = reverseConverter.convert(word);

            if (index > (1 << bitsToWrite)) {
                bitsToWrite += 8;
                modified = true;
            }

            bw.write(index, bitsToWrite);
            bitsToWrite = unitSize;
        }
        int newStartIndex = 0;
        int newEndIndex = result.length;
        /* If we haven't used the extra space due to mis-identified starter bit-length,
         * trim it off if it was in fact "extra" space.
         */
        if (!modified && totalBytes != result.length) {
            newEndIndex--;
        }
        while (result[newStartIndex] == 0) {
            newStartIndex++;
        }
        if (newStartIndex != 0 || newEndIndex != result.length) {
            byte[] tmp = new byte[newEndIndex - newStartIndex];
            System.arraycopy(result, newStartIndex, tmp, 0, tmp.length);
            result = tmp;
        }
        return result;
    }

    /**
     * Convert a sequence of mnemonic word into a byte array for validation and usage.
     *
     * @param dictionary
     *         instance to check for the presence of all words.
     * @param mnemonicWordList
     *         sequence of mnemonic words to map against a dictionary for bit values.
     *
     * @return sequence of bytes based on word list.
     */
    @Nonnull
    private static byte[] mnemonicToBytesWithMultiplication(@Nonnull Dictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        Converter<String, Integer> reverseConverter = dictionary.reverse();

        BigInteger total = BigInteger.ZERO;
        BigInteger multiplier = BigInteger.valueOf(dictionary.getSize());
        for (String word : Lists.reverse(mnemonicWordList)) {
            /* Find the word index in the wordList. */
            /* Warning suppressed due to word guaranteed non-null */
            //noinspection ConstantConditions
            int index = reverseConverter.convert(word);

            total = total.multiply(multiplier).add(BigInteger.valueOf(index));
        }

        /* Convert the resultant value to an unsigned byte-array */
        byte[] result = total.toByteArray();
        if (result[0] == 0) {
            byte[] tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
        }
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

    /**
     * Utility method to generate a MnemonicUnit wrapping the given sequence and entropy.
     *
     * @param mnemonicSequence
     *         sequence.
     * @param entropy
     *         derived copy of entropy.
     * @param supportedExtensions
     *         set of supported extensions dependent on algorithm.
     * @param extensionLoader
     *         method to calculate a given extension's value.

     * @return wrapped instance.
     */
    @Nonnull
    public MnemonicUnit build(MnemonicUnit.Builder builder, CharSequence mnemonicSequence, byte[] entropy, Set<MnemonicExtensionIdentifier> supportedExtensions, Function<MnemonicExtensionIdentifier, Object> extensionLoader) {
        return super.build(builder, mnemonicSequence, entropy, null, ImmutableSet.copyOf(supportedExtensions), extensionLoader);
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence
     *         sequence to derive entropy from.
     *
     * @return a derived copy of the entropy byte array.
     */
    @CheckForNull
    @Override
    public byte[] getEntropy(@Nonnull CharSequence mnemonicSequence) {
        List<String> mnemonicWordList = MnemonicUtility.getNormalizedWordList(mnemonicSequence);

        /* Convert the word list into a sequence of booleans representing its bits. */
        return mnemonicToBytes(dictionary, mnemonicWordList);
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param mnemonicSequence
     *         sequence to derive the seed from.
     * @param password
     *         password to supply for decoding.
     *
     * @return a derived seed.
     */
    @Nonnull
    @Override
    public byte[] getSeed(@Nonnull CharSequence mnemonicSequence, @Nullable CharSequence password) {
        byte[] mnemonicSequenceBytes = Normalizer.normalize(mnemonicSequence, Normalizer.Form.NFKD).getBytes(Charsets.UTF_8);

        /* Normalize the password and get the UTF-8 bytes. */
        String normalizedPassword = "mnemonic";
        if (null != password && 0 != password.length()) {
            normalizedPassword = normalizedPassword + Normalizer.normalize(password, Normalizer.Form.NFKD);
        }
        byte[] passwordBytes = normalizedPassword.getBytes(Charsets.UTF_8);
        return MnemonicUtility.deriveSeed(passwordBytes, mnemonicSequenceBytes);
    }
}
