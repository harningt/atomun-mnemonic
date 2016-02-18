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

package us.eharning.atomun.mnemonic.spi.electrum.legacy;

import com.google.common.base.CharMatcher;
import com.google.common.base.Converter;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;
import us.eharning.atomun.mnemonic.utility.dictionary.DictionaryIdentifier;
import us.eharning.atomun.mnemonic.utility.dictionary.DictionarySource;

import java.util.ArrayList;
import javax.annotation.Nonnull;

/**
 * Static utility to handle encoding/decoding details of the legacy Electrum mnemonic format.
 */
final class LegacyElectrumMnemonicUtility {
    private static final Splitter WORD_SPLITTER = Splitter.on(CharMatcher.whitespace()).trimResults().omitEmptyStrings();
    private static final DictionaryIdentifier DICTIONARY_IDENTIFIER = DictionaryIdentifier.getIdentifier("english", "us/eharning/atomun/mnemonic/spi/electrum/legacy/dictionary.txt");

    /**
     * Private unused constructor to mark as utility class.
     */
    private LegacyElectrumMnemonicUtility() {
    }

    /**
     * Simple modular math hack to deal with signed/unsigned integer issues and java.
     *
     * @param value
     *         signed integer to apply modulo operator to.
     * @param mod
     *         modulo operator parameter.
     *
     * @return value % mod honoring signed/unsigned rules for this usage.
     */
    private static int mn_mod(int value, int mod) {
        return value < 0 ? mod + value : value % mod;
    }

    /**
     * Utility method to add a 32-bit integer to a byte array.
     *
     * @param buffer
     *         byte array to write to.
     * @param currentIndex
     *         offset into buffer to write into.
     * @param value
     *         32-bit integer to write at buffer[currentIndex].
     */
    private static void putInteger(@Nonnull byte[] buffer, int currentIndex, int value) {
        buffer[currentIndex] = (byte) ((value >> 24) & 0xFF);
        buffer[currentIndex + 1] = (byte) ((value >> 16) & 0xFF);
        buffer[currentIndex + 2] = (byte) ((value >> 8) & 0xFF);
        buffer[currentIndex + 3] = (byte) (value & 0xFF);
    }

    /**
     * Utility method to extract a 32-bit integer from a byte array.
     *
     * @param buffer
     *         byte array to read from.
     * @param currentIndex
     *         offset into buffer to read from.
     *
     * @return 32-bit integer stored at buffer[currentIndex]
     */
    private static int getInteger(@Nonnull byte[] buffer, int currentIndex) {
        return (buffer[currentIndex] & 0xFF) << 24
                | (buffer[currentIndex + 1] & 0xFF) << 16
                | (buffer[currentIndex + 2] & 0xFF) << 8
                | buffer[currentIndex + 3] & 0xFF;
    }

    /**
     * Encode a sequence of bytes to a space-delimited series of mnemonic words.
     *
     * @param entropy
     *         value to encode.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    @Nonnull
    static String toMnemonic(@Nonnull byte[] entropy) {
        final Dictionary dictionary = DictionarySource.getDictionary(DICTIONARY_IDENTIFIER);
        final int N = dictionary.getSize();
        int entropyIndex = 0;
        ArrayList<String> encoded = Lists.newArrayList();
        encoded.ensureCapacity(entropy.length / 8 * 3);
        while (entropyIndex < entropy.length) {
            long subValue = getInteger(entropy, entropyIndex) & 0xFFFFFFFFL;
            entropyIndex += 4;
            int w1 = (int) (subValue % N);
            int w2 = (int) (subValue / N + w1) % N;
            int w3 = (int) (subValue / N / N + w2) % N;
            encoded.add(dictionary.convert(w1));
            encoded.add(dictionary.convert(w2));
            encoded.add(dictionary.convert(w3));
        }
        return Joiner.on(' ').join(encoded);
    }

    /**
     * Decode a space-delimited sequence of mnemonic words.
     *
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words to toEntropy.
     *
     * @return encoded value.
     */
    @Nonnull
    static byte[] toEntropy(@Nonnull CharSequence mnemonicSequence) {
        final Dictionary dictionary = DictionarySource.getDictionary(DICTIONARY_IDENTIFIER);
        final int N = dictionary.getSize();

        String[] mnemonicWords = Iterables.toArray(WORD_SPLITTER.split(mnemonicSequence), String.class);
        byte[] entropy = new byte[mnemonicWords.length * 4 / 3];
        int entropyIndex = 0;
        Converter<String, Integer> reverseDictionary = dictionary.reverse();
        if (mnemonicWords.length % 3 != 0) {
            throw new IllegalArgumentException("Mnemonic sequence is not a multiple of 3");
        }
        for (int i = 0; i < mnemonicWords.length; i += 3) {
            String word1 = mnemonicWords[i].toLowerCase();
            String word2 = mnemonicWords[i + 1].toLowerCase();
            String word3 = mnemonicWords[i + 2].toLowerCase();
            Integer w1 = reverseDictionary.convert(word1);
            Integer w2 = reverseDictionary.convert(word2);
            Integer w3 = reverseDictionary.convert(word3);
            /* NOTE: Impossible scenario as covert only returns null IFF null is passed in */

            //noinspection ConstantConditions
            int subValue = w1 + N * mn_mod(w2 - w1, N) + N * N * mn_mod(w3 - w2, N);
            /* Convert to 4 bytes */
            putInteger(entropy, entropyIndex, subValue);
            entropyIndex += 4;
        }
        return entropy;
    }
}
