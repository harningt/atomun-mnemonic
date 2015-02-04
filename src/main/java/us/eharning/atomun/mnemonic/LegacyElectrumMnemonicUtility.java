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

import com.google.common.base.*;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;

/**
 * Static utility to handle encoding/decoding details of the legacy Electrum mnemonic format.
 */
class LegacyElectrumMnemonicUtility {
    private static final Splitter WORD_SPLITTER = Splitter.on(CharMatcher.WHITESPACE).trimResults().omitEmptyStrings();
    private static final BidirectionalDictionary DICTIONARY;
    private static final int N;

    static {
        try {
            DICTIONARY = new BidirectionalDictionary(LegacyElectrumMnemonicUtility.class.getResource("legacy_electrum_dictionary.txt"));
        } catch (IOException e) {
            throw new Error("Failed to read legacy_electrum_dictionary.txt for initialization", e);
        }
        N = DICTIONARY.getSize();
    }

    /* Simple modular math hack to deal with signed/unsigned integer issues
     * and java
     */
    private static int mn_mod(int value, int mod) {
        return value < 0 ? mod + value : value % mod;
    }

    private static ImmutableList<String> resourceToLines(URL resource) throws IOException {
        LineProcessor<ImmutableList<String>> lineProcess = new LineProcessor<ImmutableList<String>>() {
            final ImmutableList.Builder<String> result = ImmutableList.builder();
            @Override
            public boolean processLine(String line) throws IOException {
                result.add(line);
                return true;
            }

            @Override
            public ImmutableList<String> getResult() {
                return result.build();
            }
        };
        return Resources.readLines(resource, Charsets.US_ASCII, lineProcess);
    }

    /**
     * Encode a sequence of bytes to a space-delimited series of mnemonic words.
     *
     * @param entropy value to encode.
     * @return space-delimited sequence of mnemonic words.
     */
    static String toMnemonic(byte[] entropy) {
        ArrayList<String> encoded = Lists.newArrayList();
        encoded.ensureCapacity(entropy.length / 8 * 3);
        DataInput input = new DataInputStream(new ByteArrayInputStream(entropy));
        try {
            //noinspection InfiniteLoopStatement
            while (true) {
                long x = input.readInt() & 0xFFFFFFFFL;
                int w1 = (int)(x % N);
                int w2 = (int)(x / N + w1) % N;
                int w3 = (int)(x / N / N + w2) % N;
                encoded.add(DICTIONARY.doForward(w1));
                encoded.add(DICTIONARY.doForward(w2));
                encoded.add(DICTIONARY.doForward(w3));
            }
        } catch (EOFException ignored) {
            /* End of stream */
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
        return Joiner.on(' ').join(encoded);
    }

    /**
     * Decode a space-delimited sequence of mnemonic words.
     *
     * @param mnemonicSequence space-delimited sequence of mnemonic words to toEntropy.
     *
     * @return encoded value.
     */
    static byte[] toEntropy(CharSequence mnemonicSequence) {
        String[] mnemonicWords = Iterables.toArray(WORD_SPLITTER.split(mnemonicSequence), String.class);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (mnemonicWords.length % 3 != 0) {
            throw new IllegalArgumentException("Mnemonic sequence is not a multiple of 3");
        }
        for (int i = 0; i < mnemonicWords.length; i += 3) {
            String word1 = mnemonicWords[i].toLowerCase();
            String word2 = mnemonicWords[i + 1].toLowerCase();
            String word3 = mnemonicWords[i + 2].toLowerCase();
            Integer w1 = DICTIONARY.doBackward(word1);
            Integer w2 = DICTIONARY.doBackward(word2);
            Integer w3 = DICTIONARY.doBackward(word3);
            if (null == w1 || null == w2 || null == w3) {
                throw new IllegalArgumentException("Unknown mnemonic word used");
            }
            int x = w1 + N * mn_mod(w2 - w1, N) + N * N * mn_mod(w3 - w2, N);
            /* Convert to 4 bytes */
            output.write((x >> 24) & 0xFF);
            output.write((x >> 16) & 0xFF);
            output.write((x >> 8) & 0xFF);
            output.write(x & 0xFF);
        }
        return output.toByteArray();
    }
}
