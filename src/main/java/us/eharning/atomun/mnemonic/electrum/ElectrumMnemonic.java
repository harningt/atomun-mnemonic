/*
 * Copyright 2014 Thomas Harning Jr. <harningt@gmail.com>
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
package us.eharning.atomun.mnemonic.electrum;

import com.google.common.base.*;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;
import us.eharning.atomun.mnemonic.Mnemonic;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Mnemonic handler that applies the standard Electrum rules for encoding/decoding.
 */
public class ElectrumMnemonic implements Mnemonic {
    private static final Splitter WORD_SPLITTER = Splitter.on(CharMatcher.WHITESPACE).trimResults().omitEmptyStrings();
    private static final ImmutableList<String> INTEGER_TO_DICTIONARY;
    private static final ImmutableMap<String, Integer> DICTIONARY_TO_INTEGER;
    private static final int N;

    static {
        try {
            INTEGER_TO_DICTIONARY = resourceToLines(ElectrumMnemonic.class.getResource("dictionary.txt"));
        } catch (IOException e) {
            throw new Error("Failed to read dictionary.txt for initialization", e);
        }
        ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();
        for (int i = 0; i < INTEGER_TO_DICTIONARY.size(); i++) {
            builder.put(INTEGER_TO_DICTIONARY.get(i), i);
        }
        DICTIONARY_TO_INTEGER = builder.build();
        N = INTEGER_TO_DICTIONARY.size();
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
     * Encode a sequence of bytes to its series of mnemonic words.
     * @param data value to encode.
     * @return sequence of mnemonic words.
     */
    @Override
    public Iterable<String> encodeToIterable(byte[] data) {
        ArrayList<String> encoded = Lists.newArrayList();
        encoded.ensureCapacity(data.length / 8 * 3);
        DataInput input = new DataInputStream(new ByteArrayInputStream(data));
        try {
            //noinspection InfiniteLoopStatement
            while (true) {
                long x = input.readInt() & 0xFFFFFFFFL;
                int w1 = (int)(x % N);
                int w2 = (int)(x / N + w1) % N;
                int w3 = (int)(x / N / N + w2) % N;
                encoded.add(INTEGER_TO_DICTIONARY.get(w1));
                encoded.add(INTEGER_TO_DICTIONARY.get(w2));
                encoded.add(INTEGER_TO_DICTIONARY.get(w3));
            }
        } catch (EOFException ignored) {
            /* End of stream */
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
        return encoded;
    }

    /**
     * Encode a sequence of bytes to a space-delimited series of mnemonic words.
     * @param data value to encode.
     * @return space-delimited sequence of mnemonic words.
     */
    @Override
    public String encodeToString(byte[] data) {
        return Joiner.on(' ').join(encodeToIterable(data));
    }

    /**
     * Decode a space-delimited sequence of mnemonic words.
     * @param words space-delimited sequence of mnemonic words to decode.
     * @return encoded value.
     */
    @Override
    public byte[] decode(CharSequence words) {
        return decode(WORD_SPLITTER.split(words));
    }

    /**
     * Decode a sequence of mnemonic words.
     * @param words sequence of mnemonic words to decode.
     * @return encoded value.
     */
    @Override
    public byte[] decode(Iterable<String> words) {
        Iterator<String> iter = words.iterator();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while (iter.hasNext()) {
            String word1 = iter.next();
            String word2 = iter.next();
            String word3 = iter.next();
            Integer w1 = DICTIONARY_TO_INTEGER.get(word1);
            Integer w2 = DICTIONARY_TO_INTEGER.get(word2);
            Integer w3 = DICTIONARY_TO_INTEGER.get(word3);
            if (null == w1 || null == w2 || null == w3) {
                throw new NoSuchElementException();
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
