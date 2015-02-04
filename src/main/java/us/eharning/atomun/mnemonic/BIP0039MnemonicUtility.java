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

import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Utility class to support BIP0039 mnemonics.
 */
class BIP0039MnemonicUtility {
    private final static List<String> KNOWN_DICTIONARIES = ImmutableList.of(
            "english",
            "japanese"
    );
    private final static ConcurrentMap<String, BidirectionalDictionary> dictionaries = new ConcurrentHashMap<>();
    private static final int PBKDF_ROUNDS = 2048;
    private static final String PBKDF_MAC = "HmacSHA512";
    private static final int PBKDF_SEED_OUTPUT = 64;

    /**
     * Utility method to obtain a dictionary given the wordListIdentifier.
     * @param wordListIdentifier name of the word list to retrieve.
     * @return dictionary for the given word list.
     *
     * @throws java.lang.IllegalArgumentException If the word list cannot be found/loaded.
     */
    static BidirectionalDictionary getDictionary(String wordListIdentifier) {
        BidirectionalDictionary dictionary = dictionaries.get(wordListIdentifier);
        if (null == dictionary) {
            URL dictionaryLocation = BIP0039MnemonicUtility.class.getResource("bip0039-" + wordListIdentifier + ".txt");
            if (dictionaryLocation == null) {
                throw new IllegalArgumentException("Unknown wordListIdentifier requested");
            }
            try {
                dictionary = new BidirectionalDictionary(dictionaryLocation);
            } catch (IOException e) {
                throw new IllegalArgumentException("Inaccessible wordListIdentifier requested");
            }
            dictionaries.putIfAbsent(wordListIdentifier, dictionary);
        }
        return dictionary;
    }

    /**
     * Simple utility to calculate the SHA-256 digest.
     * @param data value to digest.
     * @return sha256-digest of data.
     *
     * @throws java.lang.Error if the digest cannot be found (should not happen).
     */
    static byte[] sha256digest(byte[] data) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        return digest.digest(data);
    }

    /**
     * Utility method to derive a seed given the password and processed mnemonic sequence.
     * @param passwordBytes UTF-8 byte sequence representing the password to use.
     * @param mnemonicSequenceBytes UTF-8 byte sequence representing the mnemonic sequence.
     * @return 64-byte seed value
     *
     * @throws java.lang.Error if the Mac cannot be found (should not happen).
     */
    static byte[] deriveSeed(byte[] passwordBytes, byte[] mnemonicSequenceBytes) {
        try {
            return PBKDF2.pbkdf2(PBKDF_MAC, mnemonicSequenceBytes, passwordBytes, PBKDF_ROUNDS, PBKDF_SEED_OUTPUT);
        } catch (GeneralSecurityException e) {
            throw new Error(e);
        }
    }

    /**
     * Utility method to retrieve all known dictionaries.
     *
     * @return iterable that contains known dictionaries.
     */
    static Iterable<BidirectionalDictionary> getDictionaries() {
        Iterable<BidirectionalDictionary> dictionaryIterable = Iterables.transform(KNOWN_DICTIONARIES, new Function<String, BidirectionalDictionary>() {
            @Override
            public BidirectionalDictionary apply(String input) {
                try {
                    return getDictionary(input);
                } catch (Throwable ignored) {
                    return null;
                }
            }
        });
        /* Filter out any missing dictionaries */
        dictionaryIterable = Iterables.filter(dictionaryIterable, Predicates.notNull());
        return dictionaryIterable;
    }
}
