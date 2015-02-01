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

import java.io.IOException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Utility class to support BIP0039 mnemonics.
 *
 * @since 0.1.0
 */
class BIP0039MnemonicUtility {
    private final static ConcurrentMap<String, BidirectionalDictionary> dictionaries = new ConcurrentHashMap<>();

    static BidirectionalDictionary getDictionary(String wordList) {
        BidirectionalDictionary dictionary = dictionaries.get(wordList);
        if (null == dictionary) {
            URL dictionaryLocation = BIP0039MnemonicUtility.class.getResource("bip0039-" + wordList + ".txt");
            if (dictionaryLocation == null) {
                throw new IllegalArgumentException("Unknown wordList requested");
            }
            try {
                dictionary = new BidirectionalDictionary(dictionaryLocation);
            } catch (IOException e) {
                throw new IllegalArgumentException("Inaccessible wordList requested");
            }
            dictionaries.putIfAbsent(wordList, dictionary);
        }
        return dictionary;
    }

    static byte[] sha256digest(byte[] data) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        return digest.digest(data);
    }
}
