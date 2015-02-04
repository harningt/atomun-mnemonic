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

import com.google.common.base.Charsets;
import com.google.common.base.Splitter;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.List;

/**
 * Decoder system for the BIP0039 mnemonic system.
 *
 * Thanks to the BitcoinJ project for inspiration of the boolean-array based decoder.
 */
class BIP0039MnemonicDecoderSystem extends MnemonicDecoderSystem {
    /**
     * Decodes a given mnemonic into a unit.
     * The word list is to be automatically detected and it is expected that only one matches.
     *
     * @param mnemonicSequence   space-delimited sequence of mnemonic words.
     * @param wordListIdentifier optional word list identifier
     *
     * @return mnemonic unit
     *
     * @throws IllegalArgumentException the sequence cannot match
     */
    @Override
    public MnemonicUnit decode(CharSequence mnemonicSequence, String wordListIdentifier) {
        byte[] entropy = toEntropy(mnemonicSequence, wordListIdentifier);
        return new MnemonicUnit(new BIP0039MnemonicUnit(mnemonicSequence, entropy));
    }

    private byte[] toEntropy(CharSequence mnemonicSequence, String wordListIdentifier) {
        List<String> mnemonicWordList = Splitter.onPattern(" |\u3000").splitToList(mnemonicSequence);
        /* Verify word list has an appropriate length */
        if (mnemonicWordList.size() % 3 != 0) {
            throw new IllegalArgumentException("Word list of the wrong length");
        }
        BidirectionalDictionary dictionary;
        if (null == wordListIdentifier || wordListIdentifier.isEmpty()) {
            dictionary = detectWordList(mnemonicWordList);
            if (null == dictionary) {
                throw new IllegalArgumentException("Could not detect dictionary for words");
            }
        } else {
            dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
            if (!verifyDictionary(dictionary, mnemonicWordList)) {
                throw new IllegalArgumentException("Words not in dictionary");
            }
        }

        /* Convert the word list into a sequence of booleans representing its bits. */
        boolean[] mnemonicSentenceBits = mnemonicToBits(dictionary, mnemonicWordList);

        /* Extract from the bits the entropy prefix */
        byte[] entropy = extractEntropy(mnemonicSentenceBits);

        /* Verify that the word list is valid using the checksum at the end of the data */
        if (!verifyEntropyMatch(entropy, mnemonicSentenceBits)) {
            throw new IllegalArgumentException("Checksum does not match");
        }

        return entropy;
    }

    private static boolean[] mnemonicToBits(BidirectionalDictionary dictionary, List<String> mnemonicWordList) {
        /* Each word represents 11 bits of entropy (2^11 => 2048 words) */
        int mnemonicSentenceBitCount = mnemonicWordList.size() * 11;
        boolean[] mnemonicSentenceBits = new boolean[mnemonicSentenceBitCount];
        int bitIndex = 0;
        for (String word: mnemonicWordList) {
            /* Find the word index in the wordList. */
            int index = dictionary.doBackward(word);

            /* Set the next 11 bits to the value of the index. */
            for (int i = 0; i < 11; i++) {
                mnemonicSentenceBits[bitIndex] = (index & (1 << (10 - i))) != 0;
                bitIndex++;
            }
        }
        return mnemonicSentenceBits;
    }

    private static byte[] extractEntropy(boolean[] mnemonicSentenceBits) {
        int checksumBitCount = mnemonicSentenceBits.length / 33;
        int entropyBitCount = mnemonicSentenceBits.length - checksumBitCount;

        /* Extract original entropy as bytes. */
        byte[] entropy = new byte[entropyBitCount / 8];
        int bitIndex = 0;
        for (int i = 0; i < entropy.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                if (mnemonicSentenceBits[bitIndex]) {
                    entropy[i] |= 1 << (7 - j);
                }
                bitIndex++;
            }
        }
        return entropy;
    }

    private static boolean verifyEntropyMatch(byte[] entropy, boolean[] mnemonicSentenceBits) {
        int entropyBitCount = entropy.length * 8;
        int checksumBitCount = entropyBitCount / 32;
        // Take the digest of the entropy.
        byte[] hash = BIP0039MnemonicUtility.sha256digest(entropy);

        // Check all the checksum bits.
        for (int i = 0; i < checksumBitCount; ++i) {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            if (mnemonicSentenceBits[entropyBitCount + i] != ((hash[byteIndex] & (1 << (7 - bitIndex))) != 0)) {
                return false;
            }
        }
        return true;
    }


    private static BidirectionalDictionary detectWordList(List<String> mnemonicWordList) {
    /* Need to autodetect the word list from the sequence. */
        for (BidirectionalDictionary availableDictionary: BIP0039MnemonicUtility.getDictionaries()) {
            /* Check that all the words are in the dictionary and if so, found */
            if (verifyDictionary(availableDictionary, mnemonicWordList)) {
                return availableDictionary;
            }
        }
        return null;
    }

    private static boolean verifyDictionary(BidirectionalDictionary dictionary, List<String> mnemonicWordList) {
        /* Due to inability for converters to return null as a valid response, need to catch thrown exception */
        try {
            for (String word: mnemonicWordList) {
                dictionary.doBackward(word);
            }
        } catch (IllegalArgumentException ignored) {
            return false;
        }
        return true;
    }

    /**
     * Internal class to implement the BIP0039 mnemonic details.
     */
    private static class BIP0039MnemonicUnit extends MnemonicUnitSpi {
        private final byte[] entropy;
        private final byte[] mnemonicSequenceBytes;

        private BIP0039MnemonicUnit(CharSequence mnemonicSequence, byte[] entropy) {
            super(mnemonicSequence);
            /* Byte sequence is based on the normalized form */
            this.mnemonicSequenceBytes = Normalizer.normalize(mnemonicSequence, Normalizer.Form.NFKD).getBytes(Charsets.UTF_8);
            this.entropy = entropy;
        }

        /**
         * Get the entropy if possible.
         *
         * @return a copy of the entropy byte array or null if inaccessible.
         */
        @Override
        public byte[] getEntropy() {
            return Arrays.copyOf(entropy, entropy.length);
        }

        /**
         * Get a seed from this mnemonic without supplying a password.
         *
         * @return a decoded seed.
         */
        @Override
        public byte[] getSeed() {
            return getSeed(null);
        }

        /**
         * Get a seed from this mnemonic.
         *
         * @param password password to supply for decoding.
         *
         * @return a decoded seed.
         */
        @Override
        public byte[] getSeed(CharSequence password) {
            /* Normalize the password and get the UTF-8 bytes. */
            String normalizedPassword = "mnemonic";
            if (null != password && 0 != password.length()) {
                normalizedPassword = normalizedPassword + Normalizer.normalize(password, Normalizer.Form.NFKD);
            }
            byte[] passwordBytes = normalizedPassword.getBytes(Charsets.UTF_8);
            return BIP0039MnemonicUtility.deriveSeed(passwordBytes, mnemonicSequenceBytes);
        }
    }
}
