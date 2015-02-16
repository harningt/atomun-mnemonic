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

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.MnemonicUnitSpi;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.text.Normalizer;
import java.util.List;

/**
 * Internal class to implement the BIP0039 mnemonic details.
 */
@Immutable
class BIP0039MnemonicUnitSpi extends MnemonicUnitSpi {
    private final BidirectionalDictionary dictionary;

    /**
     * Construct a BIP0039 decoder SPI instance for the given dictionary.
     *
     * @param dictionary instance to match mnemonic words against.
     */
    public BIP0039MnemonicUnitSpi(@Nonnull BidirectionalDictionary dictionary) {
        this.dictionary = dictionary;
    }

    /**
     * Utility method to generate a MnemonicUnit wrapping the given sequence and entropy.
     *
     * @param mnemonicSequence sequence.
     * @param entropy derived copy of entropy.
     *
     * @return wrapped instance.
     */
    @Nonnull
    public MnemonicUnit build(CharSequence mnemonicSequence, byte[] entropy) {
        return super.build(mnemonicSequence, entropy, null, ImmutableMap.<String, Object>of());
    }

    /**
     * Convert a sequence of mnemonic word into a bit array for validation and usage.
     *
     * @param dictionary instance to check for the presence of all words.
     * @param mnemonicWordList sequence of mnemonic words to map against a dictionary for bit values.
     *
     * @return sequence of bits based on word list.
     */
    @Nonnull
    private static boolean[] mnemonicToBits(@Nonnull BidirectionalDictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        /* Each word represents 11 bits of entropy (2^11 => 2048 words) */
        int mnemonicSentenceBitCount = mnemonicWordList.size() * 11;
        boolean[] mnemonicSentenceBits = new boolean[mnemonicSentenceBitCount];
        int bitIndex = 0;
        Converter<String, Integer> reverseConverter = dictionary.reverse();
        for (String word: mnemonicWordList) {
            /* Find the word index in the wordList. */
            /* Warning suppressed due to word guaranteed non-null */
            //noinspection ConstantConditions
            int index = reverseConverter.convert(word);

            /* Set the next 11 bits to the value of the index. */
            for (int i = 0; i < 11; i++) {
                mnemonicSentenceBits[bitIndex] = (index & (1 << (10 - i))) != 0;
                bitIndex++;
            }
        }
        return mnemonicSentenceBits;
    }

    /**
     * Extract the entropy portion from the mnemonic sentence bits as a byte array.
     *
     * @param mnemonicSentenceBits container of entropy bits.
     *
     * @return array of bytes containing the entropy.
     */
    @Nonnull
    private static byte[] extractEntropy(@Nonnull boolean[] mnemonicSentenceBits) {
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

    /**
     * Verify that the entropy matches the checksum embedded in the mnemonic sentence bits.
     *
     * @param entropy bytes to validate checksum of.
     * @param mnemonicSentenceBits container of checksum bits.
     *
     * @return true if the checksum matches, else false.
     */
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

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence sequence to derive entropy from.
     *
     * @return a derived copy of the entropy byte array.
     */
    @CheckForNull
    @Override
    public byte[] getEntropy(@Nonnull CharSequence mnemonicSequence) {
        List<String> mnemonicWordList = Splitter.onPattern(" |\u3000").splitToList(mnemonicSequence);
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

    /**
     * Get a seed from this mnemonic.
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
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
        return BIP0039MnemonicUtility.deriveSeed(passwordBytes, mnemonicSequenceBytes);
    }
}
