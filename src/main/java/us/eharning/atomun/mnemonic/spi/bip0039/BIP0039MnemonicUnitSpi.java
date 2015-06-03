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
import com.google.common.collect.ImmutableMap;
import com.tomgibara.crinch.bits.BitWriter;
import com.tomgibara.crinch.bits.ByteArrayBitWriter;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;
import us.eharning.atomun.mnemonic.spi.MnemonicUnitSpi;

import java.text.Normalizer;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Internal class to implement the BIP0039 mnemonic details.
 */
@Immutable
class BIP0039MnemonicUnitSpi extends MnemonicUnitSpi {
    private final BidirectionalDictionary dictionary;

    /**
     * Construct a BIP0039 decoder SPI instance for the given dictionary.
     *
     * @param dictionary
     *         instance to match mnemonic words against.
     */
    public BIP0039MnemonicUnitSpi(@Nonnull BidirectionalDictionary dictionary) {
        super(MnemonicAlgorithm.BIP0039);
        this.dictionary = dictionary;
    }

    /**
     * Convert a sequence of mnemonic word into a bit array for validation and usage.
     *
     * @param dictionary
     *         instance to check for the presence of all words.
     * @param mnemonicWordList
     *         sequence of mnemonic words to map against a dictionary for bit values.
     *
     * @return sequence of bytes based on word list.
     */
    @Nonnull
    private static byte[] mnemonicToBytes(@Nonnull BidirectionalDictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        /* Each word represents 11 bits of entropy (2^11 => 2048 words) */
        int mnemonicSentenceBitCount = mnemonicWordList.size() * 11;
        int mnemonicSentenceByteCount = (mnemonicSentenceBitCount + 7) / 8;

        byte[] mnemonicSentenceBytes = new byte[mnemonicSentenceByteCount];
        BitWriter bitWriter = new ByteArrayBitWriter(mnemonicSentenceBytes);
        Converter<String, Integer> reverseConverter = dictionary.reverse();
        for (String word : mnemonicWordList) {
            /* Find the word index in the wordList. */
            /* Warning suppressed due to word guaranteed non-null */
            //noinspection ConstantConditions
            int index = reverseConverter.convert(word);

            bitWriter.write(index, 11);
        }
        bitWriter.flush();
        return mnemonicSentenceBytes;
    }

    /**
     * Extract the entropy portion from the mnemonic sentence bits as a byte array.
     *
     * @param mnemonicSentenceBytes
     *         container of entropy bytes.
     * @param mnemonicSentenceBitCount
     *         number of bits representative of sequence.
     *
     * @return array of bytes containing the entropy.
     */
    @Nonnull
    private static byte[] extractEntropy(@Nonnull byte[] mnemonicSentenceBytes, int mnemonicSentenceBitCount) {
        int checksumBitCount = mnemonicSentenceBitCount / 33;
        int entropyBitCount = mnemonicSentenceBytes.length * 8 - checksumBitCount;

        /* Extract original entropy as bytes. */
        byte[] entropy = new byte[entropyBitCount / 8];
        System.arraycopy(mnemonicSentenceBytes, 0, entropy, 0, entropy.length);
        return entropy;
    }

    /**
     * Verify that the entropy matches the checksum embedded in the mnemonic sentence bits.
     *
     * @param entropy
     *         bytes to validate checksum of.
     * @param mnemonicSentenceBytes
     *         container of checksum bits.
     *
     * @return true if the checksum matches, else false.
     */
    private static boolean verifyEntropyMatch(byte[] entropy, byte[] mnemonicSentenceBytes, int mnemonicSentenceBitCount) {
        int checksumBitCount = mnemonicSentenceBitCount / 32;
        // Take the digest of the entropy.
        byte[] hash = BIP0039MnemonicUtility.sha256digest(entropy);

        /* TODO: Optimize hash check to use masks to bulk check. */
        for (int i = 0; i < checksumBitCount; ++i) {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            if ((mnemonicSentenceBytes[entropy.length + byteIndex] & (1 << (7 - bitIndex))) != ((hash[byteIndex] & (1 << (7 - bitIndex))))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Utility method to generate a MnemonicUnit wrapping the given sequence and entropy.
     *
     * @param builder
     *         instance maker.
     * @param mnemonicSequence
     *         sequence.
     * @param entropy
     *         derived copy of entropy.
     *
     * @return wrapped instance.
     */
    @Nonnull
    public MnemonicUnit build(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nonnull byte[] entropy) {
        return super.build(builder, mnemonicSequence, entropy, entropy, ImmutableMap.<MnemonicExtensionIdentifier, Object>of());

    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence
     *         sequence to derive entropy from.
     *
     * @return a derived copy of the entropy byte array.
     */
    @Nonnull
    @Override
    public byte[] getEntropy(@Nonnull CharSequence mnemonicSequence) {
        List<String> mnemonicWordList = BIP0039MnemonicUtility.getNormalizedWordList(mnemonicSequence);
        int mnemonicSentenceBitCount = mnemonicWordList.size() * 11;
        byte[] mnemonicSentenceBytes = mnemonicToBytes(dictionary, mnemonicWordList);

        /* Extract from the bits the entropy prefix */
        byte[] entropy = extractEntropy(mnemonicSentenceBytes, mnemonicSentenceBitCount);

        /* Verify that the word list is valid using the checksum at the end of the data */
        if (!verifyEntropyMatch(entropy, mnemonicSentenceBytes, mnemonicSentenceBitCount)) {
            throw new IllegalArgumentException("Checksum does not match");
        }
        return entropy;
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
        return BIP0039MnemonicUtility.deriveSeed(passwordBytes, mnemonicSequenceBytes);
    }
}
