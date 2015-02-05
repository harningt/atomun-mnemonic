package us.eharning.atomun.mnemonic.spi.bip0039;

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Splitter;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.MnemonicUnitSpi;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;

import java.text.Normalizer;
import java.util.List;

/**
 * Internal class to implement the BIP0039 mnemonic details.
 */
class BIP0039MnemonicUnitSpi extends MnemonicUnitSpi {
    private final BidirectionalDictionary dictionary;

    public BIP0039MnemonicUnitSpi(BidirectionalDictionary dictionary) {
        this.dictionary = dictionary;
    }

    private static boolean[] mnemonicToBits(BidirectionalDictionary dictionary, List<String> mnemonicWordList) {
        /* Each word represents 11 bits of entropy (2^11 => 2048 words) */
        int mnemonicSentenceBitCount = mnemonicWordList.size() * 11;
        boolean[] mnemonicSentenceBits = new boolean[mnemonicSentenceBitCount];
        int bitIndex = 0;
        Converter<String, Integer> reverseConverter = dictionary.reverse();
        for (String word: mnemonicWordList) {
            /* Find the word index in the wordList. */
            int index = reverseConverter.convert(word);

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
    @Override
    public byte[] getEntropy(CharSequence mnemonicSequence) {
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
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     */
    @Override
    public byte[] getSeed(CharSequence mnemonicSequence, CharSequence password) {
        byte[] mnemonicSequenceBytes = Normalizer.normalize(mnemonicSequence, Normalizer.Form.NFKD).getBytes(Charsets.UTF_8);

        /* Normalize the password and get the UTF-8 bytes. */
        String normalizedPassword = "mnemonic";
        if (null != password && 0 != password.length()) {
            normalizedPassword = normalizedPassword + Normalizer.normalize(password, Normalizer.Form.NFKD);
        }
        byte[] passwordBytes = normalizedPassword.getBytes(Charsets.UTF_8);
        return BIP0039MnemonicUtility.deriveSeed(passwordBytes, mnemonicSequenceBytes);
    }

    public MnemonicUnit build(CharSequence mnemonicSequence, byte[] entropy) {
        return super.build(mnemonicSequence, entropy, null, null);
    }

}
