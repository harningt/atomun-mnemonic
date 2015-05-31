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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Function;
import com.google.common.base.MoreObjects;
import com.google.common.base.Predicates;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;
import us.eharning.atomun.mnemonic.spi.PBKDF2;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class to support electrum v2 mnemonics.
 */
class MnemonicUtility {
    private static final List<String> KNOWN_DICTIONARIES = ImmutableList.of(
            "english",
            "japanese",
            "portuguese",
            "spanish"
    );
    private static final ConcurrentMap<String, BidirectionalDictionary> dictionaries = new ConcurrentHashMap<>();
    private static final BidirectionalDictionary LEGACY_DICTIONARY;
    private static final int PBKDF_ROUNDS = 2048;
    private static final String PBKDF_MAC = "HmacSHA512";
    private static final int PBKDF_SEED_OUTPUT = 64;
    private static Pattern DIACRITICAL_MATCH = Pattern.compile("[\\p{M}]+");
    private static Pattern WHITESPACE_MATCH = Pattern.compile("[\\p{Space}\u3000]");
    private static CJKCleanupUtility cleanupUtility = new CJKCleanupUtility();

    static {
        try {
            LEGACY_DICTIONARY = new BidirectionalDictionary(LegacyElectrumMnemonicService.class.getResource("dictionary.txt"), "english");
        } catch (IOException e) {
            throw new Error("Failed to read dictionary.txt for initialization", e);
        }
    }


    /**
     * Utility method to obtain a dictionary given the wordListIdentifier.
     *
     * @param wordListIdentifier
     *         name of the word list to retrieve.
     *
     * @return dictionary for the given word list.
     *
     * @throws IllegalArgumentException
     *         If the word list cannot be found/loaded.
     */
    @Nonnull
    static BidirectionalDictionary getDictionary(@Nonnull String wordListIdentifier) {
        BidirectionalDictionary dictionary = dictionaries.get(wordListIdentifier);
        if (null == dictionary) {
            URL dictionaryLocation = MnemonicUtility.class.getResource(wordListIdentifier + ".txt");
            if (dictionaryLocation == null) {
                throw new IllegalArgumentException("Unknown wordListIdentifier requested");
            }
            try {
                dictionary = new BidirectionalDictionary(dictionaryLocation, wordListIdentifier);
            } catch (IOException e) {
                throw new IllegalArgumentException("Inaccessible wordListIdentifier requested");
            }
            /* Use the value found in the map just in case 2 created to prevent multiple copies */
            dictionary = MoreObjects.firstNonNull(dictionaries.putIfAbsent(wordListIdentifier, dictionary), dictionary);
        }
        return dictionary;
    }

    /**
     * Get normalized list of split words.
     *
     * @param mnemonicSequence
     *         space-separated list of words to split/normalize.
     *
     * @return list of normalized words.
     */
    @Nonnull
    public static List<String> getNormalizedWordList(@Nonnull CharSequence mnemonicSequence) {
        /* Normalize after splitting due to wide spaces getting normalized into space+widener */
        List<String> mnemonicWordList = Splitter.onPattern(" |\u3000").splitToList(mnemonicSequence);
        return Lists.transform(mnemonicWordList, new Function<String, String>() {
            @Nullable
            @Override
            public String apply(@Nullable String input) {
                if (null == input) {
                    return null;
                }
                return Normalizer.normalize(input, Normalizer.Form.NFKD);
            }
        });
    }

    /**
     * Utility method to derive a seed given the password and processed mnemonic sequence.
     *
     * @param passwordBytes
     *         UTF-8 byte sequence representing the password to use.
     * @param mnemonicSequenceBytes
     *         UTF-8 byte sequence representing the mnemonic sequence.
     *
     * @return 64-byte seed value
     *
     * @throws Error
     *         if the Mac cannot be found (should not happen).
     */
    @Nonnull
    static byte[] deriveSeed(@Nonnull byte[] passwordBytes, @Nonnull byte[] mnemonicSequenceBytes) {
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
    @Nonnull
    static Iterable<BidirectionalDictionary> getDictionaries() {
        Iterable<BidirectionalDictionary> dictionaryIterable = Iterables.transform(KNOWN_DICTIONARIES, new Function<String, BidirectionalDictionary>() {
            @Nullable
            @Override
            public BidirectionalDictionary apply(String input) {
                if (null == input) {
                    return null;
                }
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

    /**
     * Utility method to normalize the seed according to the specification.
     *
     * @param seed
     *         data to normalize.
     *
     * @return normalized data.
     */
    static String normalizeSeed(CharSequence seed) {
        String normalizedSeed = Normalizer.normalize(seed, Normalizer.Form.NFKD);
        normalizedSeed = normalizedSeed.toLowerCase();
        normalizedSeed = DIACRITICAL_MATCH.matcher(normalizedSeed).replaceAll("");
        normalizedSeed = WHITESPACE_MATCH.matcher(normalizedSeed).replaceAll(" ");
        normalizedSeed = cleanupUtility.cleanup(normalizedSeed);

        return normalizedSeed;
    }

    /**
     * Utility method to check that the given seed is a valid v2 seed.
     *
     * @param seed
     *         space-separated list of words to validate.
     * @param prefix
     *         bytes that must be at the beginning of the seed version mac
     * @param prefixMask
     *         byte-mask to apply to the data bytes to best handle prefixes not a multiple of 8 bits
     *
     * @return true if the seed can be interpreted as the v2 format but not the legacy format.
     */
    public static boolean isValidGeneratedSeed(CharSequence seed, byte[] prefix, byte[] prefixMask) {
        return !isOldSeed(seed) && isNewSeed(seed, prefix, prefixMask);
    }

    /**
     * Utility method to extract the seed version bytes from the seed.
     *
     * @param seed
     *         space-separated list of words to validate.
     *
     * @return byte array with the seed version bytes value
     */
    static byte[] getSeedVersionBytes(CharSequence seed) throws GeneralSecurityException {
        String normalizedSeed = MnemonicUtility.normalizeSeed(seed);
        byte[] seedBytes = normalizedSeed.getBytes(Charsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec("Seed version".getBytes(Charsets.US_ASCII), "HmacSHA512"));
        return mac.doFinal(seedBytes);
    }

    /**
     * Utility method to determine if a given seed is of the "old" format.
     *
     * @param seed
     *         space-separated list of words to validate.
     * @param prefix
     *         bytes that must be at the beginning of the seed version mac
     * @param prefixMask
     *         byte-mask to apply to the data bytes to best handle prefixes not a multiple of 8 bits
     *
     * @return true if the seed can be interpreted as the v2 format.
     */
    private static boolean isNewSeed(CharSequence seed, byte[] prefix, byte[] prefixMask) {
        try {
            byte[] macBytes = getSeedVersionBytes(seed);

            /* Check the mask bytes */
            if (prefix.length > macBytes.length) {
                return false;
            }
            for (int i = 0; i < prefix.length; i++) {
                /* NOTE: mask presumed to already be applied to prefix */
                if (prefix[i] != (prefixMask[i] & macBytes[i])) {
                    return false;
                }
            }
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Utility method to determine if a given seed is of the "old" format.
     *
     * @param seed
     *         space-separated list of words to validate.
     *
     * @return true if the seed can be interpreted as a legacy format.
     */
    private static boolean isOldSeed(CharSequence seed) {
        List<String> words = Splitter.on(WHITESPACE_MATCH).splitToList(seed);
        if (words.size() % 3 != 0) {
            /* Not a multiple of 3 words, not an old seed */
            return false;
        }
        Converter<String, Integer> reverse = LEGACY_DICTIONARY.reverse();
        try {
            for (String word : words) {
                reverse.convert(word);
            }
        } catch (IllegalArgumentException ignored) {
            return false;
        }
        /* All words were found and there were a multiple of 3 */
        return true;
    }

}
