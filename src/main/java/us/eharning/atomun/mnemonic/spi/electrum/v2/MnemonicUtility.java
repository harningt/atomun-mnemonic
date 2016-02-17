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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.base.Splitter;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import us.eharning.atomun.core.crypto.PBKDF2;
import us.eharning.atomun.mnemonic.api.electrum.v2.VersionPrefix;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;
import us.eharning.atomun.mnemonic.utility.dictionary.DictionaryIdentifier;
import us.eharning.atomun.mnemonic.utility.dictionary.DictionarySource;

import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.List;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class to support electrum v2 mnemonics.
 */
final class MnemonicUtility {
    private static final List<String> KNOWN_DICTIONARIES = ImmutableList.of(
            "english",
            "japanese",
            "portuguese",
            "spanish"
    );
    private static final DictionaryIdentifier LEGACY_DICTIONARY_IDENTIFIER
            = DictionaryIdentifier.getIdentifier("english", "us/eharning/atomun/mnemonic/spi/electrum/legacy/dictionary.txt");
    private static final int PBKDF_ROUNDS = 2048;
    private static final String PBKDF_MAC = "HmacSHA512";
    private static final int PBKDF_SEED_OUTPUT = 64;
    private static final Pattern DIACRITICAL_MATCH = Pattern.compile("[\\p{M}]+");
    private static final Pattern WHITESPACE_MATCH = Pattern.compile("[\\p{Space}\u3000]");
    private static final CJKCleanupUtility cleanupUtility = new CJKCleanupUtility();

    /**
     * Private unused constructor to mark as utility class.
     */
    private MnemonicUtility() {
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
    static Dictionary getDictionary(@Nonnull String wordListIdentifier) {
        DictionaryIdentifier identifier = DictionaryIdentifier.getIdentifier(wordListIdentifier, "us/eharning/atomun/mnemonic/spi/electrum/v2/" + wordListIdentifier + ".txt");
        return DictionarySource.getDictionary(identifier);
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
    static List<String> getNormalizedWordList(@Nonnull CharSequence mnemonicSequence) {
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
    static Iterable<Dictionary> getDictionaries() {
        Iterable<Dictionary> dictionaryIterable = Iterables.transform(KNOWN_DICTIONARIES, new Function<String, Dictionary>() {
            @Nullable
            @Override
            public Dictionary apply(String input) {
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
     * @param versionPrefix
     *         prefix value that must be at the beginning of the seed version mac
     *
     * @return true if the seed can be interpreted as the v2 format but not the legacy format.
     */
    static boolean isValidGeneratedSeed(CharSequence seed, VersionPrefix versionPrefix) {
        return !isOldSeed(seed) && isNewSeed(seed, versionPrefix);
    }

    /**
     * Utility method to extract the seed version bytes from the seed.
     *
     * @param seed
     *         space-separated list of words to validate.
     *
     * @return byte array with the seed version bytes value
     */
    static byte[] getSeedVersionBytes(CharSequence seed) {
        String normalizedSeed = MnemonicUtility.normalizeSeed(seed);
        byte[] seedBytes = normalizedSeed.getBytes(Charsets.UTF_8);
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec("Seed version".getBytes(Charsets.US_ASCII), "HmacSHA512"));
            return mac.doFinal(seedBytes);
        } catch (GeneralSecurityException e) {
            /* Rethrow this (generally) impossible case */
            throw Throwables.propagate(e);
        }
    }

    /**
     * Utility method to determine if a given seed is of the "new" format.
     *
     * @param seed
     *         space-separated list of words to validate.
     * @param versionPrefix
     *         prefix value that must be at the beginning of the seed version mac
     *
     * @return true if the seed can be interpreted as the v2 format.
     */
    private static boolean isNewSeed(CharSequence seed, VersionPrefix versionPrefix) {
        byte[] macBytes = getSeedVersionBytes(seed);

        return versionPrefix.matches(macBytes);
    }

    /**
     * Utility method to determine if a given seed is of the "old" format.
     *
     * @param seed
     *         space-separated list of words to validate.
     *
     * @return true if the seed can be interpreted as a legacy format.
     */
    public static boolean isOldSeed(CharSequence seed) {
        List<String> words = Splitter.on(WHITESPACE_MATCH).splitToList(seed);
        if (words.size() % 3 != 0) {
            /* Not a multiple of 3 words, not an old seed */
            return false;
        }
        Dictionary legacyDictionary = DictionarySource.getDictionary(LEGACY_DICTIONARY_IDENTIFIER);
        Converter<String, Integer> reverse = legacyDictionary.reverse();
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
