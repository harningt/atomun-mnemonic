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

import com.google.common.base.Converter;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.MoreMnemonicExtensionIdentifiers;
import us.eharning.atomun.mnemonic.api.electrum.v2.ElectrumV2ExtensionIdentifier;
import us.eharning.atomun.mnemonic.api.electrum.v2.VersionPrefix;
import us.eharning.atomun.mnemonic.spi.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Decoder system for the electrum v2 mnemonic system.
 */
@Immutable
class MnemonicDecoderSpiImpl extends MnemonicDecoderSpi {
    private static final ConcurrentMap<String, MnemonicUnitSpiImpl> WORD_LIST_SPI = new ConcurrentHashMap<>();

    private static final byte[] STANDARD_PREFIX = new byte[] { 0x01 };
    private static final byte[] STANDARD_PREFIX_MASK = new byte[] { (byte)0xFF };
    private static final Set<MnemonicExtensionIdentifier> SUPPORTED_READABLE_EXTENSIONS;

    static {
        SUPPORTED_READABLE_EXTENSIONS = MoreMnemonicExtensionIdentifiers.canGet(ElectrumV2ExtensionIdentifier.values());
    }

    /**
     * Detect the appropriate word list for the given mnemonic sequence.
     *
     * @param mnemonicWordList
     *         sequence of mnemonic words to match up against a dictionary.
     *
     * @return a dictionary instance if found, else null.
     */
    @CheckForNull
    private static Dictionary detectWordList(@Nonnull List<String> mnemonicWordList) {
        /* Need to autodetect the word list from the sequence. */
        for (Dictionary availableDictionary : MnemonicUtility.getDictionaries()) {
            /* Check that all the words are in the dictionary and if so, found */
            if (verifyDictionary(availableDictionary, mnemonicWordList)) {
                return availableDictionary;
            }
        }
        return null;
    }

    /**
     * Verify that the dictionary contains all of the words in the given mnemonic sequence.
     *
     * @param dictionary
     *         instance to check for the presence of all words.
     * @param mnemonicWordList
     *         sequence of mnemonic words to match up against a dictionary.
     *
     * @return true if dictionary contains all words in mnemonicWordList.
     */
    private static boolean verifyDictionary(@Nonnull Dictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        Converter<String, Integer> reverseDictionary = dictionary.reverse();
        /* Due to inability for converters to return null as a valid response, need to catch thrown exception */
        try {
            for (String word : mnemonicWordList) {
                reverseDictionary.convert(word);
            }
        } catch (IllegalArgumentException ignored) {
            return false;
        }
        return true;
    }

    /**
     * Decodes a given mnemonic into a unit.
     * The word list is to be automatically detected and it is expected that only one matches.
     *
     * @param builder
     *         instance maker.
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
     * @param wordListIdentifier
     *         optional word list identifier.
     *
     * @return mnemonic unit.
     *
     * @throws IllegalArgumentException
     *         the sequence cannot match
     */
    @Nonnull
    @Override
    public MnemonicUnit decode(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
        /* Known prefixes => 1 */
        /* Verify that the seed is normal */
        /* Perform each step independently to permit re-use of pieces */
        if (MnemonicUtility.isOldSeed(mnemonicSequence)) {
            throw new IllegalArgumentException("Mnemonic does not have the expected seed version");
        }
        byte[] seedVersionData;
        try {
            seedVersionData = MnemonicUtility.getSeedVersionBytes(mnemonicSequence);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to calculate the seed version data", e);
        }
        VersionPrefix versionPrefix = null;
        for (VersionPrefix testVersionPrefix: VersionPrefix.values()) {
            if (testVersionPrefix.matches(seedVersionData)) {
                versionPrefix = testVersionPrefix;
                break;
            }
        }
        if (null == versionPrefix) {
            throw new IllegalArgumentException("Mnemonic does not have the expected seed version");
        }
        List<String> mnemonicWordList = MnemonicUtility.getNormalizedWordList(mnemonicSequence);
        Dictionary dictionary;
        if (null == wordListIdentifier) {
            dictionary = detectWordList(mnemonicWordList);
            if (null == dictionary) {
                throw new IllegalArgumentException("Could not detect dictionary for words");
            }
        } else {
            dictionary = MnemonicUtility.getDictionary(wordListIdentifier);
            if (!verifyDictionary(dictionary, mnemonicWordList)) {
                throw new IllegalArgumentException("Words not in dictionary");
            }
        }

        return getMnemonicUnit(builder, mnemonicSequence, dictionary, versionPrefix);
    }

    /**
     * Static utility method to factor value construction.
     *
     * @param builder
     *         instance maker.
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
     * @param dictionary
     *         word list dictionary.
     * @param versionPrefix
     *         detected sequence version.
     *
     * @return mnemonic unit.
     */
    @Nonnull
    static MnemonicUnit getMnemonicUnit(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nonnull Dictionary dictionary, @Nonnull VersionPrefix versionPrefix) {
        String wordListIdentifier = dictionary.getWordListIdentifier();
        MnemonicUnitSpiImpl unit = WORD_LIST_SPI.get(wordListIdentifier);
        if (null == unit) {
            unit = new MnemonicUnitSpiImpl(dictionary);
            WORD_LIST_SPI.putIfAbsent(wordListIdentifier, unit);
        }

        byte[] entropy = unit.getEntropy(mnemonicSequence);
        return unit.build(builder, mnemonicSequence, entropy, SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(versionPrefix));
    }
}
