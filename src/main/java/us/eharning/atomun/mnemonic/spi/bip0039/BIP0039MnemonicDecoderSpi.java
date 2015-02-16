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

import com.google.common.base.Converter;
import com.google.common.base.Splitter;
import us.eharning.atomun.mnemonic.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Decoder system for the BIP0039 mnemonic system.
 *
 * Thanks to the BitcoinJ project for inspiration of the boolean-array based decoder.
 */
@Immutable
class BIP0039MnemonicDecoderSpi extends MnemonicDecoderSpi {
    private static final ConcurrentMap<String, BIP0039MnemonicUnitSpi> WORD_LIST_SPI = new ConcurrentHashMap<>();

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
    @Nonnull
    @Override
    public MnemonicUnit decode(@Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
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
            wordListIdentifier = dictionary.getWordListIdentifier();
        } else {
            dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
            if (!verifyDictionary(dictionary, mnemonicWordList)) {
                throw new IllegalArgumentException("Words not in dictionary");
            }
        }

        BIP0039MnemonicUnitSpi unit = WORD_LIST_SPI.get(wordListIdentifier);
        if (null == unit) {
            unit = new BIP0039MnemonicUnitSpi(dictionary);
            WORD_LIST_SPI.putIfAbsent(wordListIdentifier, unit);
        }

        byte[] entropy = unit.getEntropy(mnemonicSequence);
        return unit.build(mnemonicSequence, entropy);
    }

    /**
     * Detect the appropriate word list for the given mnemonic sequence.
     *
     * @param mnemonicWordList sequence of mnemonic words to match up against a dictionary.
     *
     * @return a dictionary instance if found, else null.
     */
    @CheckForNull
    private static BidirectionalDictionary detectWordList(@Nonnull List<String> mnemonicWordList) {
    /* Need to autodetect the word list from the sequence. */
        for (BidirectionalDictionary availableDictionary: BIP0039MnemonicUtility.getDictionaries()) {
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
     * @param dictionary instance to check for the presence of all words.
     * @param mnemonicWordList sequence of mnemonic words to match up against a dictionary.
     *
     * @return true if dictionary contains all words in mnemonicWordList.
     */
    private static boolean verifyDictionary(@Nonnull BidirectionalDictionary dictionary, @Nonnull List<String> mnemonicWordList) {
        Converter<String, Integer> reverseDictionary = dictionary.reverse();
        /* Due to inability for converters to return null as a valid response, need to catch thrown exception */
        try {
            for (String word: mnemonicWordList) {
                reverseDictionary.convert(word);
            }
        } catch (IllegalArgumentException ignored) {
            return false;
        }
        return true;
    }
}
