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

import com.google.common.base.Supplier;

/**
 * Service provider for the BIP0039 mnemonic specification.
 */
class BIP0039MnemonicBuilderSpi extends BasicMnemonicBuilderSpi {
    public static final Supplier<MnemonicBuilderSpi> SUPPLIER = new Supplier<MnemonicBuilderSpi>() {
        @Override
        public MnemonicBuilderSpi get() {
            return new BIP0039MnemonicBuilderSpi();
        }
    };
    private static final String DEFAULT_DICTIONARY = "english";
    private BidirectionalDictionary dictionary;

    private BIP0039MnemonicBuilderSpi() {
        dictionary = BIP0039MnemonicUtility.getDictionary(DEFAULT_DICTIONARY);
    }

    /**
     * Encode the given entropy to a space-delimited series of mnemonic words.
     *
     * @param entropy source entropy data.
     * @return space-delimited sequence of mnemonic words.
     */
    @Override
    protected String build(byte[] entropy) {
        int[] indexArray = BIP0039MnemonicIndexGenerators.OPTIMAL_GENERATOR.generateIndices(entropy);
        StringBuilder mnemonicSentence = new StringBuilder();
        for (int i = 0; i < indexArray.length; i++) {
            String word = dictionary.doForward(indexArray[i]);
            if (i != 0) {
                mnemonicSentence.append(' ');
            }
            mnemonicSentence.append(word);
        }
        return mnemonicSentence.toString();
    }

    /**
     * Return if the given entropy length is valid.
     *
     * @param entropyLength number of bytes of entropy.
     * @throws IllegalArgumentException if the entropyLength is invalid
     */
    @Override
    protected void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
        }
    }

    /**
     * Set the word list to use for encoding the mnemonic.
     * <p/>
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param wordListIdentifier name of the word list to use.
     */
    @Override
    public void setWordList(String wordListIdentifier) {
        dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
    }
}
