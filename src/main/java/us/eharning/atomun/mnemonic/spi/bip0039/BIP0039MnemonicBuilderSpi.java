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

import us.eharning.atomun.mnemonic.spi.*;

/**
 * Service provider for the BIP0039 mnemonic specification.
 */
class BIP0039MnemonicBuilderSpi extends MnemonicBuilderSpi {
    private static final EntropyBuilderParameter DEFAULT_ENTROPY_PARAMETER = EntropyBuilderParameter.getRandom(128 / 8);
    private static final WordListBuilderParameter DEFAULT_WORDLIST_PARAMETER = WordListBuilderParameter.getWordList("english");

    /**
     * Return if the given entropy length is valid.
     *
     * @param entropyLength number of bytes of entropy.
     * @throws IllegalArgumentException if the entropyLength is invalid
     */
    private void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
        }
    }

    @Override
    public String generateMnemonic(BuilderParameter... parameters) {
        byte[] entropy = null;
        String wordListIdentifier = null;
        for (BuilderParameter parameter: parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                entropy = ((EntropyBuilderParameter)parameter).getEntropy();
                continue;
            }
            if (parameter instanceof WordListBuilderParameter) {
                wordListIdentifier = ((WordListBuilderParameter)parameter).getWordListIdentifier();
                continue;
            }
        }
        if (null == entropy) {
            /* Use default */
            entropy = DEFAULT_ENTROPY_PARAMETER.getEntropy();
        }
        if (null == wordListIdentifier) {
            wordListIdentifier = DEFAULT_WORDLIST_PARAMETER.getWordListIdentifier();
        }
        BidirectionalDictionary dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
        int[] indexArray = BIP0039MnemonicIndexGenerators.OPTIMAL_GENERATOR.generateIndices(entropy);
        StringBuilder mnemonicSentence = new StringBuilder();
        for (int i = 0; i < indexArray.length; i++) {
            String word = dictionary.convert(indexArray[i]);
            if (i != 0) {
                mnemonicSentence.append(' ');
            }
            mnemonicSentence.append(word);
        }
        return mnemonicSentence.toString();
    }

    @Override
    public void validate(BuilderParameter... parameters) {
        for (BuilderParameter parameter: parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                checkEntropyLengthValid(((EntropyBuilderParameter) parameter).getEntropyLength());
                continue;
            }
            if (parameter instanceof WordListBuilderParameter) {
                BIP0039MnemonicUtility.getDictionary(((WordListBuilderParameter)parameter).getWordListIdentifier());
                continue;
            }
            throw new UnsupportedOperationException("Unsupported parameter type: " + parameter);
        }
    }
}
