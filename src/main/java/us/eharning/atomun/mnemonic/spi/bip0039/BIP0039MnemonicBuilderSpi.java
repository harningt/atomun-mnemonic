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

import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;
import us.eharning.atomun.mnemonic.spi.BuilderParameter;
import us.eharning.atomun.mnemonic.spi.EntropyBuilderParameter;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;
import us.eharning.atomun.mnemonic.spi.WordListBuilderParameter;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Service provider for the BIP0039 mnemonic specification.
 */
@Immutable
class BIP0039MnemonicBuilderSpi extends MnemonicBuilderSpi {
    private static final EntropyBuilderParameter DEFAULT_ENTROPY_PARAMETER
            = EntropyBuilderParameter.getRandom(128 / 8);
    private static final WordListBuilderParameter DEFAULT_WORDLIST_PARAMETER
            = WordListBuilderParameter.getWordList("english");

    /**
     * Construct a new SPI with the given algorithm.
     */
    protected BIP0039MnemonicBuilderSpi() {
        super(MnemonicAlgorithm.BIP0039);
    }

    /**
     * Return if the given entropy length is valid.
     *
     * @param entropyLength
     *         number of bytes of entropy.
     *
     * @throws IllegalArgumentException
     *         if the entropyLength is invalid
     */
    private static void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
        }
    }

    /**
     * Extracts the entropy parameter from parameters, else a default.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return entropy
     */
    @Nonnull
    private static byte[] getParameterEntropy(BuilderParameter... parameters) {
        byte[] entropy = null;
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                entropy = ((EntropyBuilderParameter) parameter).getEntropy();
            } else if (parameter instanceof WordListBuilderParameter) {
                /* Not used */
            } else {
                throw new UnsupportedOperationException("Unsupported parameter type: " + parameter);
            }
        }
        if (null == entropy) {
            /* Use default */
            entropy = DEFAULT_ENTROPY_PARAMETER.getEntropy();
        }
        return entropy;
    }

    /**
     * Extracts the word list parameter from parameters, else a default.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return word list identifier.
     */
    @Nonnull
    private static String getParameterWordListIdentifier(BuilderParameter... parameters) {
        String wordListIdentifier = null;
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                /* Not used */
            } else if (parameter instanceof WordListBuilderParameter) {
                wordListIdentifier = ((WordListBuilderParameter) parameter).getWordListIdentifier();
            } else {
                throw new UnsupportedOperationException("Unsupported parameter type: " + parameter);
            }
        }
        if (null == wordListIdentifier) {
            wordListIdentifier = DEFAULT_WORDLIST_PARAMETER.getWordListIdentifier();
        }
        return wordListIdentifier;
    }

    /**
     * Generates a mnemonic sequence from the provided entropy using the dictionary.
     *
     * @param entropy
     *         value to encode.
     * @param dictionary
     *         dictionary to encode entropy with.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    @Nonnull
    private static String generateMnemonicSequence(@Nonnull byte[] entropy, @Nonnull BidirectionalDictionary dictionary) {
        int[] indexArray = BIP0039MnemonicIndexGenerator.generateIndices(entropy);
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

    /**
     * Generate the mnemonic sequence given the input parameters.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return the generated mnemonic sequence.
     *
     * @since 0.1.0
     */
    @Nonnull
    @Override
    public String generateMnemonic(BuilderParameter... parameters) {
        byte[] entropy = getParameterEntropy(parameters);
        String wordListIdentifier = getParameterWordListIdentifier(parameters);
        BidirectionalDictionary dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
        return generateMnemonicSequence(entropy, dictionary);
    }

    /**
     * Encode this instance to a wrapped mnemonic unit.
     *
     * @param builder
     *         instance to construct MnemonicUnit with.
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return MnemonicUnit instance wrapping build results.
     *
     * @since 0.2.0
     */
    @Nonnull
    @Override
    public MnemonicUnit generateMnemonicUnit(@Nonnull MnemonicUnit.Builder builder, BuilderParameter... parameters) {
        byte[] entropy = getParameterEntropy(parameters);
        String wordListIdentifier = getParameterWordListIdentifier(parameters);
        BidirectionalDictionary dictionary = BIP0039MnemonicUtility.getDictionary(wordListIdentifier);
        String mnemonicSequence = generateMnemonicSequence(entropy, dictionary);

        BIP0039MnemonicUnitSpi spi = BIP0039MnemonicDecoderSpi.getMnemonicUnitSpi(dictionary);
        return spi.build(builder, mnemonicSequence, entropy);
    }

    /**
     * Validate the builder parameters.
     *
     * @param parameters
     *         builder parameters to validate.
     *
     * @throws RuntimeException
     *         varieties in case of invalid input.
     * @since 0.1.0
     */
    @Override
    public void validate(BuilderParameter... parameters) {
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                checkEntropyLengthValid(((EntropyBuilderParameter) parameter).getEntropyLength());
            } else if (parameter instanceof WordListBuilderParameter) {
                BIP0039MnemonicUtility.getDictionary(((WordListBuilderParameter) parameter).getWordListIdentifier());
            } else {
                throw new UnsupportedOperationException("Unsupported parameter type: " + parameter);
            }
        }
    }
}
