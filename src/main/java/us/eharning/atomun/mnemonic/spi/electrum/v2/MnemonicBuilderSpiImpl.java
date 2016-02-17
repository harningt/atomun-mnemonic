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

import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.math.BigIntegerMath;
import us.eharning.atomun.mnemonic.ElectrumMnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.api.electrum.v2.ElectrumV2ExtensionIdentifier;
import us.eharning.atomun.mnemonic.api.electrum.v2.VersionPrefix;
import us.eharning.atomun.mnemonic.spi.BuilderParameter;
import us.eharning.atomun.mnemonic.spi.EntropyBuilderParameter;
import us.eharning.atomun.mnemonic.spi.ExtensionBuilderParameter;
import us.eharning.atomun.mnemonic.spi.WordListBuilderParameter;
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary;

import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Service provider for the electrum v2 mnemonic specification.
 */
@Immutable
class MnemonicBuilderSpiImpl extends us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi {
    private static final EntropyBuilderParameter DEFAULT_ENTROPY_PARAMETER = EntropyBuilderParameter.getRandom(128 / 8);
    private static final WordListBuilderParameter DEFAULT_WORDLIST_PARAMETER = WordListBuilderParameter.getWordList("english");
    static final Set<? extends MnemonicExtensionIdentifier> KNOWN_EXTENSION_IDENTIFIERS = ImmutableSet.copyOf(EnumSet.allOf(ElectrumV2ExtensionIdentifier.class));

    /**
     * Construct a new SPI with the given algorithm.
     */
    protected MnemonicBuilderSpiImpl() {
        super(ElectrumMnemonicAlgorithm.ElectrumV2);
    }

    /**
     * Check if the given entropy length is valid.
     *
     * @param entropyLength
     *         number of bytes of entropy.
     *
     * @throws IllegalArgumentException
     *         if the entropyLength is invalid
     */
    private static void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0) {
            throw new IllegalArgumentException("entropyLength must be a positive value");
        }
    }

    /**
     * Checks that the given extension parameter is valid.
     *
     * @param parameter
     *         instance containing extension parameters.
     *
     * @throws IllegalArgumentException
     *         if the parameter contains unknown parameters.
     */
    private static void checkExtensions(ExtensionBuilderParameter parameter) {
        Map<MnemonicExtensionIdentifier, Object> extensions = parameter.getExtensions();
        if (!KNOWN_EXTENSION_IDENTIFIERS.containsAll(extensions.keySet())) {
            Iterable<MnemonicExtensionIdentifier> unknownNames = Iterables.filter(extensions.keySet(), Predicates.not(Predicates.in(KNOWN_EXTENSION_IDENTIFIERS)));
            throw new IllegalArgumentException("Found unhandled extension names: " + Iterables.toString(unknownNames));
        }
        for (Map.Entry<MnemonicExtensionIdentifier, Object> entry: extensions.entrySet()) {
            switch ((ElectrumV2ExtensionIdentifier)entry.getKey()) {
            case CUSTOM_ENTROPY:
                if (!(entry.getValue() instanceof BigInteger)) {
                    throw new IllegalArgumentException("Found unexpected value type for extension: " + entry.getKey() + " " + entry.getValue().getClass());
                }
                BigInteger customEntropy = (BigInteger) entry.getValue();
                if (0 <= BigInteger.ZERO.compareTo(customEntropy)) {
                    throw new IllegalArgumentException("Found illegal value for extension: " + entry.getKey());
                }
                break;
            default:
                /* Never reached */
                break;
            }
        }
    }

    /**
     * Generate the mnemonic sequence given the input parameters.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return the generated mnemonic sequence.
     */
    @Nonnull
    @Override
    public String generateMnemonic(BuilderParameter... parameters) {
        return new BuilderInstance(parameters).generateMnemonic();
    }

    /**
     * Encode this instance to a wrapped mnemonic unit.
     * The default implementation performs a naive generation without optimisation.
     *
     * @param builder
     *         instance to construct MnemonicUnit with.
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return MnemonicUnit instance wrapping build results.
     *
     * @since 0.4.0
     */
    @Override
    @Nonnull
    public MnemonicUnit generateMnemonicUnit(@Nonnull MnemonicUnit.Builder builder, BuilderParameter... parameters) {
        return new BuilderInstance(parameters).generateMnemonicUnit(builder);
    }

    /**
     * Validate the builder parameters.
     *
     * @param parameters
     *         builder parameters to validate.
     *
     * @throws RuntimeException
     *         varieties in case of invalid input.
     */
    @Override
    public void validate(BuilderParameter... parameters) {
        for (BuilderParameter parameter : parameters) {
            if (null == parameter) {
                continue;
            }
            if (parameter instanceof EntropyBuilderParameter) {
                EntropyBuilderParameter entropyBuilder = (EntropyBuilderParameter) parameter;
                if (entropyBuilder.isStatic()) {
                    throw new IllegalArgumentException("Unsupported entropy parameter mode: static");
                }
                checkEntropyLengthValid(entropyBuilder.getEntropyLength());
            } else if (parameter instanceof WordListBuilderParameter) {
                MnemonicUtility.getDictionary(((WordListBuilderParameter) parameter).getWordListIdentifier());
            } else if (parameter instanceof ExtensionBuilderParameter) {
                checkExtensions((ExtensionBuilderParameter) parameter);
            } else {
                throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
            }
        }
    }

    private static class BuilderInstance {
        private static final VersionPrefix DEFAULT_VERSION_PREFIX = VersionPrefix.STANDARD;

        private int entropyLengthBytes = -1;
        private String wordListIdentifier = null;
        private Dictionary dictionary;
        private VersionPrefix versionPrefix = null;

        private BigInteger customEntropy = BigInteger.ONE;
        private BigInteger nonce;
        private BigInteger customGeneratedEntropy;

        public BuilderInstance(BuilderParameter[] parameters) {
            Map<MnemonicExtensionIdentifier, Object> extensions = null;
            for (BuilderParameter parameter : parameters) {
                if (null == parameter) {
                    continue;
                }
                if (parameter instanceof EntropyBuilderParameter) {
                    EntropyBuilderParameter entropyBuilder = (EntropyBuilderParameter) parameter;
                    entropyLengthBytes = entropyBuilder.getEntropyLength();
                } else if (parameter instanceof WordListBuilderParameter) {
                    wordListIdentifier = ((WordListBuilderParameter) parameter).getWordListIdentifier();
                } else if (parameter instanceof ExtensionBuilderParameter) {
                    extensions = ((ExtensionBuilderParameter) parameter).getExtensions();
                } else {
                    throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
                }
            }
            if (entropyLengthBytes < 0) {
                entropyLengthBytes = DEFAULT_ENTROPY_PARAMETER.getEntropyLength();
            }
            if (null == wordListIdentifier) {
                wordListIdentifier = DEFAULT_WORDLIST_PARAMETER.getWordListIdentifier();
            }
            if (null == extensions) {
                extensions = Collections.emptyMap();
            }
            versionPrefix = (VersionPrefix) extensions.get(ElectrumV2ExtensionIdentifier.VERSION_PREFIX);
            if (null == versionPrefix) {
                versionPrefix = DEFAULT_VERSION_PREFIX;
            }
            if (extensions.containsKey(ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY))  {
                customEntropy = (BigInteger) extensions.get(ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY);
            }
            dictionary = MnemonicUtility.getDictionary(wordListIdentifier);
        }

        private void prepareRandomData() {
            /* Based on make_seed algorithm */
            int customEntropyBits = BigIntegerMath.log2(customEntropy, RoundingMode.CEILING);

            int prefixLength = versionPrefix.getValueBitLength();
            int entropyLengthBits = entropyLengthBytes * 8;
            int randomEntropy = Math.max(16, prefixLength + entropyLengthBits - customEntropyBits);
            BigInteger generatedEntropy = new BigInteger(randomEntropy, new SecureRandom());
            /* Algorithm:
             * {
             *      nonce = 1
             *      i = custom_entropy * (generated entropy + nonce)
             *      if (not valid) nonce += 1; retry
             * }
             * {
             *      nonce = 1
             *      i = custom_entropy * generated entropy + custom_entropy * nonce
             *      if (not valid) nonce += 1; retry
             * }
             * {
             *      nonce = custom_entropy
             *      i = custom_entropy * generated entropy + nonce
             *      if (not valid) nonce += custom_entropy; retry
             * }
             * {
             *      customGeneratedEntropy = custom_entropy * generated_entropy
             *      nonce = custom_entropy
             *      i = customGeneratedEntropy + nonce
             *      if (not valid) nonce += custom_entropy; retry
             * }
             */
            /* Start this off with nonce=1 and post-increment */
            nonce = customEntropy;
            customGeneratedEntropy = customEntropy.multiply(generatedEntropy);
        }

        public String generateMnemonic() {
            prepareRandomData();
            while (true) {
                BigInteger value = customGeneratedEntropy.add(nonce);
                String seed = encodeSeed(dictionary, value);
                if (MnemonicUtility.isValidGeneratedSeed(seed, versionPrefix)) {
                    return seed;
                }
                nonce = nonce.add(customEntropy);
            }
        }

        private MnemonicUnit deriveMnemonicUnit(MnemonicUnit.Builder builder, String mnemonicSequence) {
            /* Known prefixes => 1 */
            /* Verify that the seed is normal */
            /* Perform each step independently to permit re-use of pieces */
            if (MnemonicUtility.isOldSeed(mnemonicSequence)) {
                return null;
            }
            byte[] seedVersionData = MnemonicUtility.getSeedVersionBytes(mnemonicSequence);
            if (!versionPrefix.matches(seedVersionData)) {
                return null;
            }
            return MnemonicDecoderSpiImpl.getMnemonicUnit(builder, mnemonicSequence, dictionary, versionPrefix);
        }

        public MnemonicUnit generateMnemonicUnit(MnemonicUnit.Builder builder) {
            prepareRandomData();
            while (true) {
                BigInteger value = customGeneratedEntropy.add(nonce);
                String seed = encodeSeed(dictionary, value);
                MnemonicUnit unit = deriveMnemonicUnit(builder, seed);
                if (null != unit) {
                    return unit;
                }
                nonce = nonce.add(customEntropy);
            }
        }

        private String encodeSeed(Dictionary dictionary, BigInteger value) {
            int[] indexArray = MnemonicIndexGenerator.generateIndices(value, dictionary);
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
    }
}
