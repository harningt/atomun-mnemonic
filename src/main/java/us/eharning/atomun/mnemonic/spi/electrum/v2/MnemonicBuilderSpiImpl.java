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
import com.google.common.base.Predicates;
import com.google.common.base.Verify;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.math.BigIntegerMath;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.spi.BidirectionalDictionary;
import us.eharning.atomun.mnemonic.spi.BuilderParameter;
import us.eharning.atomun.mnemonic.spi.EntropyBuilderParameter;
import us.eharning.atomun.mnemonic.spi.ExtensionBuilderParameter;
import us.eharning.atomun.mnemonic.spi.WordListBuilderParameter;

import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Service provider for the electrum v2 mnemonic specification.
 */
@Immutable
class MnemonicBuilderSpiImpl extends us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi {
    private static final EntropyBuilderParameter DEFAULT_ENTROPY_PARAMETER = EntropyBuilderParameter.getRandom(128 / 8);
    private static final WordListBuilderParameter DEFAULT_WORDLIST_PARAMETER = WordListBuilderParameter.getWordList("english");
    private static final Set<String> KNOWN_EXTENSION_NAMES = ElectrumV2Constants.KNOWN_EXTENSION_NAMES;
    private static final Set<String> CJK_IDENTIFIER_SET = ImmutableSet.of("japanese");
    private static final Pattern DIACRITICAL_MATCH = Pattern.compile("[\\p{InCombiningDiacriticalMarks}]+");
    private static final Pattern WHITESPACE_MATCH = Pattern.compile("[\\p{Space}]");

    /**
     * Construct a new SPI with the given algorithm.
     */
    protected MnemonicBuilderSpiImpl() {
        super(MnemonicAlgorithm.ElectrumV2);
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
        /* TODO: validate/define */
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
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
    private static void checkExtensionNames(ExtensionBuilderParameter parameter) {
        Map<String, Object> extensions = parameter.getExtensions();
        if (!KNOWN_EXTENSION_NAMES.containsAll(extensions.keySet())) {
            Iterable<String> unknownNames = Iterables.filter(extensions.keySet(), Predicates.not(Predicates.in(KNOWN_EXTENSION_NAMES)));
            throw new IllegalArgumentException("Found unhandled extension names: " + Iterables.toString(unknownNames));
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
        int entropyLengthBytes = -1;
        String wordListIdentifier = null;
        Map<String, Object> extensions = null;
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
        /* DUMMY */
        Verify.verifyNotNull(extensions);
        BidirectionalDictionary dictionary = MnemonicUtility.getDictionary(wordListIdentifier);

        BigInteger customEntropy = BigInteger.ONE;
        /* Based on make_seed algorithm */
        int customEntropyBits = BigIntegerMath.log2(customEntropy, RoundingMode.CEILING);
        /* Prefix is a sequence of nibbles, technically we can construct partial-byte
         * prefixes by using a nice mask. */
        byte[] prefix = {0x01};
        byte[] prefixMask = {(byte) 0xFF};
        int prefixLength = prefix.length * 8;
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
        BigInteger nonce = customEntropy;
        BigInteger customGeneratedEntropy = customEntropy.multiply(generatedEntropy);
        while (true) {
            BigInteger value = customGeneratedEntropy.add(nonce);
            String seed = encodeSeed(dictionary, value);
            if (MnemonicUtility.isValidGeneratedSeed(seed, prefix, prefixMask)) {
                return seed;
            }
            nonce = nonce.add(customEntropy);
        }
    }

    private boolean isValidGeneratedSeed(String seed, String wordListIdentifier, byte[] prefix, byte[] prefixMask) {
        return !isOldSeed(seed) && isNewSeed(seed, wordListIdentifier, prefix, prefixMask);
    }

    private boolean isNewSeed(String seed, String wordListIdentifier, byte[] prefix, byte[] prefixMask) {
        seed = normalizeSeed(seed, wordListIdentifier);
        byte[] seedBytes = seed.getBytes(Charsets.UTF_8);
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec("Seed version".getBytes(Charsets.US_ASCII), "HmacSHA512"));
            byte[] macBytes = mac.doFinal(seedBytes);

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
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    private String normalizeSeed(String seed, String wordListIdentifier) {
        seed = Normalizer.normalize(seed, Normalizer.Form.NFKD);
        seed = seed.toLowerCase();
        seed = DIACRITICAL_MATCH.matcher(seed).replaceAll("");

        /* Alternate option if Regex too slow or incorrect */
        //seed = Joiner.on(' ').join(Splitter.on(CharMatcher.WHITESPACE).split(seed));
        if (CJK_IDENTIFIER_SET.contains(wordListIdentifier)) {
            /* CJK drops all whitespace */
            seed = WHITESPACE_MATCH.matcher(seed).replaceAll("");
        } else {
            seed = WHITESPACE_MATCH.matcher(seed).replaceAll(" ");
        }

        return seed;
    }

    private boolean isOldSeed(String seed) {
        return false;
    }

    private String encodeSeed(BidirectionalDictionary dictionary, BigInteger value) {
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
                checkExtensionNames((ExtensionBuilderParameter) parameter);
            } else {
                throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
            }
        }
    }
}
