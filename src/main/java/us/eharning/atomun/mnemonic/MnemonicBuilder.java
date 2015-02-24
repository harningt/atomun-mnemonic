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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import us.eharning.atomun.mnemonic.spi.*;
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Map;

/**
 * Builder API to generate mnemonic sequences.
 *
 * @since 0.0.1
 */
@NotThreadSafe
public final class MnemonicBuilder {
    private static final ImmutableList<MnemonicServiceProvider> SERVICE_PROVIDERS = ImmutableList.of(
            new LegacyElectrumMnemonicService(),
            new BIP0039MnemonicService()
    );

    /**
     * Implementation instance.
     */
    private final MnemonicBuilderSpi newSpi;

    /* Current known number of parameters - internal detail.
     * Current slot dictates:
     *  1 - entropy
     *  2 - wordList
     *  3 - extensions
     */
    private final BuilderParameter[] parameters = new BuilderParameter[3];

    /**
     * Construct a MnemonicBuilder around the given implementation.
     *
     * @param spi implementation provider.
     */
    private MnemonicBuilder(@Nonnull MnemonicBuilderSpi spi) {
        this.newSpi = spi;
    }

    /**
     * Construct a new MnemonicBuilder for the named algorithm.
     *
     * @param algorithm kind of instance to construct.
     *
     * @return new builder instance.
     *
     * @since 0.0.1
     */
    @Nonnull
    public static MnemonicBuilder newBuilder(@Nonnull MnemonicAlgorithm algorithm) {
        for (MnemonicServiceProvider provider: SERVICE_PROVIDERS) {
            MnemonicBuilderSpi spi = provider.getMnemonicBuilder(algorithm);
            if (null != spi) {
                return new MnemonicBuilder(spi);
            }
        }
        throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm);
    }

    /**
     * Encode this instance to a space-delimited series of mnemonic words.
     *
     * @return space-delimited sequence of mnemonic words.
     *
     * @since 0.0.1
     */
    @Nonnull
    public String build() {
        try {
            newSpi.validate(parameters);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return newSpi.generateMnemonic(parameters);
    }

    /**
     * Encode this instance to a wrapped mnemonic unit.
     *
     * @return MnemonicUnit instance wrapping build results.
     *
     * @since 0.2.0
     */
    @Nonnull
    public MnemonicUnit buildUnit() {
        try {
            newSpi.validate(parameters);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return newSpi.generateMnemonicUnit(parameters);
    }

    /**
     * Set the entropy to generate the mnemonic with.
     *
     * @param entropy data to encode.
     *
     * @return this to allow chaining.
     *
     * @since 0.0.1
     */
    @Nonnull
    public MnemonicBuilder setEntropy(@Nonnull byte[] entropy) {
        parameters[0] = EntropyBuilderParameter.getStatic(entropy);
        newSpi.validate(parameters);
        return this;
    }

    /**
     * Set the length of the desired entropy to generate the mnemonic with.
     *
     * @param entropyLength number of bytes of entropy to use.
     *
     * @return this to allow chaining.
     *
     * @since 0.0.1
     */
    @Nonnull
    public MnemonicBuilder setEntropyLength(int entropyLength) {
        parameters[0] = EntropyBuilderParameter.getRandom(entropyLength);
        newSpi.validate(parameters);
        return this;
    }

    /**
     * Sets extensions for this builder, replacing any prior set extensions.
     *
     * @param extensions map of extension property-to-value elements, algorithm-dependent.
     *
     * @return this to allow chaining.
     *
     * @since 0.1.0
     */
    @Nonnull
    public MnemonicBuilder setExtensions(Map<String, Object> extensions) {
        parameters[2] = ExtensionBuilderParameter.getExtensionsParameter(ImmutableMap.copyOf(extensions));
        newSpi.validate(parameters);
        return this;
    }

    /**
     * Set the word list to use for encoding the mnemonic.
     *
     * @param wordListIdentifier name of the word list to use.
     *
     * @return this to allow chaining.
     *
     * @since 0.0.1
     */
    @Nonnull
    public MnemonicBuilder setWordList(@Nonnull String wordListIdentifier) {
        parameters[1] = WordListBuilderParameter.getWordList(wordListIdentifier);
        newSpi.validate(parameters);
        return this;
    }
}
