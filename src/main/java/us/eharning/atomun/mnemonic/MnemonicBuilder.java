/*
 * Copyright 2014 Thomas Harning Jr. <harningt@gmail.com>
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
import com.google.common.collect.ImmutableMap;

/**
 * Builder API to generate mnemonic sequences.
 */
public final class MnemonicBuilder {
    /**
     * Mapping of algorithms to implementation instance suppliers.
     *
     * May be replaced with a mutable map if custom implementations allowed.
     */
    private static final ImmutableMap<MnemonicAlgorithm, Supplier<MnemonicBuilderSpi>> constructorMap;
    static {
        constructorMap = ImmutableMap.of(
            MnemonicAlgorithm.LegacyElectrum, LegacyElectrumMnemonicBuilderSpi.SUPPLIER
        );
    }

    /**
     * Implementation instance.
     */
    private final MnemonicBuilderSpi spi;

    /**
     * Construct a MnemonicBuilder around the given implementation.
     * @param mnemonicBuilderSpi implementation to wrap.
     */
    private MnemonicBuilder(MnemonicBuilderSpi mnemonicBuilderSpi) {
        this.spi = mnemonicBuilderSpi;
    }

    /**
     * Construct a new MnemonicBuilder for the named algorithm.
     * @param algorithm kind of instance to construct.
     * @return new builder instance.
     */
    public static MnemonicBuilder newBuilder(MnemonicAlgorithm algorithm) {
        Supplier<MnemonicBuilderSpi> supplier = constructorMap.get(algorithm);
        if (null == supplier) {
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm);
        }
        return new MnemonicBuilder(supplier.get());
    }

    /**
     * Encode this instance to a space-delimited series of mnemonic words.
     * @return space-delimited sequence of mnemonic words.
     */
    public String build() {
        return spi.build();
    }

    /**
     * Set a custom property specialized for the given algorithm.
     * @param extensionType kind of builder extension to obtain.
     */
    public <T> T getExtension(Class<T> extensionType) {
        return spi.getExtension(extensionType);
    }

    /**
     * Set the entropy to generate the mnemonic with.
     * @param entropy data to encode.
     */
    public void setEntropy(byte[] entropy) {
        spi.setEntropy(entropy);
    }

    /**
     * Set the length of the desired entropy to generate the mnemonic with.
     * @param entropyLength number of bytes of entropy to use.
     */
    public void setEntropyLength(int entropyLength) {
        spi.setEntropyLength(entropyLength);
    }

    /**
     * Set the word list to use for encoding the mnemonic.
     * @param wordListIdentifier name of the word list to use.
     */
    public void setWordList(String wordListIdentifier) {
        spi.setWordList(wordListIdentifier);
    }
}
