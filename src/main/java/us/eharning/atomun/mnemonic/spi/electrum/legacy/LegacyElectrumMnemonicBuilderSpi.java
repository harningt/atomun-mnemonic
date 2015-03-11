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

package us.eharning.atomun.mnemonic.spi.electrum.legacy;

import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.spi.BuilderParameter;
import us.eharning.atomun.mnemonic.spi.EntropyBuilderParameter;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Service provider for the legacy Electrum mnemonic format.
 */
@Immutable
class LegacyElectrumMnemonicBuilderSpi extends MnemonicBuilderSpi {
    private static final EntropyBuilderParameter DEFAULT_ENTROPY_PARAMETER = EntropyBuilderParameter.getRandom(128 / 8);

    /**
     * Construct a new SPI with the given algorithm.
     */
    protected LegacyElectrumMnemonicBuilderSpi() {
        super(MnemonicAlgorithm.LegacyElectrum);
    }

    /**
     * Check that a given entropy length is valid.
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
        return LegacyElectrumMnemonicUtility.toMnemonic(entropy);
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
     * @since 0.2.0
     */
    @Nonnull
    @Override
    public MnemonicUnit generateMnemonicUnit(@Nonnull MnemonicUnit.Builder builder, BuilderParameter... parameters) {
        byte[] entropy = getParameterEntropy(parameters);
        String mnemonicSequence = LegacyElectrumMnemonicUtility.toMnemonic(entropy);
        return LegacyElectrumMnemonicDecoderSpi.SPI.build(builder, mnemonicSequence, entropy);
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
                continue;
            }
            throw new IllegalArgumentException("Unsupported parameter type: " + parameter);
        }
    }
}
