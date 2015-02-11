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
     * Check that a given entropy length is valid.
     *
     * @param entropyLength number of bytes of entropy.
     *
     * @throws IllegalArgumentException if the entropyLength is invalid
     */
    private void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
        }
    }

    @Nonnull
    @Override
    public String generateMnemonic(BuilderParameter... parameters) {
        byte[] entropy = null;
        for (BuilderParameter parameter: parameters) {
            if (parameter instanceof EntropyBuilderParameter) {
                entropy = ((EntropyBuilderParameter)parameter).getEntropy();
            }
        }
        if (null == entropy) {
            /* Use default */
            entropy = DEFAULT_ENTROPY_PARAMETER.getEntropy();
        }
        return LegacyElectrumMnemonicUtility.toMnemonic(entropy);
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
            throw new UnsupportedOperationException("Unsupported parameter type: " + parameter);
        }
    }
}
