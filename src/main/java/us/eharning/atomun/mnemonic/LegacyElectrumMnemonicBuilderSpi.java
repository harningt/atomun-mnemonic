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

/**
 * Service provider for the legacy Electrum mnemonic format.
 */
class LegacyElectrumMnemonicBuilderSpi extends BasicMnemonicBuilderSpi {
    public static final Supplier<MnemonicBuilderSpi> SUPPLIER = new Supplier<MnemonicBuilderSpi>() {
        @Override
        public MnemonicBuilderSpi get() {
            return new LegacyElectrumMnemonicBuilderSpi();
        }
    };

    /**
     * Private constructor to enforce use of SUPPLIER.
     */
    private LegacyElectrumMnemonicBuilderSpi() {
    }

    /**
     * Encode the given entropy to a space-delimited series of mnemonic words.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    @Override
    protected String build(byte[] entropy) {
        return LegacyElectrumMnemonicUtility.toMnemonic(entropy);
    }

    /**
     * Check that a given entropy length is valid.
     *
     * @param entropyLength number of bytes of entropy.
     *
     * @throws java.lang.IllegalArgumentException if the entropyLength is invalid
     */
    @Override
    protected void checkEntropyLengthValid(int entropyLength) {
        if (entropyLength <= 0 || entropyLength % 4 != 0) {
            throw new IllegalArgumentException("entropyLength must be a positive multiple of 4");
        }
    }
}
