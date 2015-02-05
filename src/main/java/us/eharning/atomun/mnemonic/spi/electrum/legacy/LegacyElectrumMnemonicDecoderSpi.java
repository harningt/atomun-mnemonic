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

import us.eharning.atomun.mnemonic.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.MnemonicUnit;

/**
 * Decoder system for the legacy Electrum mnemonic system.
 */
class LegacyElectrumMnemonicDecoderSpi extends MnemonicDecoderSpi {
    private static final LegacyElectrumMnemonicUnitSpi SPI = new LegacyElectrumMnemonicUnitSpi();

    /**
     * Decodes a given mnemonic into a unit.
     * The word list is to be automatically detected and it is expected that only one matches.
     *
     * @param mnemonicSequence   space-delimited sequence of mnemonic words.
     * @param wordListIdentifier optional word list identifier
     *
     * @return mnemonic unit
     *
     * @throws IllegalArgumentException the sequence cannot match
     */
    @Override
    public MnemonicUnit decode(CharSequence mnemonicSequence, String wordListIdentifier) {
        if (null != wordListIdentifier && !wordListIdentifier.isEmpty()) {
            /* There are no custom word lists for legacy Electrum mnemonic system. */
            throw new UnsupportedOperationException("No custom wordListIdentifiers allowed");
        }
        byte[] entropy = LegacyElectrumMnemonicUtility.toEntropy(mnemonicSequence);
        return SPI.build(mnemonicSequence, entropy);
    }

}