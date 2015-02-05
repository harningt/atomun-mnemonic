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

import us.eharning.atomun.mnemonic.*;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

/**
 * Registration class to perform the necessary default service provider registrations.
 */
public class LegacyElectrumMnemonicService extends MnemonicServiceProvider {
    private static final MnemonicBuilderSpi BUILDER_SPI = new LegacyElectrumMnemonicBuilderSpi();
    private static final MnemonicDecoderSpi DECODER_SPI = new LegacyElectrumMnemonicDecoderSpi();

    @Override
    public MnemonicBuilderSpi getMnemonicBuilder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return BUILDER_SPI;
    }

    @Override
    public MnemonicDecoderSpi getMnemonicDecoder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return DECODER_SPI;
    }

}
