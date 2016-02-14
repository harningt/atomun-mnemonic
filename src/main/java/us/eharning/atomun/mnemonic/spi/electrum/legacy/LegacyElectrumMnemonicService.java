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

package us.eharning.atomun.mnemonic.spi.electrum.legacy;

import us.eharning.atomun.mnemonic.ElectrumMnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;
import us.eharning.atomun.mnemonic.spi.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Registration class to perform the necessary default service provider registrations.
 *
 * @since 0.1.0
 */
@Immutable
public class LegacyElectrumMnemonicService extends MnemonicServiceProvider {
    private static final MnemonicBuilderSpi BUILDER_SPI = new LegacyElectrumMnemonicBuilderSpi();
    private static final MnemonicDecoderSpi DECODER_SPI = new LegacyElectrumMnemonicDecoderSpi();

    /**
     * Obtain a mnemonic builder SPI for the given algorithm.
     *
     * @param algorithm
     *         mnemonic algorithm to try to retrieve.
     *
     * @return SPI instance for the given algorithm, else null.
     *
     * @since 0.1.0
     */
    @CheckForNull
    @Override
    public MnemonicBuilderSpi getMnemonicBuilder(@Nonnull MnemonicAlgorithm algorithm) {
        if (algorithm != ElectrumMnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return BUILDER_SPI;
    }

    /**
     * Obtain a mnemonic decoder SPI for the given algorithm.
     *
     * @param algorithm
     *         mnemonic algorithm to try to retrieve.
     *
     * @return SPI instance for the given algorithm, else null.
     *
     * @since 0.1.0
     */
    @CheckForNull
    @Override
    public MnemonicDecoderSpi getMnemonicDecoder(@Nonnull MnemonicAlgorithm algorithm) {
        if (algorithm != ElectrumMnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return DECODER_SPI;
    }

}
