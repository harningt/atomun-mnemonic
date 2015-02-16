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
package us.eharning.atomun.mnemonic.spi.bip0039;

import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.MnemonicServiceProvider;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Registration class to perform the necessary default service provider registrations.
 *
 * @since 0.1.0
 */
@Immutable
public class BIP0039MnemonicService extends MnemonicServiceProvider {
    private static final MnemonicBuilderSpi BUILDER_SPI = new BIP0039MnemonicBuilderSpi();
    private static final MnemonicDecoderSpi DECODER_SPI = new BIP0039MnemonicDecoderSpi();

    /**
     * Obtain a mnemonic builder SPI for the given algorithm.
     *
     * @param algorithm mnemonic algorithm to try to retrieve.
     *
     * @return SPI instance for the given algorithm, else null.
     */
    @CheckForNull
    @Override
    public MnemonicBuilderSpi getMnemonicBuilder(@Nonnull MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.BIP0039) {
            return null;
        }
        return BUILDER_SPI;
    }

    /**
     * Obtain a mnemonic decoder SPI for the given algorithm.
     *
     * @param algorithm mnemonic algorithm to try to retrieve.
     *
     * @return SPI instance for the given algorithm, else null.
     */
    @CheckForNull
    @Override
    public MnemonicDecoderSpi getMnemonicDecoder(@Nonnull MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.BIP0039) {
            return null;
        }
        return DECODER_SPI;
    }

}
