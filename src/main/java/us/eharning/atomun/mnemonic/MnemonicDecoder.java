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
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Builder API to decode mnemonic sequences.
 *
 * @since 0.0.1
 */
public final class MnemonicDecoder {
    private static final ImmutableList<MnemonicServiceProvider> SERVICE_PROVIDERS = ImmutableList.of(
            new LegacyElectrumMnemonicService(),
            new BIP0039MnemonicService()
    );

    /**
     * Deny construction of this static utility class.
     */
    private MnemonicDecoder() {
    }

    /**
     * Decodes a mnemonic, returning an iterable with all of the successful decoding results.
     *
     * @param mnemonicSequence space-delimited sequence of mnemonic words.
     *
     * @return sequence of successful decoding results or empty.
     *
     * @since 0.0.1
     */
    @Nonnull
    public static Iterable<MnemonicUnit> decodeMnemonic(@Nonnull CharSequence mnemonicSequence) {
        return decodeMnemonic(mnemonicSequence, null);
    }

    /**
     * Decodes a mnemonic, returning an iterable with all of the successful decoding results.
     *
     * @param mnemonicSequence space-delimited sequence of mnemonic words.
     * @param wordListIdentifier identifier for the word list to use.
     *
     * @return sequence of successful decoding results or empty.
     *
     * @since 0.1.0
     */
    @Nonnull
    public static Iterable<MnemonicUnit> decodeMnemonic(@Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
        ImmutableList.Builder<MnemonicUnit> unitListBuilder = ImmutableList.builder();
        for (MnemonicServiceProvider serviceProvider: SERVICE_PROVIDERS) {
            for (MnemonicAlgorithm algorithm: MnemonicAlgorithm.values()) {
                MnemonicDecoderSpi system = serviceProvider.getMnemonicDecoder(algorithm);
                if (null == system) {
                    continue;
                }
                try {
                    MnemonicUnit unit = system.decode(mnemonicSequence, wordListIdentifier);
                    unitListBuilder.add(unit);
                } catch (UnsupportedOperationException | IllegalArgumentException ignored) {
                }
            }
        }
        return unitListBuilder.build();
    }

    /**
     * Decode a mnemonic for a specific algorithm.
     *
     * @param mnemonicAlgorithm identifier for which algorithm to use.
     * @param mnemonicSequence space-delimited sequence of mnemonic words.
     *
     * @return successful decoding results.
     * @throws java.lang.IllegalArgumentException on decoding failure.
     *
     * @since 0.0.1
     */
    @Nonnull
    public static MnemonicUnit decodeMnemonic(@Nonnull MnemonicAlgorithm mnemonicAlgorithm, @Nonnull CharSequence mnemonicSequence) {
        return decodeMnemonic(mnemonicAlgorithm, mnemonicSequence, null);
    }

    /**
     * Decode a mnemonic for a specific algorithm and word list.
     *
     * @param mnemonicAlgorithm identifier for which algorithm to use.
     * @param mnemonicSequence space-delimited sequence of mnemonic words.
     * @param wordListIdentifier identifier for the word list to use.
     *
     * @return successful decoding results.
     * @throws java.lang.IllegalArgumentException on decoding failure.
     *
     * @since 0.0.1
     */
    @Nonnull
    public static MnemonicUnit decodeMnemonic(@Nonnull MnemonicAlgorithm mnemonicAlgorithm, @Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
        for (MnemonicServiceProvider serviceProvider: SERVICE_PROVIDERS) {
            MnemonicDecoderSpi system = serviceProvider.getMnemonicDecoder(mnemonicAlgorithm);
            if (null == system) {
                continue;
            }
            return system.decode(mnemonicSequence, wordListIdentifier);
        }
        throw new UnsupportedOperationException("Unsupported algorithm " + mnemonicAlgorithm);
    }
}
