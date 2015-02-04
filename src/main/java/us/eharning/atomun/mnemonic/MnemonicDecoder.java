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

/**
 * Builder API to decode mnemonic sequences.
 */
public final class MnemonicDecoder {
    /**
     * Mapping of algorithms to implementation instance suppliers.
     *
     * May be replaced with a mutable map if custom implementations allowed.
     */
    private static final ImmutableMap<MnemonicAlgorithm, MnemonicDecoderSystem> constructorMap;
    static {
        constructorMap = ImmutableMap.of(
            MnemonicAlgorithm.LegacyElectrum, (MnemonicDecoderSystem)new LegacyElectrumMnemonicDecoderSystem()
        );
    }

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
    public static Iterable<MnemonicUnit> decodeMnemonic(CharSequence mnemonicSequence) {
        ImmutableList.Builder<MnemonicUnit> unitListBuilder = ImmutableList.builder();
        for (MnemonicDecoderSystem system: constructorMap.values()) {
            try {
                MnemonicUnit unit = system.decode(mnemonicSequence, null);
                unitListBuilder.add(unit);
            } catch (IllegalArgumentException ignored) {
                /* On failure, ignore the error and continue on */
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
    public static MnemonicUnit decodeMnemonic(MnemonicAlgorithm mnemonicAlgorithm, CharSequence mnemonicSequence) {
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
    public static MnemonicUnit decodeMnemonic(MnemonicAlgorithm mnemonicAlgorithm, CharSequence mnemonicSequence, String wordListIdentifier) {
        MnemonicDecoderSystem system = constructorMap.get(mnemonicAlgorithm);
        if (null == system) {
            throw new UnsupportedOperationException("Unsupported algorithm " + mnemonicAlgorithm);
        }
        return system.decode(mnemonicSequence, wordListIdentifier);
    }
}
