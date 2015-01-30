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

import java.util.Arrays;

/**
 * Decoder system for the legacy Electrum mnemonic system.
 */
class LegacyElectrumMnemonicDecoderSystem extends MnemonicDecoderSystem {
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
        return new MnemonicUnit(new LegacyElectrumMnemonicUnit(mnemonicSequence, entropy));
    }

    /**
     * Internal class to implement the legacy Electrum mnemonic details.
     */
    private static class LegacyElectrumMnemonicUnit extends MnemonicUnitSpi {
        private final byte[] entropy;

        private LegacyElectrumMnemonicUnit(CharSequence mnemonicSequence, byte[] entropy) {
            super(mnemonicSequence);
            this.entropy = entropy;
        }

        /**
         * Get the entropy if possible.
         *
         * @return a copy of the entropy byte array or null if inaccessible.
         */
        @Override
        public byte[] getEntropy() {
            return Arrays.copyOf(entropy, entropy.length);
        }

        /**
         * Get a seed from this mnemonic without supplying a password.
         *
         * @return a decoded seed.
         */
        @Override
        public byte[] getSeed() {
            return Arrays.copyOf(entropy, entropy.length);
        }

        /**
         * Get a seed from this mnemonic.
         *
         * @param password password to supply for decoding.
         *
         * @return a decoded seed.
         */
        @Override
        public byte[] getSeed(CharSequence password) {
            if (password != null && password.length() != 0) {
                throw new UnsupportedOperationException("password usage is not supported");
            }
            return getSeed();
        }
    }
}
