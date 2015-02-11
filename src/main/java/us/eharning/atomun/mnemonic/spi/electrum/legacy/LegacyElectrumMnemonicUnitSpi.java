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

import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.MnemonicUnitSpi;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Internal class to implement the legacy Electrum mnemonic details.
 */
@Immutable
class LegacyElectrumMnemonicUnitSpi extends MnemonicUnitSpi {
    public MnemonicUnit build(CharSequence mnemonicSequence, byte[] entropy) {
        /* Entropy is the seed for this */
        return super.build(mnemonicSequence, entropy, entropy, null);
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence sequence to derive entropy from.
     *
     * @return a derived copy of the entropy byte array.
     */
    @Nonnull
    @Override
    public byte[] getEntropy(@Nonnull CharSequence mnemonicSequence) {
        return LegacyElectrumMnemonicUtility.toEntropy(mnemonicSequence);
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     */
    @Nonnull
    @Override
    public byte[] getSeed(@Nonnull CharSequence mnemonicSequence, @Nullable CharSequence password) {
        if (password != null && password.length() != 0) {
            throw new UnsupportedOperationException("password usage is not supported");
        }
        return getEntropy(mnemonicSequence);
    }
}
