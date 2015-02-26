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

package us.eharning.atomun.mnemonic.spi;

import com.google.common.base.Verify;
import com.google.common.collect.ImmutableMap;
import us.eharning.atomun.mnemonic.MnemonicUnit;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Service provider to back the MnemonicDecoder.
 * Primarily to present a consistent API.
 *
 * @since 0.1.0
 */
@Immutable
public abstract class MnemonicUnitSpi {
    /**
     * Utility method to return a wrapped instance of this SPI.
     *
     * @param builder instance maker.
     * @param mnemonicSequence represented sequence.
     * @param entropy derived entropy or null if on-demand.
     * @param seed derived seed or null if on-demand.
     * @param extensions map of property-to-value dependent on algorithm.
     *
     * @return wrapped instance.
     *
     * @since 0.1.0
     */
    @Nonnull
    protected MnemonicUnit build(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nonnull ImmutableMap<String, Object> extensions) {
        Verify.verifyNotNull(mnemonicSequence);
        Verify.verifyNotNull(extensions);
        return builder.build(this, mnemonicSequence, entropy, seed, extensions);
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence sequence to derive the entropy for.
     *
     * @return a copy of the entropy byte array or null if inaccessible.
     *
     * @since 0.1.0
     */
    @CheckForNull
    public abstract byte[] getEntropy(@Nonnull CharSequence mnemonicSequence);

    /**
     * Get a seed from this mnemonic.
     *
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     *
     * @since 0.1.0
     */
    @Nonnull
    public abstract byte[] getSeed(@Nonnull CharSequence mnemonicSequence, @Nullable CharSequence password);
}
