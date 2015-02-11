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

import com.google.common.collect.ClassToInstanceMap;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * Service provider to back the MnemonicDecoder.
 * Primarily to present a consistent API.
 *
 * @since 0.0.1
 */
@Immutable
public final class MnemonicUnit {
    private final MnemonicUnitSpi spi;
    private final CharSequence mnemonicSequence;
    private final byte[] entropy;
    private final byte[] seed;
    private final ClassToInstanceMap<Object> extensions;

    /**
     * Construct a new MnemonicUnit wrapping the given implementation.
     *
     * @param spi implementation details.
     * @param mnemonicSequence represented sequence.
     * @param entropy derived entropy or null if on-demand.
     * @param seed derived seed or null if on-demand
     * @param extensions implementation extensions or null if on-demand/non-existent.
     */
    MnemonicUnit(@Nonnull MnemonicUnitSpi spi, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nullable ClassToInstanceMap<Object> extensions) {
        this.spi = spi;
        this.mnemonicSequence = mnemonicSequence;
        this.entropy = entropy;
        this.seed = seed;
        this.extensions = extensions;
    }

    /**
     * Get the entropy if possible.
     *
     * @return a copy of the entropy byte array or null if inaccessible.
     *
     * @since 0.0.1
     */
    @CheckForNull
    public byte[] getEntropy() {
        if (null != entropy) {
            return entropy;
        }
        return spi.getEntropy(mnemonicSequence);
    }

    /**
     * Get a custom decoder extension to obtain custom values.
     *
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param extensionType kind of decoder extension to obtain.
     *
     * @return typed extension if available, else null.
     *
     * @since 0.0.1
     */
    @CheckForNull
    public <T> T getExtension(@Nonnull Class<T> extensionType) {
        if (null != extensions) {
            return extensions.getInstance(extensionType);
        }
        return spi.getExtension(mnemonicSequence, extensionType);
    }

    /**
     * Get the associated mnemonic string.
     *
     * @return space-delimited sequence of mnemonic words.
     *
     * @since 0.0.1
     */
    @Nonnull
    public CharSequence getMnemonic() {
        return mnemonicSequence;
    }

    /**
     * Get a seed from this mnemonic without supplying a password.
     *
     * @return a derived seed.
     *
     * @since 0.0.1
     */
    @Nonnull
    public byte[] getSeed() {
        if (null != seed) {
            return seed;
        }
        return spi.getSeed(mnemonicSequence, null);
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     *
     * @since 0.0.1
     */
    @Nonnull
    public byte[] getSeed(@Nullable CharSequence password) {
        if (null == password || password.length() == 0) {
            return getSeed();
        }
        return spi.getSeed(mnemonicSequence, password);
    }
}
