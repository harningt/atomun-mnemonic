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

package us.eharning.atomun.mnemonic.spi;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;
import us.eharning.atomun.mnemonic.MnemonicServices;
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
@Nonnull
public abstract class MnemonicUnitSpi {
    private final MnemonicAlgorithm algorithm;

    /**
     * Construct a service provider for the given algorithm.
     *
     * @param algorithm the associated mnemonic algorithm implemented.
     *
     * @since 0.2.0
     */
    protected MnemonicUnitSpi(@Nonnull MnemonicAlgorithm algorithm) {
        checkNotNull(algorithm);
        if (!MnemonicServices.getRegisteredAlgorithms().contains(algorithm)) {
            throw new UnsupportedOperationException("Unregistered algorithm: " + algorithm);
        }
        this.algorithm = algorithm;
    }

    /**
     * Utility method to return a wrapped instance of this SPI.
     *
     * @param builder
     *         instance maker.
     * @param mnemonicSequence
     *         represented sequence.
     * @param entropy
     *         derived entropy or null if on-demand.
     * @param seed
     *         derived seed or null if on-demand.
     * @param extensions
     *         map of property-to-value dependent on algorithm.
     *
     * @return wrapped instance.
     *
     * @since 0.4.0
     */
    @Nonnull
    protected MnemonicUnit build(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nonnull ImmutableMap<MnemonicExtensionIdentifier, Object> extensions) {
        checkNotNull(mnemonicSequence);
        checkNotNull(extensions);
        return builder.build(this, mnemonicSequence, entropy, seed, extensions.keySet(), Functions.forMap(extensions));
    }

    /**
     * Utility method to return a wrapped instance of this SPI.
     *
     * @param builder
     *         instance maker.
     * @param mnemonicSequence
     *         represented sequence.
     * @param entropy
     *         derived entropy or null if on-demand.
     * @param seed
     *         derived seed or null if on-demand.
     * @param supportedExtensions
     *         set of supported extensions dependent on algorithm.
     * @param extensionLoader
     *         method to calculate a given extension's value.
     *
     * @return wrapped instance.
     *
     * @since 0.4.0
     */
    @Nonnull
    protected MnemonicUnit build(@Nonnull MnemonicUnit.Builder builder, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nonnull ImmutableSet<MnemonicExtensionIdentifier> supportedExtensions, @Nonnull Function<MnemonicExtensionIdentifier, Object> extensionLoader) {
        checkNotNull(mnemonicSequence);
        checkNotNull(supportedExtensions);
        checkNotNull(extensionLoader);
        return builder.build(this, mnemonicSequence, entropy, seed, supportedExtensions, extensionLoader);
    }

    /**
     * Get the mnemonic algorithm implemented.
     *
     * @return the constant algorithm for this SPI.
     *
     * @since 0.2.0
     */
    @Nonnull
    public final MnemonicAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence
     *         sequence to derive the entropy for.
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
     * @param mnemonicSequence
     *         sequence to derive the seed from.
     * @param password
     *         password to supply for decoding.
     *
     * @return a derived seed.
     *
     * @since 0.1.0
     */
    @Nonnull
    public abstract byte[] getSeed(@Nonnull CharSequence mnemonicSequence, @Nullable CharSequence password);
}
