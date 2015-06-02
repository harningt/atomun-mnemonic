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

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.base.Verify;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import us.eharning.atomun.mnemonic.spi.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider;
import us.eharning.atomun.mnemonic.spi.MnemonicUnitSpi;
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.v2.ElectrumV2MnemonicService;

import java.util.Arrays;
import java.util.Set;
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
    static final Builder BUILDER = new Builder();
    private static final ImmutableList<MnemonicServiceProvider> SERVICE_PROVIDERS = ImmutableList.of(
            new LegacyElectrumMnemonicService(),
            new BIP0039MnemonicService(),
            new ElectrumV2MnemonicService()
    );

    private final MnemonicUnitSpi spi;
    private final CharSequence mnemonicSequence;
    private final byte[] entropy;
    private final byte[] seed;
    private final ImmutableSet<MnemonicExtensionIdentifier> supportedExtensions;
    private final Function<MnemonicExtensionIdentifier, Object> extensionLoader;

    /**
     * Construct a new MnemonicUnit wrapping the given implementation.
     *
     * @param spi
     *         implementation details.
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
     */
    private MnemonicUnit(@Nonnull MnemonicUnitSpi spi, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nonnull ImmutableSet<MnemonicExtensionIdentifier> supportedExtensions, @Nonnull Function<MnemonicExtensionIdentifier, Object> extensionLoader) {
        Verify.verifyNotNull(spi);
        Verify.verifyNotNull(mnemonicSequence);
        Verify.verifyNotNull(supportedExtensions);
        Verify.verifyNotNull(extensionLoader);
        this.spi = spi;
        this.mnemonicSequence = mnemonicSequence;
        this.entropy = entropy == null ? null : Arrays.copyOf(entropy, entropy.length);
        this.seed = seed == null ? null : Arrays.copyOf(seed, seed.length);
        this.supportedExtensions = supportedExtensions;
        this.extensionLoader = extensionLoader;
    }

    /**
     * Decodes a mnemonic, returning an iterable with all of the successful decoding results.
     *
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
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
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
     * @param wordListIdentifier
     *         identifier for the word list to use.
     *
     * @return sequence of successful decoding results or empty.
     *
     * @since 0.1.0
     */
    @Nonnull
    public static Iterable<MnemonicUnit> decodeMnemonic(@Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
        ImmutableList.Builder<MnemonicUnit> unitListBuilder = ImmutableList.builder();
        for (MnemonicServiceProvider serviceProvider : SERVICE_PROVIDERS) {
            for (MnemonicAlgorithm algorithm : MnemonicAlgorithm.values()) {
                MnemonicDecoderSpi system = serviceProvider.getMnemonicDecoder(algorithm);
                if (null == system) {
                    continue;
                }
                try {
                    MnemonicUnit unit = system.decode(BUILDER, mnemonicSequence, wordListIdentifier);
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
     * @param mnemonicAlgorithm
     *         identifier for which algorithm to use.
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
     *
     * @return successful decoding results.
     *
     * @throws java.lang.IllegalArgumentException
     *         on decoding failure.
     * @since 0.0.1
     */
    @Nonnull
    public static MnemonicUnit decodeMnemonic(@Nonnull MnemonicAlgorithm mnemonicAlgorithm, @Nonnull CharSequence mnemonicSequence) {
        return decodeMnemonic(mnemonicAlgorithm, mnemonicSequence, null);
    }

    /**
     * Decode a mnemonic for a specific algorithm and word list.
     *
     * @param mnemonicAlgorithm
     *         identifier for which algorithm to use.
     * @param mnemonicSequence
     *         space-delimited sequence of mnemonic words.
     * @param wordListIdentifier
     *         identifier for the word list to use.
     *
     * @return successful decoding results.
     *
     * @throws java.lang.IllegalArgumentException
     *         on decoding failure.
     * @since 0.0.1
     */
    @Nonnull
    public static MnemonicUnit decodeMnemonic(@Nonnull MnemonicAlgorithm mnemonicAlgorithm, @Nonnull CharSequence mnemonicSequence, @Nullable String wordListIdentifier) {
        for (MnemonicServiceProvider serviceProvider : SERVICE_PROVIDERS) {
            MnemonicDecoderSpi system = serviceProvider.getMnemonicDecoder(mnemonicAlgorithm);
            if (null == system) {
                continue;
            }
            return system.decode(BUILDER, mnemonicSequence, wordListIdentifier);
        }
        throw new UnsupportedOperationException("Unsupported algorithm " + mnemonicAlgorithm);
    }

    /**
     * Get the mnemonic algorithm implemented.
     *
     * @return the constant algorithm for this instance.
     *
     * @since 0.2.0
     */
    @Nonnull
    public MnemonicAlgorithm getAlgorithm() {
        return spi.getAlgorithm();
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
            return Arrays.copyOf(entropy, entropy.length);
        }
        return spi.getEntropy(mnemonicSequence);
    }

    /**
     * Get the supported extension identifiers.
     *
     * @return set of supported extensions dependent on algorithm.
     *
     * @since 0.4.0
     */
    @Nonnull
    public Set<MnemonicExtensionIdentifier> getSupportedExtensions() {
        return supportedExtensions;
    }

    /**
     * Get the associated extension value.
     *
     * @param extensionIdentifier
     *         identifier for which extension to retrieve.
     *
     * @return given extension value.
     *
     * @since 0.4.0
     */
    @CheckForNull
    public Object getExtensionValue(MnemonicExtensionIdentifier extensionIdentifier) {
        Preconditions.checkArgument(extensionIdentifier.canGet(), "Cannot get extension: %s", extensionIdentifier);
        return extensionLoader.apply(extensionIdentifier);
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
            return Arrays.copyOf(seed, seed.length);
        }
        return spi.getSeed(mnemonicSequence, null);
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param password
     *         password to supply for decoding.
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

    public static class Builder {
        /**
         * Protected constructor so that only MnemonicUnit can pass along.
         */
        Builder() {
        }

        @Nonnull
        public final MnemonicUnit build(@Nonnull MnemonicUnitSpi spi, @Nonnull CharSequence mnemonicSequence, @Nullable byte[] entropy, @Nullable byte[] seed, @Nonnull ImmutableSet<MnemonicExtensionIdentifier> supportedExtensions, @Nonnull Function<MnemonicExtensionIdentifier, Object> extensionLoader) {
            return new MnemonicUnit(spi, mnemonicSequence, entropy, seed, supportedExtensions, extensionLoader);
        }
    }
}
