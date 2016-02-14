/*
 * Copyright 2016 Thomas Harning Jr. <harningt@gmail.com>
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

import com.google.common.annotations.Beta;
import com.google.common.collect.ImmutableSet;
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider;
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.v2.ElectrumV2MnemonicService;

import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Utility class where mnemonic instances are registered.
 *
 * @since 0.7.0
 */
@Beta
public final class MnemonicServices {
    /**
     * List of current registered algorithms.
     */
    private static final ImmutableSet<MnemonicAlgorithm> REGISTERED_ALGORITHMS = ImmutableSet.<MnemonicAlgorithm>builder()
            .add(BIPMnemonicAlgorithm.values())
            .add(ElectrumMnemonicAlgorithm.values())
            .build();

    /**
     * List of current service providers.
     */
    private static final ImmutableSet<MnemonicServiceProvider> SERVICE_PROVIDERS = ImmutableSet.of(
            new LegacyElectrumMnemonicService(),
            new BIP0039MnemonicService(),
            new ElectrumV2MnemonicService()
    );

    /**
     * Prevent external construction since it is a utility class.
     */
    private MnemonicServices() {
    }

    /**
     * Obtain a set of registered algorithms.
     *
     * @return set containing all registered algorithms.
     *
     * @since 0.7.0
     */
    @Nonnull
    public static Set<MnemonicAlgorithm> getRegisteredAlgorithms() {
        return REGISTERED_ALGORITHMS;
    }

    /**
     * Obtain a list of current service providers.
     *
     * @return sequence of service providers.
     *
     * @since 0.7.0
     */
    @Nonnull
    public static Iterable<MnemonicServiceProvider> getServiceProviders() {
        return SERVICE_PROVIDERS;
    }
}
