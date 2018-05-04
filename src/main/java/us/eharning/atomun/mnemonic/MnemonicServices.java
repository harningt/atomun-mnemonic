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
import com.google.common.collect.ImmutableList;
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider;
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.legacy.LegacyElectrumMnemonicService;
import us.eharning.atomun.mnemonic.spi.electrum.v2.ElectrumV2MnemonicService;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import javax.annotation.Nonnull;

/**
 * Utility class where mnemonic instances are registered.
 *
 * @since 0.7.0
 */
@Beta
@Nonnull
public final class MnemonicServices {
    /*
     * Uses a CopyOnWriteArraySet due to small element count and infrequent
     * mutation. If larger sets to be used, then an atomic-reference +
     * immutable set may be better (since it offers ln(n) search).
     */

    /**
     * List of current registered algorithms.
     */
    private static final Set<MnemonicAlgorithm> REGISTERED_ALGORITHMS;
    private static final Set<MnemonicAlgorithm> REGISTERED_ALGORITHMS_MUTABLE;

    static {
        REGISTERED_ALGORITHMS_MUTABLE = new CopyOnWriteArraySet<>(ImmutableList.<MnemonicAlgorithm>builder()
                .add(BIPMnemonicAlgorithm.values())
                .add(ElectrumMnemonicAlgorithm.values())
                .build());
        REGISTERED_ALGORITHMS = Collections.unmodifiableSet(REGISTERED_ALGORITHMS_MUTABLE);
    }

    /**
     * List of current service providers.
     */
    private static final Set<MnemonicServiceProvider> SERVICE_PROVIDERS;
    private static final Set<MnemonicServiceProvider> SERVICE_PROVIDERS_MUTABLE;

    static {
        SERVICE_PROVIDERS_MUTABLE = new CopyOnWriteArraySet<>(Arrays.asList(
                new LegacyElectrumMnemonicService(),
                new BIP0039MnemonicService(),
                new ElectrumV2MnemonicService()
        ));
        SERVICE_PROVIDERS = Collections.unmodifiableSet(SERVICE_PROVIDERS_MUTABLE);
    }

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
