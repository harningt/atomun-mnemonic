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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;

import javax.annotation.Nullable;

/**
 * Closure encapsulating the extension => value conversion process.
 */
class ElectrumV2ExtensionLoader implements Function<MnemonicExtensionIdentifier, Object> {
    private VersionPrefix versionPrefix;

    ElectrumV2ExtensionLoader(VersionPrefix versionPrefix) {
        this.versionPrefix = versionPrefix;
    }

    @Nullable
    @Override
    public Object apply(MnemonicExtensionIdentifier input) {
        Preconditions.checkNotNull(input);
        Preconditions.checkArgument(input instanceof ElectrumV2ExtensionIdentifiers, "Mnemonic extension not supported");
        Preconditions.checkArgument(input.canGet(), "Mnemonic extension is not readable");

        switch ((ElectrumV2ExtensionIdentifiers) input) {
        case MNEMONIC_VERSION_PREFIX:
            return versionPrefix;
        default:
            return null;
        }
    }
}
