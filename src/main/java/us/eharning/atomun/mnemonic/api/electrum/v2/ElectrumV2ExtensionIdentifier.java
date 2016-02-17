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

package us.eharning.atomun.mnemonic.api.electrum.v2;

import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;

/**
 * Enumeration for Electrum V2 extension identifiers.
 *
 * @since 0.7.0
 */
public enum ElectrumV2ExtensionIdentifier implements MnemonicExtensionIdentifier {
    /**
     * Identifier indicating the version prefix in the final output.
     *
     * @see VersionPrefix for I/O value type
     */
    VERSION_PREFIX(true, true),
    /**
     * BigInteger indicating the number to use when generating as a factor.
     * <p>
     *     This entropy is verifiable after the fact by converting the entropy
     *     to a BigInteger and verifying that you can divide it with 0 remainder.
     * </p>
     *
     */
    CUSTOM_ENTROPY(false, true)
    ;

    private boolean canGet;
    private boolean canSet;

    ElectrumV2ExtensionIdentifier(boolean canGet, boolean canSet) {
        this.canGet = canGet;
        this.canSet = canSet;
    }

    /**
     * Whether or not this value can be read.
     *
     * @return true if it can only be retrieved from MnemonicUnit.
     */
    @Override
    public boolean canGet() {
        return canGet;
    }

    /**
     * Whether or or not this value can be set.
     *
     * @return true if it can be set in MnemonicBuilder.
     */
    @Override
    public boolean canSet() {
        return canSet;
    }
}
