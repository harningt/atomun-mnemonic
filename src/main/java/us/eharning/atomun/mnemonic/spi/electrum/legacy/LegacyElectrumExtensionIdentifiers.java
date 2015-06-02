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

import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier;

/**
 * Enumeration for Legacy Electrum extension identifiers.
 *
 * @since 0.4.0
 */
public enum LegacyElectrumExtensionIdentifiers implements MnemonicExtensionIdentifier {
    ;

    @Override
    public boolean canGet() {
        return false;
    }

    @Override
    public boolean canSet() {
        return false;
    }
}
