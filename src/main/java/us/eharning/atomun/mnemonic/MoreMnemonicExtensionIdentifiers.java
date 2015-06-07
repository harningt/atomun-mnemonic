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

import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import java.util.Set;

/**
 * Utility class to help manage mnemonic extension identifiers.
 *
 * @since 0.4.0
 */
public class MoreMnemonicExtensionIdentifiers {
    /**
     * Predicate to filter extension identifiers that you cen set.
     */
    public static final Predicate<MnemonicExtensionIdentifier> CAN_SET = new Predicate<MnemonicExtensionIdentifier>() {
        @Override
        public boolean apply(MnemonicExtensionIdentifier input) {
            return input != null ? input.canSet() : false;
        }
    };

    /**
     * Predicate to filter extension identifiers that you cen get.
     */
    public static final Predicate<MnemonicExtensionIdentifier> CAN_GET = new Predicate<MnemonicExtensionIdentifier>() {
        @Override
        public boolean apply(MnemonicExtensionIdentifier input) {
            return input != null ? input.canGet() : false;
        }
    };

    /**
     * Obtains the extension identifiers from the set that canGet.
     *
     * @param mnemonicExtensionIdentifiers
     *         set of extension identifiers to filter.
     *
     * @return filtered set of identifiers
     */
    public static Set<MnemonicExtensionIdentifier> canGet(Set<MnemonicExtensionIdentifier> mnemonicExtensionIdentifiers) {
        return Sets.filter(mnemonicExtensionIdentifiers, CAN_GET);
    }

    /**
     * Obtains the extension identifiers from the set that canGet.
     *
     * @param mnemonicExtensionIdentifiers
     *         set of extension identifiers to filter.
     *
     * @return filtered set of identifiers
     */
    public static Set<MnemonicExtensionIdentifier> canGet(MnemonicExtensionIdentifier... mnemonicExtensionIdentifiers) {
        return canGet(ImmutableSet.copyOf(mnemonicExtensionIdentifiers));
    }

    /**
     * Obtains the extension identifiers from the set that canSet.
     *
     * @param mnemonicExtensionIdentifiers
     *         set of extension identifiers to filter.
     *
     * @return filtered set of identifiers
     */
    public static Set<MnemonicExtensionIdentifier> canSet(Set<MnemonicExtensionIdentifier> mnemonicExtensionIdentifiers) {
        return Sets.filter(mnemonicExtensionIdentifiers, CAN_SET);
    }

    /**
     * Obtains the extension identifiers from the set that canSet.
     *
     * @param mnemonicExtensionIdentifiers
     *         set of extension identifiers to filter.
     *
     * @return filtered set of identifiers
     */
    public static Set<MnemonicExtensionIdentifier> canSet(MnemonicExtensionIdentifier... mnemonicExtensionIdentifiers) {
        return canSet(ImmutableSet.copyOf(mnemonicExtensionIdentifiers));
    }
}
