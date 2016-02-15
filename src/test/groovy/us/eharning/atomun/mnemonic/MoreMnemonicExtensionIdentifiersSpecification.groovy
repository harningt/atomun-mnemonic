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

package us.eharning.atomun.mnemonic

import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Specification

/**
 * Tests covering MoreMnemonicExtensionIdentifiers operations.
 */
public class MoreMnemonicExtensionIdentifiersSpecification extends Specification {
    def "MoreMnemonicExtensionIdentifiers is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(MoreMnemonicExtensionIdentifiers.class)
        then:
        noExceptionThrown()
    }

    def "canSet can handle null properly"() {
        expect:
        !MoreMnemonicExtensionIdentifiers.CAN_SET.apply(null)
    }

    def "canGet can handle null properly"() {
        expect:
        !MoreMnemonicExtensionIdentifiers.CAN_GET.apply(null)
    }

    def "canSet/canGet properly reports exactly what the interface indicates"(final boolean canGet, final boolean canSet) {
        given:
        def item = new MnemonicExtensionIdentifier() {
            @Override
            boolean canGet() {
                return canGet
            }
            @Override
            boolean canSet() {
                return canSet
            }
        }
        expect:
        MoreMnemonicExtensionIdentifiers.CAN_GET.apply(item) == canGet
        MoreMnemonicExtensionIdentifiers.CAN_SET.apply(item) == canSet
        where:
        canGet | canSet
        true   | true
        true   | false
        false  | true
        false  | false
    }
}
