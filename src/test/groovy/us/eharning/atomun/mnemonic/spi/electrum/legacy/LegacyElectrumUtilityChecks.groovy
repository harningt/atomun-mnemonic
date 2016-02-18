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

package us.eharning.atomun.mnemonic.spi.electrum.legacy

import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Specification

/**
 * Test sequence for the Electrum mnemonic utility classes
 */
class LegacyElectrumUtilityChecks extends Specification {
    def "LegacyElectrumMnemonicUtility is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(LegacyElectrumMnemonicUtility)
        then:
        noExceptionThrown()
    }

    def "LegacyElectrumMnemonicUtility fails to initialize when dictionary is not present"() {
    }
}
