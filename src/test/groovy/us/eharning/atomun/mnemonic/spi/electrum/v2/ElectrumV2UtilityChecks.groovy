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

package us.eharning.atomun.mnemonic.spi.electrum.v2

import com.google.common.base.Function
import com.google.common.collect.Iterables
import net.trajano.commons.testing.UtilityClassTestUtil
import org.joor.Reflect
import spock.lang.Specification
import us.eharning.atomun.mnemonic.utility.dictionary.Dictionary
import us.eharning.atomun.mnemonic.utility.dictionary.DictionaryIdentifier
import us.eharning.atomun.mnemonic.utility.dictionary.DictionarySource

/**
 * Test sequence for the Electrum mnemonic utility classes
 */
class ElectrumV2UtilityChecks extends Specification {
    def "MnemonicIndexGenerator is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(MnemonicIndexGenerator)
        then:
        noExceptionThrown()
    }

    def "MnemonicUtility is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(MnemonicUtility)
        then:
        noExceptionThrown()
    }

    def "MnemonicUtility absorbs dictionary load failures"() {
        setup:
        def oldLoader = Reflect.on(DictionarySource).get("loader")
        Reflect.on(DictionarySource).set("loader", {
            throw new IllegalArgumentException("Unknown dictionary")
        } as Function<DictionaryIdentifier, Dictionary>)
        expect:
        Iterables.isEmpty(MnemonicUtility.dictionaries)
        cleanup:
        Reflect.on(DictionarySource).set("loader", oldLoader)

    }
}
