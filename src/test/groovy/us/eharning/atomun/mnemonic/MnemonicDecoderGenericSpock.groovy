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

package us.eharning.atomun.mnemonic

import com.google.common.collect.Iterables
import spock.lang.Specification

import java.lang.reflect.Field

/**
 * Generic decoding handler test.
 */
class MnemonicDecoderGenericSpock extends Specification {
    def "requesting a unlisted algorithm results in failure"() {
        when:
        def someUnlistedAlgorithm = new MnemonicAlgorithm() {}
        MnemonicUnit.decodeMnemonic(someUnlistedAlgorithm, "TEST")
        then:
        thrown(UnsupportedOperationException)
    }

    def "requesting a null algorithm results in failure"() {
        when:
        MnemonicUnit.decodeMnemonic((MnemonicAlgorithm)null, "TEST")
        then:
        thrown(NullPointerException)
    }

    def "requesting a certainly invalid mnemonic results in empty list"(String mnemonic) {
        expect:
        Iterables.isEmpty(MnemonicUnit.decodeMnemonic(mnemonic))
        where:
        _ | mnemonic
        _ | "123FAKE"
        /* To at least meet the 3-word chunk limit for BIP0039 */
        _ | "123 Fake Foux"
    }

    static Object getFinalStatic(Class<?> clazz, String fieldName) throws Exception {
        Field field = clazz.getDeclaredField(fieldName)
        field.setAccessible(true);

        return field.get(null);
    }

    def "requesting an algorithm not known by any providers results in failure"() {
        /* Requires reflection hack due to all known algorithms having a provider */
        setup:
        def providerSet = getFinalStatic(MnemonicServices, "SERVICE_PROVIDERS_MUTABLE")
        def backup = providerSet.toArray()
        providerSet.clear()
        when:
        MnemonicUnit.decodeMnemonic(BIPMnemonicAlgorithm.BIP0039, "")
        then:
        thrown(UnsupportedOperationException)
        cleanup:
        providerSet.addAll(backup)
    }
}
