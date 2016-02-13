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
package us.eharning.atomun.mnemonic

import com.google.common.collect.Iterables
import spock.lang.Specification

/**
 * Generic decoding handler test.
 */
class MnemonicDecoderGenericSpock extends Specification {
    def "requesting an unlisted algorithm results in failure"() {
        when:
        MnemonicUnit.decodeMnemonic((MnemonicAlgorithm) null, "TEST")
        then:
        thrown(UnsupportedOperationException)
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
}