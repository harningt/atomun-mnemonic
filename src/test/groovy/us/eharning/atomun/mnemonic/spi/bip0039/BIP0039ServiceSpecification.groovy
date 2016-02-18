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

package us.eharning.atomun.mnemonic.spi.bip0039

import com.google.common.collect.Iterables
import spock.lang.Specification
import us.eharning.atomun.mnemonic.BIPMnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicServices
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider

import static com.google.common.base.Predicates.equalTo
import static com.google.common.base.Predicates.not

/**
 * Test sequence for the legacy Electrum mnemonic service
 */
class BIP0039ServiceSpecification extends Specification {
    MnemonicServiceProvider service = new BIP0039MnemonicService()
    static final def ALG = BIPMnemonicAlgorithm.BIP0039

    def "returns non-null for requests for appropriate algorithm"() {
        expect:
        service.getMnemonicBuilder(ALG)
        service.getMnemonicDecoder(ALG)
    }

    def "returns null for requests for appropriate algorithm"(MnemonicAlgorithm alg) {
        expect:
        !service.getMnemonicBuilder(alg)
        !service.getMnemonicDecoder(alg)
        where:
        alg << Iterables.filter(MnemonicServices.registeredAlgorithms, not(equalTo(ALG)))
    }
}
