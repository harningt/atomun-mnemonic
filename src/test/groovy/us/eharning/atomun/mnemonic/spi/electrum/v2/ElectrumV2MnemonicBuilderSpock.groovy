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
package us.eharning.atomun.mnemonic.spi.electrum.v2

import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039TestData

import java.text.Normalizer

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class ElectrumV2MnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.ElectrumV2

    def "check word lists supported"() {
        given:
            MnemonicBuilder.newBuilder(ALG).setWordList("english")
    }
    def "check unknown word lists throw"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList("UNKNOWN")
        then:
            thrown(IllegalArgumentException)
    }
    def "check custom entropy throws"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setEntropy(new byte[32])
        then:
            thrown(IllegalArgumentException)
    }
    def "check encode in each word list"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList(wordList)
            builder.build()
        then:
            noExceptionThrown()
        where:
            wordList    | _
            "english"   | _
            "japanese"  | _
            "spanish"   | _
            "portuguese"| _
    }
    def "check encoding passes when no state set with safe defaults"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.build()
        then:
            noExceptionThrown()
    }
    def "check encoding fails when attempted entropyLength set fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            try { builder.setEntropyLength(1) } catch(ignored) {}
            builder.build()
        then:
            thrown(IllegalStateException)
    }
    def "check encoding fails when attempted entropy set fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            try { builder.setEntropy(new byte[1]) } catch(ignored) {}
            builder.build()
        then:
            thrown(IllegalStateException)
    }
    def "check encoding fails for invalid entropyLength values"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setEntropyLength(length)
        then:
            thrown(IllegalArgumentException)
        where:
            _ | length
            _ | -1
            _ | 0
            _ | 1
            _ | 2
            _ | 3
            _ | 5
            _ | 9
            _ | 1022
    }
    def "check encoding fails for unknown extension properties"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setExtensions(["x": 1])
        then:
            thrown(IllegalArgumentException)
    }
    def "check encoding passes for valid entropy lengths"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setEntropyLength(length)
        then:
            builder.build() != null
        where:
            _ | length
            _ | 4 * 1
            _ | 4 * 9
            _ | 4 * 100
    }
    def "check that settings entropy length after failed set entropy passes"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            try {   builder.setEntropy(new byte[4]) } catch (ignored) {}
            builder.setEntropyLength(4)
        then:
            noExceptionThrown()
    }
}
