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
package us.eharning.atomun.mnemonic.spi.electrum.legacy

import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder
import us.eharning.atomun.mnemonic.MnemonicUnit

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class LegacyElectrumMnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.LegacyElectrum
    static String[][] pairs = [
            ["pleasure patience practice", "01234567"],
            ["pleasure patience practice offer jeans sister", "0123456789012345"],
            ["speak lunch group spring ring branch sign reflect cage slowly only carefully", "eeb15bed5a8ee524e254c5eab327c49c"],
            ["happen made spring knock heart middle suppose fish bought plain real ignore", "88c811176129b2882fc4737728195b87"],
            ["class group aside accept eat howl harm world ignorance brain count dude", "f9379762a6da83b4e40e31b682a6dd8d"]
    ]

    def "check word lists not supported"() {
        when:
        MnemonicBuilder.newBuilder(ALG).setWordList("TEST")
        then:
        thrown IllegalArgumentException
    }

    def "check #encoded encodes to #mnemonic"(String mnemonic, String hex) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        builder.setEntropy(hex.decodeHex())
        expect:
        mnemonic == builder.build()
        mnemonic == builder.buildUnit().getMnemonic()
        where:
        [mnemonic, hex] << pairs
    }

    def "check roundtrip unit #encoded <-> #mnemonic"(String mnemonic, String hex) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        builder.setEntropy(hex.decodeHex())
        MnemonicUnit unit = builder.buildUnit()
        expect:
        mnemonic == unit.getMnemonic()
        hex.decodeHex() == unit.getEntropy()
        where:
        [mnemonic, hex] << pairs
    }

    def "check encoding succeeds with safe defaults when no state set"() {
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
        try {
            builder.setEntropyLength(1)
        } catch (ignored) {
        }
        builder.build()
        then:
        thrown(IllegalStateException)
    }

    def "check encoding fails when attempted entropy set fails"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        try {
            builder.setEntropy(new byte[1])
        } catch (ignored) {
        }
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

    def "check encoding fails for invalid entropy values"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setEntropy(new byte[length])
        then:
        thrown(IllegalArgumentException)
        where:
        _ | length
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

    def "check that settings entropy after entropy length passes"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setEntropyLength(4)
        builder.setEntropy(new byte[4])
        then:
        noExceptionThrown()
    }

    def "check that settings entropy length after entropy passes"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setEntropy(new byte[4])
        builder.setEntropyLength(4)
        then:
        noExceptionThrown()
    }
}
