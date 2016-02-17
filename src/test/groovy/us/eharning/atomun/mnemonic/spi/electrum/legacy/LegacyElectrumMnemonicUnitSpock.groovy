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

import net.trajano.commons.testing.EqualsTestUtil
import org.joor.Reflect
import spock.lang.Ignore
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicUnit.Builder

/**
 * Test sequence for the legacy Electrum mnemonic unit SPI
 */
class LegacyElectrumMnemonicUnitSpock extends Specification {
    static final LegacyElectrumMnemonicUnitSpi spi = new LegacyElectrumMnemonicUnitSpi()
    static final Builder builder = Reflect.on(Builder).create().get()

    static String[][] pairs = [
            ["pleasure patience practice", "01234567"],
            ["pleasure patience practice offer jeans sister", "0123456789012345"],
            ["speak lunch group spring ring branch sign reflect cage slowly only carefully", "eeb15bed5a8ee524e254c5eab327c49c"],
            ["happen made spring knock heart middle suppose fish bought plain real ignore", "88c811176129b2882fc4737728195b87"],
            ["class group aside accept eat howl harm world ignorance brain count dude", "f9379762a6da83b4e40e31b682a6dd8d"]
    ]

    def "check #mnemonic represents #hex"(String mnemonic, String hex) {
        expect:
        spi.getEntropy(mnemonic).encodeHex().toString() == hex
        spi.getSeed(mnemonic, null).encodeHex().toString() == hex

        where:
        [mnemonic, hex] << pairs
    }
    def "check #mnemonic represents #hex for object form"(String mnemonic, String hex) {
        given:
        def unit = spi.build(builder, mnemonic, null)
        def unitWithEntropy = spi.build(builder, mnemonic, hex.decodeHex())

        expect:
        unit.getEntropy().encodeHex().toString() == hex
        unit.getSeed(null).encodeHex().toString() == hex

        unitWithEntropy.getEntropy().encodeHex().toString() == hex
        unitWithEntropy.getSeed(null).encodeHex().toString() == hex

        where:
        [mnemonic, hex] << pairs
    }

    @Ignore
    def "check #mnemonic represents #hex for object form are properly equal"(String mnemonic, String hex) {
        given:
        def unit = spi.build(builder, mnemonic, null)
        def unitWithEntropy = spi.build(builder, mnemonic, hex.decodeHex())

        when:
        EqualsTestUtil.assertEqualsImplementedCorrectly(unit)
        EqualsTestUtil.assertEqualsImplementedCorrectly(unitWithEntropy)
        EqualsTestUtil.assertEqualsImplementedCorrectly(unit, unitWithEntropy)
        then:
        noExceptionThrown()

        where:
        [mnemonic, hex] << pairs
    }


    def "check seed retrieval fails with a password"(String mnemonic, String hex) {
        given:
        def unitWithEntropy = spi.build(builder, mnemonic, hex.decodeHex())

        when:
        unitWithEntropy.getSeed("password")

        then:
        thrown(UnsupportedOperationException)

        where:
        [mnemonic, hex] << pairs
    }
}
