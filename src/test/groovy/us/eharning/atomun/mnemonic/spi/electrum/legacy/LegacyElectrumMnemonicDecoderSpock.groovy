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

import com.google.common.collect.Iterables
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier
import us.eharning.atomun.mnemonic.MnemonicUnit
import us.eharning.atomun.mnemonic.MoreMnemonicExtensionIdentifiers

/**
 * Test around the legacy Electrum mnemonic decoder system.
 */
class LegacyElectrumMnemonicDecoderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.LegacyElectrum
    static String[][] pairs = [
            ["pleasure patience practice", "01234567"],
            ["pleasure patience practice offer jeans sister", "0123456789012345"],
            ["speak lunch group spring ring branch sign reflect cage slowly only carefully", "eeb15bed5a8ee524e254c5eab327c49c"],
            ["happen made spring knock heart middle suppose fish bought plain real ignore", "88c811176129b2882fc4737728195b87"],
            ["class group aside accept eat howl harm world ignorance brain count dude", "f9379762a6da83b4e40e31b682a6dd8d"]
    ]
    static final Set<MnemonicExtensionIdentifier> GETTABLE_EXTENSIONS = MoreMnemonicExtensionIdentifiers.onlyCanGet(LegacyElectrumExtensionIdentifier.values())


    def "check #mnemonic string decodes to #encoded"(String mnemonic, String hex) {
        given:
        MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, mnemonic)
        expect:
        unit.getEntropy() == hex.decodeHex()
        unit.getSeed() == hex.decodeHex()
        unit.getSeed(null) == hex.decodeHex()
        unit.getSeed("") == hex.decodeHex()
        unit.getMnemonic() == mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        [mnemonic, hex] << pairs
    }

    def "generic check #mnemonic string decodes to #encoded with single valid element"(String mnemonic, String hex) {
        given:
        Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(mnemonic)
        MnemonicUnit unit = Iterables.getFirst(Iterables.filter(units, { it.algorithm == ALG }), null)
        expect:
        Iterables.size(units) >= 1
        unit.getEntropy() == hex.decodeHex()
        unit.getSeed() == hex.decodeHex()
        unit.getSeed(null) == hex.decodeHex()
        unit.getSeed("") == hex.decodeHex()
        unit.getMnemonic() == mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        [mnemonic, hex] << pairs
    }

    def "check #mnemonic string with non-standard case decodes to #encoded"(String mnemonic, String hex) {
        given:
        MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, mnemonic)
        expect:
        unit.getEntropy() == hex.decodeHex()
        unit.getSeed() == hex.decodeHex()
        unit.getSeed(null) == hex.decodeHex()
        unit.getSeed("") == hex.decodeHex()
        unit.getMnemonic() == mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        [mnemonic, hex] << pairs
    }

    def "generic check #mnemonic string with non-standard case decodes to #encoded with single valid element"(String mnemonic, String hex) {
        given:
        Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(mnemonic.toUpperCase())
        MnemonicUnit unit = Iterables.getFirst(Iterables.filter(units, { it.algorithm == ALG }), null)
        expect:
        Iterables.size(units) >= 1
        unit.getEntropy() == hex.decodeHex()
        unit.getSeed() == hex.decodeHex()
        unit.getSeed(null) == hex.decodeHex()
        unit.getSeed("") == hex.decodeHex()
        unit.getMnemonic() == mnemonic.toUpperCase()
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        [mnemonic, hex] << pairs
    }

    def "seed generation with password is unsupported"(String mnemonic) {
        when:
        MnemonicUnit.decodeMnemonic(ALG, mnemonic).getSeed("TEST")
        then:
        thrown(UnsupportedOperationException)
        where:
        [mnemonic, _] << pairs
    }

    def "decoding mnemonics with custom word lists is unsupported"(String mnemonic) {
        when:
        MnemonicUnit.decodeMnemonic(ALG, mnemonic, "CUSTOM")
        then:
        thrown(UnsupportedOperationException)
        where:
        [mnemonic, _] << pairs
    }

    def "mnemonic decoding of invalid too-short values throw"() {
        when:
        MnemonicUnit.decodeMnemonic(ALG, "practice")
        then:
        thrown IllegalArgumentException
    }

    def "unspecified mnemonic decoding of invalid too-short values results in empty list"() {
        expect:
        Iterables.isEmpty(MnemonicUnit.decodeMnemonic("practice"))
    }

    def "mnemonic decoding with invalid dictionary words throw"() {
        when:
        MnemonicUnit.decodeMnemonic(ALG, "practice practice FAILURE")
        then:
        thrown IllegalArgumentException
    }

    def "unspecified mnemonic decoding with invalid dictionary words result in empty list"() {
        expect:
        Iterables.isEmpty(MnemonicUnit.decodeMnemonic("practice practice FAILURE"))
    }
}
