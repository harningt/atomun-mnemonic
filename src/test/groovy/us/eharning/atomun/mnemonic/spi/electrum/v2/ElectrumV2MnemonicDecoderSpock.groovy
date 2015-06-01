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

import com.google.common.collect.Iterables
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicUnit

/**
 * Test around the legacy Electrum mnemonic decoder system.
 */
class ElectrumV2MnemonicDecoderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.ElectrumV2

    def "check #mnemonic string decodes to matching values for standard vectors"() {
        given:
            MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, testCase.mnemonic, testCase.wordList)
        expect:
            unit.getEntropy() == testCase.entropyBytes
            //unit.getSeed(testCase.passphrase) == testCase.seedBytes
            unit.getMnemonic() == testCase.mnemonic
            unit.getSupportedExtensions().containsAll(EnumSet.allOf(ElectrumV2ExtensionIdentifiers.class))
        where:
            testCase << ElectrumV2TestData.STANDARD_VECTORS
    }
    def "check #mnemonic string decodes to matching values for other-language vectors"() {
        given:
            MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, testCase.mnemonic, testCase.wordList)
        expect:
            unit.getEntropy() == testCase.entropyBytes
            //unit.getSeed(testCase.passphrase) == testCase.seedBytes
            unit.getMnemonic() == testCase.mnemonic
            unit.getSupportedExtensions().containsAll(EnumSet.allOf(ElectrumV2ExtensionIdentifiers.class))
        where:
            testCase << ElectrumV2TestData.LANGUAGE_VECTORS
    }
    def "check normalized mnemonic values match"() {
        expect:
            testCase.normalizedMnemonic == MnemonicUtility.normalizeSeed(testCase.mnemonic)
        where:
            testCase << Iterables.filter(ElectrumV2TestData.LANGUAGE_VECTORS, { null != it.normalizedMnemonic })
    }

    def "generic check #mnemonic string decodes to #encoded with single valid element with specific wordList"() {
        given:
            Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(testCase.mnemonic, testCase.wordList)
            MnemonicUnit unit = Iterables.getFirst(units, null)
        expect:
            Iterables.size(units) == 1
            unit.getEntropy() == testCase.entropyBytes
            //unit.getSeed(testCase.passphrase) == testCase.seedBytes
            unit.getMnemonic() == testCase.mnemonic
            unit.getSupportedExtensions().containsAll(EnumSet.allOf(ElectrumV2ExtensionIdentifiers.class))
        where:
            testCase << ElectrumV2TestData.ALL_VECTORS
    }
    def "generic check #mnemonic string decodes to #encoded with single valid element with unspecified wordList"() {
        given:
            Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(testCase.mnemonic)
            MnemonicUnit unit = Iterables.getFirst(units, null)
        expect:
            Iterables.size(units) == 1
            unit.getEntropy() == testCase.entropyBytes
            //unit.getSeed(testCase.passphrase) == testCase.seedBytes
            unit.getMnemonic() == testCase.mnemonic
            unit.getSupportedExtensions().containsAll(EnumSet.allOf(ElectrumV2ExtensionIdentifiers.class))
        where:
            testCase << ElectrumV2TestData.ALL_VECTORS
    }

    def "decoding mnemonics with unknown word lists is unsupported"() {
        when:
            MnemonicUnit.decodeMnemonic(ALG, mnemonic, "CUSTOM")
        then:
            thrown IllegalArgumentException
        where:
            mnemonic = "word face make"
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
