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

package us.eharning.atomun.mnemonic.spi.bip0039

import com.google.common.collect.ImmutableSet
import com.google.common.collect.Iterables
import spock.lang.Specification
import us.eharning.atomun.mnemonic.BIPMnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier
import us.eharning.atomun.mnemonic.MnemonicUnit

import java.text.Normalizer

/**
 * Test around the legacy Electrum mnemonic decoder system.
 */
class BIP0039MnemonicDecoderSpock extends Specification {
    static final MnemonicAlgorithm ALG = BIPMnemonicAlgorithm.BIP0039
    static final Set<MnemonicExtensionIdentifier> GETTABLE_EXTENSIONS = ImmutableSet.of() //MoreMnemonicExtensionIdentifiers.canGet(BIP0039ExtensionIdentifier.values())

    def "check #mnemonic string decodes to #seed for standard vector"() {
        given:
        MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, testCase.mnemonic, testCase.wordList)
        expect:
        unit.getEntropy() == testCase.entropyBytes
        unit.getSeed() != testCase.seedBytes
        unit.getSeed(null) != testCase.seedBytes
        unit.getSeed("") != testCase.seedBytes
        unit.getSeed(testCase.passphrase) == testCase.seedBytes
        unit.getMnemonic() == testCase.mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        /* Round-trip test */
        /* Replace ideographic space by space always */
        unit.getMnemonic().replace("\u3000", " ") == MnemonicBuilder.newBuilder(ALG).setEntropy(testCase.entropyBytes).setWordList(testCase.wordList).build()
        where:
        testCase << BIP0039TestData.TREZOR_OFFICIAL_VECTORS
    }

    def "check #mnemonic string decodes to #seed for JP vector"() {
        given:
        MnemonicUnit unit = MnemonicUnit.decodeMnemonic(ALG, testCase.mnemonic, testCase.wordList)
        expect:
        unit.getEntropy() == testCase.entropyBytes
        unit.getSeed() != testCase.seedBytes
        unit.getSeed(null) != testCase.seedBytes
        unit.getSeed("") != testCase.seedBytes
        unit.getSeed(testCase.passphrase) == testCase.seedBytes
        unit.getMnemonic() == testCase.mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        /* Round-trip test */
        /* Replace ideographic space by space always */
        Normalizer.normalize(unit.getMnemonic().replace("\u3000", " "), Normalizer.Form.NFKD) == Normalizer.normalize(MnemonicBuilder.newBuilder(ALG).setEntropy(testCase.entropyBytes).setWordList(testCase.wordList).build(), Normalizer.Form.NFKD)
        where:
        testCase << BIP0039TestData.JP_VECTORS
    }

    def "generic check #mnemonic string decodes to #encoded with single valid element with specific wordList"() {
        given:
        Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(testCase.mnemonic, testCase.wordList)
        MnemonicUnit unit = Iterables.getFirst(Iterables.filter(units, { it.algorithm == ALG }), null)
        expect:
        Iterables.size(units) >= 1
        unit.getEntropy() == testCase.entropyBytes
        unit.getSeed() != testCase.seedBytes
        unit.getSeed(null) != testCase.seedBytes
        unit.getSeed("") != testCase.seedBytes
        unit.getSeed(testCase.passphrase) == testCase.seedBytes
        unit.getMnemonic() == testCase.mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        testCase << BIP0039TestData.TREZOR_OFFICIAL_VECTORS
    }

    def "generic check #mnemonic string decodes to #encoded with single valid element with unspecified wordList"() {
        given:
        Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(testCase.mnemonic)
        MnemonicUnit unit = Iterables.getFirst(Iterables.filter(units, { it.algorithm == ALG }), null)
        expect:
        Iterables.size(units) >= 1
        unit.getEntropy() == testCase.entropyBytes
        unit.getSeed() != testCase.seedBytes
        unit.getSeed(null) != testCase.seedBytes
        unit.getSeed("") != testCase.seedBytes
        unit.getSeed(testCase.passphrase) == testCase.seedBytes
        unit.getMnemonic() == testCase.mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        testCase << BIP0039TestData.TREZOR_OFFICIAL_VECTORS
    }

    def "japanese: generic check #mnemonic string decodes to #encoded with single valid element with unspecified wordList"() {
        given:
        Iterable<MnemonicUnit> units = MnemonicUnit.decodeMnemonic(testCase.mnemonic)
        MnemonicUnit unit = Iterables.getFirst(Iterables.filter(units, { it.algorithm == ALG }), null)
        expect:
        Iterables.size(units) >= 1
        unit.getEntropy() == testCase.entropyBytes
        unit.getSeed() != testCase.seedBytes
        unit.getSeed(null) != testCase.seedBytes
        unit.getSeed("") != testCase.seedBytes
        unit.getSeed(testCase.passphrase) == testCase.seedBytes
        unit.getMnemonic() == testCase.mnemonic
        unit.getSupportedExtensions().containsAll(GETTABLE_EXTENSIONS)
        where:
        testCase << BIP0039TestData.JP_VECTORS
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

    def "mnemonic decoding with invalid dictionary words in a specific dictionary throw"() {
        when:
        MnemonicUnit.decodeMnemonic(ALG, "practice practice FAILURE", "english")
        then:
        thrown IllegalArgumentException
    }

    def "unspecified mnemonic decoding with invalid dictionary words result in empty list"() {
        expect:
        Iterables.isEmpty(MnemonicUnit.decodeMnemonic("practice practice FAILURE"))
    }

    def "unspecified mnemonic decoding with invalid dictionary words in a specific dictionary result in empty list"() {
        expect:
        Iterables.isEmpty(MnemonicUnit.decodeMnemonic("practice practice FAILURE", "english"))
    }
}
