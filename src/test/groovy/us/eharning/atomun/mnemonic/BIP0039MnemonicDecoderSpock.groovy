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

import com.google.common.base.Charsets
import com.google.common.collect.Iterables
import groovy.json.JsonSlurper
import spock.lang.Specification

import java.text.Normalizer

/**
 * Test around the legacy Electrum mnemonic decoder system.
 */
class BIP0039MnemonicDecoderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.BIP0039
    static final String TREZOR_OFFICIAL_PASSWORD = "TREZOR"
    static final TREZOR_OFFICIAL_VECTORS
    static final JP_VECTORS
    private static Object parseResource(String resourceName) {
        InputStream input = BIP0039MnemonicBuilderSpock.class.classLoader.getResourceAsStream(resourceName)
        return new JsonSlurper().parse(new InputStreamReader(input, Charsets.UTF_8));
    }
    static {
        TREZOR_OFFICIAL_VECTORS = parseResource("us/eharning/atomun/mnemonic/BIP0039_TREZOR_VECTORS.json")
        JP_VECTORS = parseResource("us/eharning/atomun/mnemonic/BIP0039-test_JP.json")
    }

    Iterable<Object[]> getEncodingCombinations() {
        /* Returns out items of: wordList, entropy, wordList, seed */
        List<Object[]> combinations = new ArrayList<>()
        TREZOR_OFFICIAL_VECTORS.each{
            String wordList = it.key
            it.value.each{ test ->
                Object[] item = [ wordList, test[0].decodeHex(), Normalizer.normalize(test[1], Normalizer.Form.NFKD), test[2].decodeHex()]
                combinations.add(item)
            }
        }
        return combinations
    }
    def "check #mnemonic string decodes to #seed for standard vector"() {
        given:
            MnemonicUnit unit = MnemonicDecoder.decodeMnemonic(ALG, mnemonic, wordList)
        expect:
            unit.getEntropy() == entropy
            unit.getSeed() != seed
            unit.getSeed(null) != seed
            unit.getSeed("") != seed
            unit.getSeed(password) == seed
            unit.getMnemonic() == mnemonic
            unit.getExtension(Object) == null
            /* Round-trip test */
            /* Replace ideographic space by space always */
            unit.getMnemonic().replace("\u3000", " ") == MnemonicBuilder.newBuilder(ALG).setEntropy(entropy).setWordList(wordList).build()
        where:
            [wordList, entropy, mnemonic, seed] << getEncodingCombinations()
            password = TREZOR_OFFICIAL_PASSWORD
    }

    def "check #mnemonic string decodes to #seed for JP vector"() {
        given:
            MnemonicUnit unit = MnemonicDecoder.decodeMnemonic(ALG, mnemonic, wordList)
        expect:
            unit.getEntropy() == entropy
            unit.getSeed() != seed
            unit.getSeed(null) != seed
            unit.getSeed("") != seed
            unit.getSeed(password) == seed
            unit.getMnemonic() == mnemonic
            unit.getExtension(Object) == null
            /* Round-trip test */
            /* Replace ideographic space by space always */
            unit.getMnemonic().replace("\u3000", " ") == MnemonicBuilder.newBuilder(ALG).setEntropy(entropy).setWordList(wordList).build()
        where:
            wordList = "japanese"
            testCase << JP_VECTORS
            mnemonic = testCase.mnemonic
            password = testCase.passphrase
            entropy = testCase.entropy.decodeHex()
            seed = testCase.seed.decodeHex()
    }
    def "generic check #mnemonic string decodes to #encoded with single valid element with specific wordList"() {
        given:
            Iterable<MnemonicUnit> units = MnemonicDecoder.decodeMnemonic(mnemonic, wordList)
            MnemonicUnit unit = Iterables.getFirst(units, null)
        expect:
            Iterables.size(units) == 1
            unit.getEntropy() == entropy
            unit.getSeed() != seed
            unit.getSeed(null) != seed
            unit.getSeed("") != seed
            unit.getSeed(password) == seed
            unit.getMnemonic() == mnemonic
            unit.getExtension(Object) == null
        where:
            [wordList, entropy, mnemonic, seed] << getEncodingCombinations()
            password = TREZOR_OFFICIAL_PASSWORD
    }
    def "generic check #mnemonic string decodes to #encoded with single valid element with unspecified wordList"() {
        given:
            Iterable<MnemonicUnit> units = MnemonicDecoder.decodeMnemonic(mnemonic)
            MnemonicUnit unit = Iterables.getFirst(units, null)
        expect:
            Iterables.size(units) == 1
            unit.getEntropy() == entropy
            unit.getSeed() != seed
            unit.getSeed(null) != seed
            unit.getSeed("") != seed
            unit.getSeed(password) == seed
            unit.getMnemonic() == mnemonic
            unit.getExtension(Object) == null
        where:
            [wordList, entropy, mnemonic, seed] << getEncodingCombinations()
            password = TREZOR_OFFICIAL_PASSWORD
    }
    def "japanese: generic check #mnemonic string decodes to #encoded with single valid element with unspecified wordList"() {
        given:
            Iterable<MnemonicUnit> units = MnemonicDecoder.decodeMnemonic(mnemonic)
            MnemonicUnit unit = Iterables.getFirst(units, null)
        expect:
            Iterables.size(units) == 1
            unit.getEntropy() == entropy
            unit.getSeed() != seed
            unit.getSeed(null) != seed
            unit.getSeed("") != seed
            unit.getSeed(password) == seed
            unit.getMnemonic() == mnemonic
            unit.getExtension(Object) == null
        where:
            wordList = "japanese"
            testCase << JP_VECTORS
            mnemonic = testCase.mnemonic
            password = testCase.passphrase
            entropy = testCase.entropy.decodeHex()
            seed = testCase.seed.decodeHex()
    }

    def "decoding mnemonics with unknown word lists is unsupported"() {
        when:
            MnemonicDecoder.decodeMnemonic(ALG, mnemonic, "CUSTOM")
        then:
            thrown IllegalArgumentException
        where:
            mnemonic = "word face make"
    }

    def "mnemonic decoding of invalid too-short values throw"() {
        when:
            MnemonicDecoder.decodeMnemonic(ALG, "practice")
        then:
            thrown IllegalArgumentException
    }
    def "unspecified mnemonic decoding of invalid too-short values results in empty list"() {
        expect:
            Iterables.isEmpty(MnemonicDecoder.decodeMnemonic("practice"))
    }
    def "mnemonic decoding with invalid dictionary words throw"() {
        when:
            MnemonicDecoder.decodeMnemonic(ALG, "practice practice FAILURE")
        then:
            thrown IllegalArgumentException
    }
    def "unspecified mnemonic decoding with invalid dictionary words result in empty list"() {
        expect:
            Iterables.isEmpty(MnemonicDecoder.decodeMnemonic("practice practice FAILURE"))
    }
}
