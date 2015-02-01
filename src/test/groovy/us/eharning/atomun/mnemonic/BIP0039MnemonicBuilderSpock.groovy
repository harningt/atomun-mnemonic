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

import groovy.json.JsonSlurper
import spock.lang.Specification

import java.text.Normalizer

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class BIP0039MnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.BIP0039
    static final String OFFICIAL_PASSWORD = "Trezor"
    static final OFFICIAL_VECTORS
    static final JP_VECTORS
    static {
        OFFICIAL_VECTORS = new JsonSlurper().parseURL(BIP0039MnemonicBuilderSpock.class.classLoader.getResource("us/eharning/atomun/mnemonic/BIP0039_TREZOR_VECTORS.json"), null)
        JP_VECTORS = new JsonSlurper().parseURL(BIP0039MnemonicBuilderSpock.class.classLoader.getResource("us/eharning/atomun/mnemonic/BIP0039-test_JP.json"), null)
    }

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
    Iterable<Object[]> getEncodingCombinations() {
        /* Returns out items of: wordList, entropy, wordList, seed */
        List<Object[]> combinations = new ArrayList<>()
        OFFICIAL_VECTORS.each{
            String wordList = it.key
            it.value.each{ test ->
                Object[] item = [ wordList, test[0].decodeHex(), Normalizer.normalize(test[1], Normalizer.Form.NFKD), test[2].decodeHex()]
                combinations.add(item)
            }
        }
        return combinations
    }
    def "check standard test vectors"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList(wordList)
            builder.setEntropy(entropy)
        then:
            mnemonic == builder.build()
        where:
            [wordList, entropy, mnemonic, _] << getEncodingCombinations()
    }

    def "check jp test vectors"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList("japanese")
            builder.setEntropy(entropy)
        then:
            mnemonic == builder.build()
        where:
            testCase << JP_VECTORS
            entropy = testCase.entropy.decodeHex()
            /* Specification declares that mnemonics are normalized to NFKD.
             * Inputs must be normalized properly due to user keyboard/etc. */
            mnemonic = Normalizer.normalize(testCase.mnemonic, Normalizer.Form.NFKD)
    }
    def "null extension return"() {
        expect:
            null == MnemonicBuilder.newBuilder(ALG).getExtension(Object)
    }
    def "check encoding fails when no state set"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.build()
        then:
            thrown(IllegalStateException)
    }
    def "check encoding fails when attempted entropyLength set fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            try { builder.setEntropyLength(1) } catch(e) {}
            builder.build()
        then:
            thrown(IllegalStateException)
    }
    def "check encoding fails when attempted entropy set fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            try { builder.setEntropyLength(new byte[1]) } catch(e) {}
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
    def "check that settings entropy after entropy length fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setEntropyLength(4)
            builder.setEntropy(new byte[4])
        then:
            thrown(IllegalStateException)
    }
    def "check that settings entropy length after entropy fails"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setEntropy(new byte[4])
            builder.setEntropyLength(4)
        then:
            thrown(IllegalStateException)
    }
}
