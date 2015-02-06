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
package us.eharning.atomun.mnemonic.spi.bip0039

import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder

import java.text.Normalizer

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class BIP0039MnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.BIP0039

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
    def "check standard test vectors"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList(testCase.wordList)
            builder.setEntropy(testCase.entropyBytes)
        then:
            /* Normalize output to ensure it properly matches normalized test case */
            testCase.normalizedMnemonic == Normalizer.normalize(builder.build(), Normalizer.Form.NFKD)
        where:
            testCase << BIP0039TestData.TREZOR_OFFICIAL_VECTORS
    }

    def "check jp test vectors"() {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setWordList(testCase.wordList)
            builder.setEntropy(testCase.entropyBytes)
        then:
            /* Normalize output to ensure it properly matches normalized test case */
            testCase.normalizedMnemonic == Normalizer.normalize(builder.build(), Normalizer.Form.NFKD)
        where:
            testCase << BIP0039TestData.JP_VECTORS
    }
    def "null extension return"() {
        expect:
            null == MnemonicBuilder.newBuilder(ALG).getExtension(Object)
    }
    def "check encoding paases when no state set with safe defaults"() {
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
