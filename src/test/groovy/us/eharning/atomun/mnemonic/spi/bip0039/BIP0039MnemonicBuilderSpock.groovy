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

import com.google.common.base.Predicates
import com.google.common.collect.ImmutableSet
import com.google.common.collect.Iterables
import spock.lang.IgnoreIf
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier
import us.eharning.atomun.mnemonic.MnemonicUnit
import us.eharning.atomun.mnemonic.MoreMnemonicExtensionIdentifiers

import java.text.Normalizer

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class BIP0039MnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.BIP0039

    static final Set<BIP0039ExtensionIdentifier> NON_GETTABLE_EXTENSIONS = ImmutableSet.copyOf(Iterables.filter(Arrays.asList(BIP0039ExtensionIdentifier.values()), Predicates.not(MoreMnemonicExtensionIdentifiers.CAN_SET)))
    static final Set<BIP0039ExtensionIdentifier> NON_SETTABLE_EXTENSIONS = ImmutableSet.copyOf(Iterables.filter(Arrays.asList(BIP0039ExtensionIdentifier.values()), Predicates.not(MoreMnemonicExtensionIdentifiers.CAN_GET)))

    private static def RW_IDENTIFIER = new MnemonicExtensionIdentifier() {
        @Override
        boolean canGet() {
            return true
        }

        @Override
        boolean canSet() {
            return true
        }
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

    def "check standard test vectors"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setWordList(testCase.wordList)
        builder.setEntropy(testCase.entropyBytes)
        then:
        /* Normalize output to ensure it properly matches normalized test case */
        testCase.normalizedMnemonic == Normalizer.normalize(builder.build(), Normalizer.Form.NFKD)
        testCase.normalizedMnemonic == Normalizer.normalize(builder.buildUnit().getMnemonic(), Normalizer.Form.NFKD)
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
        testCase.normalizedMnemonic == Normalizer.normalize(builder.buildUnit().getMnemonic(), Normalizer.Form.NFKD)
        where:
        testCase << BIP0039TestData.JP_VECTORS
    }

    def "check standard test vectors roundtrip"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        builder.setWordList(testCase.wordList)
        builder.setEntropy(testCase.entropyBytes)
        MnemonicUnit unit = builder.buildUnit()
        expect:
        /* Normalize output to ensure it properly matches normalized test case */
        testCase.normalizedMnemonic == Normalizer.normalize(unit.mnemonic, Normalizer.Form.NFKD)
        testCase.entropyBytes == unit.entropy
        where:
        testCase << BIP0039TestData.TREZOR_OFFICIAL_VECTORS
    }

    def "check jp test vectors roundtrip"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        builder.setWordList(testCase.wordList)
        builder.setEntropy(testCase.entropyBytes)
        MnemonicUnit unit = builder.buildUnit()
        expect:
        /* Normalize output to ensure it properly matches normalized test case */
        testCase.normalizedMnemonic == Normalizer.normalize(unit.mnemonic, Normalizer.Form.NFKD)
        testCase.entropyBytes == unit.entropy
        where:
        testCase << BIP0039TestData.JP_VECTORS
    }

    def "check encoding paases when no state set with safe defaults"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.build()
        then:
        noExceptionThrown()
    }

    @IgnoreIf({ NON_SETTABLE_EXTENSIONS.empty })
    def "check non-settable values cause failure on set"(MnemonicExtensionIdentifier extensionIdentifier) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setExtensions([ (extensionIdentifier): new Object() ])
        then:
        thrown(IllegalArgumentException)
        where:
        extensionIdentifier << NON_SETTABLE_EXTENSIONS
    }

    @IgnoreIf({ NON_GETTABLE_EXTENSIONS.empty })
    def "check non-gettable values cause failure on retrieval"(MnemonicExtensionIdentifier extensionIdentifier) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        def unit = builder.buildUnit()
        when:
        unit.getExtensionValue(extensionIdentifier)
        then:
        thrown(IllegalArgumentException)
        where:
        extensionIdentifier << NON_GETTABLE_EXTENSIONS
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
        builder.setExtensions([(RW_IDENTIFIER): 1])
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
