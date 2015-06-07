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

import com.google.common.base.Predicates
import com.google.common.collect.ImmutableSet
import com.google.common.collect.Iterables
import spock.lang.IgnoreIf
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicBuilder
import us.eharning.atomun.mnemonic.MnemonicExtensionIdentifier
import us.eharning.atomun.mnemonic.MoreMnemonicExtensionIdentifiers

import java.security.SecureRandom

/**
 * Test sequence for the legacy Electrum mnemonic builder
 */
class ElectrumV2MnemonicBuilderSpock extends Specification {
    static final MnemonicAlgorithm ALG = MnemonicAlgorithm.ElectrumV2
    static final SecureRandom RNG = new SecureRandom()

    static final Set<ElectrumV2ExtensionIdentifier> NON_GETTABLE_EXTENSIONS = ImmutableSet.copyOf(Iterables.filter(Arrays.asList(ElectrumV2ExtensionIdentifier.values()), Predicates.not(MoreMnemonicExtensionIdentifiers.CAN_SET)))
    static final Set<ElectrumV2ExtensionIdentifier> NON_SETTABLE_EXTENSIONS = ImmutableSet.copyOf(Iterables.filter(Arrays.asList(ElectrumV2ExtensionIdentifier.values()), Predicates.not(MoreMnemonicExtensionIdentifiers.CAN_GET)))

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
    def "check encoding passes with each version prefix"(VersionPrefix versionPrefix) {
        given:
            def builder = MnemonicBuilder.newBuilder(ALG)
        when:
            builder.setExtensions([ (ElectrumV2ExtensionIdentifier.VERSION_PREFIX): versionPrefix ])
        then:
            noExceptionThrown()
        expect:
            builder.buildUnit().getExtensionValue(ElectrumV2ExtensionIdentifier.VERSION_PREFIX) == versionPrefix
        where:
            versionPrefix << VersionPrefix.values()
    }
    def "check encoding fails with illegal custom entropy"(BigInteger customEntropy) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        when:
        builder.setExtensions([ (ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY): customEntropy ])
        then:
        thrown(IllegalArgumentException)
        where:
        customEntropy | _
        BigInteger.ZERO | _
        BigInteger.ONE.negate() | _
    }
    def "check encoding passes with custom entropy"(int entropyBitLength) {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        BigInteger customEntropy = BigInteger.probablePrime(entropyBitLength, RNG)
        when:
        builder.setExtensions([ (ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY): customEntropy ])
        then:
        noExceptionThrown()
        expect:
        new BigInteger(1, builder.buildUnit().entropy).remainder(customEntropy) == BigInteger.ZERO
        where:
        entropyBitLength | _
        8 | _
        16 | _
        64 | _
        128 | _
        512 | _
    }
    def "check encoding passes with custom entropy but cannot retrieve"() {
        given:
        def builder = MnemonicBuilder.newBuilder(ALG)
        BigInteger customEntropy = BigInteger.probablePrime(8, RNG)
        builder.setExtensions([ (ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY): customEntropy ])
        def unit = builder.buildUnit()
        when:
        unit.getExtensionValue(ElectrumV2ExtensionIdentifier.CUSTOM_ENTROPY)
        then:
        thrown(IllegalArgumentException)
    }
    def "check encoding passes when no state set with safe defaults"() {
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
