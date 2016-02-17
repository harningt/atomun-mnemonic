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

package us.eharning.atomun.mnemonic.spi.electrum.v2

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import net.trajano.commons.testing.EqualsTestUtil
import org.joor.Reflect
import spock.lang.Ignore
import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicUnit.Builder

/**
 * Test sequence for the legacy Electrum mnemonic unit SPI
 */
class ElectrumV2MnemonicUnitSpock extends Specification {
    static final LoadingCache<String, MnemonicUnitSpiImpl> spiMap = CacheBuilder.newBuilder().build(new CacheLoader<String, MnemonicUnitSpiImpl>() {
        @Override
        MnemonicUnitSpiImpl load(String key) throws Exception {
            return new MnemonicUnitSpiImpl(MnemonicUtility.getDictionary(key))
        }
    })
    static final Builder builder = Reflect.on(Builder).create().get()

    def "generic check #testCase.mnemonic string represents #testCase.entropy "() {
        given:
        def spi = spiMap.get(testCase.wordList)
        expect:
        spi.getEntropy(testCase.mnemonic).encodeHex().toString() == testCase.entropy
        spi.getSeed(testCase.mnemonic, null)
        spi.getSeed(testCase.mnemonic, testCase.passphrase)
        spi.getSeed(testCase.mnemonic, "password")

        where:
        testCase << ElectrumV2TestData.ALL_VECTORS
    }

    def "check #testCase.mnemonic represents #testCase.entropy for object form"() {
        given:
        def spi = spiMap.get(testCase.wordList)
        def unit = spi.build(builder, testCase.mnemonic, null, MnemonicDecoderSpiImpl.SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(testCase.versionPrefix))
        def unitWithEntropy  = spi.build(builder, testCase.mnemonic, testCase.entropyBytes, MnemonicDecoderSpiImpl.SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(testCase.versionPrefix))

        expect:
        unit.getEntropy().encodeHex().toString() == testCase.entropy
        unit.getSeed(null)
        unit.getSeed(testCase.passphrase)
        unit.getSeed("password")

        unitWithEntropy .getEntropy().encodeHex().toString() == testCase.entropy
        unitWithEntropy .getSeed(null)
        unitWithEntropy .getSeed(testCase.passphrase)
        unitWithEntropy .getSeed("password")
        where:
        testCase << ElectrumV2TestData.ALL_VECTORS
    }

    @Ignore
    def "check #testCase.mnemonic represents #testCase.entropy for object form are properly equal"() {
        given:
        def spi = spiMap.get(testCase.wordList)
        def unit = spi.build(builder, testCase.mnemonic, null, MnemonicDecoderSpiImpl.SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(testCase.versionPrefix))
        def unitWithEntropy  = spi.build(builder, testCase.mnemonic, testCase.entropyBytes, MnemonicDecoderSpiImpl.SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(testCase.versionPrefix))

        when:
        EqualsTestUtil.assertEqualsImplementedCorrectly(unit)
        EqualsTestUtil.assertEqualsImplementedCorrectly(unitWithEntropy)
        EqualsTestUtil.assertEqualsImplementedCorrectly(unit, unitWithEntropy)
        then:
        noExceptionThrown()

        where:
        testCase << ElectrumV2TestData.ALL_VECTORS
    }


    def "check seed retrieval passes with a password"() {
        given:
        def spi = spiMap.get(testCase.wordList)
        def unitWithEntropy  = spi.build(builder, testCase.mnemonic, testCase.entropyBytes, MnemonicDecoderSpiImpl.SUPPORTED_READABLE_EXTENSIONS, new ElectrumV2ExtensionLoader(testCase.versionPrefix))

        when:
        unitWithEntropy.getSeed("password")

        then:
        noExceptionThrown()

        where:
        testCase << ElectrumV2TestData.ALL_VECTORS
    }
}
