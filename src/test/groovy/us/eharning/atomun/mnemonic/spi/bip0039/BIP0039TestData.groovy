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

import com.google.common.base.Charsets
import com.google.common.collect.ImmutableList
import com.google.common.collect.Iterables
import groovy.json.JsonSlurper
import groovy.transform.Canonical
import org.yaml.snakeyaml.Yaml

import java.text.Normalizer

/**
 * Container for common BIP0039 test data.
 */
class BIP0039TestData {
    @Canonical
    static class MnemonicTestCase {
        String groupLabel;
        String wordList;
        String mnemonic;

        public String getNormalizedMnemonic() {
            return Normalizer.normalize(mnemonic, Normalizer.Form.NFKD);
        }
        public String passphrase;
        public String entropy;

        public byte[] getEntropyBytes() {
            return entropy.decodeHex();
        }
        public String seed;

        public byte[] getSeedBytes() {
            return seed.decodeHex();
        }
        public String bip32_xprv;
    }
    public static final Iterable<MnemonicTestCase> TREZOR_OFFICIAL_VECTORS
    public static final Iterable<MnemonicTestCase> JP_VECTORS

    private static List<MnemonicTestCase> parseYamlResource(String resourceName) {
        InputStream input = BIP0039MnemonicBuilderSpock.class.classLoader.getResourceAsStream(resourceName)
        assert(input)
        ImmutableList.Builder<MnemonicTestCase> caseBuilder = ImmutableList.builder()
        new Yaml().loadAll(input).each {
            String groupLabel = it.groupLabel
            String wordList = it.wordList
            String passphrase = it.passphrase
            if (it.skip) {
                return
            }
            it.cases.each {
                MnemonicTestCase testCase = it as MnemonicTestCase
                testCase.groupLabel = groupLabel
                if (!testCase.wordList) {
                    testCase.wordList = wordList
                }
                if (!testCase.passphrase) {
                    testCase.passphrase = passphrase
                }
                caseBuilder.add(testCase)
            }
        }
        return caseBuilder.build()
    }
    static {
        TREZOR_OFFICIAL_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/bip0039/BIP0039_TREZOR_VECTORS.yaml")
        JP_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/bip0039/BIP0039-test_JP.yaml")
    }
}
