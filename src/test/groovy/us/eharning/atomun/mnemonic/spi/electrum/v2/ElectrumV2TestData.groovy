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
package us.eharning.atomun.mnemonic.spi.electrum.v2

import com.google.common.collect.ImmutableList
import com.google.common.collect.Iterables
import groovy.transform.Canonical
import org.yaml.snakeyaml.Yaml
import us.eharning.atomun.mnemonic.api.electrum.v2.VersionPrefix
import us.eharning.atomun.mnemonic.spi.bip0039.BIP0039MnemonicBuilderSpock

/**
 * Container for common BIP0039 test data.
 */
class ElectrumV2TestData {
    @Canonical
    static class MnemonicTestCase {
        String groupLabel;
        String wordList;
        String mnemonic;
        String normalizedMnemonic;
        public String passphrase;
        public String prefix;
        public byte[] getPrefixBytes() {
            if (prefix.length() % 2 != 0) {
                /* Odd number */
                return (prefix + "0").decodeHex();
            } else {
                return prefix.decodeHex();
            }
        }
        public VersionPrefix getVersionPrefix() {
            byte[] versionPrefixBytes = getPrefixBytes();
            for (VersionPrefix prefix: VersionPrefix.values()) {
                if (prefix.matches(versionPrefixBytes)) {
                    return prefix;
                }
                return null;
            }
        }
        public byte[] getPrefixMask() {
            byte[] ret = new byte[(prefix.length() + 1) / 2];
            if (prefix.length() % 2 != 0) {
                /* Odd number of nibbles */
                Arrays.fill(ret, 0, ret.length - 1, (byte)0xFF);
                ret[ret.length - 1] = 0xF0;
            } else {
                Arrays.fill(ret, 0, ret.length, (byte)0xFF);
            }
            return ret;
        }
        public String customEntropy;
        public BigInteger getCustomEntropyNumber() {
            return new BigInteger(1, customEntropy.decodeHex());
        }
        public String entropy;
        public byte[] getEntropyBytes() {
            return entropy.decodeHex();
        }
        public String seed;
        public byte[] getSeedBytes() {
            return seed.decodeHex();
        }
    }
    public static final Iterable<MnemonicTestCase> EN_VECTORS
    public static final Iterable<MnemonicTestCase> STANDARD_VECTORS
    public static final Iterable<MnemonicTestCase> LARGE_VECTORS
    public static final Iterable<MnemonicTestCase> CUSTOM_ENTROPY_VECTORS
    public static final Iterable<MnemonicTestCase> ES_VECTORS
    public static final Iterable<MnemonicTestCase> PT_VECTORS
    public static final Iterable<MnemonicTestCase> JP_VECTORS
    public static final Iterable<MnemonicTestCase> LANGUAGE_VECTORS
    public static final Iterable<MnemonicTestCase> ALL_VECTORS

    private static List<MnemonicTestCase> parseYamlResource(String resourceName) {
        InputStream input = BIP0039MnemonicBuilderSpock.class.classLoader.getResourceAsStream(resourceName)
        assert(input)
        ImmutableList.Builder<MnemonicTestCase> caseBuilder = ImmutableList.builder()
        new Yaml().loadAll(input).each {
            String groupLabel = it.groupLabel
            String wordList = it.wordList
            String prefix = it.prefix
            if (it.skip) {
                return
            }
            it.cases.each {
                MnemonicTestCase testCase = it as MnemonicTestCase
                testCase.groupLabel = groupLabel
                if (!testCase.wordList) {
                    testCase.wordList = wordList
                }
                if (!testCase.prefix) {
                    testCase.prefix = prefix
                }
                caseBuilder.add(testCase)
            }
        }
        return caseBuilder.build()
    }
    static {
        EN_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/electrum/v2/test_english_data.yaml")
        STANDARD_VECTORS = Iterables.filter(EN_VECTORS, {
            return it.groupLabel == "simple english"
        })
        LARGE_VECTORS = Iterables.filter(EN_VECTORS, {
            return it.groupLabel == "large-entropy english"
        })
        CUSTOM_ENTROPY_VECTORS = Iterables.filter(EN_VECTORS, {
            return it.groupLabel == "custom-entropy english"
        })
        ES_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/electrum/v2/test_spanish_data.yaml")
        PT_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/electrum/v2/test_portuguese_data.yaml")
        JP_VECTORS = parseYamlResource("us/eharning/atomun/mnemonic/spi/electrum/v2/test_japanese_data.yaml")

        LANGUAGE_VECTORS = Iterables.concat(ES_VECTORS, PT_VECTORS, JP_VECTORS)

        ALL_VECTORS = Iterables.concat(
                EN_VECTORS,
                ES_VECTORS,
                PT_VECTORS,
                JP_VECTORS
        )
    }
}
