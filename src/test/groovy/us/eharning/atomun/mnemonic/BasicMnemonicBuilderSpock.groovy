/*
 * Copyright 2014 Thomas Harning Jr. <harningt@gmail.com>
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

import spock.lang.Specification


/**
 * Basic test for the BasicMnemonicBuilderSpi base class.
 */
class BasicMnemonicBuilderSpock extends Specification {
    static class DummyBuilder extends BasicMnemonicBuilderSpi {
        @Override
        protected String build(byte[] entropy) {
            return "DUMMY"
        }

        @Override
        protected void checkEntropyLengthValid(int entropyLength) {
            if (entropyLength == 0 || entropyLength % 4 != 0) {
                throw new IllegalArgumentException()
            }
        }
    }
    def "check encoding fails for invalid entropyLength values"() {
        given:
            def builder = new DummyBuilder()
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
            def builder = new DummyBuilder()
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
            def builder = new DummyBuilder()
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
            def builder = new DummyBuilder()
        when:
            builder.setEntropyLength(4)
            builder.setEntropy(new byte[4])
        then:
            thrown(IllegalStateException)
    }
    def "check that settings entropy length after entropy fails"() {
        given:
            def builder = new DummyBuilder()
        when:
            builder.setEntropy(new byte[4])
            builder.setEntropyLength(4)
        then:
            thrown(IllegalStateException)
    }
}