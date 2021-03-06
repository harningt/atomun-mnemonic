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
package us.eharning.atomun.mnemonic.spi

import spock.lang.Specification
import us.eharning.atomun.mnemonic.MnemonicAlgorithm
import us.eharning.atomun.mnemonic.MnemonicServices

import javax.annotation.Nonnull
import javax.annotation.Nullable

/**
 * Builder SPI tests
 */
class MnemonicUnitSpiSpecification extends Specification {
    class DummySpi extends MnemonicUnitSpi {
        /**
         * Construct a new SPI as if it were any passed-in algorithm.
         */
        DummySpi(MnemonicAlgorithm algorithm) {
            super(algorithm)
        }

        @Override
        byte[] getEntropy(@Nonnull CharSequence mnemonicSequence) {
            throw new UnsupportedOperationException()
        }

        @Nonnull
        @Override
        byte[] getSeed(@Nonnull CharSequence mnemonicSequence, @Nullable CharSequence password) {
            throw new UnsupportedOperationException()
        }
    }

    def "Builders must have a non-null algorithm"() {
        when:
        new DummySpi(null)
        then:
        thrown(NullPointerException)
    }

    def "Builders must have a registered algorithm"() {
        given:
        def unregisteredAlgorithm = new MnemonicAlgorithm() {}
        when:
        new DummySpi(unregisteredAlgorithm)
        then:
        thrown(UnsupportedOperationException)
    }

    def "Builders must return their expected algorithm"(MnemonicAlgorithm algorithm) {
        given:
        def spi = new DummySpi(algorithm)
        expect:
        spi.algorithm == algorithm
        where:
        algorithm << MnemonicServices.registeredAlgorithms
    }
}
