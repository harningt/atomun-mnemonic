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

package us.eharning.atomun.mnemonic

import com.google.common.base.Predicates
import com.google.common.collect.Iterables
import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.IgnoreIf
import spock.lang.Specification
import us.eharning.atomun.mnemonic.spi.MnemonicServiceProvider

/**
 * Tests covering MnemonicServices operations.
 */
public class MnemonicServicesSpecification extends Specification {
    def "MnemonicServices is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(MnemonicServices.class)
        then:
        noExceptionThrown()
    }

    def "MnemonicServices contains a sequence of service providers"() {
        given:
        def providers = MnemonicServices.serviceProviders
        expect: "it to not be null"
        providers != null
        and: "it to be non-empty in its current implementation"
        !Iterables.isEmpty(providers)
    }

    def "MnemonicServices.serviceProviders is an immutable iterable"() {
        given:
        def providers = MnemonicServices.serviceProviders
        when:
        Iterables.removeIf(providers, Predicates.alwaysTrue())
        then:
        thrown(UnsupportedOperationException)
    }

    @IgnoreIf({ !(MnemonicServices.serviceProviders instanceof Collection) })
    def "MnemonicServices.serviceProviders is an immutable collection"() {
        given:
        def providers = (Collection<MnemonicServiceProvider>)MnemonicServices.serviceProviders
        def firstProvider = Iterables.getFirst(providers, null)
        def providerCollection = Arrays.asList(firstProvider)
        when:
        providers.clear()
        then:
        thrown(UnsupportedOperationException)
        when:
        providers.remove(firstProvider)
        then:
        thrown(UnsupportedOperationException)
        when:
        providers.add(firstProvider)
        then:
        thrown(UnsupportedOperationException)
        when:
        providers.removeAll(providerCollection)
        then:
        thrown(UnsupportedOperationException)
        when:
        providers.retainAll(providerCollection)
        then:
        thrown(UnsupportedOperationException)
    }
}
