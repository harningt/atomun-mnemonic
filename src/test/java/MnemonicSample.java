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

import com.google.common.io.BaseEncoding;
import org.junit.Test;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicBuilder;
import us.eharning.atomun.mnemonic.MnemonicServices;
import us.eharning.atomun.mnemonic.MnemonicUnit;

/**
 * Sample wrapped as a test that will generate a mnemonic and derive a
 * seed from each of these.
 */
public class MnemonicSample {
    @Test
    public void generateSamples() {
        for (MnemonicAlgorithm algorithm: MnemonicServices.getRegisteredAlgorithms()) {
            /* Obtain a builder for the selected algorithm. */
            MnemonicBuilder builder = MnemonicBuilder.newBuilder(algorithm);

            /* Set the entropy length at 128-bits -> 16 bytes. */
            builder.setEntropyLength(128 / 8);

            /* Generate a mnemonic with the remaining parameters as the default. */
            String mnemonic = builder.build();

            System.out.println(algorithm);
            System.out.println("\t" + mnemonic);
            try {
                /* Decode the mnemonic into a stateful unit to operate on. */
                MnemonicUnit unit = MnemonicUnit.decodeMnemonic(algorithm, mnemonic);

                /* Extract a seed out of the mnemonic unit. */
                byte[] seed = unit.getSeed();

                System.out.println("\t" + BaseEncoding.base16().encode(seed));
            } catch (UnsupportedOperationException e) {
                System.out.println("\tSeed handling failed");
            }
        }
    }
}
