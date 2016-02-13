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

package us.eharning.atomun.mnemonic;

import com.google.caliper.Benchmark;
import com.google.caliper.runner.CaliperMain;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.tomgibara.crinch.bits.BitReader;
import com.tomgibara.crinch.bits.BitVector;
import com.tomgibara.crinch.bits.BitWriter;
import com.tomgibara.crinch.bits.ByteArrayBitReader;
import com.tomgibara.crinch.bits.ByteArrayBitWriter;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Random;
import javax.annotation.Nonnull;

/**
 * Benchmark tool for mnemonic index generation methods (aligned 11-bit reading).
 */
@SuppressFBWarnings("PREDICTABLE_RANDOM")
class IndexReaderBenchmark {
    private static final int DICTIONARY_SIZE = 2048;
    private static final int[] INPUT = new int[(128 + 10) / 11];

    static {
        Random rng = new Random(0x1234);
        for (int i = 0; i < INPUT.length; i++) {
            INPUT[i] = rng.nextInt(2048);
        }
    }

    @Benchmark
    public int bigIntegerMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            BigInteger total = BigInteger.ZERO;
            BigInteger multiplier = BigInteger.valueOf(DICTIONARY_SIZE);
            for (int index: INPUT) {
                total = total.multiply(multiplier).add(BigInteger.valueOf(index));
            }

            /* Convert the resultant value to an unsigned byte-array */
            byte[] result = total.toByteArray();
            dummy += result[0];
        }
        return dummy;
    }

    @Benchmark
    public int crinchBitWriterMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            byte[] output = new byte[(INPUT.length * 11 + 7) / 8];
            BitWriter bitWriter = new ByteArrayBitWriter(output);

            for (int index: INPUT) {
                bitWriter.write(index, 11);
            }

            dummy += output[0];
        }
        return dummy;
    }

    @Benchmark
    public int crinchBitVectorMethod(int reps) {
        int dummy = 0;
        for (int rep = 0; rep < reps; rep++) {
            BitVector bv = new BitVector(INPUT.length * 11);

            int offset = 0;
            for (int index: INPUT) {
                bv.setBits(offset, index, 11);
                offset += 11;
            }

            byte[] result = bv.toByteArray();
            dummy += result[0];
        }
        return dummy;
    }

    public static void main(String[] args) {
        CaliperMain.main(IndexReaderBenchmark.class, args);
    }
}
