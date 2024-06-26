/*
 * Copyright (c) 2021, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk.internal.random;

import java.util.concurrent.atomic.AtomicLong;
import java.util.random.RandomGenerator;
import jdk.internal.util.random.RandomSupport;
import jdk.internal.util.random.RandomSupport.AbstractSplittableWithBrineGenerator;
import jdk.internal.util.random.RandomSupport.RandomGeneratorProperties;

/**
 * A "splittable" pseudorandom number generator (PRNG) whose period
 * is roughly 2<sup>192</sup>.  Class {@link L64X128StarStarRandom} implements
 * interfaces {@link RandomGenerator} and {@link SplittableGenerator},
 * and therefore supports methods for producing pseudorandomly chosen
 * values of type {@code int}, {@code long}, {@code float}, {@code double},
 * and {@code boolean} (and for producing streams of pseudorandomly chosen
 * numbers of type {@code int}, {@code long}, and {@code double}),
 * as well as methods for creating new split-off {@link L64X128StarStarRandom}
 * objects or streams of such objects.
 *
 * <p>The {@link L64X128StarStarRandom} algorithm is a specific member of
 * the LXM family of algorithms for pseudorandom number generators;
 * for more information, see the documentation for package
 * {@link jdk.random}.  Each instance of {@link L64X128StarStarRandom}
 * has 192 bits of state plus one 64-bit instance-specific parameter.
 *
 * <p>If two instances of {@link L64X128StarStarRandom} are created with
 * the same seed within the same program execution, and the same
 * sequence of method calls is made for each, they will generate and
 * return identical sequences of values.
 *
 * <p>As with {@link java.util.SplittableRandom}, instances of
 * {@link L64X128StarStarRandom} are <em>not</em> thread-safe.  They are
 * designed to be split, not shared, across threads (see the {@link #split}
 * method). For example, a {@link java.util.concurrent.ForkJoinTask}
 * fork/join-style computation using random numbers might include a
 * construction of the form
 * {@code new Subtask(someL64X128StarStarRandom.split()).fork()}.
 *
 * <p>This class provides additional methods for generating random
 * streams, that employ the above techniques when used in
 * {@code stream.parallel()} mode.
 *
 * <p>Instances of {@link L64X128StarStarRandom} are not cryptographically
 * secure.  Consider instead using {@link java.security.SecureRandom}
 * in security-sensitive applications. Additionally,
 * default-constructed instances do not use a cryptographically random
 * seed unless the {@linkplain System#getProperty system property}
 * {@code java.util.secureRandomSeed} is set to {@code true}.
 *
 * @since   17
 *
 */
@RandomGeneratorProperties(
        name = "L64X128StarStarRandom",
        group = "LXM",
        i = 128, j = 1, k = 64,
        equidistribution = 2
)
public final class L64X128StarStarRandom extends AbstractSplittableWithBrineGenerator {

    /*
     * Implementation Overview.
     *
     * The split operation uses the current generator to choose four new 64-bit
     * long values that are then used to initialize the parameter `a` and the
     * state variables `s`, `x0`, and `x1` for a newly constructed generator.
     *
     * With extremely high probability, no two generators so chosen
     * will have the same `a` parameter, and testing has indicated
     * that the values generated by two instances of {@link L64X128StarStarRandom}
     * will be (approximately) independent if have different values for `a`.
     *
     * The default (no-argument) constructor, in essence, uses
     * "defaultGen" to generate four new 64-bit values for the same
     * purpose.  Multiple generators created in this way will certainly
     * differ in their `a` parameters.  The defaultGen state must be accessed
     * in a thread-safe manner, so we use an AtomicLong to represent
     * this state.  To bootstrap the defaultGen, we start off using a
     * seed based on current time unless the
     * java.util.secureRandomSeed property is set. This serves as a
     * slimmed-down (and insecure) variant of SecureRandom that also
     * avoids stalls that may occur when using /dev/random.
     *
     * File organization: First static fields, then instance
     * fields, then constructors, then instance methods.
     */

    /* ---------------- static fields ---------------- */

    /**
     * The seed generator for default constructors.
     */
    private static final AtomicLong defaultGen = new AtomicLong(RandomSupport.initialSeed());

    /*
     * Multiplier used in the LCG portion of the algorithm.
     * Chosen based on research by Sebastiano Vigna and Guy Steele (2019).
     * The spectral scores for dimensions 2 through 8 for the multiplier 0xd1342543de82ef95
     * are [0.958602, 0.937479, 0.870757, 0.822326, 0.820405, 0.813065, 0.760215].
     */

    private static final long M = 0xd1342543de82ef95L;

    /* ---------------- instance fields ---------------- */

    /**
     * The parameter that is used as an additive constant for the LCG.
     * Must be odd.
     */
    private final long a;

    /**
     * The per-instance state: s for the LCG; x0 and x1 for the XBG.
     * At least one of x0 and x1 must be nonzero.
     */
    private long s, x0, x1;

    /* ---------------- constructors ---------------- */

    /**
     * Basic constructor that initializes all fields from parameters.
     * It then adjusts the field values if necessary to ensure that
     * all constraints on the values of fields are met.
     *
     * @param a additive parameter for the LCG
     * @param s initial state for the LCG
     * @param x0 first word of the initial state for the XBG
     * @param x1 second word of the initial state for the XBG
     */
    public L64X128StarStarRandom(long a, long s, long x0, long x1) {
        // Force a to be odd.
        this.a = a | 1;
        this.s = s;
        this.x0 = x0;
        this.x1 = x1;
        // If x0 and x1 are both zero, we must choose nonzero values.
        if ((x0 | x1) == 0) {
       long v = s;
            // At least one of the two values generated here will be nonzero.
            this.x0 = RandomSupport.mixStafford13(v += RandomSupport.GOLDEN_RATIO_64);
            this.x1 = RandomSupport.mixStafford13(v + RandomSupport.GOLDEN_RATIO_64);
        }
    }

    /**
     * Creates a new instance of {@link L64X128StarStarRandom} using the
     * specified {@code long} value as the initial seed. Instances of
     * {@link L64X128StarStarRandom} created with the same seed in the same
     * program generate identical sequences of values.
     *
     * @param seed the initial seed
     */
    public L64X128StarStarRandom(long seed) {
        // Using a value with irregularly spaced 1-bits to xor the seed
        // argument tends to improve "pedestrian" seeds such as 0 or
        // other small integers.  We may as well use SILVER_RATIO_64.
        //
        // The seed is hashed by mixMurmur64 to produce the `a` parameter.
        // The seed is hashed by mixStafford13 to produce the initial `x0`,
        // which will then be used to produce the first generated value.
        // Then x1 is filled in as if by a SplitMix PRNG with
        // GOLDEN_RATIO_64 as the gamma value and mixStafford13 as the mixer.
        this(RandomSupport.mixMurmur64(seed ^= RandomSupport.SILVER_RATIO_64),
             1,
             RandomSupport.mixStafford13(seed),
             RandomSupport.mixStafford13(seed + RandomSupport.GOLDEN_RATIO_64));
    }

    /**
     * Creates a new instance of {@link L64X128StarStarRandom} that is likely to
     * generate sequences of values that are statistically independent
     * of those of any other instances in the current program execution,
     * but may, and typically does, vary across program invocations.
     */
    public L64X128StarStarRandom() {
        // Using GOLDEN_RATIO_64 here gives us a good Weyl sequence of values.
        this(defaultGen.getAndAdd(RandomSupport.GOLDEN_RATIO_64));
    }

    /**
     * Creates a new instance of {@link L64X128StarStarRandom} using the specified array of
     * initial seed bytes. Instances of {@link L64X128StarStarRandom} created with the same
     * seed array in the same program execution generate identical sequences of values.
     *
     * @param seed the initial seed
     */
    public L64X128StarStarRandom(byte[] seed) {
        // Convert the seed to 4 long values, of which the last 2 are not all zero.
        long[] data = RandomSupport.convertSeedBytesToLongs(seed, 4, 2);
        long a = data[0], s = data[1], x0 = data[2], x1 = data[3];
        // Force a to be odd.
        this.a = a | 1;
        this.s = s;
        this.x0 = x0;
        this.x1 = x1;
    }

    /* ---------------- public methods ---------------- */

    @Override
    public SplittableGenerator split(SplittableGenerator source, long brine) {
       // Pick a new instance "at random", but use the brine for `a`.
        return new L64X128StarStarRandom(brine << 1, source.nextLong(),
                    source.nextLong(), source.nextLong());
    }

    @Override
    public long nextLong() {
       // Compute the result based on current state information
       // (this allows the computation to be overlapped with state update).
        final long result = Long.rotateLeft((s + x0) * 5, 7) * 9;  // "starstar" scrambler

       // Update the LCG subgenerator
        s = M * s + a;

       // Update the XBG subgenerator
        long q0 = x0, q1 = x1;
        {   // xoroshiro128v1_0
            q1 ^= q0;
            q0 = Long.rotateLeft(q0, 24);
            q0 = q0 ^ q1 ^ (q1 << 16);
            q1 = Long.rotateLeft(q1, 37);
        }
        x0 = q0; x1 = q1;

        return result;
    }

}
