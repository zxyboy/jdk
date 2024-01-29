/*
 * Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

/*
 * @test NestedCgroup
 * @key cgroups
 * @requires os.family == "linux"
 * @requires vm.flagless
 * @library /testlibrary /test/lib
 * @run driver jdk.test.lib.helpers.ClassFileInstaller
 * @run main/othervm NestedCgroup
 */

import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.Platform;
import jdk.test.lib.JDKToolFinder;
import jdk.test.lib.Asserts;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import jtreg.SkippedException;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.file.NoSuchFileException;

public class NestedCgroup {
    public static final String CGROUP_OUTER = "jdktest" + ProcessHandle.current().pid();
    public static final String CGROUP_INNER = "inner";
    public static final String CONTROLLERS_PATH_OUTER = "memory:" + CGROUP_OUTER;
    public static final String CONTROLLERS_PATH = CONTROLLERS_PATH_OUTER + "/" + CGROUP_INNER;
    public static final String LINE_DELIM = "-".repeat(80);
    public static final String MOUNTINFO = "/proc/self/mountinfo";

    // A real usage on x86_64 fits in 39 MiB.
    public static final int MEMORY_MAX = 500 * 1024 * 1024;
    public static final String MEMORY_LIMIT_MB = "500.00M";

    public static void lineDelim(String str, String label) {
        System.err.print(LINE_DELIM + " " + label + "\n" + str);
        if (!str.isEmpty() && !str.endsWith("\n")) {
            System.err.println();
        }
    }

    public static OutputAnalyzer pSystem(List<String> args, String rootFailStderr, String failExplanation) throws Exception {
        System.err.println(LINE_DELIM + " command: " + String.join(" ",args));
        System.err.println(LINE_DELIM + " command: " + String.join(" ",args));
        ProcessBuilder pb = new ProcessBuilder(args);
        Process process = pb.start();
        OutputAnalyzer output = new OutputAnalyzer(process);
        int exitValue = process.waitFor();
        lineDelim(output.getStdout(), "stdout");
        lineDelim(output.getStderr(), "stderr");
        System.err.println(LINE_DELIM);
        if (!rootFailStderr.isEmpty() && output.getStderr().equals(rootFailStderr + "\n")) {
            throw new SkippedException(failExplanation + ": " + rootFailStderr);
        }
        Asserts.assertEQ(0, exitValue, "Process returned unexpected exit code: " + exitValue);
        return output;
    }

    public static OutputAnalyzer pSystem(List<String> args) throws Exception {
        return pSystem(args, "", "");
    }

    public static void main(String[] args) throws Exception {
        List<String> cgdelete = new ArrayList<>();
        cgdelete.add("cgdelete");
        cgdelete.add("-r");
        cgdelete.add("-g");
        cgdelete.add(CONTROLLERS_PATH_OUTER);
        pSystem(cgdelete, "cgdelete: libcgroup initialization failed: Cgroup is not mounted", "cgroup/cgroup2 is not mounted");

        List<String> cgcreate = new ArrayList<>();
        cgcreate.add("cgcreate");
        cgcreate.add("-g");
        cgcreate.add(CONTROLLERS_PATH);
        pSystem(cgcreate, "cgcreate: can't create cgroup " + CGROUP_OUTER + "/" + CGROUP_INNER + ": Cgroup, operation not allowed", "Missing root permission");

        String mountInfo;
        try {
            mountInfo = Files.readString(Path.of(MOUNTINFO));
        } catch (NoSuchFileException e) {
            throw new SkippedException("Cannot open " + MOUNTINFO);
        }

        Matcher matcher = Pattern.compile("^(?:\\S+\\s+){4}(\\S+)\\s.*\\scgroup2(?:\\s+\\S+){2}$", Pattern.MULTILINE).matcher(mountInfo);
        if (!matcher.find()) {
            System.err.println(mountInfo);
            throw new SkippedException("cgroup2 filesystem mount point not found");
        }
        String sysFsCgroup = matcher.group(1);
        System.err.println(LINE_DELIM + " cgroup2 mount point: " + sysFsCgroup);
        Files.writeString(Path.of(sysFsCgroup + "/" + CGROUP_OUTER + "/memory.max"), "" + MEMORY_MAX);

        // Here starts a copy of ProcessTools.createJavaProcessBuilder.
        List<String> cgexec = new ArrayList<>();
        cgexec.add("cgexec");
        cgexec.add("-g");
        cgexec.add(CONTROLLERS_PATH);
        cgexec.add(JDKToolFinder.getJDKTool("java"));
        cgexec.add("-cp");
        cgexec.add(System.getProperty("java.class.path"));
        cgexec.add("-XshowSettings:system");
        cgexec.add("-Xlog:os+container=trace");
        cgexec.add("-version");
        OutputAnalyzer output = pSystem(cgexec);
        output.shouldMatch("^ *Memory Limit: " + MEMORY_LIMIT_MB + "$");
        output.shouldMatch("\\[trace\\]\\[os,container\\] Memory Limit is: " + MEMORY_MAX + "$");

        pSystem(cgdelete);
    }
}
