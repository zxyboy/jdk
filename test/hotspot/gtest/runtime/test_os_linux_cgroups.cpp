/*
 * Copyright (c) 2022, Red Hat, Inc.
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

#include "precompiled.hpp"

#ifdef LINUX

#include "cgroupV1Subsystem_linux.hpp"
#include "cgroupV2Subsystem_linux.hpp"
#include "unittest.hpp"

typedef struct {
  const char* mount_path;
  const char* root_path;
  const char* cgroup_path;
  const char** expected_path;
} TestCase;

static void test_expected_path(const TestCase *testCase, CgroupController* ctrl) {
  for (size_t dir_ix = 0;; ++dir_ix) {
    const char *expected_path = testCase->expected_path[dir_ix];
    const char *subsystem_path = ctrl->subsystem_path(dir_ix);
    if (expected_path == nullptr || subsystem_path == nullptr) {
      ASSERT_EQ(expected_path, subsystem_path);
      break;
    }
    ASSERT_STREQ(expected_path, subsystem_path);
  }
}

TEST(cgroupTest, set_cgroupv1_subsystem_path) {
  static const char* host_expected_path[] = {
    "/sys/fs/cgroup/memory/user.slice/user-1000.slice/user@1000.service",
    nullptr
  };
  TestCase host = {
    "/sys/fs/cgroup/memory",                                             // mount_path
    "/",                                                                 // root_path
    "/user.slice/user-1000.slice/user@1000.service",                     // cgroup_path
    host_expected_path                                                   // expected_path
  };
  static const char* container_engine_expected_path[] = {
    "/sys/fs/cgroup/mem",
    nullptr
  };
  TestCase container_engine = {
    "/sys/fs/cgroup/mem",                            // mount_path
    "/user.slice/user-1000.slice/user@1000.service", // root_path
    "/user.slice/user-1000.slice/user@1000.service", // cgroup_path
    container_engine_expected_path                   // expected_path
  };
  int length = 2;
  TestCase* testCases[] = { &host,
                            &container_engine };
  for (int i = 0; i < length; i++) {
    CgroupV1Controller* ctrl = new CgroupV1Controller( (char*)testCases[i]->root_path,
                                                       (char*)testCases[i]->mount_path);
    ctrl->set_subsystem_path((char*)testCases[i]->cgroup_path);
    test_expected_path(testCases[i], ctrl);
  }
}

TEST(cgroupTest, set_cgroupv2_subsystem_path) {
  static const char* at_mount_root_expected_path[] = {
    "/sys/fs/cgroup",
    nullptr
  };
  TestCase at_mount_root = {
    "/sys/fs/cgroup",           // mount_path
    nullptr,                       // root_path, ignored
    "/",                        // cgroup_path
    at_mount_root_expected_path // expected_path
  };
  static const char* sub_path_expected_path[] = {
    "/sys/fs/cgroup/foobar",
    nullptr
  };
  TestCase sub_path = {
    "/sys/fs/cgroup",       // mount_path
    nullptr,                // root_path, ignored
    "/foobar",              // cgroup_path
    sub_path_expected_path  // expected_path
  };
  static const char* nested_path_expected_path[] = {
    "/sys/fs/cgroup/outer/inner",
    "/sys/fs/cgroup/outer",
    nullptr
  };
  TestCase nested_path = {
    "/sys/fs/cgroup",         // mount_path
    nullptr,                     // root_path, ignored
    "/outer/inner",           // cgroup_path
    nested_path_expected_path // expected_path
  };
  static const char* nested_path_doubleslash_expected_path[] = {
    "/sys/fs/cgroup/outer//inner",
    "/sys/fs/cgroup/outer/",
    "/sys/fs/cgroup/outer",
    nullptr
  };
  TestCase nested_path_doubleslash = {
    "/sys/fs/cgroup",                     // mount_path
    nullptr,                                 // root_path, ignored
    "/outer//inner",                      // cgroup_path
    nested_path_doubleslash_expected_path // expected_path
  };
  int length = 4;
  TestCase* testCases[] = { &at_mount_root,
                            &sub_path,
                            &nested_path,
                            &nested_path_doubleslash };
  for (int i = 0; i < length; i++) {
    CgroupV2Controller* ctrl = new CgroupV2Controller( (char*)testCases[i]->mount_path,
                                                       (char*)testCases[i]->cgroup_path);
    test_expected_path(testCases[i], ctrl);
  }
}

#endif
