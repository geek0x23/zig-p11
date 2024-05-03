const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "p11",
        .root_source_file = .{ .path = "src/p11.zig" },
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();
    lib.addIncludePath(.{ .path = "vendor" });

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .name = "p11-tests",
        .root_source_file = .{ .path = "src/p11.zig" },
        .target = target,
        .optimize = optimize,
    });

    const module = b.option([]const u8, "pkcs11-module", "Executes tests against the given library.") orelse "/lib64/softhsm/libsofthsm.so";
    const options = b.addOptions();
    options.addOption([]const u8, "module", module);

    lib_unit_tests.linkLibC();
    lib_unit_tests.addIncludePath(.{ .path = "vendor" });
    lib_unit_tests.root_module.addOptions("config", options);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    b.installArtifact(lib_unit_tests);
}
