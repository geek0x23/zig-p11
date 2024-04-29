const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "p11",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();
    lib.addIncludePath(.{ .path = "include" });

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .name = "p11",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const module = b.option([]const u8, "pkcs11-module", "Executes tests against the given library.") orelse "/lib64/softhsm/libsofthsm.so";
    const options = b.addOptions();
    options.addOption([]const u8, "module", module);

    lib_unit_tests.linkLibC();
    lib_unit_tests.addIncludePath(.{ .path = "include" });
    lib_unit_tests.root_module.addOptions("config", options);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
