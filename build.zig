const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pkcs11_headers = b.dependency("pkcs11", .{});
    const pkcs11_header_path = pkcs11_headers.path("published/2-40-errata-1");
    const pkcs11_translate = b.addTranslateC(.{
        .root_source_file = b.path("include/cryptoki.h"),
        .target = target,
        .optimize = optimize,
    });

    pkcs11_translate.addIncludeDir(pkcs11_header_path.getPath(b));
    const pkcs11_module = pkcs11_translate.createModule();

    const module = b.option([]const u8, "pkcs11-module", "Executes tests against the given library.") orelse "/lib64/softhsm/libsofthsm.so";
    const options = b.addOptions();
    options.addOption([]const u8, "module", module);

    const lib = b.addStaticLibrary(.{
        .name = "p11",
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();

    lib.root_module.addOptions("config", options);
    lib.root_module.addImport("pkcs11", pkcs11_module);

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .name = "p11-tests",
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkLibC();
    lib_unit_tests.root_module.addOptions("config", options);
    lib_unit_tests.root_module.addImport("pkcs11", pkcs11_module);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    b.installArtifact(lib_unit_tests);
}
