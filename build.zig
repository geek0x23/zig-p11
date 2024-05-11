const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Dependencies
    const pkcs11_headers = b.dependency("pkcs11", .{});
    const pkcs11_header_path = pkcs11_headers.path("published/2-40-errata-1");
    const pkcs11_translate = b.addTranslateC(.{
        .root_source_file = b.path("include/cryptoki.h"),
        .target = target,
        .optimize = optimize,
    });
    pkcs11_translate.addIncludeDir(pkcs11_header_path.getPath(b));
    const pkcs11_module = pkcs11_translate.createModule();

    // Options
    const module = b.option([]const u8, "pkcs11-module", "Executes tests against the given library.") orelse "/lib64/softhsm/libsofthsm.so";
    const options = b.addOptions();
    options.addOption([]const u8, "module", module);

    // Zig module
    const p11 = b.addModule("p11", .{
        .root_source_file = b.path("src/main.zig"),
        .link_libc = true,
    });

    p11.addOptions("config", options);
    p11.addImport("pkcs11", pkcs11_module);

    // Tests
    const tests = b.addTest(.{
        .name = "p11-tests",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    tests.linkLibC();
    tests.root_module.addOptions("config", options);
    tests.root_module.addImport("pkcs11", pkcs11_module);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    b.installArtifact(tests);
}
