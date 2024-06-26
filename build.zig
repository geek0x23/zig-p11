const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Dependencies
    const pkcs11 = b.dependency("pkcs11", .{}).path("common");

    // Options
    const module = b.option([]const u8, "pkcs11-module", "Executes tests against the given library.") orelse "/lib64/p11-kit-proxy.so";
    const options = b.addOptions();
    options.addOption([]const u8, "module", module);

    // Zig module
    const p11 = b.addModule("p11", .{
        .root_source_file = b.path("src/main.zig"),
        .link_libc = true,
    });

    p11.addIncludePath(pkcs11);
    p11.addIncludePath(b.path("include"));

    // Tests
    const tests = b.addTest(.{
        .name = "p11-tests",
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    tests.root_module.addOptions("config", options);
    tests.root_module.addImport("p11", p11);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    b.installArtifact(tests);
}
