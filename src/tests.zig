const config = @import("config");
const p11 = @import("p11");
const std = @import("std");

const testing = std.testing;

test "it can load a PKCS#11 module." {
    var mod = try p11.init(testing.allocator, config.module);
    defer mod.deinit();
}

test "it can initialize and finalize the module." {
    var mod = try p11.init(testing.allocator, config.module);
    defer mod.deinit();

    try mod.initialize();
    try mod.finalize();
}

test "it can get all the infos" {
    const allocator = testing.allocator;
    var mod = try p11.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);
    try testing.expect(slots.len > 0);
    const slot = slots[0];

    const slot_info = try mod.getSlotInfo(slot);
    try testing.expectStringStartsWith(&slot_info.description, "SoftHSM");
    try testing.expect(slot_info.flags.token_present);

    const info = try mod.getInfo();
    try testing.expectStringStartsWith(&info.manufacturer_id, "SoftHSM");

    const token_info = try mod.getTokenInfo(slot);
    try testing.expectStringStartsWith(&token_info.manufacturer_id, "SoftHSM");

    const mechs = try mod.getMechanismList(slot);
    defer allocator.free(mechs);
    try testing.expect(mechs.len > 0);

    var mech_info = try mod.getMechanismInfo(slot, p11.MechanismType.aes_cbc);
    try testing.expect(mech_info.flags.encrypt);
    try testing.expect(mech_info.flags.decrypt);

    mech_info = try mod.getMechanismInfo(slot, p11.MechanismType.ec_key_pair_gen);
    try testing.expect(mech_info.flags.generate_key_pair);
    try testing.expect(mech_info.flags.ec.named_curve);
    try testing.expect(mech_info.flags.ec.uncompress);

    try mod.finalize();
}

test "it can initialize a new token" {
    const allocator = testing.allocator;
    var mod = try p11.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);

    // In SoftHSM, you init new tokens using the last slot.
    const slot = slots[slots.len - 1];

    try mod.initToken(slot, "1234", "zig-p11");

    var sess = try mod.openSession(slot, .{});
    defer sess.deinit();

    try sess.login(p11.UserType.system_operator, "1234");
    try sess.initPIN("4321");
    try sess.logout();
}

test "it can open and close a session" {
    const allocator = testing.allocator;
    var mod = try p11.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);

    const slot = slots[1];
    var sess = try mod.openSession(slot, .{});
    defer sess.deinit();
    try sess.close();

    var sess2 = try mod.openSession(slot, .{});
    defer sess2.deinit();
    try mod.closeAllSessions(slot);
}
