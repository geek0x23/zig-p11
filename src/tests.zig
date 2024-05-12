const config = @import("config");
const p11 = @import("p11");
const std = @import("std");

const testing = std.testing;
const alloc = testing.allocator;

const MechanismType = p11.module.MechanismType;
const SessionState = p11.session.SessionState;
const UserType = p11.session.UserType;

test "it can load a PKCS#11 module." {
    var mod = try p11.init(alloc, config.module);
    defer mod.deinit();
}

test "it can initialize and finalize the module." {
    var mod = try p11.init(alloc, config.module);
    defer mod.deinit();

    try mod.initialize();
    try mod.finalize();
}

test "it can get all the infos" {
    var mod = try p11.init(alloc, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(alloc, true);
    defer alloc.free(slots);
    try testing.expect(slots.len > 0);
    const slot = slots[0];

    const slot_info = try mod.getSlotInfo(slot);
    try testing.expectStringStartsWith(&slot_info.description, "SoftHSM");
    try testing.expect(slot_info.flags.token_present);

    const info = try mod.getInfo();
    try testing.expectStringStartsWith(&info.manufacturer_id, "SoftHSM");

    const token_info = try mod.getTokenInfo(slot);
    try testing.expectStringStartsWith(&token_info.manufacturer_id, "SoftHSM");

    const mechs = try mod.getMechanismList(alloc, slot);
    defer alloc.free(mechs);
    try testing.expect(mechs.len > 0);

    var mech_info = try mod.getMechanismInfo(slot, MechanismType.aes_cbc);
    try testing.expect(mech_info.flags.encrypt);
    try testing.expect(mech_info.flags.decrypt);

    mech_info = try mod.getMechanismInfo(slot, MechanismType.ec_key_pair_gen);
    try testing.expect(mech_info.flags.generate_key_pair);
    try testing.expect(mech_info.flags.ec.named_curve);
    try testing.expect(mech_info.flags.ec.uncompress);

    var sess = try mod.openSession(slot, .{});
    const sess_info = try sess.getSessionInfo();
    try testing.expect(sess_info.state == SessionState.read_write_public);
    try testing.expect(sess_info.flags.read_write);
    try testing.expect(sess_info.flags.serial);
    try testing.expect(sess_info.slot_id == slot);
    try testing.expect(sess_info.device_error == 0);
}

test "it can initialize a new token and set user PIN." {
    var mod = try p11.init(alloc, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(alloc, true);
    defer alloc.free(slots);

    // In SoftHSM, you init new tokens using the last slot.
    const slot = slots[slots.len - 1];

    try mod.initToken(slot, "1234", "zig-p11");

    var sess = try mod.openSession(slot, .{});
    defer sess.close() catch {};

    try sess.login(UserType.system_operator, "1234");
    try sess.initPIN("4321");
    try sess.logout();

    try sess.login(UserType.user, "4321");
    try sess.setPIN("4321", "1234");
    try sess.logout();
    try sess.login(UserType.user, "1234");
}

test "it can open and close a session" {
    var mod = try p11.init(alloc, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(alloc, true);
    defer alloc.free(slots);

    const slot = slots[1];
    var sess = try mod.openSession(slot, .{});
    try sess.close();

    _ = try mod.openSession(slot, .{});
    try mod.closeAllSessions(slot);
}

const TestSession = struct {
    mod: p11.Module,
    sess: p11.Session,
    slots: []c_ulong,

    pub fn init() !TestSession {
        const mod = try p11.init(alloc, config.module);
        try mod.initialize();

        const slots = try mod.getSlotList(alloc, true);
        const slot = slots[1];

        const sess = try mod.openSession(slot, .{});

        return .{ .mod = mod, .sess = sess, .slots = slots };
    }

    pub fn authenticated() !TestSession {
        const ts = try TestSession.init();
        try ts.sess.login(p11.UserType.user, "1234");
        return ts;
    }

    pub fn deinit(self: *TestSession) void {
        alloc.free(self.slots);
        self.mod.deinit();
    }
};

// TODO: Find a token that works with state management so I can test this.
//       Right now, SoftHSM simply returns CKR_FUNCTION_NOT_SUPPORTED.

// test "it can do session state management" {
//     var ts = try TestSession.authenticated();
//     defer ts.deinit();

//     const state = try ts.sess.getOperationState(alloc);
//     defer alloc.free(state);

//     try ts.sess.setOperationState(state, null, null);

//     try testing.expect(state.len > 0);
// }
