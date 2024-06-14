const config = @import("config");
const p11 = @import("p11");
const std = @import("std");

const testing = std.testing;
const alloc = testing.allocator;

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
    try testing.expect(slot_info.flags.token_present);

    const info = try mod.getInfo();
    try testing.expect(info.cryptoki_version.major >= 2);

    const token_info = try mod.getTokenInfo(slot);
    try testing.expect(token_info.flags.token_initialized);

    const mechs = try mod.getMechanismList(alloc, slot);
    defer alloc.free(mechs);
    try testing.expect(mechs.len > 0);

    var mech_info = try mod.getMechanismInfo(slot, .aes_cbc);
    try testing.expect(mech_info.flags.encrypt);
    try testing.expect(mech_info.flags.decrypt);

    mech_info = try mod.getMechanismInfo(slot, .ec_key_pair_gen);
    try testing.expect(mech_info.flags.generate_key_pair);
    try testing.expect(mech_info.flags.ec.named_curve);
    try testing.expect(mech_info.flags.ec.uncompress);

    var sess = try mod.openSession(slot, .{});
    const sess_info = try sess.getSessionInfo();
    try testing.expect(sess_info.state == .read_write_public);
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

    try sess.login(.system_operator, "1234");
    try sess.initPIN("4321");
    try sess.logout();

    try sess.login(.user, "4321");
    try sess.setPIN("4321", "1234");
    try sess.logout();
    try sess.login(.user, "1234");
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
    mod: p11.module.Module,
    sess: p11.session.Session,
    slots: []c_ulong,

    pub fn init() !TestSession {
        var mod = try p11.init(alloc, config.module);
        errdefer mod.deinit();
        try mod.initialize();

        const slots = try mod.getSlotList(alloc, true);
        errdefer alloc.free(slots);
        const slot = slots[1];

        var sess = try mod.openSession(slot, .{});
        errdefer sess.close();

        return .{ .mod = mod, .sess = sess, .slots = slots };
    }

    pub fn with_user_auth() !TestSession {
        var ts = try TestSession.init();
        errdefer ts.deinit();
        try ts.sess.login(.user, "1234");
        return ts;
    }

    pub fn with_so_auth() !TestSession {
        var ts = try TestSession.init();
        errdefer ts.deinit();
        try ts.sess.login(.system_operator, "1234");
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
//     var ts = try TestSession.with_user_auth();
//     defer ts.deinit();

//     const state = try ts.sess.getOperationState(alloc);
//     defer alloc.free(state);

//     try ts.sess.setOperationState(state, null, null);

//     try testing.expect(state.len > 0);
// }

test "it can import objects" {
    var ts = try TestSession.with_user_auth();
    defer ts.deinit();

    const buff = [_]u8{1} ** 16;
    const ObjectClass = p11.session.ObjectClass;
    const Attribute = p11.session.Attribute;

    var template = [_]p11.session.Attribute{
        Attribute.new(.label, "test-create-object"),
        Attribute.new(.token, false),
        Attribute.new(.encrypt, true),
        Attribute.new(.decrypt, true),
        Attribute.new(.class, ObjectClass.secret_key),
        Attribute.new(.value, &buff),
    };

    const obj = try ts.sess.createObject(&template);
    try testing.expect(obj.handle > 0);
}
