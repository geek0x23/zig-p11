const constants = @import("constants.zig");

const Error = constants.Error;
const ReturnValue = constants.ReturnValue;

pub fn returnIfError(rv: c_ulong) Error!void {
    const result: ReturnValue = @enumFromInt(rv);
    if (result != ReturnValue.ok) {
        return result.toError();
    }
}
