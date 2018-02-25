import idc
import idautils

# Register mapping:


output = ""

g_tmp = "r12"

def emit(s):
    global output
    output += s + "\n"


def arm_reg(ida_reg):
    if not ida_reg[0] == "$":
        raise RuntimeError("bad ida_reg: {}".format(ida_reg))
    if ida_reg[1:] == "sp":
        return "sp"
    number = int(ida_reg[1:])
    # if number == 7:
    #     raise RuntimeError("lol nope")
    # if number == 12:
    #     number = 7
    if number > 11:
        raise RuntimeError("you're fucked")
    if number == 11:
        return "lr"
    if number == 0:
        number = 11
    else:
        number -= 1
    return "r{}".format(number)


def convert_label(lbl):
    return lbl.replace("locret", "loc")


def c_add3(addr):
    dis = idc.GetDisasm(addr)
    op2 = idc.GetOpnd(addr, 1)
    if not op2 and ", $sp, " in dis:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        imm = idc.GetOperandValue(addr, 2)
        emit("add {}, sp, #0x{:X}".format(op1, imm))
    else:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = arm_reg(idc.GetOpnd(addr, 1))
        imm = idc.GetOperandValue(addr, 2)
        emit("add {}, {}, #0x{:X}".format(op1, op2, imm))


def c_and(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    op2 = arm_reg(idc.GetOpnd(addr, 1))
    emit("and {}, {}, {}".format(op1, op1, op2))


def c_extuh(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    emit("uxth {0}, {0}".format(op1))


def c_sw(addr):
    # TODO: sw_sp, sw_tp, sw_disp16, sw_abs24
    dis = idc.GetDisasm(addr)
    if "($sp)" in dis:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        disp = idc.GetOperandValue(addr, 1)
        emit("str {}, [sp, #0x{:X}]".format(op1, disp))
    elif not idc.GetOpnd(addr, 2):
        src = arm_reg(idc.GetOpnd(addr, 0))
        dst = arm_reg(idc.GetOpnd(addr, 1))
        emit("str {}, [{}]".format(src, dst))
    else:
        # lw_disp16
        dst = arm_reg(idc.GetOpnd(addr, 0))
        disp = idc.GetOperandValue(addr, 1)
        src = arm_reg(idc.GetOpnd(addr, 2))
        emit("str {}, [{}, #0x{:X}]".format(dst, src, disp))


def c_lw(addr):
    dis = idc.GetDisasm(addr)
    if "($sp)" in dis:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        disp = idc.GetOperandValue(addr, 1)
        emit("ldr {}, [sp, #0x{:X}]".format(op1, disp))
    elif not idc.GetOpnd(addr, 2):
        # lw_rm
        dst = arm_reg(idc.GetOpnd(addr, 0))
        src = arm_reg(idc.GetOpnd(addr, 1))
        emit("ldr {}, [{}]".format(dst, src))
    else:
        # lw_disp16
        dst = arm_reg(idc.GetOpnd(addr, 0))
        disp = idc.GetOperandValue(addr, 1)
        src = arm_reg(idc.GetOpnd(addr, 2))
        emit("ldr {}, [{}, #0x{:X}]".format(dst, src, disp))


def c_movh(addr):
    reg = arm_reg(idc.GetOpnd(addr, 0))
    value = idc.GetOperandValue(addr, 1)
    emit("ldr {}, =0x{:08X}".format(reg, value << 16))


def c_movu(addr):
    reg = arm_reg(idc.GetOpnd(addr, 0))
    value = idc.GetOperandValue(addr, 1)

    emit("ldr {}, =0x{:08X}".format(reg, value))


def c_or(addr):
    dst = arm_reg(idc.GetOpnd(addr, 0))
    src = arm_reg(idc.GetOpnd(addr, 1))
    emit("orr {}, {}, {}".format(dst, dst, src))


def c_or3(addr):
    dst = arm_reg(idc.GetOpnd(addr, 0))
    src = arm_reg(idc.GetOpnd(addr, 1))
    imm16 = idc.GetOperandValue(addr, 2)
    emit("mov {}, #0x{:X}".format(g_tmp, imm16))
    emit("orr {}, {}, {}".format(dst, src, g_tmp))


def c_mov(addr):
    op2 = idc.GetOpnd(addr, 1)
    if op2[0] != "$":
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = int(op2.rstrip("h"), 16)
        if op2 < 0:
            op2 = op2 & 0xFFFFFFFF
            emit("ldr {}, =0x{:08X}".format(op1, op2))
        else:
            emit("movw {}, 0x{:08X}".format(op1, op2))
    else:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = arm_reg(idc.GetOpnd(addr, 1))
        emit("mov {}, {}".format(op1, op2))


def c_ret(addr):
    emit("bx lr")


def c_jmp(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    emit("bx {}".format(op1))


def c_bsr(addr):
    op1 = idc.GetOpnd(addr, 0)
    emit("bl {}".format(op1))


def c_ldc(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    dis = idc.GetDisasm(addr)
    op2 = dis.split(", ")[-1]
    if op2 != "$lp":
        raise RuntimeError("ldc failed at 0x{:08X}, op2={}".format(addr, op2))
    emit("mov {}, lr".format(op1))


def c_bnez(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    lbl = convert_label(idc.GetOpnd(addr, 1))
    emit("cmp {}, #0".format(op1))
    emit("bne {}".format(lbl))


def c_beqz(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    lbl = convert_label(idc.GetOpnd(addr, 1))
    emit("cmp {}, #0".format(op1))
    emit("beq {}".format(lbl))


def c_sltu3(addr):
    dis = idc.GetDisasm(addr)
    if "sltu3   $0," in dis:
        op1 = arm_reg("$0")
        op2 = arm_reg(idc.GetOpnd(addr, 0))
        if "h" in idc.GetOpnd(addr, 1):
            op3 = "#{}".format(idc.GetOperandValue(addr, 1))
        else:
            op3 = arm_reg(idc.GetOpnd(addr, 1))

        emit("cmp {}, {}".format(op2, op3))
        emit("movhs {}, #0".format(op1)) # higher or same => 0
        emit("movlo {}, #1".format(op1)) # strictly lower => 1
    else:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = arm_reg(idc.GetOpnd(addr, 1))
        imm = idc.GetOperandValue(addr, 2)
        emit("cmp {}, #{}".format(op2, imm))
        emit("movhs {}, #0".format(op1)) # higher or same => 0
        emit("movlo {}, #1".format(op1)) # strictly lower => 1


def c_sll(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    emit("lsl {}, #{}".format(op1, imm))


def c_add(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    emit("add {}, #0x{:x}".format(op1, imm))


def c_bra(addr):
    op = convert_label(idc.GetOpnd(addr, 0))
    emit("b {}".format(op))


def c_srl(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    emit("lsr {}, #{}".format(op1, imm))


def c_and3(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    op2 = arm_reg(idc.GetOpnd(addr, 1))
    imm = idc.GetOperandValue(addr, 2)
    emit("and {}, {}, #0x{:x}".format(op1, op2, imm))


def c_bnei(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    dst = idc.GetOperandValue(addr, 2)
    emit("cmp {}, #{}".format(op1, imm))
    emit("bne loc_{:X}".format(dst))


def c_bne(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    op2 = arm_reg(idc.GetOpnd(addr, 1))
    dst = idc.GetOperandValue(addr, 2)
    emit("cmp {}, {}".format(op1, op2))
    emit("bne loc_{:X}".format(dst))


def c_blti(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    dst = idc.GetOperandValue(addr, 2)
    emit("cmp {}, #{}".format(op1, imm))
    emit("blo loc_{:X}".format(dst))


def c_bgei(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    imm = idc.GetOperandValue(addr, 1)
    dst = idc.GetOperandValue(addr, 2)
    emit("cmp {}, #{}".format(op1, imm))
    emit("bge loc_{:X}".format(dst))


def c_lbu(addr):
    disp = 0
    if idc.GetOpnd(addr, 2):
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = arm_reg(idc.GetOpnd(addr, 2))
        disp = idc.GetOperandValue(addr, 1)
    else:
        op1 = arm_reg(idc.GetOpnd(addr, 0))
        op2 = arm_reg(idc.GetOpnd(addr, 1))
    emit("ldrb {}, [{}, #{}]".format(op1, op2, disp))


def c_nor(addr):
    op1 = idc.GetOpnd(addr, 0)
    op2 = idc.GetOpnd(addr, 1)
    emit("orr {}, {}, {}".format(op1, op1, op2))
    emit("mov {}, #0xFFFFFFFF".format(g_tmp))
    emit("eor {}, {}".format(op1, g_tmp))


def c_extb(addr):
    op1 = arm_reg(idc.GetOpnd(addr, 0))
    emit("sxtb {0}, {0}".format(op1))


rpb = 0
rpe = 0

def c_erepeat(addr):
    global rpb
    global rpe

    rpe = idc.GetOperandValue(addr, 0)
    rpb = addr


codegen = {
    "and3": c_and3,
    "add": c_add,
    "add3": c_add3,
    "and": c_and,
    "extuh": c_extuh,
    "lw": c_lw,
    "mov": c_mov,
    "movh": c_movh,
    "movu": c_movu,
    "or": c_or,
    "or3": c_or3,
    "sw": c_sw,
    "ret": c_ret,
    "jmp": c_jmp,
    "bsr": c_bsr,
    "ldc": c_ldc,
    "bnez": c_bnez,
    "beqz": c_beqz,
    "sltu3": c_sltu3,
    "sll": c_sll,
    "bra": c_bra,
    "srl": c_srl,
    "bnei": c_bnei,
    "bne": c_bne,
    "blti": c_blti,
    "bgei": c_bgei,
    "erepeat": c_erepeat,
    "lbu": c_lbu,
    "nor": c_nor,
    "extb": c_extb,
}

def decompile(ea):
    ea = idaapi.get_func(ea).startEA

    rpb_in = -1

    name = GetFunctionName(ea).replace(":", "_")

    emit(".global {}".format(name))
    emit("{}:".format(name))

    for (startea, endea) in Chunks(ea):
        for head in Heads(startea, endea):
            if head == rpe:
                rpb_in = 2

            emit("loc_{:X}:".format(head))
            # print "0x{:08X}".format(head)
            mnem = idc.GetMnem(head)
            if mnem in codegen:
                codegen[mnem](head)
            else:
                print "Unknown instruction {} at 0x{:08X}".format(mnem, head)

            if rpb_in > 0:
                rpb_in -= 1
            if rpb_in == 0:
                rpb_in = -1
                emit("b loc_{:X}".format(rpb))


decompile(ScreenEA())

# print("-" * 80)
# print(output)
# print("-" * 80)

with open("F:/test.asm", "w") as fout:
    fout.write(output)
