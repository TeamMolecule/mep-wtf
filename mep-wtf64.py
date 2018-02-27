#
# Copyright 2018 molecule. All rights reserved.
#
# This software is intellectual property of molecule.
# You may not copy, republish, display, distribute, transmit, sell, rent, lease, loan
# or otherwise make available in any form or by any means all or any portion of this software.
#


import idc
import idautils
import string
from idaapi import o_reg, o_imm

# Register mapping:
#--Scratch:
# W4 = $0
# W0  = $1 (arg0)
# W1  = $2 (arg1)
# W2  = $3 (arg2)
# W3  = $4 (arg3)
#--Preserved:
# W19 = $5
# W20 = $6
# W21 = $7
# W22 = $8
#--Scratch:
# W9  = $9
# W10 = $10
# W11 = $11
# W12 = $12
#--Special:
# W27 = $13 - TP
# W28 = $14 - GP
# SP  = $15 - SP

# X30 (LR) = $lp

output = []

g_tmp = "W5"
g_tmp64 = "X5"
g_arm_rpc_reg = "W6"

class mep:
    MEP_INSN_X_INVALID  = 1
    MEP_INSN_STCB_R  = 2
    MEP_INSN_LDCB_R  = 3
    MEP_INSN_PREF  = 4
    MEP_INSN_PREFD  = 5
    MEP_INSN_CASB3  = 6
    MEP_INSN_CASH3  = 7
    MEP_INSN_CASW3  = 8
    MEP_INSN_SBCP  = 9
    MEP_INSN_LBCP  = 10
    MEP_INSN_LBUCP  = 11
    MEP_INSN_SHCP  = 12
    MEP_INSN_LHCP  = 13
    MEP_INSN_LHUCP  = 14
    MEP_INSN_LBUCPA  = 15
    MEP_INSN_LHUCPA  = 16
    MEP_INSN_LBUCPM0  = 17
    MEP_INSN_LHUCPM0  = 18
    MEP_INSN_LBUCPM1  = 19
    MEP_INSN_LHUCPM1  = 20
    MEP_INSN_UCI  = 21
    MEP_INSN_DSP  = 22
    MEP_INSN_DSP0  = 23
    MEP_INSN_DSP1  = 24
    MEP_INSN_SB  = 25
    MEP_INSN_SH  = 26
    MEP_INSN_SW  = 27
    MEP_INSN_LB  = 28
    MEP_INSN_LH  = 29
    MEP_INSN_LW  = 30
    MEP_INSN_LBU  = 31
    MEP_INSN_LHU  = 32
    MEP_INSN_SW_SP  = 33
    MEP_INSN_LW_SP  = 34
    MEP_INSN_SB_TP  = 35
    MEP_INSN_SH_TP  = 36
    MEP_INSN_SW_TP  = 37
    MEP_INSN_LB_TP  = 38
    MEP_INSN_LH_TP  = 39
    MEP_INSN_LW_TP  = 40
    MEP_INSN_LBU_TP  = 41
    MEP_INSN_LHU_TP  = 42
    MEP_INSN_SB16  = 43
    MEP_INSN_SH16  = 44
    MEP_INSN_SW16  = 45
    MEP_INSN_LB16  = 46
    MEP_INSN_LH16  = 47
    MEP_INSN_LW16  = 48
    MEP_INSN_LBU16  = 49
    MEP_INSN_LHU16  = 50
    MEP_INSN_SW24  = 51
    MEP_INSN_LW24  = 52
    MEP_INSN_EXTB  = 53
    MEP_INSN_EXTH  = 54
    MEP_INSN_EXTUB  = 55
    MEP_INSN_EXTUH  = 56
    MEP_INSN_SSARB  = 57
    MEP_INSN_MOV  = 58
    MEP_INSN_MOVI8  = 59
    MEP_INSN_MOVI16  = 60
    MEP_INSN_MOVU24  = 61
    MEP_INSN_MOVU16  = 62
    MEP_INSN_MOVH  = 63
    MEP_INSN_ADD3  = 64
    MEP_INSN_ADD  = 65
    MEP_INSN_ADD3I  = 66
    MEP_INSN_ADVCK3  = 67
    MEP_INSN_SUB  = 68
    MEP_INSN_SBVCK3  = 69
    MEP_INSN_NEG  = 70
    MEP_INSN_SLT3  = 71
    MEP_INSN_SLTU3  = 72
    MEP_INSN_SLT3I  = 73
    MEP_INSN_SLTU3I  = 74
    MEP_INSN_SL1AD3  = 75
    MEP_INSN_SL2AD3  = 76
    MEP_INSN_ADD3X  = 77
    MEP_INSN_SLT3X  = 78
    MEP_INSN_SLTU3X  = 79
    MEP_INSN_OR  = 80
    MEP_INSN_AND  = 81
    MEP_INSN_XOR  = 82
    MEP_INSN_NOR  = 83
    MEP_INSN_OR3  = 84
    MEP_INSN_AND3  = 85
    MEP_INSN_XOR3  = 86
    MEP_INSN_SRA  = 87
    MEP_INSN_SRL  = 88
    MEP_INSN_SLL  = 89
    MEP_INSN_SRAI  = 90
    MEP_INSN_SRLI  = 91
    MEP_INSN_SLLI  = 92
    MEP_INSN_SLL3  = 93
    MEP_INSN_FSFT  = 94
    MEP_INSN_BRA  = 95
    MEP_INSN_BEQZ  = 96
    MEP_INSN_BNEZ  = 97
    MEP_INSN_BEQI  = 98
    MEP_INSN_BNEI  = 99
    MEP_INSN_BLTI  = 100
    MEP_INSN_BGEI  = 101
    MEP_INSN_BEQ  = 102
    MEP_INSN_BNE  = 103
    MEP_INSN_BSR12  = 104
    MEP_INSN_BSR24  = 105
    MEP_INSN_JMP  = 106
    MEP_INSN_JMP24  = 107
    MEP_INSN_JSR  = 108
    MEP_INSN_RET  = 109
    MEP_INSN_REPEAT  = 110
    MEP_INSN_EREPEAT  = 111
    MEP_INSN_STC_LP  = 112
    MEP_INSN_STC_HI  = 113
    MEP_INSN_STC_LO  = 114
    MEP_INSN_STC  = 115
    MEP_INSN_LDC_LP  = 116
    MEP_INSN_LDC_HI  = 117
    MEP_INSN_LDC_LO  = 118
    MEP_INSN_LDC  = 119
    MEP_INSN_DI  = 120
    MEP_INSN_EI  = 121
    MEP_INSN_RETI  = 122
    MEP_INSN_HALT  = 123
    MEP_INSN_SLEEP  = 124
    MEP_INSN_SWI  = 125
    MEP_INSN_BREAK  = 126
    MEP_INSN_SYNCM  = 127
    MEP_INSN_STCB  = 128
    MEP_INSN_LDCB  = 129
    MEP_INSN_BSETM  = 130
    MEP_INSN_BCLRM  = 131
    MEP_INSN_BNOTM  = 132
    MEP_INSN_BTSTM  = 133
    MEP_INSN_TAS  = 134
    MEP_INSN_CACHE  = 135
    MEP_INSN_MUL  = 136
    MEP_INSN_MULU  = 137
    MEP_INSN_MULR  = 138
    MEP_INSN_MULRU  = 139
    MEP_INSN_MADD  = 140
    MEP_INSN_MADDU  = 141
    MEP_INSN_MADDR  = 142
    MEP_INSN_MADDRU  = 143
    MEP_INSN_DIV  = 144
    MEP_INSN_DIVU  = 145
    MEP_INSN_DRET  = 146
    MEP_INSN_DBREAK  = 147
    MEP_INSN_LDZ  = 148
    MEP_INSN_ABS  = 149
    MEP_INSN_AVE  = 150
    MEP_INSN_MIN  = 151
    MEP_INSN_MAX  = 152
    MEP_INSN_MINU  = 153
    MEP_INSN_MAXU  = 154
    MEP_INSN_CLIP  = 155
    MEP_INSN_CLIPU  = 156
    MEP_INSN_SADD  = 157
    MEP_INSN_SSUB  = 158
    MEP_INSN_SADDU  = 159
    MEP_INSN_SSUBU  = 160
    MEP_INSN_SWCP  = 161
    MEP_INSN_LWCP  = 162
    MEP_INSN_SMCP  = 163
    MEP_INSN_LMCP  = 164
    MEP_INSN_SWCPI  = 165
    MEP_INSN_LWCPI  = 166
    MEP_INSN_SMCPI  = 167
    MEP_INSN_LMCPI  = 168
    MEP_INSN_SWCP16  = 169
    MEP_INSN_LWCP16  = 170
    MEP_INSN_SMCP16  = 171
    MEP_INSN_LMCP16  = 172
    MEP_INSN_SBCPA  = 173
    MEP_INSN_LBCPA  = 174
    MEP_INSN_SHCPA  = 175
    MEP_INSN_LHCPA  = 176
    MEP_INSN_SWCPA  = 177
    MEP_INSN_LWCPA  = 178
    MEP_INSN_SMCPA  = 179
    MEP_INSN_LMCPA  = 180
    MEP_INSN_SBCPM0  = 181
    MEP_INSN_LBCPM0  = 182
    MEP_INSN_SHCPM0  = 183
    MEP_INSN_LHCPM0  = 184
    MEP_INSN_SWCPM0  = 185
    MEP_INSN_LWCPM0  = 186
    MEP_INSN_SMCPM0  = 187
    MEP_INSN_LMCPM0  = 188
    MEP_INSN_SBCPM1  = 189
    MEP_INSN_LBCPM1  = 190
    MEP_INSN_SHCPM1  = 191
    MEP_INSN_LHCPM1  = 192
    MEP_INSN_SWCPM1  = 193
    MEP_INSN_LWCPM1  = 194
    MEP_INSN_SMCPM1  = 195
    MEP_INSN_LMCPM1  = 196
    MEP_INSN_BCPEQ  = 197
    MEP_INSN_BCPNE  = 198
    MEP_INSN_BCPAT  = 199
    MEP_INSN_BCPAF  = 200
    MEP_INSN_SYNCCP  = 201
    MEP_INSN_JSRV  = 202
    MEP_INSN_BSRV  = 203
    MEP_INSN_CP  = 204
    MEP_INSN_SIM_SYSCALL  = 205
    MEP_INSN_RI_0  = 206
    MEP_INSN_RI_1  = 207
    MEP_INSN_RI_2  = 208
    MEP_INSN_RI_3  = 209
    MEP_INSN_RI_4  = 210
    MEP_INSN_RI_5  = 211
    MEP_INSN_RI_6  = 212
    MEP_INSN_RI_7  = 213
    MEP_INSN_RI_8  = 214
    MEP_INSN_RI_9  = 215
    MEP_INSN_RI_10  = 216
    MEP_INSN_RI_11  = 217
    MEP_INSN_RI_12  = 218
    MEP_INSN_RI_13  = 219
    MEP_INSN_RI_14  = 220
    MEP_INSN_RI_15  = 221
    MEP_INSN_RI_17  = 222
    MEP_INSN_RI_20  = 223
    MEP_INSN_RI_21  = 224
    MEP_INSN_RI_22  = 225
    MEP_INSN_RI_23  = 226
    MEP_INSN_RI_26 = 227


class Insn:

    def __init__(self, s):
        self.s = s


class Loc:

    def __init__(self, s):
        self.s = s


def emit(s):
    output.append(Insn(s))

def emit_loc(s):
    output.append(Loc(s))


used_locs = set()

def format_loc(addr):
    return "loc_{:X}".format(addr)


def use_loc(addr):
    used_locs.add(addr)
    return format_loc(addr)


def safe(s):
    allowed = string.ascii_letters + string.digits
    out = ""
    for c in s:
        if c not in allowed:
            out += "_"
        else:
            out += c
    return out


def function_name(name):
    name = safe(name)
    if name.startswith("sub_"):
        name = "_" + name
    return name


def arm_reg(num):
    # https://github.com/yifanlu/toshiba-mep-idp/blob/11082f689ed2cf0d6c0793beb84cff599de22a73/reg.cpp#L29
    if num == 14:
        # map $tp to W27
        return "W27"
    if num == 15:
        # map $gp to W28
        return "W28"
    if num == 1:
        # map $0 to W4
        return "W4"
    if num >= 2 and num <= 5:
        # map $1-$4 to W0-W2
        return "W{}".format(num - 2)
    if num == 16:
        # map $sp to SP
        return "SP"
    if num >= 6 and num <= 9:
        # map $5-$8 to W19-W22
        return "W{}".format(num + 13)
    if num >= 10 and num <= 13:
        # map $9-$12 to W9-W12
        return "W{}".format(num - 1)

    raise RuntimeError("reg #{} is not supported yet!".format(num))


def arm_reg64(num):
    return arm_reg(num).replace("W", "X")


def unsigned2signed32(val):
    if val >= 2 ** 31:
        val -= 2 ** 32

    return val


def out_of_range(val):
    return val >= 2 ** 11 or val <= -(2 ** 11)


def c_and(insn):
    # GR(n) = GR(n) & GR(m);

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    
    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("AND {0}, {0}, {1}".format(op1, op2))


def c_xor(insn):
    # GR(n) = GR(n) ^ GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    
    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    if op1 == "SP":
        if op2 != "SP":
            raise RuntimeError("tried to EOR SP, something...")
        emit("MOV {}, #0".format(g_tmp))
        emit("MOV SP, {}".format(g_tmp64))
    else:
        emit("EOR {0}, {0}, {1}".format(op1, op2))


def c_lw_rm(insn):
    # GR(n) = Load4(GR(m))

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("LDR {}, [{}]".format(op1, op2))


def c_lb_rm(insn):
    # GR(n) = SignExt(Load1(GR(m)), 8, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("LDRSB {}, [{}]".format(op1, op2))


def c_sw_rm(insn):
    # Store4(GR(n), GR(m))

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("STR {}, [{}]".format(op1, op2))


def make_load_store_abs24(mnem):
    def inner(insn):
        assert insn.Op1.type == o_reg
        assert insn.Op2.type == o_mem

        op1 = arm_reg(insn.Op1.reg)
        op2 = insn.Op2.addr

        emit("LDR {}, =0x{:X}".format(g_tmp, op2))
        emit("{} {}, [{}]".format(mnem, op1, g_tmp64))

    return inner


def c_sb(insn):
    # Store1(GR(n), GR(m));

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("STRB {}, [{}]".format(op1, op2))


def c_sh_rm(insn):
    # Store1(GR(n), GR(m));

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("STRH {}, [{}]".format(op1, op2))


def make_load_store_disp16(mnem):
    def inner(insn):
        assert insn.Op1.type == o_reg
        assert insn.Op2.type == o_imm
        assert insn.Op3.type == o_reg

        op1 = arm_reg(insn.Op1.reg)
        imm = unsigned2signed32(insn.Op2.value)
        op2 = arm_reg64(insn.Op3.reg)

        if out_of_range(imm):
            emit("LDR {}, ={}".format(g_tmp, imm))
            emit("{} {}, [{}, {}]".format(mnem, op1, op2, g_tmp64))
        else:
            emit("{} {}, [{}, #{}]".format(mnem, op1, op2, imm))

    return inner


def c_lw_sp(insn):
    # GR(n) = Load4(GRN(sp) + disp7)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    if op1 == "SP":
        emit("LDR {}, [SP, #{}]".format(g_tmp, imm))
        emit("MOV SP, {}".format(g_tmp64))
    else:
        emit("LDR {}, [SP, #{}]".format(op1, imm))


def c_sw_sp(insn):
    # Store4(GR(n), GRN(sp) + disp7)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("STR {}, [SP, #{}]".format(op1, imm))


def c_movh(insn):
    # GR(n) = imm16 << 16

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    reg = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    if reg == "SP":
        emit("LDR {}, =0x{:08X}".format(g_tmp, imm << 16))
        emit("MOV SP, {}".format(g_tmp64))
    else:
        emit("LDR {}, =0x{:08X}".format(reg, imm << 16))


def c_movu(insn):
    # GR(n) = imm16/imm24

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm or insn.Op2.type == o_mem

    reg = arm_reg(insn.Op1.reg)
    if insn.Op2.type == o_imm:
        imm = insn.Op2.value
    else:
        imm = insn.Op2.addr

    emit("LDR {}, =0x{:08X}".format(reg, imm))


def c_or(insn):
    # GR(n) = GR(n) | GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    
    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("ORR {0}, {0}, {1}".format(op1, op2))


def c_or3(insn):
    # GR(n) = GR(m) | imm16

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    imm = insn.Op3.value

    emit("MOV {}, #0x{:X}".format(g_tmp, imm))
    emit("ORR {}, {}, {}".format(op1, op2, g_tmp))


def c_mov_rm(insn):
    # GR(n) = GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg64(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("MOV {}, {}".format(op1, op2))


def c_mov_imm8(insn):
    # GR(n) = SignExt(imm8, 8, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("LDR {}, =0x{:X}".format(op1, imm))


def c_ret(insn):
    emit("RET")


def c_jmp_rm(insn):
    # BRA(GR(m) & 0xFFFFFFFE)

    assert insn.Op1.type == o_reg

    op1 = arm_reg64(insn.Op1.reg)

    if op1 == "X11":
        emit("RET {}".format(op1))
    else:
        emit("BR {}".format(op1))


def c_jsr(insn):
    # CRN(lp) = CRN(pc); BRA(GR(m) & 0xFFFFFFFE);

    assert insn.Op1.type == o_reg

    op1 = arm_reg64(insn.Op1.reg)

    emit("BLR {}".format(op1))


def c_jmp_target24(insn):
    # BRA((CRN(pc) & 0xf0000000) | target24)

    op1 = function_name(idc.GetOpnd(insn.ip, 0))
    emit("B {}".format(op1))


def c_bsr(insn):
    op1 = function_name(idc.GetOpnd(insn.ip, 0))
    emit("BL {}".format(op1))


def c_ldc_lp(insn):
    # GR(n) = CR(imm5)

    assert insn.Op1.type == o_reg

    op1 = arm_reg64(insn.Op1.reg)

    emit("MOV {}, LR".format(op1))


def c_stc_lp(insn):
    assert insn.Op1.type == o_reg

    op1 = arm_reg64(insn.Op1.reg)

    emit("MOV LR, {}".format(op1))


def make_cmpz_b(mnem):
    def inner(insn):
        assert insn.Op1.type == o_reg
        assert insn.Op2.type == o_near

        op1 = arm_reg(insn.Op1.reg)
        lbl = use_loc(idc.GetOperandValue(insn.ip, 1))

        emit("CMP {}, #0".format(op1))
        emit("{} {}".format(mnem, lbl))

    return inner


def make_cmp_b_rin(mnem):
    # For the record, rin here stands for register/immediate/near:
    # the operands we support
    def inner(insn):
        assert insn.Op1.type == o_reg
        assert insn.Op2.type == o_imm
        assert insn.Op3.type == o_near

        op1 = arm_reg(insn.Op1.reg)
        imm = insn.Op2.value
        lbl = use_loc(idc.GetOperandValue(insn.ip, 2))

        emit("CMP {}, #{}".format(op1, imm))
        emit("{} {}".format(mnem, lbl))

    return inner


def make_cmp_b(mnem):
    def inner(insn):
        assert insn.Op1.type == o_reg
        assert insn.Op2.type == o_reg
        assert insn.Op3.type == o_near

        op1 = arm_reg(insn.Op1.reg)
        op2 = arm_reg(insn.Op2.reg)
        lbl = use_loc(idc.GetOperandValue(insn.ip, 2))

        emit("CMP {}, {}".format(op1, op2))
        emit("{} {}".format(mnem, lbl))

    return inner


def c_beq(insn):
    # if (GR(n) == GR(m)) BRA(CRN(pc) + SignExt(disp17, 17, 32) - 4);

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_near

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    lbl = use_loc(idc.GetOperandValue(insn.ip, 2))

    emit("CMP {}, {}".format(op1, op2))
    emit("BEQ {}".format(lbl))


def c_sltu3_imm16(insn):
    # GR(n) = GR(m) < imm16

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    imm = insn.Op3.value

    emit("CMP {}, #{}".format(op2, imm))
    emit("CSET {}, LO".format(op1))


def c_slt3_imm16(insn):
    # GR(n) = (int32_t)GR(m) < (int32_t)SignExt(imm16, 16, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    imm = insn.Op3.value

    emit("CMP {}, #{}".format(op2, imm))
    emit("CSET {}, LT".format(op1))


def c_sltu3_r0(insn):
    # GRN(r0) = GR(n) < GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("CMP {}, {}".format(op1, op2))
    emit("CSET {}, LO".format(arm_reg(1)))


def c_slt3_r0(insn):
    # GRN(r0) = (int32_t)GR(n) < (int32_t)GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("CMP {}, {}".format(op1, op2))
    emit("CSET {}, LT".format(arm_reg(1)))


def c_sltu3_imm5(insn):
    # GRN(r0) = GR(n) < imm5

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("CMP {}, #{}".format(op1, imm))
    emit("CSET {}, LO".format(arm_reg(1)))


def c_sll_imm5(insn):
    # GR(n) = GR(n) << Imm5

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("LSL {0}, {0}, #{1}".format(op1, imm))


def c_sll_rm(insn):
    # GR(n) = GR(n) << (GR(m) & 0b11111)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("AND {}, {}, #0b11111".format(g_tmp, op2))
    emit("LSL {0}, {0}, {1}".format(op1, g_tmp))


def c_srl_rm(insn):
    # GR(n) = GR(n) >> (GR(m) & 0b11111)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("AND {}, {}, #0b11111".format(g_tmp, op2))
    emit("LSR {0}, {0}, {1}".format(op1, g_tmp))


def c_sll3(insn):
    # GR(0) = GR(n) << imm5

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    r0 = arm_reg(1)
    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("LSL {}, {}, #{}".format(r0, op1, imm))


def c_srl_imm5(insn):
    # GR(n) = GR(n) >> Imm5

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("LSR {0}, {0}, #{1}".format(op1, imm))


def c_sra_imm5(insn):
    # GR(n) = SignExt((GR(n) >> Imm5), 32 - Imm5, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = insn.Op2.value

    emit("ASR {0}, {0}, #{1}".format(op1, imm))


def c_bra(insn):
    op1 = use_loc(insn.Op1.addr)
    emit("B {}".format(op1))


def c_and3(insn):
    # GR(n) = GR(m) & imm16

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    imm = insn.Op3.value

    emit("LDR {}, =0x{:X}".format(g_tmp, imm))
    emit("AND {}, {}, {}".format(op1, op2, g_tmp))


def c_xor3(insn):
    # GR(n) = GR(m) ^ imm16

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    imm = insn.Op3.value

    emit("LDR {}, =0x{:X}".format(g_tmp, imm))
    emit("EOR {}, {}, {}".format(op1, op2, g_tmp))


def c_lbu_rm(insn):
    # GR(n) = Load1(GR(m));

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("LDRB {}, [{}]".format(op1, op2))


def c_lhu_rm(insn):
    # GR(n) = Load2(GR(m))

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg64(insn.Op2.reg)

    emit("LDRH {}, [{}]".format(op1, op2))


def c_nor(insn):
    # GR(n) = ~(GR(n) | GR(m));

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("ORR {}, {}, {}".format(op1, op1, op2))
    emit("MOV {}, #0xFFFFFFFF".format(g_tmp))
    emit("EOR {0}, {0}, {1}".format(op1, g_tmp))


def c_neg(insn):
    # GR(n) = -GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("NEG {}, {}".format(op1, op2))


def c_add3_imm16(insn):
    # GR(n) = GR(m) + SignExt(i, 16, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_imm

    op2 = arm_reg(insn.Op2.reg)
    if op2 == "SP":
        op1 = arm_reg64(insn.Op1.reg)
    else:
        op1 = arm_reg(insn.Op1.reg)
    imm = unsigned2signed32(insn.Op3.value)

    if out_of_range(imm):
        emit("LDR {}, ={}".format(g_tmp, imm))
        emit("ADD {}, {}, {}".format(op1, op2, g_tmp))
    else:
        emit("ADD {}, {}, #{}".format(op1, op2, imm))


def c_add3_rl(insn):
    # GR(l) = GR(n) + GR(m)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg
    assert insn.Op3.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)
    op3 = arm_reg(insn.Op3.reg)

    emit("ADD {}, {}, {}".format(op1, op2, op3))


def c_add3_sp(insn):
    # GR(n) = imm7 + GRN(sp)

    assert insn.Op1.type == o_reg
    assert insn.Op3.type == o_imm

    op1 = arm_reg64(insn.Op1.reg)
    imm = insn.Op3.value

    emit("ADD {}, SP, #{}".format(op1, imm))


def c_add(insn):
    # GR(n) = GR(n) + SignExt(imm6, 6, 32)

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_imm

    op1 = arm_reg(insn.Op1.reg)
    imm = unsigned2signed32(insn.Op2.value)

    emit("ADD {0}, {0}, #{1}".format(op1, imm))


def c_sub(insn):
    # GR(n) = GR(n) - GR(m);

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("SUB {0}, {0}, {1}".format(op1, op2))


def make_ext(mnem):
    def inner(insn):
        assert insn.Op1.type == o_reg
        op1 = arm_reg(insn.Op1.reg)
        emit("{mnem} {op}, {op}".format(mnem=mnem, op=op1))

    return inner


def c_abs(insn):
    # Rn <- |Rn - Rm|

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_reg

    op1 = arm_reg(insn.Op1.reg)
    op2 = arm_reg(insn.Op2.reg)

    emit("SUBS {0}, {0}, {1}".format(op1, op2))
    emit("CSNEG {0}, {0}, {0}, PL".format(op1))


rpb = 0
rpe = 0
is_erepeat = False

def c_erepeat(insn):
    global rpb
    global rpe
    global is_erepeat

    assert insn.Op1.type == o_near

    rpe = idc.GetOperandValue(insn.ip, 0)
    rpb = insn.ip
    is_erepeat = True


def c_repeat(insn):
    global rpb
    global rpe
    global is_erepeat

    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_near

    rpe = idc.GetOperandValue(insn.ip, 1)
    # Hack: works around us inserting an additional instruction here...
    rpb = insn.ip + 4
    is_erepeat = False

    op1 = arm_reg(insn.Op1.reg)

    # initialize our "rpc" simulator
    emit("ADD {}, {}, #1".format(g_arm_rpc_reg, op1))


def c_sys(insn):
    # dis = idc.GetDisasm(insn.ip)
    # emit("BL {}".format(safe(dis)))
    emit("BRK #0")


codegen = {
    # Repeats. These are pretty special
    mep.MEP_INSN_EREPEAT: c_erepeat,
    mep.MEP_INSN_REPEAT: c_repeat,

    mep.MEP_INSN_MOVH: c_movh,
    mep.MEP_INSN_MOVU24: c_movu,
    mep.MEP_INSN_OR3: c_or3,

    # Load/Store abs24
    mep.MEP_INSN_SW24: make_load_store_abs24("STR"),
    mep.MEP_INSN_LW24: make_load_store_abs24("LDR"),

    # Load/Store disp16
    mep.MEP_INSN_SB16: make_load_store_disp16("STRB"),
    mep.MEP_INSN_LB16: make_load_store_disp16("LDRSB"),
    mep.MEP_INSN_LBU16: make_load_store_disp16("LDRB"),
    mep.MEP_INSN_SH16: make_load_store_disp16("STRH"),
    mep.MEP_INSN_LH16: make_load_store_disp16("LDRSH"),
    mep.MEP_INSN_LHU16: make_load_store_disp16("LDRH"),
    mep.MEP_INSN_SW16: make_load_store_disp16("STR"),
    mep.MEP_INSN_LW16: make_load_store_disp16("LDR"),

    mep.MEP_INSN_SW: c_sw_rm,
    mep.MEP_INSN_LW: c_lw_rm,

    mep.MEP_INSN_SH: c_sh_rm,

    mep.MEP_INSN_SB: c_sb,
    mep.MEP_INSN_LB: c_lb_rm,

    mep.MEP_INSN_LW_SP: c_lw_sp,
    mep.MEP_INSN_SW_SP: c_sw_sp,

    mep.MEP_INSN_MOV: c_mov_rm,
    mep.MEP_INSN_MOVI8: c_mov_imm8,
    mep.MEP_INSN_RET: c_ret,
    mep.MEP_INSN_ADD3X: c_add3_imm16,
    mep.MEP_INSN_LDC_LP: c_ldc_lp,
    mep.MEP_INSN_STC_LP: c_stc_lp,

    mep.MEP_INSN_SLT3X: c_slt3_imm16,
    mep.MEP_INSN_SLTU3X: c_sltu3_imm16,

    mep.MEP_INSN_JMP: c_jmp_rm,
    mep.MEP_INSN_JMP24: c_jmp_target24,

    mep.MEP_INSN_BNE: make_cmp_b("BNE"),
    mep.MEP_INSN_BEQ: make_cmp_b("BEQ"),
    mep.MEP_INSN_BNEZ: make_cmpz_b("BNE"),
    mep.MEP_INSN_BEQZ: make_cmpz_b("BEQ"),
    mep.MEP_INSN_BNEI: make_cmp_b_rin("BNE"),
    mep.MEP_INSN_BEQI: make_cmp_b_rin("BEQ"),
    mep.MEP_INSN_BLTI: make_cmp_b_rin("BLT"),
    mep.MEP_INSN_BGEI: make_cmp_b_rin("BGE"),

    mep.MEP_INSN_BSR12: c_bsr,
    mep.MEP_INSN_BSR24: c_bsr,
    mep.MEP_INSN_JSR: c_jsr,
    mep.MEP_INSN_SLLI: c_sll_imm5,
    mep.MEP_INSN_SRLI: c_srl_imm5,
    mep.MEP_INSN_ADD: c_add,
    mep.MEP_INSN_SUB: c_sub,
    
    mep.MEP_INSN_OR: c_or,
    mep.MEP_INSN_AND: c_and,
    mep.MEP_INSN_XOR: c_xor,

    mep.MEP_INSN_BRA: c_bra,
    mep.MEP_INSN_ADD3: c_add3_rl,
    mep.MEP_INSN_AND3: c_and3,
    mep.MEP_INSN_XOR3: c_xor3,
    mep.MEP_INSN_ADD3I: c_add3_sp,
    mep.MEP_INSN_SLT3: c_slt3_r0,
    mep.MEP_INSN_SLTU3: c_sltu3_r0,
    mep.MEP_INSN_MOVI16: c_mov_imm8,
    mep.MEP_INSN_LBU: c_lbu_rm,
    mep.MEP_INSN_LHU: c_lhu_rm,
    
    mep.MEP_INSN_SLL: c_sll_rm,
    mep.MEP_INSN_SRL: c_srl_rm,
    mep.MEP_INSN_SLL3: c_sll3,
    mep.MEP_INSN_NOR: c_nor,
    mep.MEP_INSN_SLTU3I: c_sltu3_imm5,
    mep.MEP_INSN_NEG: c_neg,

    mep.MEP_INSN_EXTB: make_ext("SXTB"),
    mep.MEP_INSN_EXTUB: make_ext("UXTB"),
    mep.MEP_INSN_EXTH: make_ext("SXTH"),
    mep.MEP_INSN_EXTUH: make_ext("UXTH"),

    mep.MEP_INSN_SRAI: c_sra_imm5,

    mep.MEP_INSN_ABS: c_abs,

    # System instructions we can't support
    mep.MEP_INSN_STC_HI: c_sys,
    mep.MEP_INSN_STC_LO: c_sys,
    mep.MEP_INSN_STC: c_sys,
    mep.MEP_INSN_LDC_HI: c_sys,
    mep.MEP_INSN_LDC_LO: c_sys,
    mep.MEP_INSN_LDC: c_sys,
    mep.MEP_INSN_EI: c_sys,
    mep.MEP_INSN_DI: c_sys,
    mep.MEP_INSN_SLEEP: c_sys,
    mep.MEP_INSN_RETI: c_sys,
    mep.MEP_INSN_STCB: c_sys,
    mep.MEP_INSN_STCB_R: c_sys,
    mep.MEP_INSN_LDCB: c_sys,
    mep.MEP_INSN_LDCB_R: c_sys,
}


def decompile(ea):
    ea = idaapi.get_func(ea).startEA

    rpb_in = -1

    name = function_name(GetFunctionName(ea))

    emit(".global {}".format(name))
    emit("{}:".format(name))

    for (startea, endea) in Chunks(ea):
        for addr in Heads(startea, endea):
            # Display a comment for easier debugging
            emit("// 0x{:08X}".format(addr))

            # If we've reached rpe of current repeat/erepeat, we will jump back to rpb in 2 instructions
            if addr == rpe:
                rpb_in = 2

            insn = idautils.DecodeInstruction(addr)
            # print "0x{:X}".format(addr), insn, hex(insn.itype)

            code = insn.itype

            output.append(Loc(addr))

            if code in codegen:
                try:
                    codegen[code](insn)
                except:
                    print("Errored at 0x{:08X}!".format(addr))
                    raise
            else:
                dis = idc.GetDisasm(addr)
                print("at 0x{:08X}: unknown instruction code={:3}, disasm={}".format(addr, code, dis))
                emit("BRK #0")

            # If there's a jump to rpb pending, decrease its counter...
            if rpb_in > 0:
                rpb_in -= 1
            # If we need to jump to rpb, go ahead and do that!
            if rpb_in == 0:
                rpb_in = -1
                if is_erepeat:
                    emit("// erepeat -> 0x{:08X}".format(rpb))
                    emit("B {}".format(use_loc(rpb)))
                else:
                    emit("// repeat -> 0x{:08X}".format(rpb))
                    emit("SUBS {0}, {0}, #1".format(g_arm_rpc_reg))
                    emit("BNE {}".format(use_loc(rpb)))


for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        decompile(funcea)

s = ""
for item in output:
    if isinstance(item, Insn):
        s += item.s + "\n"
    if isinstance(item, Loc) and item.s in used_locs:
        s += format_loc(item.s) + ":\n"


with open("F:/test.asm", "w") as fout:
    fout.write(s)
