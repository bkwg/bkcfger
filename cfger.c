#include <stdio.h>
#include <Zydis/Zydis.h>
#include <string.h>
#include "data.h"
#include "bk_types.h"

#define MAX_TARGETS     2
#define MAX_BB          10000
#define UNKNOWN_TARGET  0
#define MAX_INSN_BUFFER_SIZE 1000

#define ADDRESS_64(x)      ((U64)x)

typedef struct basic_block
{
    U64    leader;
    U64    tail;
    U64    targets[MAX_TARGETS];
    char*  str;
} BB;

typedef struct control_flow_graph
{
    U64 bb_count;
    U64 leaders_table[MAX_BB];
    U64 bb_table[MAX_BB][1];
} CFG;

typedef struct disassembly_info
{
    unsigned char* data;
    U64 data_length;
    U64 runtime_address;
    U64 last_address;
    U64 current_offset;
    U64 current_bb_address;
    void* instruction; // This will have to be casted
} DisasInfo;

void init_bb(BB* bb, U64 leader, U64 tail, U64 target1, U64 target2)
{
    bb->leader = leader;
    bb->tail = tail;
    bb->targets[0] = target1;
    bb->targets[1] = target2;
    bb->str = calloc(MAX_INSN_BUFFER_SIZE, sizeof(char));
}

BkBool BB_contains(BB* bb, U64 address)
{
    if (!bb)
        return BK_FALSE;

    if ((bb->leader <= address) && (address <= bb->tail))
        return BK_TRUE;

    return BK_FALSE;
}

void add_bb(CFG* cfg, BB* bb)
{
    if (!bb || !cfg)
        return;

    *cfg->bb_table[bb->leader % MAX_BB] = ADDRESS_64(bb);
    cfg->leaders_table[cfg->bb_count] = bb->leader;
    cfg->bb_count += 1;
}

BB* get_bb_from_address(CFG* cfg, U64 address)
{
    return (BB*)*cfg->bb_table[address % MAX_BB];
}

void print_bb(BB* bb)
{
    if (!bb)
        return;

    puts(  " _____________ BB ____________");
    printf("| LEADER: 0x%015lX   |\n", bb->leader);
    printf("| END: 0x%015lX      |\n", bb->tail);

    for (U64 i = 0; i < MAX_TARGETS; ++i)
    {
        if (bb->targets[i])
            printf("|    |_ T%lu: 0x%015lX |\n", i, bb->targets[i]);
    }

    puts(  " _____________________________\n");
}

void print_cfg(CFG* cfg)
{
    printf(">> Number of leaders: %ld\n", cfg->bb_count);

    for (uint32_t i = 0; i < cfg->bb_count; ++i)
    {
        print_bb(get_bb_from_address(cfg, cfg->leaders_table[i]));
    }
}

BkBool has_operands(void* insn)
{
    return ((ZydisDecodedInstruction*)insn)->operand_count;
}

BkBool is_branch(void* insn)
{
    return ((ZydisDecodedInstruction*)insn)->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE;
}

BkBool is_first_insn(U64 offset)
{
    return offset == 0;
}

BkBool is_conditional(void* instruction)
{
    ZydisCPUFlags flags = { 0 };
    ZydisGetAccessedFlagsByAction((ZydisDecodedInstruction*)instruction,
            ZYDIS_CPUFLAG_ACTION_TESTED, &flags);

    return flags != 0;
}

BkBool is_last_insn(U64 address, U64 insn_length, U64 last_address)
{
    if ((address + insn_length) > last_address)
        return BK_TRUE;

    return BK_FALSE;
}

void append_leader(CFG* cfg, U64 address)
{
    if (!cfg)
        return;

    if (get_bb_from_address(cfg, address) == 0)
    {
        BB* current_bb = malloc(sizeof(BB));
        init_bb(current_bb, address, UNKNOWN_TARGET, UNKNOWN_TARGET, UNKNOWN_TARGET);
        add_bb(cfg, current_bb);
    }
}

void record_potential_leader(CFG* cfg, DisasInfo* disas_info,
    void* insn)
{
    ZydisDecodedInstruction* instruction = (ZydisDecodedInstruction*)insn;

    // First instruction is always a leader
    if (is_first_insn(disas_info->current_offset))
    {
        append_leader(cfg, disas_info->runtime_address);
    }

    // The first instruction can be a cflow, thus no elif

    if ((has_operands(instruction) != 0) && is_branch(instruction))
    {
        ZydisDecodedOperand op = instruction->operands[0];

        switch(op.type)
        {
            case ZYDIS_OPERAND_TYPE_MEMORY:
            case ZYDIS_OPERAND_TYPE_POINTER:
            case ZYDIS_OPERAND_TYPE_REGISTER:
                {
                    // We do not handle them yet
                    // TODO: handle RET
                    break;
                }
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                {
                    U64 target1 = op.imm.value.u;

                    if (op.imm.is_relative)
                        ZydisCalcAbsoluteAddress(instruction, &op,
                                disas_info->runtime_address, &target1);

                    // First, we add the immediate target
                    append_leader(cfg, target1);

                    // Then, if conditional, we add the fallthrough
                    // but NOT if it is the last instruction in the buffer
                    if (is_conditional(instruction)
                        && !is_last_insn(disas_info->runtime_address,
                        instruction->length, disas_info->last_address))
                    {
                        U64 target2 = disas_info->runtime_address
                            + instruction->length;
                        append_leader(cfg, target2);
                    }

                    break;
                }
            default:
                break;
        }
    }
}

void save_target(CFG* cfg, U64 current_bb_address,
    U64 target1, U64 target2, U64 tail)
{
    BB* bb = get_bb_from_address(cfg, current_bb_address);
    bb->targets[0] = target1;
    bb->targets[1] = target2;
    bb->tail = tail;
}

BkBool bb_contains(BB* bb, U64 address)
{
    if (!bb)
        return BK_FALSE;

    return (bb->tail >= address) && (address >= bb->leader);
}

BkBool is_a_leader(CFG* cfg, U64 address)
{
    return get_bb_from_address(cfg, address) != 0;
}

void record_targets(CFG* cfg, DisasInfo* disas_info, void* insn)
{
    // In this function the previous instruction is the 'instruction',
    // unless we reached the end of the disassembly.

    ZydisDecodedInstruction* instruction =
        (ZydisDecodedInstruction*)insn;

    uint64_t tail = disas_info->runtime_address - instruction->length;

    // If the insn is not a cflow, and is the 1st, we have nothing to do.
    // If the insn is not a cflow, but not the 1st, deal with it.
    // If the first insn is a cflow, and is the 1st, deal with it.

    if ((instruction->meta.branch_type == ZYDIS_BRANCH_TYPE_NONE))
    {
        if (disas_info->current_offset)
        {
            save_target(cfg, disas_info->current_bb_address,
                disas_info->runtime_address, UNKNOWN_TARGET, tail);
        }
    }
    else
    {
        ZydisDecodedOperand op = instruction->operands[0];

        switch(op.type)
        {
            case ZYDIS_OPERAND_TYPE_MEMORY:
            case ZYDIS_OPERAND_TYPE_POINTER:
            case ZYDIS_OPERAND_TYPE_REGISTER:
            {
                // If those instructions are leaders we have to BB them.
                // But because the target is unknown, we put a sentinel value.
                save_target(cfg, disas_info->current_bb_address, UNKNOWN_TARGET,
                    UNKNOWN_TARGET, tail);
                break;
            }
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            {
                U64 target1 = op.imm.value.u;
                ZydisCPUFlags flags = { 0 };

                if (op.imm.is_relative)
                    ZydisCalcAbsoluteAddress(instruction, &op,
                        tail, &target1);

                ZydisGetAccessedFlagsByAction(instruction,
                    ZYDIS_CPUFLAG_ACTION_TESTED, &flags);
                if (flags && !is_last_insn(disas_info->runtime_address,
                    instruction->length, disas_info->last_address))
                {
                    U64 target2 = disas_info->runtime_address;
                    save_target(cfg, disas_info->current_bb_address, target2,
                        target1, tail);
                }
                else
                {
                    save_target(cfg, disas_info->current_bb_address, target1,
                        UNKNOWN_TARGET, tail);
                }

                break;
            }
            default:
                break;
        }
    }
}

void bb_dump_to_dot(CFG* cfg, BB* bb, FILE* dot)
{
    char buf[1000];

    for (U64 i = 0; i < MAX_TARGETS; ++i)
    {
        if (bb->targets[i])
        {
            BB* tbb = get_bb_from_address(cfg, bb->targets[i]);

            if (!tbb)
                continue;

            int nmemb = snprintf(buf, 500, "\t\"%s\" -> \"%s\";\n",
                bb->str, tbb->str);
            fwrite(buf, 1, nmemb, dot);
        }
    }
}

void print_cfg_to_dot(CFG* cfg)
{
    const char* file = "graph.dot";
    FILE* dot = fopen(file, "w");

    puts("\n[+] Dumping to dot");
    fwrite("digraph {\n", 1, 10, dot);

    for (U64 i = 0; i < cfg->bb_count; ++i)
    {
        BB* bb = get_bb_from_address(cfg, cfg->leaders_table[i]);
        if (bb != 0)
        {
            bb_dump_to_dot(cfg, bb, dot);
        }
    }

    fwrite("}", 1, 1, dot);
    fclose(dot);
    printf("[+] Done dumping dot to file: %s\n", file);
}

void print_instruction(BB* bb, uint64_t address, void* insn)
{
    if (!bb)
        return;

    ZydisDecodedInstruction* instruction = (ZydisDecodedInstruction*)insn;
    char decoded_insn_buffer[64] = { 0 };
    char insn_buffer[256] = { 0 };
    ZydisFormatter formatter;

    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisFormatterFormatInstruction(
        &formatter,
        instruction,
        decoded_insn_buffer,
        sizeof(decoded_insn_buffer),
        address);

    snprintf(insn_buffer, sizeof(insn_buffer), "%016lX %s\n",
        address, decoded_insn_buffer);
    strcat(bb->str, insn_buffer);
    printf("%s", insn_buffer);
}

ZyanStatus disassemble(ZydisDecoder* decoder, uint8_t buffer[],
    ZyanUSize remaining_length, void* insn)
{
    ZyanU8* data            = (ZyanU8*)buffer;
    ZyanUSize offset        = 0;

    return ZydisDecoderDecodeBuffer(decoder, data + offset,
        remaining_length, insn);
}

void disassemble_all_callback(CFG* cfg, DisasInfo* disas_info,
    void(*callback)(CFG* cfg, DisasInfo*, void*))
{
    if (!cfg || !disas_info)
        return;

    ZydisDecodedInstruction instruction = { 0 };
    ZydisDecodedInstruction previous_instruction = { 0 };
    ZydisDecoder decoder = { 0 };

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_ADDRESS_WIDTH_64);
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
        &decoder,
        disas_info->data + disas_info->current_offset,
        disas_info->data_length - disas_info->current_offset,
        &instruction)))
    {
        callback(cfg, disas_info, (void*)&instruction);

        previous_instruction = instruction;
        disas_info->instruction = (void*)&previous_instruction;
        disas_info->current_offset += instruction.length;
        disas_info->runtime_address += instruction.length;
    }

    return;
}

void find_leaders(CFG* cfg, DisasInfo* disas_info, void* insn)
{
    record_potential_leader(cfg, disas_info, insn);
}

void record_target(CFG* cfg, DisasInfo* disas_info, void* insn)
{
    ZydisDecodedInstruction* instruction = (ZydisDecodedInstruction*)insn;

    // If we entered a new BB or we reached the end
    if (is_a_leader(cfg, disas_info->runtime_address))
    {
        // Declare the BB, save it, refresh current_bb_address

        insn = disas_info->instruction;
        record_targets(cfg, disas_info, insn);
        disas_info->current_bb_address = disas_info->runtime_address;
    }
    else if (is_last_insn(disas_info->runtime_address, instruction->length,
           disas_info->last_address))
    {
        // If it is the last instruction we shouldn't change the bb_address
        disas_info->runtime_address += instruction->length;
        record_targets(cfg, disas_info, insn);
        disas_info->runtime_address -= instruction->length;
    }

    // TODO: Put it where it belongs
    print_instruction(get_bb_from_address(cfg, disas_info->current_bb_address),
        disas_info->runtime_address, instruction);
}

void free_cfg(CFG* cfg)
{
    for (uint32_t i = 0; i < cfg->bb_count; ++i)
    {
        free(get_bb_from_address(cfg, cfg->leaders_table[i])->str);
        free(get_bb_from_address(cfg, cfg->leaders_table[i]));
    }
}

void init_disas_info(DisasInfo* disas_info, U64 runtime_address,
    unsigned char* data, USize data_length)
{
    disas_info->data = data;
    disas_info->data_length = data_length;
    disas_info->runtime_address = runtime_address;
    disas_info->last_address = disas_info->runtime_address + disas_info->data_length - 1;
    disas_info->current_bb_address = disas_info->runtime_address;
}

int main(void)
{
    CFG cfg = { 0 };
    DisasInfo disas_info = { 0 };
    uint64_t runtime_address = 0x007FFFFFFF400000;

    // TODO: Compute size of data in a more consistent way
    init_disas_info(&disas_info, runtime_address, data, sizeof(data));

    disassemble_all_callback(&cfg, &disas_info, &find_leaders);

    // Reset following variables
    disas_info.runtime_address = *cfg.leaders_table;
    disas_info.current_offset = 0;

    disassemble_all_callback(&cfg, &disas_info, &record_target);

    print_cfg(&cfg);

    print_cfg_to_dot(&cfg);

    free_cfg(&cfg);

    return 0;
}
