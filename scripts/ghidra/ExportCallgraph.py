# Ghidra script: ExportCallgraph.py
# Export function call graph to JSON file
# Usage: analyzeHeadless ... -postScript ExportCallgraph.py /output/callgraph.json

import json

def run():
    output_path = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "/tmp/callgraph.json"

    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()

    callgraph = {
        "nodes": [],
        "edges": []
    }

    func_addresses = {}

    # First pass: collect all functions (nodes)
    for func in fm.getFunctions(True):
        addr = str(func.getEntryPoint())
        func_addresses[func.getEntryPoint()] = func.getName()
        callgraph["nodes"].append({
            "name": func.getName(),
            "address": addr
        })

    # Second pass: collect all calls (edges)
    for func in fm.getFunctions(True):
        caller_name = func.getName()
        caller_addr = func.getEntryPoint()

        # Iterate through all addresses in this function
        body = func.getBody()
        addr_iter = body.getAddresses(True)

        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs = ref_mgr.getReferencesFrom(addr)

            for ref in refs:
                if ref.getReferenceType().isCall():
                    callee_addr = ref.getToAddress()
                    callee_func = fm.getFunctionAt(callee_addr)

                    if callee_func:
                        callee_name = callee_func.getName()
                    else:
                        # External or indirect call
                        callee_name = str(callee_addr)

                    callgraph["edges"].append({
                        "caller": caller_name,
                        "callee": callee_name,
                        "callSite": str(addr)
                    })

    # Write to file
    with open(output_path, 'w') as f:
        json.dump(callgraph, f, indent=2)

    print("Exported {} nodes and {} edges to {}".format(
        len(callgraph["nodes"]),
        len(callgraph["edges"]),
        output_path
    ))

run()
