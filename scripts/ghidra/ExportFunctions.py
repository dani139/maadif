# Ghidra script: ExportFunctions.py
# Export all functions to JSON file
# Usage: analyzeHeadless ... -postScript ExportFunctions.py /output/functions.json

import json

def run():
    output_path = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "/tmp/functions.json"

    fm = currentProgram.getFunctionManager()
    functions = []

    for func in fm.getFunctions(True):
        func_data = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "isExternal": func.isExternal(),
            "isThunk": func.isThunk(),
            "callingConvention": func.getCallingConventionName(),
            "parameterCount": func.getParameterCount()
        }

        # Get signature
        try:
            func_data["signature"] = str(func.getSignature())
        except:
            func_data["signature"] = None

        functions.append(func_data)

    # Write to file
    with open(output_path, 'w') as f:
        json.dump(functions, f, indent=2)

    print("Exported {} functions to {}".format(len(functions), output_path))

run()
