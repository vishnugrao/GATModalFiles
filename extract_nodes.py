import re

def extract_nodes_and_instructions(dot_file_content):
    # First find all nodes (both in definitions and edges)
    node_pattern = r'Node0x[0-9a-fA-F]+'
    nodes = set(re.findall(node_pattern, dot_file_content))
    
    # Then find node definitions with their labels
    def_pattern = r'(Node0x[0-9a-fA-F]+)\s*\[shape=.*?label="(.*?)".*?\]'
    label_matches = re.findall(def_pattern, dot_file_content, re.DOTALL)
    
    # Create dictionary with node hex ID as key and instruction as value
    node_instructions = {}
    for node, label_content in label_matches:
        node_type = ""
        raw_instruction = ""
        node_id = "Unknown"
        
        # Get node type and ID from first part before \n
        type_id_match = re.search(r'\{(\w+)\s+ID:\s*(\d+)', label_content)
        if type_id_match:
            node_type = type_id_match.group(1)
            node_id = type_id_match.group(2)
        
        # Get instruction part after \n
        instr_match = re.search(r'\\n\s+(.*?)\s*\}"', label_content + "\"")
        if instr_match:
            raw_instruction = instr_match.group(1)
        
        if node not in node_instructions:
            node_instructions[node] = (node_type if node_type else "Unknown", node_id, raw_instruction)
    
    # For nodes without definitions, add them with empty info
    for node in nodes:
        if node not in node_instructions:
            node_instructions[node] = ("Unknown", "Unknown", "")
    
    # Sort nodes by their hex ID for consistent output
    sorted_nodes = sorted(node_instructions.items(), key=lambda x: x[0])
    
    return sorted_nodes

def create_instruction_patterns():
    patterns = {
        # Binary operations (add, sub, mul, etc)
        'binary': {
            'opcodes': {'add', 'sub', 'mul', 'udiv', 'sdiv', 'urem', 'srem', 'shl', 'lshr', 'ashr', 'and', 'or', 'xor'},
            'pattern': r'(\S+)\s+(\S+),\s*(\S+)',  # return_type, op1, op2
            'groups': ['return_type', 'op1_type', 'op2_type']
        },
        # Copy instruction
        'copy': {
            'opcodes': {'null'},  # Special case for "ptr null { constant data }"
            'pattern': r'(ptr)\s+null\s*\{\s*constant\s+(data)\s*\}',  # ptr null { constant data }
            'groups': ['return_type', 'operand_type']
        },
        # Cast operations (trunc, zext, sext, etc)
        'cast': {
            'opcodes': {'trunc', 'zext', 'sext', 'fptoui', 'fptosi', 'uitofp', 'sitofp', 'fptrunc', 'fpext', 'ptrtoint', 'inttoptr', 'bitcast', 'addrspacecast'},
            'pattern': r'(\S+)\s+%\S+\s+to\s+(\S+)',  # i64 %6 to i32
            'groups': ['source_type', 'result_type']
        },
        # Alloca instruction
        'alloca': {
            'opcodes': {'alloca'},
            'pattern': r'(\S+)(?:,\s*.*)?',  # type [, size]
            'groups': ['return_type']
        },
        # Call instructions
        'call': {
            'opcodes': {'call'},
            'pattern': r'(\S+)\s+@\S+\((.*?)\)',  # return_type @func(args)
            'groups': ['return_type', 'args']
        },
        # Load instruction
        'load': {
            'opcodes': {'load'},
            'pattern': r'(\S+),\s*(\S+)',  # return_type, ptr_type
            'groups': ['return_type', 'ptr_type']
        },
        # Store instruction
        'store': {
            'opcodes': {'store'},
            'pattern': r'(\S+)\s+(\S+),\s*(\S+)',  # val_type, val, ptr_type
            'groups': ['val_type', 'ignored', 'ptr_type']
        },
        # GetElementPtr
        'gep': {
            'opcodes': {'getelementptr'},
            'pattern': r'(?:inbounds\s+)?(\S+)(?:,\s*(.+))?',  # [inbounds] return_type [, operands]
            'groups': ['return_type', 'operands']
        },
        # Compare instructions
        'cmp': {
            'opcodes': {'icmp', 'fcmp'},
            'pattern': r'\S+\s+(\S+),\s*(\S+)',  # pred type1, type2
            'groups': ['op1_type', 'op2_type']
        },
        # Atomic operations
        'atomic': {
            'opcodes': {'atomicrmw', 'cmpxchg'},
            'pattern': r'(\S+)\s*,\s*(\S+)',  # ptr_type, val_type
            'groups': ['ptr_type', 'val_type']
        },
        # Formal parameter nodes
        'formal': {
            'opcodes': {'formal'},
            'pattern': r'(i\d+|ptr)\s+%\d+\s*\{\s*\d+th\s+arg\s+\S+\s*\}',  # i32 %0 { 0th arg main }
            'groups': ['return_type']
        },
    }
    return patterns

def parse_instruction(raw_instruction):
    if not raw_instruction:
        return None, None, []
    
    # Special case for formal parameter format "i32 %0 { 0th arg main }"
    formal_match = re.match(r'(i\d+|ptr)\s+%\d+\s*\{\s*\d+th\s+arg\s+\S+\s*\}', raw_instruction)
    if formal_match:
        return "formal", formal_match.group(1), []
    
    # Special case for copy instruction with format "ptr null { constant data }"
    copy_match = re.match(r'(ptr)\s+null\s*\{\s*constant\s+(data)\s*\}', raw_instruction)
    if copy_match:
        return "copy", copy_match.group(1), [copy_match.group(2)]
    
    # Remove alignment info
    instruction = re.sub(r',?\s*align\s+\d+', '', raw_instruction)
    
    # Split into result and operation if assignment exists
    if '=' in instruction:
        _, operation = instruction.split('=', 1)
        operation = operation.strip()
    else:
        operation = instruction.strip()
    
    # Get opcode
    parts = operation.split(None, 1)
    if not parts:
        return None, None, []
    
    opcode = parts[0]
    remainder = parts[1] if len(parts) > 1 else ""
    
    # Get patterns dictionary
    patterns = create_instruction_patterns()
    
    # Find matching pattern group
    pattern_group = None
    for group, info in patterns.items():
        if opcode in info['opcodes']:
            pattern_group = info
            break
    
    if not pattern_group:
        return opcode, None, []
        
    # Parse according to pattern
    match = re.match(pattern_group['pattern'], remainder)
    if not match:
        return opcode, None, []
        
    # Extract types based on pattern group
    if pattern_group == patterns['call']:
        return_type = match.group(1)
        args = match.group(2)
        operand_types = []
        for arg in args.split(','):
            arg = arg.strip()
            type_match = re.match(r'([^%\s]+)', arg)
            if type_match:
                operand_types.append(type_match.group(1))
        return opcode, return_type, operand_types
        
    elif pattern_group == patterns['cast']:
        source_type = match.group(1)
        result_type = match.group(2)
        return opcode, result_type, [source_type]
        
    elif pattern_group == patterns['gep']:
        # Handle array types in GEP instructions
        full_type = match.group(1)
        
        # Extract the complete array type
        array_match = re.match(r'(\[[\d\s]*x\s*[^\s,\]]+\])', full_type)
        if array_match:
            return_type = array_match.group(1)
        else:
            # Remove 'inbounds' if present and get basic type
            basic_type = re.sub(r'^inbounds\s+', '', full_type)
            # Get type before any comma
            type_match = re.match(r'([^\s,]+)', basic_type)
            return_type = type_match.group(1) if type_match else basic_type.rstrip(',')
        
        operand_types = []
        if match.group(2):
            # Split operands and extract their types
            ops = match.group(2).split(',')
            for op in ops:
                op = op.strip()
                # Match type patterns:
                # - ptr for pointer types
                # - i64 for integer types
                type_match = re.match(r'(?:ptr|i\d+)', op)
                if type_match:
                    operand_types.append(type_match.group(0))
        
        return opcode, return_type, operand_types
        
    else:
        # Handle other patterns
        groups = match.groups()
        if 'return_type' in pattern_group['groups']:
            idx = pattern_group['groups'].index('return_type')
            return_type = groups[idx]
        else:
            return_type = None
            
        operand_types = []
        for i, group in enumerate(groups):
            if pattern_group['groups'][i].endswith('_type') and not pattern_group['groups'][i].startswith('return'):
                if group and not group.startswith('%'):
                    operand_types.append(group)
                    
        return opcode, return_type, operand_types

def print_nodes_and_instructions(nodes):
    print(f"Found {len(nodes)} unique nodes:")
    for node, (node_type, node_id, raw_instruction) in nodes:
        print(f"\nnode: {node}")
        print(f"id: {node_id}")
        print(f"type: {node_type}")
        print(f"raw instruction: {raw_instruction}")
        
        if raw_instruction:
            opcode, return_type, operand_types = parse_instruction(raw_instruction)
            if opcode:
                print(f"opcode: {opcode}")
                if return_type:
                    print(f"return type: {return_type}")
                for i, op_type in enumerate(operand_types, 1):
                    print(f"operand {i} type: {op_type}")

def main():
    try:
        with open('./temp_med_container/juliet-medium-ivfg/CWE127/13/bad/CWE127/13/bad/CWE127_Buffer_Underread__char_alloca_cpy_13.dot', 'r') as file:
            content = file.read()
            
        # Extract and print unique nodes with their instructions
        nodes = extract_nodes_and_instructions(content)
        print_nodes_and_instructions(nodes)
        
    except FileNotFoundError:
        print("Error: Dot file not found")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main() 