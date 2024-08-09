import re
import json
import argparse
import tqdm
from collections import defaultdict
import util
import const

# playground: https://regexr.com/7snrp
DEFAULT_PATTERN = r'(?P<ts>\d{2}\:\d{2}\:\d{2}\.\d+)(\*|\s)+(?P<thread>\w+)\s+(?P<tracepoint>(\w|\.)+)\s(.+)\[(?P<stack_pos>\d+)\]\s(?P<class_method_name>.+)(?P<input_params>\(\S*\))(?P<return_type>\S+)\s(\(\@\:(?P<pc>\d+)\,line\:(?P<line_no>\d+)\)\s)?(invkCD\:(?P<invoke_count_down>\d+)\,)?(?P<exec_type>\((compiled|native)\))?(\sstrtCnt\:(?P<start_sample_count>\d+)\,\sgblCnt\:(?P<global_sample_count>\d+)\,\scpu\:(?P<cpu>\d+\.\d+)\%\,)?\s(?P<method_size>\d+)\sbcsz'
# playground: https://regexr.com/7tj6i
INLINE_PATTERN = r'(?P<ts>\d{2}\:\d{2}\:\d{2}\.\d+)(\*|\s)+(?P<thread>\w+)\s+(?P<tracepoint>(\w|\.)+)\s(.+)\#(?P<callee_index>\d+)\-\>\#(?P<caller_index>(\-|\d)+)\s\@(?P<pc>\d+)\s(?P<class_method_name>.+)(?P<input_params>\(\S*\))(?P<return_type>\S+)\s(?P<method_size>\d+)\sbcsz'

class LogStackEntry:
    def __init__(self, data):
        self._data = data
        convert_to_int_keys = ["stack_pos", "caller_index", "pc", "callee_index"]
        for k in convert_to_int_keys:
            if k in self._data and self._data[k] is not None:
                self._data[k] = int(self._data[k])
        self._data["class_name"], self._data["method_name"] = data["class_method_name"].rsplit(".", 1)
        self._data["method_descriptor"] = f'{data["input_params"]}{data["return_type"]}'

    def is_inline_entry(self):
        return self.get_caller_index() is not None

    def get_thread(self):
        return self.get_value('thread')    

    def get_call_site(self):
        return self.get_value('pc') # or 'line_no'

    def get_tracepoint(self):
        return self.get_value('tracepoint')
    
    def get_signature(self):
        return f'{self.get_value("class_name")}.{self.get_value("method_name")}{self.get_value("method_descriptor")}'

    def get_class_name(self):
        return self.get_value("class_name")

    def get_method_name(self):
        return self.get_value("method_name")
    
    def get_stack_pos(self):
        return self.get_value("stack_pos")

    def get_caller_index(self):
        return self.get_value("caller_index")

    def get_exec_type(self):
        t = self.get_value("exec_type")
        if t:
            t = t.lower().split(" ")[0].replace("(", "").replace(")", "")
        return t if t else "interpreted"
    
    def get_value(self, key):
        return self._data[key] if key in self._data else None

def parse_line_for_data(line):
    try:
        inline_match = re.search(INLINE_PATTERN, line)
        if inline_match:
            return LogStackEntry(inline_match.groupdict())
        else:
            default_match = re.search(DEFAULT_PATTERN, line)
            if default_match:
                return LogStackEntry(default_match.groupdict())
            else:
                # print(f"No match found: {line}")
                return None
    except Exception as e:
        print(f"Error processing line: {line}\nError: {e}\n")
        import sys; sys.exit(0)
        return None

def add_method(json_methods: list, entry, inline_list: list, method_map: dict, next_method_id: int):
    key = entry.get_signature()
    if key not in method_map:
        for ie in inline_list:
            if ie["callerIndex"] == -1: # replace -1 with current method id now that we know the id for root of inlines
                ie["caller"] = next_method_id
        method_map[key] = next_method_id
        json_methods.append({
            "id": next_method_id,
            "className": entry.get_class_name(),
            "methodName": entry.get_method_name(),
            "methodDescriptor": entry.get_value("method_descriptor"),
            "metrics": [
                {"key": "methodSize", "value": entry.get_value("method_size")},
                {"key": "cpu", "value": entry.get_value("cpu")}
            ],
            "inlines": [i for i in inline_list],
            "sampleCount": 1 if entry.get_stack_pos() == 1 else 0,
        })
        next_method_id += 1
    else:
        #TODO: aggregate metrics here??
        # update inlines
        for ie in inline_list:
            if ie["callerIndex"] == -1: # replace -1 with current method id now that we know the id for root of inlines
                ie["caller"] = method_map[key]
        if len(inline_list) > 0:
            json_methods[method_map[key]]["inlines"] = inline_list.copy()
        # update sampleCount
        if entry.get_stack_pos() == 1:
            json_methods[method_map[key]]["sampleCount"] += 1
    return next_method_id

def add_paths(json_paths: list, call_stack: list, method_id_map: dict):
    current_level = json_paths
    prev_entry = None
    n = len(call_stack)
    i = n-1
    # inline_stack = list()
    while i >= 0:
        # deal with inline entries by stacking first (because caller-callee order is reversed (top-down) in logs)
        # while i >= 0 and call_stack[i].is_inline_entry():
        #     inline_stack.append(call_stack[i])
        #     i -= 1
        # level_map = {-1: current_level} # map from caller_index to list of children
        # while len(inline_stack) > 0:
        #     inline_entry = inline_stack.pop()
        #     inline_entry_id = method_id_map[inline_entry.get_signature()]
        #     inline_site = inline_entry.get_call_site() # position where inline happened 
        #     level = level_map[inline_entry.get_value("caller_index")] # get the level that corresponds to the caller_index
        #     new_entry = {"id": inline_entry_id, "callSite": inline_site, "execType": "inline", "children": list()}
        #     level.append(new_entry)
        #     # callee_index is guruanteed to be unique across a set of inline entries
        #     level_map[inline_entry.get_value("callee_index")] = new_entry["children"]
        # skip inline entries in paths
        if call_stack[i].is_inline_entry():
            i -= 1
            continue
        current_entry = call_stack[i]
        current_id = method_id_map[current_entry.get_signature()]
        call_site = prev_entry.get_call_site() if prev_entry else current_entry.get_thread()
        exec_type = current_entry.get_exec_type()
        found = False
        for entry in current_level:
            # match criteria:
            # - same id (same method being called)
            # - called from same call-site (unless its at the bottom of stack)
            if entry["id"] == current_id and (call_site is None or entry["callSite"] == call_site):  
                found = True
                current_level = entry["children"]
                break
        if not found:
            # print(f'new entry: {current_entry.get_signature()}' )
            new_entry = {"id": current_id, "callSite": call_site, "execType": exec_type, "children": list()}
            current_level.append(new_entry)
            current_level = new_entry["children"]
        prev_entry = current_entry
        i -= 1

def process_call_stack(call_stack, method_id_map, next_method_id, json_methods, json_paths):
    # update methods
    inline_list = list()
    inline_map = dict()
    for entry in call_stack:
        if entry.is_inline_entry():
            next_method_id = add_method(json_methods, entry, list(), method_id_map, next_method_id)
            inline_map[entry.get_value("callee_index")] = method_id_map[entry.get_signature()]
            inline_list.append({
                "caller": inline_map.get(entry.get_value("caller_index"), -1), # set to -1 in case caller is the root of the inline, in which case we don't know the id until later in the call stack
                "callerIndex": entry.get_value("caller_index"),
                "callee": inline_map[entry.get_value("callee_index")],
                "calleeIndex": entry.get_value("callee_index"),
                "callSite": entry.get_call_site(),
                "size": int(entry.get_value("method_size"))
            })
        else:
            next_method_id = add_method(json_methods, entry, inline_list, method_id_map, next_method_id)
            inline_map.clear()
            inline_list.clear()
    # update paths
    add_paths(json_paths, call_stack, method_id_map)
    return next_method_id

def read_in_call_stacks(file_path, file, yield_tracepoint):
    call_stacks = defaultdict(list)
    for line in tqdm.tqdm(file, total=util.get_num_lines(file_path)):
        entry = parse_line_for_data(line)
        if entry is None:
            continue
        thread_id = entry.get_thread()
        if thread_id in call_stacks and entry.get_tracepoint() == yield_tracepoint:
            carry_over_entries = list()
            while call_stacks[thread_id] and call_stacks[thread_id][-1].is_inline_entry():
                carry_over_entries.append(call_stacks[thread_id].pop())
            yield call_stacks[thread_id]
            call_stacks[thread_id].clear()
            while len(carry_over_entries) > 0:
                call_stacks[thread_id].append(carry_over_entries.pop())
        call_stacks[thread_id].append(entry)
    # clean up
    for thread in call_stacks:
        if len(call_stacks[thread]) > 0:
            yield call_stacks[thread]

def main():
    parser = argparse.ArgumentParser(description='Script for converting JVM tracepoint output into JSON format which can be used for caller-callee visualizations.')
    parser.add_argument('--input', '-i', type=str, required=True, help='path to input (.log, .fmt) file to process with tracepoint output.') 
    parser.add_argument('--output', '-o', type=str, default='', help='output (.json) file name which will contain execution path information.')    
    args = parser.parse_args()
    util.mkdir(const.OUT_DIR) 
    method_id_map = {}
    next_method_id = 0
    json_methods = []
    json_paths = []

    with open(args.input, 'r') as file:
        for call_stack in read_in_call_stacks(args.input, file, "j9jit.93"):
            next_method_id = process_call_stack(call_stack, method_id_map, next_method_id, json_methods, json_paths)
    
    # structured based on outline in README
    json_output = {
        "methods": json_methods,
        "paths": json_paths
    }
    output_json = f"{const.OUT_DIR}/{args.output}"
    if args.output == '':
        log_name = util.get_file_name(args.input)
        output_json = f'{const.OUT_DIR}/{log_name}.json'
    print(f'saving to: {output_json}')
    with open(output_json, 'w') as json_file:
        json.dump(json_output, json_file, indent=2)

if __name__ == "__main__":
    main()
