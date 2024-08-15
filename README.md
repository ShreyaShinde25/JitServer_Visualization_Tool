# JitServer_Visualization_Tool




## Project Setup 

1. Download the custom JDK from: https://ibm.box.com/s/zr0b91rfozrnwsm5n50od4m3stxa3dci. After downloading, extract the contents of the .zip file to `preprocessing`. Once complete, the custom JDK should be located under the directory named `preprocessing/jdk`. (e.g. the `java` binary of the JDK should be located under the path `preprocessing/jdk/bin`)

2. [*Optional*] Download the Dacapo benchmark mark from: https://github.com/dacapobench/dacapobench/releases/tag/v23.11-chopin. 
The downloaded .zip file should be extracted to the directory `preprocessing/apps`. There should be 2 main components extracted: a folder named `dacapo-23.11-chopin` and a jar file named ` dacapo-23.11-chopin.jar`

## Visualization Input Data Generation

After completing the setup above, visualization data can be generated using the provided scripts under `preprocessing/scripts`.

### HelloWorld Program
1. Navigate to the directory `preprocessing/scripts`
2. Run the script named `gen_hello.sh` (which runs a HelloWorld program)
3. Visualization input data for the HelloWorld program should be available in the directory `preprocessing/out` with the names `hello_trace_***.json`

### Dacapo Benchmarks
0. Download the Dacapo benchmark based on instructions from Step 2 in [Project Setup](#project-setup-(optional)).
1. Navigate to the directory `preprocessing/scripts`
2. Run the script named `gen_dacapo.sh <benchmark_name>` (which runs a Dacapo benchmark)
3. Visualization input data for the benchmark program should be available in the directory `preprocessing/out` with the names `<benchmark_name>_trace_***.json`

## How to Use the Visualization Tool
0. Navigate to the `visualization/` directory.   
1. Open the `visualize.html` file in a web browser.
2. Select the `Choose File` option to upload the input data in the `***.json` format. For example, you can use `visualization/json/example.json` to visualize sample data. 
3. Interact with the visualization by clicking on nodes/edges to view more detailed information.

## Visualization Input Data Format (*Per Graph*)
- Input data should be as a **list** in JSON format
- Input data should be divided into 2 sections ```methods``` and ```paths```
```
{
  methods: [list of method objects],
  paths: [list of unique execution paths]
}
```
### Method Objects
- Each ```method object``` in the input data should have attributes in the following structure:

```
{
  "id": int,
  "className": string,
  "methodName": string,
  "methodDescriptor" string,
  "metrics": [
    {
      "key": string,
      "value": numeric
    }, 
    {
      "key": string,
      "value": numeric
    },
    ...
  ],
  "inlines": [
    {
      "caller": string,
      "callee": string,
      "callSite": int,
    },
  ],
  "sampleCount": numeric,
}

```
- Attribute details:
  - ```id```: unique identifier for the current method
  - ```className```: the Java classPath for the current method (```className```.```methodName``````methodDescriptor``` should also be able to uniquely identify the current method)
  - ```methodName```: the name of the current method
  - ```methodDescriptor```: the input type(s) and return type of the current method
  - ```metrics```: a list of collected metrics for the current method in key-value format
    - ```key```: the name of the metric collected 
    - ```value```: the value corresponding to a particular metric  
  - ```inlines```: a list of methods inlined into the current method
    - ```caller```: unique identifier for the caller method 
    - ```callerIndex```: relative method index (id) receiving inline (top-level method is -1)
    - ```callee```: unique identifier for the callee method (the method that got inlined)
    - ```calleeIndex```: relative method index (id) getting inlined
    - ```callSite```: byte code index in caller method that inlined the callee
  - ```sampleCount```: how many times the method appearred at the top of the stack while sampling the trace points

- The following keys are currently supported:
  - **methodSize**: the size of the method in bytecode
  - **cpu**: the cpu util % of the method (WIP)

### Execution Paths
- Each execution path should be stored in the following **nested/recursive** structure
```
{
  "id": string,
  "callSite": string,
  "execType": string,
  "children": 
  [
    {
      "id": string,
      "callSite": string,
      "execType": string,
      "children": 
      [
        {
          "id": string,
          "callSite": string,
          "execType": string,
          "children": 
          [
            ...
          ]
        },
        ...
      ]
    },
    ...
  ]
}

```
- Attribute details:
  - ```id```: unique identifier for the current method in the execution path (this should be the same id that uniquely identifies a method object)
  - ```callSite```: the location (in terms of bytecode index) in the caller (parent) method that called the current method. For the first entry in the path, this value is the Java Thread for which the call stack belongs to
  - ```execType```: the execution type for this invocation (i.e. interpretted, compiled, native, or inlined)
  - ```children```: a list of methods that fall under the current execution path (defined recursively). The last node in the execution path should have an empty list for its children
    - A new child should only be added under the parent when the child is called by the parent from a unique position (i.e. line number) in the code for the **first time**
    - For recursive methods, this may mean the recursion stops after just one child is added (i.e. this means the recursive call is only made from a single position in the method)