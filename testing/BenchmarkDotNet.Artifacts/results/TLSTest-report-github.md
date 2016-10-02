```ini

Host Process Environment Information:
BenchmarkDotNet.Core=v0.9.9.0
OS=Microsoft Windows NT 6.2.9200.0
Processor=Intel(R) Xeon(R) CPU E3-1505M v5 2.80GHz, ProcessorCount=8
Frequency=2742188 ticks, Resolution=364.6723 ns, Timer=TSC
CLR=MS.NET 4.0.30319.42000, Arch=64-bit RELEASE [RyuJIT]
GC=Concurrent Workstation
JitModules=clrjit-v4.6.1586.0

Type=TLSTest  Mode=Throughput  Platform=X64  
Jit=RyuJit  LaunchCount=2  WarmupCount=1  
TargetCount=3  

```
  Method | Median | StdDev | Gen 0 | Gen 1 | Gen 2 | Bytes Allocated/Op |
-------- |------- |------- |------ |------ |------ |------------------- |
 RunTest |     NA |     NA |     - |     - |     - |                  ∞ |

Benchmarks with issues:
  TLSTest_RunTest_X64_Jit-RyuJit_WarmupCount1_TargetCount3_LaunchCount2_IterationTime10000
