using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

namespace BenchMarks
{
    public class BenchConfig: ManualConfig
    {
        public BenchConfig()
        {
#if NET461
            Add(new BenchmarkDotNet.Diagnostics.Windows.MemoryDiagnoser());
#endif
            //var jryuJit = new Job()
            //{
            //    Jit = Jit.RyuJit,
            //    LaunchCount = 2,
            //    Platform = Platform.X64,
            //    Runtime = Runtime.Clr,
            //    WarmupCount = 1,
            //    TargetCount = 4
            //};
            //Add(jryuJit);
            var core = new Job()
            {
                Jit = Jit.RyuJit,
                LaunchCount = 2,
                Platform = Platform.X64,
                Runtime = Runtime.Host,
                WarmupCount = 1,
                TargetCount = 3,
                Mode = Mode.Throughput,
                IterationTime = 10000
            };
            Add(core);
        }
    }

}
