#!/usr/bin/env python3

import sys
from core.cpu_stat_collector import CpuStatCollector

if __name__ == '__main__':
   collector = CpuStatCollector(sys.argv[1])
   collector.run()
   collector.print_result()
