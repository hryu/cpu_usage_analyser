import os
import sys
import weakref

import babeltrace

from .state import State
from .sched_analyser import SchedAnalyser
from .syscall_analyser import SyscallAnalyser
from .irq_analyser import IrqAnalyser

class AnalyserRunner:
    def __init__(self, path, notifiers, stat_collector):
        self.trace_collection = babeltrace.TraceCollection()
        self.trace = self.trace_collection.add_traces_recursive(path, 'ctf')
        self.begin_ts = self.trace_collection.timestamp_begin
        self.end_ts = self.trace_collection.timestamp_end

        self.stat_collector = weakref.ref(stat_collector)

        state = State()
        self.analysers = [
            SchedAnalyser(notifiers, state),
            SyscallAnalyser(notifiers, state),
            IrqAnalyser(notifiers, state),
        ]

    def process_event(self, event):
        for analyser in self.analysers:
            analyser.analyse(event)

    def begin_analyse(self, timestamp):
        for analyser in self.analysers:
            analyser.on_begin_analyse(timestamp)

        sc = self.stat_collector()
        if sc is not None:
            sc.on_begin_analyse(timestamp)

    def end_analyse(self, timestamp):
        for analyser in self.analysers:
            analyser.on_end_analyse(timestamp)

        sc = self.stat_collector()
        if sc is not None:
            sc.on_end_analyse(timestamp)

    def run(self):
        self.begin_analyse(self.begin_ts)

        for event in self.trace_collection.events:
            self.process_event(event)

        self.end_analyse(self.end_ts)
