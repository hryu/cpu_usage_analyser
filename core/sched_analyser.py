from . import state
from .analyser import Analyser

class SchedAnalyser(Analyser):
    def __init__(self, notifiers, state):
        callbacks = {
            'sched_switch' : self.process_sched_switch,
        }

        super().__init__(callbacks, notifiers, state)

        self.begin_ts = None

    def on_begin_analyse(self, timestamp):
        self.begin_ts = timestamp

    # skip and ignore 0 (idle processes)
    def process_sched_switch(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']
        next_comm = event['next_comm']
        prev_comm = event['prev_comm']

        # for 'perf' tool
        try:
            prev_tid = event['prev_tid']
            next_tid = event['next_tid']
        except KeyError:
            prev_tid = event['prev_pid']
            next_tid = event['next_pid']

        if cpu_id not in self.state.cpus:
            self.state.cpus[cpu_id] = state.Cpu(cpu_id)

        cpu = self.state.cpus[cpu_id]

        if prev_tid != 0:
            # the first meeting of sched_out event without sched_in.
            # consider this time as starting from beginning.
            if prev_tid not in self.state.tids:
                self.state.tids[prev_tid] = state.Process(prev_tid, prev_comm)

                proc = self.state.tids[prev_tid]
                proc.duration = state.Duration(self.begin_ts)
                proc.irq_stolen_duration = state.Duration(None)
                proc.softirq_stolen_duration = state.Duration(None)

            proc = self.state.tids[prev_tid]

            # missing sched_in trace event, exclude this time.
            if proc.duration is None:
                proc.duration = state.Duration(timestamp)
                proc.irq_stolen_duration = state.Duration(None)
                proc.softirq_stolen_duration = state.Duration(None)

            proc.duration.update(timestamp)

            # exclude waiting time in syscall
            current_syscall = proc.current_syscall
            if current_syscall is not None:
                current_syscall.waiting_duration.begin(timestamp)

            self.notify('sched_out', cpu=cpu, proc=proc)

            proc.duration = None
            proc.irq_stolen_duration = None
            proc.softirq_stolen_duration = None

        if next_tid != 0:
            if next_tid not in self.state.tids:
                self.state.tids[next_tid] = state.Process(next_tid, next_comm)

            proc = self.state.tids[next_tid]
            proc.duration = state.Duration(timestamp)
            # see irq_analyser
            proc.irq_stolen_duration = state.Duration(None)
            proc.softirq_stolen_duration = state.Duration(None)

            cpu.current_proc = self.state.tids[next_tid]

            # exclude waiting time in syscall
            current_syscall = proc.current_syscall
            if current_syscall is not None:
                current_syscall.waiting_duration.accumulate(timestamp)
        else:
            cpu.current_proc = None
