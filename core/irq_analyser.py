from .analyser import Analyser
from . import state

class IrqAnalyser(Analyser):
    def __init__(self, notifiers, state):
        callbacks = {
            'irq_handler_entry' : self.process_irq_handler_entry,
            'irq_handler_exit' : self.process_irq_handler_exit,
            'irq_softirq_entry' : self.process_irq_softirq_entry,
            'irq_softirq_exit' : self.process_irq_softirq_exit,
            # perf tool compatible
            'softirq_entry' : self.process_irq_softirq_entry,
            'softirq_exit' : self.process_irq_softirq_exit,
        }

        super().__init__(callbacks, notifiers, state)

        self.begin_ts = None

    def on_begin_analyse(self, timestamp):
        self.begin_ts = timestamp

    def process_irq_handler_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']
        name = event['name']
        irq_num = event['irq']

        # ignore syscall until sched_analyse allocates the Cpu
        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]

        # steal irq time in syscall or sched_in
        if cpu.current_proc is not None:
            proc = cpu.current_proc
            syscall = proc.current_syscall
            if syscall is not None:
                syscall.irq_stolen_duration.begin(timestamp)

            proc.irq_stolen_duration.begin(timestamp)

        if cpu.current_softirq is not None:
            softirq = cpu.current_softirq
            softirq.irq_stolen_duration.begin(timestamp)

        cpu.current_irq = state.Irq(name, irq_num)
        cpu.current_irq.duration = state.Duration(timestamp)

    def process_irq_handler_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']
        irq_num = event['irq']
        ret = event['ret']

        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]

        if cpu.current_irq is None:
            return

        # steal softirq time in syscall or sched_in
        if cpu.current_proc is not None:
            proc = cpu.current_proc
            syscall = proc.current_syscall
            if syscall is not None:
                syscall.irq_stolen_duration.accumulate(timestamp)

            proc.irq_stolen_duration.accumulate(timestamp)

        if cpu.current_softirq is not None:
            softirq = cpu.current_softirq
            softirq.irq_stolen_duration.accumulate(timestamp)

        # exit without entry
        if cpu.current_irq is None:
            return

        irq = cpu.current_irq
        irq.duration.update(timestamp)

        self.notify('irq_exit', cpu=cpu, irq=irq)

        cpu.current_irq = None

    def process_irq_softirq_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']
        vec = event['vec']

        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]

        # steal irq time in syscall or sched_in
        if cpu.current_proc is not None:
            proc = cpu.current_proc
            syscall = proc.current_syscall
            if syscall is not None:
                syscall.softirq_stolen_duration.begin(timestamp)

            proc.softirq_stolen_duration.begin(timestamp)

        cpu.current_softirq = state.SoftIrq(vec)
        cpu.current_softirq.duration = state.Duration(timestamp)

    def process_irq_softirq_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']
        vec = event['vec']

        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]

        # steal softirq time in syscall or sched_in
        if cpu.current_proc is not None:
            proc = cpu.current_proc
            syscall = proc.current_syscall
            if syscall is not None:
                syscall.softirq_stolen_duration.accumulate(timestamp)

            proc.softirq_stolen_duration.accumulate(timestamp)

        # exit without entry
        if cpu.current_softirq is None:
            return

        softirq = cpu.current_softirq
        softirq.duration.update(timestamp)

        self.notify('softirq_exit', cpu=cpu, softirq=softirq)

        cpu.current_softirq = None

