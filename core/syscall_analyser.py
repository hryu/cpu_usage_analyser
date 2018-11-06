from .analyser import Analyser
from . import state

class SyscallAnalyser(Analyser):
    def __init__(self, notifiers, state):
        callbacks = {
            'syscall_entry' : self.process_syscall_entry,
            'syscall_exit' : self.process_syscall_exit,
        }

        super().__init__(callbacks, notifiers, state)

    def process_syscall_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']

        # ignore syscall until sched_analyse allocates the Cpu
        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]
        current_proc = cpu.current_proc

        if current_proc is None:
            return

        # for 'perf' tool
        event_name = event.name
        split_event_name = event.name.split(':')
        if len(split_event_name) > 1:
            event_name = split_event_name[1].strip()

        syscall_name = event_name
        if event_name.startswith('sys_enter_'):
            syscall_name = syscall_name[len('sys_enter_'):]
        elif event_name.startswith('syscall_entry_'):
            syscall_name = syscall_name[len('syscall_entry_'):]

        current_proc.current_syscall = state.Syscall(syscall_name)
        current_syscall = current_proc.current_syscall
        current_syscall.duration = state.Duration(timestamp)

    def process_syscall_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event['cpu_id']

        # ignore syscall until sched_analyse allocates the Cpu
        if cpu_id not in self.state.cpus:
            return

        cpu = self.state.cpus[cpu_id]
        current_proc = cpu.current_proc

        # ignore syscall_exit without syscall_entry
        if current_proc is None or current_proc.current_syscall is None:
            return

        current_syscall = current_proc.current_syscall
        current_syscall.duration.update(timestamp)

        self.notify('syscall_exit', cpu=cpu, syscall=current_syscall)

        current_proc.current_syscall = None
