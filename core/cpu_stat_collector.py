from .stats import DurationStats
from .stats import ProcessStats
from .stats import SyscallStats
from .stats import IrqStats, SoftIrqStats
from .stat_collector import StatCollector

class CpuStatCollector(StatCollector):
    def __init__(self, path):
        notifiers = {
            'sched_out' : self.process_sched_out,
            'syscall_exit' : self.process_syscall_exit,
            'irq_exit' : self.process_irq_exit,
            'softirq_exit' : self.process_softirq_exit,
        }

        super().__init__(path, notifiers)

        self.begin_ts = None
        self.end_ts = None

        self.per_cpu_usage_stats = {}

        self.per_cpu_app_usage_stats = {}
        self.per_tid_usage_stats = {}

        self.per_cpu_irq_usage_stats = {}
        self.per_irq_usage_stats = {}
        self.per_cpu_softirq_usage_stats = {}
        self.per_softirq_usage_stats = {}

        self.per_cpu_syscall_usage_stats = {}
        self.per_tid_syscall_usage_stats = {}

    def on_begin_analyse(self, timestamp):
        self.begin_ts = timestamp

    def on_end_analyse(self, timestamp):
        self.end_ts = timestamp

        for tid in self.per_tid_usage_stats:
            if tid not in self.per_tid_syscall_usage_stats:
                self.per_tid_syscall_usage_stats[tid] = {}
            self.per_tid_syscall_usage_stats[tid]['__total_sum__'] = 0
            self.per_tid_syscall_usage_stats[tid]['__total_count__'] = 0

        for tid in self.per_tid_syscall_usage_stats:
            self.per_tid_syscall_usage_stats[tid]['__total_sum__'] = 0
            self.per_tid_syscall_usage_stats[tid]['__total_count__'] = 0

            for syscall_name in self.per_tid_syscall_usage_stats[tid]:
                if syscall_name == '__total_sum__' or \
                   syscall_name == '__total_count__':
                    continue

                syscall_stats = \
                            self.per_tid_syscall_usage_stats[tid][syscall_name]

                self.per_tid_syscall_usage_stats[tid]['__total_sum__'] += \
                                                            syscall_stats.sum
                self.per_tid_syscall_usage_stats[tid]['__total_count__'] += \
                                                            syscall_stats.count

    def process_sched_out(self, **kwargs):
        cpu = kwargs['cpu']
        proc = kwargs['proc']

        if cpu.cpu_id not in self.per_cpu_usage_stats:
            self.per_cpu_usage_stats[cpu.cpu_id] = DurationStats()
            self.per_cpu_app_usage_stats[cpu.cpu_id] = DurationStats()

        self.per_cpu_usage_stats[cpu.cpu_id].update(proc.duration.begin_ts,
                                                    proc.duration.duration)

        self.per_cpu_app_usage_stats[cpu.cpu_id].update(proc.duration.begin_ts,
                                        proc.duration.duration -
                                        proc.irq_stolen_duration.duration -
                                        proc.softirq_stolen_duration.duration)

        if proc.tid not in self.per_tid_usage_stats:
            self.per_tid_usage_stats[proc.tid] = ProcessStats(proc.name)

        self.per_tid_usage_stats[proc.tid].update(proc.duration.begin_ts,
                                        proc.duration.duration -
                                        proc.irq_stolen_duration.duration -
                                        proc.softirq_stolen_duration.duration)

    def process_syscall_exit(self, **kwargs):
        cpu = kwargs['cpu']
        syscall = kwargs['syscall']

        proc = cpu.current_proc

        if cpu.cpu_id not in self.per_cpu_syscall_usage_stats:
            self.per_cpu_syscall_usage_stats[cpu.cpu_id] = DurationStats()

        stats = self.per_cpu_syscall_usage_stats[cpu.cpu_id]
        stats.update(syscall.duration.begin_ts,
                     syscall.duration.duration -
                     syscall.waiting_duration.duration -
                     syscall.irq_stolen_duration.duration -
                     syscall.softirq_stolen_duration.duration)

        if proc.tid not in self.per_tid_syscall_usage_stats:
            self.per_tid_syscall_usage_stats[proc.tid] = {}

        if syscall.name not in self.per_tid_syscall_usage_stats[proc.tid]:
            self.per_tid_syscall_usage_stats[proc.tid][syscall.name] = \
                        SyscallStats(syscall.name)

        stats = self.per_tid_syscall_usage_stats[proc.tid][syscall.name]
        stats.update(syscall.duration.begin_ts,
                     syscall.duration.duration -
                     syscall.waiting_duration.duration -
                     syscall.irq_stolen_duration.duration -
                     syscall.softirq_stolen_duration.duration)

    def process_irq_exit(self, **kwargs):
        cpu = kwargs['cpu']
        irq = kwargs['irq']

        if cpu.cpu_id not in self.per_cpu_irq_usage_stats:
            self.per_cpu_irq_usage_stats[cpu.cpu_id] = DurationStats()

        if irq.irq not in self.per_irq_usage_stats:
            self.per_irq_usage_stats[irq.irq] = IrqStats(irq.name)

        stats = self.per_cpu_irq_usage_stats[cpu.cpu_id]
        stats.update(irq.duration.begin_ts, irq.duration.duration)

        stats = self.per_irq_usage_stats[irq.irq]
        stats.update(irq.duration.begin_ts, irq.duration.duration)

    def process_softirq_exit(self, **kwargs):
        cpu = kwargs['cpu']
        softirq = kwargs['softirq']

        if cpu.cpu_id not in self.per_cpu_softirq_usage_stats:
            self.per_cpu_softirq_usage_stats[cpu.cpu_id] = \
                                                    SoftIrqStats(softirq.name)

        if softirq.vec not in self.per_softirq_usage_stats:
            self.per_softirq_usage_stats[softirq.vec] = \
                                                    SoftIrqStats(softirq.name)

        stats = self.per_cpu_softirq_usage_stats[cpu.cpu_id]
        stats.update(softirq.duration.begin_ts,
                     softirq.duration.duration -
                     softirq.irq_stolen_duration.duration)

        stats = self.per_softirq_usage_stats[softirq.vec]
        stats.update(softirq.duration.begin_ts,
                     softirq.duration.duration -
                     softirq.irq_stolen_duration.duration)

    def print_per_cpu_stats(self):
        table_title = '''=== Per-CPU CPU Usage ==='''

        table_row_format = '{:>5} {:>10} {:>10} {:>10} {:>10} {:>10}'
        table_label = table_row_format.format('cpu', 'usage', 'app',
                                              'syscall', 'irq', 'softirq')

        print(table_title)
        print(table_label)

        sorted_stats = sorted(self.per_cpu_usage_stats.items(),
                              key=lambda key_value: key_value[1], reverse=True)

        for cpu, stats in sorted_stats:
            app_stats = self.per_cpu_app_usage_stats[cpu]
            syscall_stats = self.per_cpu_syscall_usage_stats[cpu]
            irq_stats = self.per_cpu_irq_usage_stats[cpu]
            softirq_stats = self.per_cpu_softirq_usage_stats[cpu]

            table_content = table_row_format.format(
                '%2d' % cpu,
                '%.2f %%' % (stats.sum * 100 / (self.end_ts - self.begin_ts)),
                '%.2f %%' % (app_stats.sum * 100 / (self.end_ts - self.begin_ts)),
                '%.2f %%' % (syscall_stats.sum * 100 / \
                             (self.end_ts - self.begin_ts)),
                '%.2f %%' % (irq_stats.sum * 100 / \
                             (self.end_ts - self.begin_ts)),
                '%.2f %%' % (softirq_stats.sum * 100 / \
                             (self.end_ts - self.begin_ts)))

            print(table_content)
        print('')

    def print_per_irq_stats(self):
        table_title = '''=== Per-Irq CPU Usage ==='''

        table_row_format = '{:>25} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}'
        table_label = table_row_format.format('name (irq)', 'cpu%', 'count%',
                                              'min', 'avg', 'max', 'total',
                                              'count')
        print(table_title)
        print(table_label)

        total_sum = 0
        total_count = 0

        for irq in self.per_irq_usage_stats:
            stats = self.per_irq_usage_stats[irq]
            total_sum += stats.sum
            total_count += stats.count

        sorted_stats = sorted(self.per_irq_usage_stats.items(),
                              key=lambda key_value: key_value[1], reverse=True)

        for irq, stats in sorted_stats:
            table_content = table_row_format.format(
                '%s (%d)' % (stats.name, irq),
                '%.2f %%' % (stats.sum * 100 / total_sum),
                '%.2f %%' % (stats.count * 100 / total_count),
                stats.min_duration,
                '%.1f' % stats.average,
                stats.max_duration,
                stats.sum,
                stats.count)

            print(table_content)
        print('')

    def print_per_softirq_stats(self):
        table_title = '''=== Per-Softirq CPU Usage ==='''

        table_row_format = '{:>25} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}'
        table_label = table_row_format.format('name (softirq)', 'cpu%', 'count%',
                                              'min', 'avg', 'max', 'total',
                                              'count')
        print(table_title)
        print(table_label)

        total_sum = 0
        total_count = 0

        for irq in self.per_softirq_usage_stats:
            stats = self.per_softirq_usage_stats[irq]
            total_sum += stats.sum
            total_count += stats.count

        sorted_stats = sorted(self.per_softirq_usage_stats.items(),
                              key=lambda key_value: key_value[1], reverse=True)

        for vec, stats in sorted_stats:
            table_content = table_row_format.format(
                '%s (%d)' % (stats.name, vec),
                '%.2f %%' % (stats.sum * 100 / total_sum),
                '%.2f %%' % (stats.count * 100 / total_count),
                stats.min_duration,
                '%.1f' % stats.average,
                stats.max_duration,
                stats.sum,
                stats.count)

            print(table_content)
        print('')

    def print_per_tid_stats(self):
        table_title = '''=== Per-Tid CPU Usage ==='''

        table_row_format = '{:>25} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}'
        table_label = table_row_format.format('name (tid)', 'usage', 'syscall %',
                                              'min', 'avg', 'max', 'total',
                                              'count')
        print(table_title)
        print(table_label)

        sorted_stats = sorted(self.per_tid_usage_stats.items(),
                              key=lambda key_value: key_value[1], reverse=True)

        for tid, stats in sorted_stats:
            syscall_stats = self.per_tid_syscall_usage_stats[tid]
            total_syscall_sum = syscall_stats['__total_sum__']

            table_content = table_row_format.format(
                '%s (%d)' % (stats.name, tid),
                '%.2f %%' % (stats.sum * 100 / (self.end_ts - self.begin_ts)),
                '%.2f %%' % (total_syscall_sum * 100 / stats.sum),
                stats.min_duration,
                '%.1f' % stats.average,
                stats.max_duration,
                stats.sum,
                stats.count)

            print(table_content)
        print('')

    def print_per_tid_per_syscall_stats(self):
        table_title = '''=== Per-Tid Per-Syscall CPU Usage ==='''

        table_row_format = '{:>20} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}'
        table_label = table_row_format.format('name', 'cpu %', 'count %',
                                              'min', 'avg', 'max', 'total',
                                              'count')
        print(table_title)

        for tid in self.per_tid_usage_stats:
            tid_stats = self.per_tid_usage_stats[tid]
            tid_syscall_stats = self.per_tid_syscall_usage_stats[tid]

            total_count = tid_syscall_stats['__total_count__']
            total_sum = tid_syscall_stats['__total_sum__']

            if total_sum == 0:
                continue

            print('')
            print(tid_stats.name + ' (' + str(tid) + '):')
            print(table_label)

            sorted_stats = sorted(tid_syscall_stats.items(),
                                  key=lambda key_value: key_value[1], reverse=True)

            for syscall_name, stats in sorted_stats:
                if syscall_name == '__total_sum__' or \
                   syscall_name == '__total_count__':
                    continue

                table_content = table_row_format.format(
                    '%s' % syscall_name,
                    '%.2f %%' % (stats.sum * 100 / total_sum),
                    '%.2f %%' % (stats.count * 100 / total_count),
                    stats.min_duration,
                    '%.1f' % stats.average,
                    stats.max_duration,
                    stats.sum,
                    stats.count)

                print(table_content)
        print('')

    def print_result(self):
        self.print_per_cpu_stats()
        self.print_per_irq_stats()
        self.print_per_softirq_stats()
        self.print_per_tid_stats()
        self.print_per_tid_per_syscall_stats()
