class State:
    def __init__(self):
        self.cpus = {}
        self.tids = {}

class Cpu():
    def __init__(self, cpu_id):
        self.cpu_id = cpu_id

        self.current_proc = None
        self.current_irq = None
        self.current_softirq = None

class Process():
    def __init__(self, tid, name):
        self.tid = tid
        self.name = name

        self.current_syscall = None

        self.duration = None
        self.irq_stolen_duration = None
        self.softirq_stolen_duration = None

class Syscall():
    def __init__(self, name):
        self.name = name
        self.duration = None

        self.waiting_duration = Duration(None)
        self.irq_stolen_duration = Duration(None)
        self.softirq_stolen_duration = Duration(None)

class Irq():
    def __init__(self, name, irq):
        self.name = name
        self.irq = irq

        self.duration = None

softirq_to_name = {
    0 : 'HI_TASKLET',
    1 : 'Timer',
    2 : 'NET_TX',
    3 : 'NET_RX',
    4 : 'BLOCK',
    5 : 'IRQ_POLL',
    6 : 'TASKLET',
    7 : 'SCHED',
    8 : 'HRTIMER_SOFTIRQ',
    9 : 'RCU_SOFTIRQ',
}

class SoftIrq():
    def __init__(self, vec):
        self.name = softirq_to_name[vec]
        self.vec = vec

        self.duration = None
        self.irq_stolen_duration = Duration(None)

class Duration:
    def __init__(self, timestamp):
        self.begin_ts = timestamp
        self.duration = 0

    def begin(self, timestamp):
        self.begin_ts = timestamp

    def update(self, timestamp):
        if self.begin_ts is None:
            self.begin_ts = timestamp

        self.duration = timestamp - self.begin_ts
        self.begin_ts = None

    def accumulate(self, timestamp):

        try:
            self.duration += timestamp - self.begin_ts
        except TypeError: # when self.begin_ts is None
            pass

        self.begin_ts = None
