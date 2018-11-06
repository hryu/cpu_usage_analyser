import sys

class Stats:
    def __init__(self):
        pass

class DurationStats:
    def __init__(self):
        self.min_duration = sys.maxsize
        self.max_duration = 0
        self.sum = 0

        self.duration_list = []

    @property
    def count(self):
        return len(self.duration_list)

    @property
    def average(self):
        if self.count == 0:
            return 0

        return self.sum / len(self.duration_list)

    def update(self, begin_ts, duration):
        self.duration_list.append((begin_ts, duration))

        self.sum += duration

        if self.min_duration > duration:
            self.min_duration = duration
        if self.max_duration < duration:
            self.max_duration = duration

    def __lt__(self, other):
        try:
            lt = self.sum < other.sum
            return lt
        except:
            pass

class ProcessStats(DurationStats):
    def __init__(self, name):
        super().__init__()

        self.name = name

class SyscallStats(DurationStats):
    def __init__(self, name):
        super().__init__()

        self.name = name

class IrqStats(DurationStats):
    def __init__(self, name):
        super().__init__()

        self.name = name

class SoftIrqStats(DurationStats):
    def __init__(self, name):
        super().__init__()

        self.name = name

