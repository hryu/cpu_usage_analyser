from .analyser_runner import AnalyserRunner

class StatCollector:
    def __init__(self, path, notifiers):
        self.analyser_runner = AnalyserRunner(path, notifiers, self)

    def run(self):
        self.analyser_runner.run()

    def on_begin_analyse(self, timestamp):
        pass

    def on_end_analyse(self, timestamp):
        pass

    def print_result(self):
        pass
