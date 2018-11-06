class Analyser:
    def __init__(self, callbacks, notifiers, state):
        self.cbs = callbacks
        self.state = state
        self.notifiers = notifiers

    def on_begin_analyse(self, timestamp):
        pass

    def on_end_analyse(self, timestamp):
        pass

    def analyse(self, event):
        event_name = event.name

        # for 'perf' tool
        split_event_name = event.name.split(':')
        if len(split_event_name) > 1:
            event_name = split_event_name[1].strip()

        if event_name in self.cbs:
            self.cbs[event_name](event)
        elif (event_name.startswith('sys_enter') or \
              event_name.startswith('syscall_entry_')) and \
              'syscall_entry' in self.cbs:
            self.cbs['syscall_entry'](event)
        elif (event_name.startswith('sys_exit') or \
              event_name.startswith('syscall_exit_')) and \
              'syscall_exit' in self.cbs:
            self.cbs['syscall_exit'](event)

    def notify(self, notification_id, **kwargs):
        if notification_id in self.notifiers:
            self.notifiers[notification_id](**kwargs)
