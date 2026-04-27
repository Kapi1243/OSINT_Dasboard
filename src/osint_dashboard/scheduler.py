import time

from apscheduler.schedulers.background import BackgroundScheduler

from .pipeline import run_full_pipeline


class PipelineScheduler:
    def __init__(self, interval_minutes: int = 30):
        self.scheduler = BackgroundScheduler()
        self.interval_minutes = interval_minutes

    def start(self):
        self.scheduler.add_job(run_full_pipeline, "interval", minutes=self.interval_minutes)
        self.scheduler.start()
        print(f"Pipeline scheduler started. Interval: {self.interval_minutes} minutes")
        try:
            while True:
                time.sleep(5)
        except (KeyboardInterrupt, SystemExit):
            self.scheduler.shutdown()
            print("Pipeline scheduler stopped.")
