from osint_dashboard.scheduler import PipelineScheduler


if __name__ == "__main__":
    scheduler = PipelineScheduler(interval_minutes=30)
    scheduler.start()
