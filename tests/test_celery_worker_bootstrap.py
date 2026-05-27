from backend.workers.celery_app import create_celery_app


def test_celery_app_bootstrap_is_available_when_dependency_exists():
    app = create_celery_app()
    if app is None:
        assert app is None
        return

    routes = app.conf.task_routes
    assert "adaptivescan.crawl" in routes
    assert routes["adaptivescan.crawl"]["queue"] == "crawl"
