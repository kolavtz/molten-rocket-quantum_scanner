from locust import HttpUser, between, task


class QuantumShieldUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def view_dashboard_pages(self):
        self.client.get("/dashboard/assets")
        self.client.get("/asset-inventory")
        self.client.get("/asset-discovery")

    @task(4)
    def call_dashboard_apis(self):
        self.client.get("/api/assets?page=1&page_size=25")
        self.client.get("/api/discovery?page=1&page_size=25&tab=domains")
        self.client.get("/api/cbom?page=1&page_size=25")
        self.client.get("/api/pqc-posture?page=1&page_size=25")
        self.client.get("/api/cyber-rating?page=1&page_size=25")
        self.client.get("/api/reports?page=1&page_size=25")

    @task(1)
    def call_supporting_apis(self):
        self.client.get("/api/scans")
        self.client.get("/report/schedules")
