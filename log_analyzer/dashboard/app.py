from flask import Flask, render_template, jsonify, request
from log_analyzer.storage.database import EventStore
from log_analyzer.alerting.alerts import AlertManager

app = Flask(__name__)
store = EventStore()
alert_mgr = AlertManager()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    events = store.query(
        action=request.args.get("action"),
        source_ip=request.args.get("source_ip"),
        since=request.args.get("since"),
        severity=request.args.get("severity"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    return jsonify(store.get_stats())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(alert_mgr.get_recent())
