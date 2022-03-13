from flask import Flask
from .api.arp import arp_operations


app = Flask(__name__)
app.register_blueprint(arp_operations, url_prefix="/operations/arp")


@app.route("/")
def index():
    return ""

