from flask import Blueprint, Response, request
from agave.modules.info import iface
import json


info_operations = Blueprint('info', __name__)


def map_iface(x):
	return {
		"name": x.get("name"),
		"ip": x.get("formatted_ip"),
		"mac": x.get("formatted_eth"),
		"broadcast": x.get("broadcast"),
		"network": x.get("network")
	}

@info_operations.route("/interface")
def _iface():
	return Response(
		json.dumps(list(map(map_iface, iface.interfaces()))),
		mimetype="application/json",
		headers={
			"access-control-allow-origin": "*"
		}
	)
