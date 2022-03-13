from flask import Blueprint, Response, request
from agave.modules.arp import listen, discover, solicit


arp_operations = Blueprint('arp', __name__)


def event_stream(op, *args, **argv):
	for op, ip, mac in op(*args, **argv):
		yield "event: {}\n".format(listen.Network.OP[op])
		yield "data: " + str({"ip": ip, "mac": mac}) + "\n\n"
	yield "event: CLOSE\n"
	yield "data: operation completed, close stream.\n\n"
	return


def event_stream2(op, *args, **argv):
	op(*args, **argv)
	yield "event: CLOSE\n"
	yield "data: operation completed, close stream.\n\n"
	return


@arp_operations.route("/listen")
def _listen():
	return Response(
		event_stream(listen.listen),
		mimetype="text/event-stream",
		headers={
			"access-control-allow-origin": "*"
		}
	)


@arp_operations.route("/discover")
def _discover():
	return Response(
		event_stream(
			discover.discover,
			request.args.get("iface"),
			request.args.get("subnet"),
			request.args.get("sender_ip"),
			request.args.get("sender_mac"),
			send_interval = float(request.args.get("send_interval", 0.005)),
			final_wait = float(request.args.get("final_wait", 1)),
			repeat_solicit = int(request.args.get("repeat_solicit", 3))
		),
		mimetype="text/event-stream",
		headers={
			"access-control-allow-origin": "*"
		}
	)


@arp_operations.route("/solicit")
def _solicit():
	return Response(
		event_stream2(
			solicit.solicit,
			request.args.get("iface"),
			request.args.get("subnet"),
			request.args.get("sender_ip"),
			request.args.get("sender_mac"),
			send_interval = float(request.args.get("send_interval", 0.005)),
			repeat_solicit = int(request.args.get("repeat_solicit", 3))
		),
		mimetype="text/event-stream",
		headers={
			"access-control-allow-origin": "*"
		}
	)
