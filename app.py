from flask import Flask, render_template, jsonify
import threading
import scapy.all as scapy
import time

app = Flask(__name__)

capturing = False
packets = []


def packet_sniffer():
    """Captures packets and stores them in a list."""
    global capturing, packets
    while capturing:
        sniffed_packets = scapy.sniff(count=10)  # Capture 10 packets at a time
        for packet in sniffed_packets:
            if packet.haslayer(scapy.IP):
                payload = bytes(packet.payload)  # Extracting raw payload
                packets.append({
                    "source": packet[scapy.IP].src,
                    "destination": packet[scapy.IP].dst,
                    "protocol": packet[scapy.IP].proto,
                    "payload": payload.hex() if payload else "No Payload"
                })
        time.sleep(1)


@app.route('/')
def index():
    """Serves the main web page."""
    return render_template('index.html')


@app.route('/start', methods=['POST'])
def start_capture():
    """Starts packet capture in a separate thread."""
    global capturing
    if not capturing:
        capturing = True
        threading.Thread(target=packet_sniffer, daemon=True).start()
    return jsonify({"status": "Started packet capture"})


@app.route('/stop', methods=['POST'])
def stop_capture():
    """Stops packet capture."""
    global capturing
    capturing = False
    return jsonify({"status": "Stopped packet capture"})


@app.route('/packets')
def get_packets():
    """Returns captured packet data as JSON."""
    return jsonify(packets)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
