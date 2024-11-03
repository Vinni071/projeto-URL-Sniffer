from flask import Flask, render_template, Response
from subprocess import Popen, PIPE
import threading
import queue

app = Flask(__name__)
output_queue = queue.Queue()

def run_sniffer():
    process = Popen(['python', 'url_sniffer.py'], stdout=PIPE, stderr=PIPE, text=True)
    while True:
        line = process.stdout.readline()
        if not line:
            break
        output_queue.put(line.strip())
    
threading.Thread(target=run_sniffer, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    def generate():
        while True:
            line = output_queue.get()
            yield f"data:{line}\n\n"
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)
