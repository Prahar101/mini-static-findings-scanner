import os
import subprocess
from flask import request, send_file

app.run(debug=True)
subprocess.run("ls", shell=True)
filename = request.args.get("file")
send_file(filename)
os.system("whoami")
