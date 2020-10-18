import subprocess
#test = subprocess.Popen(["ssh -p 2249 pi@familleprost.synology.me ; python3 /home/pi/Desktop/TemperatureConnected/test.py"], stdout=subprocess.PIPE, shell=False)
test = subprocess.Popen(["ssh", "-p 2249", "pi@familleprost.synology.me", "python /home/pi/Desktop/TemperatureConnected/test.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = test.communicate()[0]
print(output)
