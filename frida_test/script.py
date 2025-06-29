import frida
import sys
import os
import time
import subprocess

def load_frida_script(js_file_path):
    with open(js_file_path, 'r') as file:
        return file.read()



def on_message(message, data):
    print(message)


def launch_process_and_inject(target_process, js_file_path):

    frida_script = load_frida_script(js_file_path)

    process = subprocess.Popen(target_process, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    device = frida.get_device_manager().get_device('local')

    session = device.attach(process.pid)

    script = session.create_script(frida_script)

    script.on('message', on_message)

    script.load()

    time.sleep(0.5)

    process.stdin.write('Hello, world!\n')
    process.stdin.flush()

    time.sleep(1)

    process.stdin.close()
    process.wait()

    print(f"Process {process} has finished execution")
    session.detach()

if __name__ == '__main__':

    target_binary = './prog'

    js_file_path = 'hook.js'


    launch_process_and_inject(target_binary, js_file_path)




