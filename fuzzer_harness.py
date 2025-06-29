import os
import signal
import sys
import resource
import subprocess
from pathlib import Path

child_pid = None

# Handle timeout
def handle_timeout(signum, frame):
    print("Program timed out - Hang / Infinite loop Detected!", file=sys.stderr)
    if child_pid:
        os.kill(child_pid, signal.SIGKILL)
        print("Killed QEMU process after timeout", file=sys.stderr)
    sys.exit(124)

def run_qemu(binary_path, input_data):
    qemu_command = "qemu-x86_64"
    args = [qemu_command, binary_path, "-nographic"]

    # Create a pipe for communication between parent and child processes
    try:
        pipe_read, pipe_write = os.pipe()
    except OSError as e:
        print(f"Failed to create pipe: {e}", file=sys.stderr)
        return 1

    pid = os.fork()
    if pid == 0:
        try:
            os.close(pipe_write)  # Close the write end of the pipe in the child
            os.dup2(pipe_read, sys.stdin.fileno())  # Redirect stdin to read from the pipe
            os.close(pipe_read)  # Close the original read end of the pipe

            # Redirect stdout and stderr to /dev/null
            with open(os.devnull, 'w') as devnull:
                os.dup2(devnull.fileno(), sys.stdout.fileno())
                os.dup2(devnull.fileno(), sys.stderr.fileno())

            # Execute QEMU
            os.execvp(qemu_command, args)

        except Exception as e:
            print(f"\033[91mQemu Failed: {e}\033[0m", file=sys.stderr)
            print(f"\033[93mFalling back to Asan!\033[0m")
            return 127

    elif pid > 0:
        # Parent process
        global child_pid
        child_pid = pid

        try:
            # Close the read end of the pipe in the parent
            os.close(pipe_read)

            # Write the input data to the pipe
            os.write(pipe_write, input_data.encode())
            os.write(pipe_write, b'\n')  # Write the newline character
            os.close(pipe_write)  # Close the write end after writing

            # Wait for the child process to complete
            pid, status = os.waitpid(pid, 0)

            # Check if the program was terminated by a signal
            if os.WIFSIGNALED(status):
                signal_num = os.WTERMSIG(status)
                print(f"Terminated by signal: {signal_num}", file=sys.stderr, end='')
                if signal_num == signal.SIGSEGV:
                    print(" - Segmentation fault (SIGSEGV)", file=sys.stderr)
                    return 39
                elif signal_num == signal.SIGFPE:
                    print(" - Floating-point exception (SIGFPE)", file=sys.stderr)
                    return 136
                elif signal_num == signal.SIGILL:
                    print(" - Illegal instruction (SIGILL)", file=sys.stderr)
                    return 132
                elif signal_num == signal.SIGABRT:
                    print(" - Abort signal (SIGABRT)", file=sys.stderr)
                    return 134
                else:
                    print('')
                    return signal_num

            elif os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
                if exit_code != 0:
                    return exit_code  # Non-zero exit code from QEMU

        except:
            try:
                # Close the read end of the pipe in the parent
                os.close(pipe_read)

                # Write the input data to the pipe
                os.write(pipe_write, input_data.encode())
                os.close(pipe_write)  # Close the write end after writing

                # Wait for the child process to complete
                pid, status = os.waitpid(pid, 0)

                # Check if the program was terminated by a signal
                if os.WIFSIGNALED(status):
                    signal_num = os.WTERMSIG(status)
                    print(f"Terminated by signal: {signal_num}", file=sys.stderr, end='')
                    if signal_num == signal.SIGSEGV:
                        print(" - Segmentation fault (SIGSEGV)", file=sys.stderr)
                        return 39
                    elif signal_num == signal.SIGFPE:
                        print(" - Floating-point exception (SIGFPE)", file=sys.stderr)
                        return 136
                    elif signal_num == signal.SIGILL:
                        print(" - Illegal instruction (SIGILL)", file=sys.stderr)
                        return 132
                    elif signal_num == signal.SIGABRT:
                        print(" - Abort signal (SIGABRT)", file=sys.stderr)
                        return 134
                    else:
                        print('')
                        return signal_num

                elif os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                    if exit_code != 0:
                        return exit_code  # Non-zero exit code from QEMU

            except OSError as e:
                return 1

    else:
        print("Failed to create the QEMU process", file=sys.stderr)
        return 2

    return 0  # QEMU ran successfully


def run_with_asan(binary_path, input_file):
    # Disable core dump
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    asan_command = ["bash", "-c", f"LD_PRELOAD=/usr/lib/libasan.so {binary_path} < {input_file}"]
    output = 'fuzzer_output/' + 'bad_' + Path(binary_path).name + '.txt'

    # Open /dev/null to discard both stdout and stderr
    with open(output, 'w') as output_file:
        try:
            # Redirect both stdout and stderr to /dev/null
            result = subprocess.run(asan_command, stdout=output_file, stderr=output_file, timeout=30)

            # Check the return code (if ASan found a hidden vulnerability)
            if result.returncode != 0:
                print("Asan found a hidden vuln!")

                # Ran out of time getting code coverage working in the docker container. Works natively :()                
                # try:
                #     coverage_command = ['python3', 'code_coverage.py', binary_path, input_file]
                #     # Capture the output of the script
                #     subprocess.run(coverage_command, capture_output=False, text=False, check=False, timeout=30)
                # except subprocess.CalledProcessError as e:
                #     print(f"\033[93mError calculating code coverage!\033[0m")
                    
                return 168

        except subprocess.TimeoutExpired:
            print("AddressSanitizer run timed out", file=sys.stderr)
            return 124

    return 0

def harness(binary_path, timeout, input_file):
    # Start a timer that triggers the timeout function if execution takes too long
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(timeout)

    # Disable core dumps to save space
    core_limit = (0, 0)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, core_limit)
    except Exception as e:
        print(f"Failed to disable core dumps: {e}", file=sys.stderr)
        return 1

    try:
        with open(input_file, 'r') as f:
            input_data = f.read()
    except IOError as e:
        print(f"Error: could not open input file {input_file}: {e}", file=sys.stderr)
        return 1

    # Step 1: Run binary under QEMU
    success = run_qemu(binary_path, input_data)

    # Step 2: If QEMU found no issue, rerun the binary with AddressSanitizer
    if success != 0:
        code = run_with_asan(binary_path, input_file)
        if code == 0:
          return success
        else:
          return code
    else:
        return 0
