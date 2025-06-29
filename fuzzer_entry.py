import os
import subprocess
import shutil

def print_welcome():
    welcome_text = r"""
__        __   _                              _          
\ \      / /__| | ___ ___  _ __ ___   ___    | |_ ___    
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \   | __/ _ \   
  \ V  V /  __/ | (_| (_) | | | | | |  __/   | || (_) |  
 _ \_/\_/ \___|_|\___\___/|_| |_| |_|\___| _  \__\___/   
| |    __ _ _ __ | |_ ___ _ __ _ __ |  ___(_)___| |__  
| |   / _` | '_ \| __/ _ \ '__| '_ \| |_  | / __| '_ \ 
| |__| (_| | | | | ||  __/ |  | | | |  _| | \__ \ | | |
|_____\__,_|_| |_|\__\___|_|  |_| |_|_|   |_|___/_| |_|
              |  ___|   _ ___________ _ __             
              | |_ | | | |_  /_  / _ \ '__|            
              |  _|| |_| |/ / / /  __/ |               
              |_|   \__,_/___/___\___|_|                   
              
        Made by Achi, Max, Charlie & Suki"""
    print(welcome_text)
    
def print_exit():
    exit_text = r"""

                  _________-----_____
       _____------           __      ----_
___----             ___------              \
   ----________        ----                 \
               -----__    |             _____)
                    __-                /     \
        _______-----    ___--          \    /)\
  ------_______      ---____            \__/  /
               -----__    \ --    _          /\
                      --__--__     \_____/   \_/\
                              ----|   /          |
                                  |  |___________|
                                  |  | ((_(_)| )_)
                                  |  \_((_(_)|/(_)
                                  \             (
                                   \_____________)"""
    print(exit_text)
    
def print_setup():
    setup_text = r"""
############################################################
# Executing Setup: Verifying directories
############################################################
"""
    print(setup_text)
    
def print_stage1():
    setup_text =r"""
############################################################
# Stage 1: Blitz - Try solve each binary within 1 minute
############################################################"""
    print(setup_text)
    
def print_stage2():
    setup_text =r"""
############################################################
# Stage 2: Pwn or bust - Retrying failed binaries
############################################################"""
    print(setup_text)
    
def print_finalizing():
    setup_text =r"""
############################################################
# Finalizing Results: Compiling results
############################################################"""
    print(setup_text)


def main():
    print_welcome()

    binaries_directory = "binaries"
    output_directory = "fuzzer_output"
    example_inputs_directory = "example_inputs/"

    print_setup()

    # Make sure the directory exists
    print("Verifying directory '/binaries' exist.")
    if not os.path.isdir(binaries_directory):
        print("The directory '/binaries' does not exist.")
        return

    print("Verifying directory '/example_inputs' exist.")
    if not os.path.isdir(example_inputs_directory):
        print("The directory '/example_inputs/' does not exist.")
        return

    # if os.path.isdir(output_directory):
    #     # Remove the folder and all its contents
    #     shutil.rmtree(output_directory)
    #     print(f"\033[93mDeleted existing folder: {output_directory}\033[0m")
    # # Create the folder
    # os.makedirs(output_directory)
    # print(f"Created new folder: {output_directory}")

    # List all files in the directory
    files = [f for f in os.listdir(binaries_directory) if os.path.isfile(os.path.join(binaries_directory, f))]
    print("\nScanning'/binaries' directories for targets.")

    completed = []
    retry = []

    # If no files found, print a message
    if not files:
        print(f"No files found in the directory {binaries_directory}.")
        return
    else:
          print("Targets Found:")
          print(f"\033[94m{files}\033[0m")

    print_stage1()

    # Loop through each file and call fuzzer.py
    for binary_file in files:

        input_file = os.path.join(example_inputs_directory, binary_file) + ".txt"

        # Construct the command to run fuzzer.py
        command = ['python3', 'fuzzer.py', os.path.join(binaries_directory, binary_file), input_file]

        # Call fuzzer.py for the current binary file
        print(f"\033[94m\nRunning fuzzer for {binary_file}...\033[0m")

        try:
            result = subprocess.run(command, check=True, timeout=60) #5 SECONDS ONLY FOR TESTING, CHANGE THIS TO 60 (1 MINUTE)
            print(f"\033[93mCode Coverage: NaN%\033[0m")
            print(f"\033[92mFuzzing complete for {binary_file}\033[0m")
            completed.append(binary_file)
        except subprocess.TimeoutExpired:
            retry.append(binary_file)
            print(f"\033[93mTimed Out! - Will retry in stage 2\033[0m")
        except subprocess.CalledProcessError as e:
            retry.append(binary_file)
            print(f"\033[93mError while fuzzing {binary_file} with input {input_file}: {e}\033[0m")
        except Exception as e:
            retry.append(binary_file)
            print(f"\033[93mUnexpected error: {e}\033[0m")

    print_stage2()

    for binary_file in retry:

        input_file = os.path.join(example_inputs_directory, binary_file) + ".txt"

        # Construct the command to run fuzzer.py
        command = ['python3', 'fuzzer.py', os.path.join(binaries_directory, binary_file), input_file]

        # Call fuzzer.py for the current binary file
        print(f"\033[94m\nRetrying fuzzer for {binary_file}...\033[0m")

        try:
            result = subprocess.run(command, check=True, timeout=30) #5 SECONDS ONLY FOR TESTING, CHANGE THIS TO 60 (1 MINUTE)
            print(f"\033[93mCode Coverage: NaN%\033[0m")
            print(f"\033[92mFuzzing complete for {binary_file}\033[0m")
            completed.append(binary_file)
        except subprocess.TimeoutExpired as e:
            print(f"\033[93mTimed Out! - binary is cooked :(\033[0m")
        except subprocess.CalledProcessError as e:
            print(f"\033[93mError while fuzzing {binary_file} with input {input_file}: {e}\033[0m")
        except Exception as e:
            print(f"\033[93mUnexpected error: {e}\033[0m")

    print_finalizing()

    file_path = 'input.txt'
    # Cleanup env
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"\033[94m\nCleanup complete '{file_path}' has been deleted.\033[0m")

    print(f"\033[92m\nSuccessfully Pwned: {completed}\033[0m")
    print(f"\033[91mfailed to pwn: {retry}\033[0m")

    print_exit()

if __name__ == '__main__':
    main()
