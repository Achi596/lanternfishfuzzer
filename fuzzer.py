import sys
import os
import fuzzer_harness
import mutator_factory
from pathlib import Path

def main():
    # Check that the fuzzer is being used correctly
    if len(sys.argv) != 3:
        print('Usage: python3 fuzzer.py <binary> <sample_input>')
        sys.exit(-1)

    # Passing the command line args into variables
    binary_name = sys.argv[1]
    input_file_name = sys.argv[2]

    # Check that the binary file exists
    if not os.path.isfile(binary_name):
        print(f'The binary file {binary_name} does not exist')
        sys.exit(-1)

    # Check the input file exists
    if not os.path.isfile(input_file_name):
        print(f'The input file {input_file_name} does not exist')
        sys.exit(-1)

    # Check if an appropriate mutator exists
    try:
      m = mutator_factory.get_mutator(input_file_name)
    except:
      print(f"\033[91mMutator not implemented for file type provided!\033[0m")
      sys.exit(-1)

    counter = 0

    while True:
        for ele in m.mutations_to_run:
            # Write the input file contents to a mutation file
            with open('input.txt', 'w') as input_file:
                input_file.write(ele)

            retcode = fuzzer_harness.harness(binary_name, 100, 'input.txt')
            counter += 1

            if retcode != 0:
                print(f"Found vuln in {counter} iterations")

                try:
                    output = 'fuzzer_output/' + 'bad_' + Path(binary_name).name + '.txt'
              
                    with open(output, 'a') as file:
                        file.write("\n\nBad input that caused crash:\n")
                        file.write(ele + "\n")
                        print(f"Successfully wrote diagnostic data to: {output}")
                except:
                    print(f"\033[93mFailed to write diagnostic data to: {output}\033[0m")

                sys.exit(0)

        m.update_mutations()

    # How did we get here?
    sys.exit(-1)

if __name__ == '__main__':
    main()
