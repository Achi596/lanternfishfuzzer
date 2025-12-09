# Lanternfishfuzzer

![image](https://cdn.openspaces.penguinserver.net/i/19e9cf78-f6c5-4f86-9497-96663706ff6a.jpg)

Lanternfishfuzzer is a blackbox fuzzing tool that given a sample input, is capable of testing and identifying vulnerabilities in binaries that accept plaintext, CSV, JSON, and XML inputs.

## Authors

- Achi
- Max
- Charlie
- Suki


## Findable Bug Classes and Mutation strategies
Lanternfishfuzzer is capable of discovering the following classes of bugs:
- Buffer overflows
- Integer over/underflows
- Format String vulnerabilities

The fuzzer uses a number of mostly random generation based methods to discover these vulnerabilities. The various filetype-dependent mutators which do this generation are outlined below.

## Choosing a Mutator with `mutator_factory`
Given a filepath to a sample input, `mutator_factory` will attempt to open the file at that location and read its contents.
`mutator_factory` will then attempt to parse the contents with JSON, XML and CSV parsers. If the contents are successfully parsed by one of these parsers, a `Mutator` object for the successful filetype is created and returned. If none of these are successful, a `PlaintextMutator` object will be created and returned.

## Mutators
All mutators implement the abstract class `Mutator`. We do this to allow easy extensibility if more mutators were to be added in the future.

All mutators store a list of `mutations_to_run` and `mutations_already_run`. If the mutator is not successful after the first few inputs, it will begin using previously mutated outputs as input, meaning there will be little repeated input - potentially allowing for greater coverage.


### `PlaintextMutator`
`PlaintextMutator` applies mutations per-line of example input. The mutator selects a random line, and determines if it is a number or text.

If it is a number, randomly choose one of the following mutations:
- Change the number to 0
- Change the number to 9999
- Change the number to -9999
- multiply the number by 2

If it is not a number:
- Append a very long string
- Append a format string that will cause a crash if interpreted
- Append a random ascii character

Once the mutation has been applied, the newly mutated content is returned.



### `CSVMutator`
`CSVMutator` mutates a random entry in the csv table. The mutator selects a random entry, and determines if it is a number or text.

If it is a number, randomly choose one of the following mutations:
- Replace with 0
- Replace with 2000

If it is not a number:
- Replace it with an empty string
- Replace it with a very long string


### `XMLMutator`
`XMLMutator` randomly mutates the text in an element, the text in an attribute, or creates a new nested element containing the selected mutation. Once a location for the mutation is selected, one of the following mutations is applied:

- Selected text is replaced with a very long string
- Selected text is replaced with a format string that will cause a crash if interpreted

### `JSONMutator`
`JSONMutator` recursively selects an element to mutate within the provided json input.

If the element found is a JSON object it randomly does one of the following actions:
- Selects a random key value pair and changes the key to either an empty string or a really large string
- Selects a random key value pair and performs a mutation on the value
- Inserts a number of key value pairs into the json object

If the element found is a list it:
- Recursively mutates an element in the list

If the element found is a string it:
- Randomly sets the string to either the empty string or a large string

If the element found is a number it:
- Randomly sets it to a large positive/negative value or 0

## Harness

Our fuzzing harness does two things:
- Runs the binary with the desired input in qemu. This part extracts the return value from running the binary to indicate if the program crashed and for what reason. 
- Runs the binary with the desired input with asan. asan is used to detect hidden vulnerabilities in the binary relating to memory.
- Runs the binary with a code coverage script using frida. The code coverage script relies on Stalker, which is frida's code tracing engine. The code coverage script logs each memory address accessed on a particular running of the binary.

Some things that we would like to improve with our harness would be:
- Implementing a more optimised strategy for passing input to the binary. This may have looked like:
    - Using qemu to memory map the input file to the running process.
    - Using frida to create hooks to functions that accept input, and rerunning these hooks with different inputs. This prevents having to restart the binary
- Implementing a more targeted approach to using code coverage. Ideally our code coverage output would have informed how mutations are performed to the input to crash the program faster. A simple implementation would have involved a priority queue that orders mutations based on the level of code coverage achieved.





