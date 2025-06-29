from mutator import Mutator
import random
import string

class PlaintextMutator(Mutator):

    def __init__(self, content):
        super().__init__(content)

    def to_str(self, content):
        return content

    def from_str(self, content):
        return content

    def mutate(self, content):
        # split up by newlines as most plaintext binaries will accept text one line at a time
        lines = content.splitlines()
        
        # random idx into lines
        rand_idx = random.randrange(len(lines))


        # apply random mutation strategy, depending on if str or int
        if (lines[rand_idx].isdigit()):
            match random.choice([1,2,3,4]):
                case 1:
                    lines[rand_idx] = '0'
                case 2:
                    lines[rand_idx] = '9999'
                case 3:
                    lines[rand_idx] = '-9999'
                case 4:
                    doubled = int(lines[rand_idx]) * 2
                    lines[rand_idx] = str(doubled)
        # when data is not int
        else:

            match random.choice([1,2,3]):
                case 1:
                    # add long str
                    lines[rand_idx] += 'A' * 1000

                case 2:
                    # add format string that can cause crash
                    lines[rand_idx] += '%10x%n'

                case 3:
                    # append random ascii char
                    lines[rand_idx] += random.choice(string.printable)


        # join mutated list back into a string
        mutated_content = '\n'.join(lines)

        return mutated_content
