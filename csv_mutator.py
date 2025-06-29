import random
import csv
import io
from mutator import Mutator

class CSVMutator(Mutator):

    def __init__(self, content):
        super().__init__(content)

    def to_str(self, content):
        return content

    def from_str(self, content):
        return content

    def mutate(self, content):
        
        # parse the csv string into a list of lists
        reader = csv.reader(io.StringIO(content))
        csv_input = list(reader)

        # Make a copy of the CSV data
        csv_output = [row[:] for row in csv_input]
        
        # randomly double number of rows 50% of the time
        if random.choice([True,False]):
            csv_output *= 2

        # get random index into the file
        rand_row_idx = random.randrange(len(csv_output))
        rand_tok_idx = random.randrange(len(csv_output[rand_row_idx]))

        token = csv_output[rand_row_idx][rand_tok_idx]



        # check if the token is a number
        if token.isdigit():
            # randomly choose a number mutation
            if random.choice([True, False]):
                token = '0'
            else:
                token = '2000'
        else:
            # token is assumed to be string otherwise
            # randomly choose str mutation
            if random.choice([True, False]):
                token = ''
            else:
                token += 'A' * 1000

        # put mutated token back into csv_output
        csv_output[rand_row_idx][rand_tok_idx] = token

        # convert mutated csv back into a string
        output_f = io.StringIO()
        writer = csv.writer(output_f)
        writer.writerows(csv_output)
        mutated_content = output_f.getvalue()

        return mutated_content


