import random
import json
from mutator import Mutator

class JSONMutator(Mutator):

    def __init__(self, content):
        super().__init__(content)

    def to_str(self, content):
        return json.dumps(content)

    def from_str(self, content):
        return json.loads(content)

    def mutate(self, json_content):
        # Should consider adding and deleting nodes
        if type(json_content) == list:
            idx = random.randint(1, len(json_content)) - 1
            json_content[idx] = self.mutate(json_content[idx])
        elif type(json_content) == dict:
            key = random.choice(list(json_content.keys()))
            choice = random.randint(1, 10)
            if choice == 1:
                json_content[""] = json_content.pop(key)
            elif choice == 2:
                json_content["a" * 1000] = json_content.pop(key)
            elif choice < 5:
                num_elements = random.randrange(50, 2000, 10)
                for i in range(num_elements):
                    json_content[f"{i}"] = i
            else:
                json_content[key] = self.mutate(json_content[key])
        elif type(json_content) == str:
            if random.randint(1, 2) == 1:
                json_content = "a" * 1000
            else:
                json_content = ""
        elif type(json_content) == int:
            choice = random.randint(1, 3)
            if choice == 1:
                json_content = 0
            elif choice == 2:
                json_content = -1000000
            else:
                json_content = 1000000
        elif type(json_content) == float:
            choice = random.randint(1, 3)
            if choice == 1:
                json_content = 0.0
            elif choice == 2:
                json_content = 1000000.0
            else:
                json_content = -1000000.0
        elif type(json_content) == bool:
            if json_content:
                json_content = False
            else:
                json_content = True
        elif type(json_content) == None:
            pass
        else:
            print('Got an unknown type')
            print(type(json_content))

        return json_content
