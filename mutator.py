from abc import ABC, abstractmethod
import random

class Mutator(ABC):
    
    def __init__(self, content):
        self.mutations_to_run = []

        # Stores a list of tuples, second part of the tuple contains the coverage report
        self.mutations_already_run = []
        for _ in range(10):
            self.mutations_to_run.append(self.to_str(self.mutate(self.from_str(content))))

    def update_mutations(self):
    
        self.mutations_already_run += self.mutations_to_run

        new_mutations = []
        for _ in range(10):
            mutation = self.from_str(random.choice(self.mutations_already_run))
            new_mutations.append(self.to_str(self.mutate(mutation)))
        
        self.mutations_to_run = new_mutations

    @abstractmethod
    def mutate(self, content):
        pass
    
    @abstractmethod
    def to_str(self, content):
        pass
    
    @abstractmethod
    def from_str(self, content):
        pass
    

