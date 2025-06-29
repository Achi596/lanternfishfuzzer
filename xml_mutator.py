import random
import string
import xml.etree.ElementTree as ET
from mutator import Mutator

class XMLMutator(Mutator):

    def __init__(self, content):
        super().__init__(content)

    def to_str(self, content):
        return content

    def from_str(self, content):
        return content


    def mutate(self, content):

        # build tree structure from the text input
        tree = ET.ElementTree(ET.fromstring(content))

        # list of all elements in the tree
        elements = list(tree.iter())

        # list of all elements with attributes
        els_with_attrs = [el for el in elements if el.attrib]
        
        # list of mutations that can be applied, so far:
        # a long string
        # a format string that will cause a crash

        mutations = ['A'*1000, '%10x%n']

        # choose which mutation to use
        mut = random.choice(mutations)

        # choose where to apply mutation
        match random.choice([1,2,3]):
            case 1:
                # create a new nested node
                parent = random.choice(elements)
                new_tag = ET.Element('nested')
                new_tag.text = mut
                parent.append(new_tag)
                
            case 2:
                # mutate text in an element
                el = random.choice(elements)
                if el.text:
                    el.text += mut

            case 3:
                # mutate text in an attribute
                if not els_with_attrs:
                    pass
                el = random.choice(els_with_attrs)
                attr_name = random.choice(list(el.attrib.keys()))
                # Modify the attribute value
                el.attrib[attr_name] += mut


        xml_string = ET.tostring(tree.getroot(), encoding='unicode')
        return xml_string





