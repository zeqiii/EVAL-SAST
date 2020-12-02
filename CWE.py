import os, sys

try:
  import xml.etree.cElementTree as ET
except ImportError:
  import xml.etree.ElementTree as ET


class CWEEntity():
    def __init__(self):
        self.ID = -1
        self.Type = ""  # view, category, class, base, variant
        # relationship could be "HasMember", "ChildOf", "CanPrecede", ...
        self.relationship = {} # {relationship1:[entitiy IDs], relationship2:[entitiy IDs], ...}


    def tostring(self):
        l = []
        for key in self.relationship.keys():
            l.extend(self.relationship[key])
        return str(self.ID) + " relation:" + str(l)



class CWETree():
    def __init__(self, xmlfile):
        self.xml_file = xmlfile
        self.xml_root = ET.parse(self.xml_file).getroot()
        self.view_name = "research view"
        self.view_id = 1000
        self.entities = {}  # {entityID1:CWEEntityObj1, entityID2:CWEEntityObj2, ...}
        self.parse()


    def output(self):
        for key in self.entities.keys():
            print(self.entities[key].tostring())


    def hasRelation(self, e1, e2):
        # the relations recorded in cwe-1000.xml are one-way
        # so just traverse all around, there is no need to worry about cycling
        if type(e1) == type(1):
            e1 = self.entities[e1]
        if type(e2) == type(1):
            e2 = self.entities[e2]
        stack = []
        used  = []

        # e1 -> e2
        for key in e1.relationship.keys():
            stack.extend(e1.relationship[key])
        while len(stack) > 0:
            if e2.ID in stack:
                return True
            used.extend(stack)
            stack_tmp = []
            for one in stack:
                if one not in self.entities.keys():
                    continue
                e_tmp = self.entities[one]
                for key in e_tmp.relationship.keys():
                    for one in e_tmp.relationship[key]:
                        if one not in used:
                            stack_tmp.append(one)
            stack = stack_tmp

        stack = []
        used = []
        # e2 -> e1
        for key in e2.relationship.keys():
            stack.extend(e2.relationship[key])
        while len(stack) > 0:
            if e1.ID in stack:
                return True
            used.extend(stack)
            stack_tmp = []
            for one in stack:
                if one not in self.entities.keys():
                    continue
                e_tmp = self.entities[one]
                for key in e_tmp.relationship.keys():
                    for one in e_tmp.relationship[key]:
                        if one not in used:
                            stack_tmp.append(one)
            stack = stack_tmp
        return False

    def parse_views(self):
        views = self.xml_root.findall("Views")[0]
        for view in views:
            ID = int(view.attrib["ID"])
            if ID in self.entities.keys():
                continue
            entity = CWEEntity()
            entity.ID = ID
            entity.Type = "view"
            for relationship in view.find("Relationships"):
                nature = relationship.find("Relationship_Nature").text
                targetID = relationship.find("Relationship_Target_ID").text
                if nature not in entity.relationship.keys():
                    entity.relationship[nature] = []
                entity.relationship[nature].append(int(targetID))
            self.entities[ID] = entity


    def parse_categories(self):
        categories = self.xml_root.findall("Categories")[0]
        for category in categories:
            ID = int(category.attrib["ID"])
            if ID in self.entities.keys():
                continue
            entity = CWEEntity()
            entity.ID = ID
            entity.Type = "category"
            for relationship in category.find("Relationships"):
                nature = relationship.find("Relationship_Nature").text
                targetID = relationship.find("Relationship_Target_ID").text
                if nature not in entity.relationship.keys():
                    entity.relationship[nature] = []
                entity.relationship[nature].append(int(targetID))
            self.entities[ID] = entity


    def parse_weaknesses(self):
        weaknesses = self.xml_root.findall("Weaknesses")[0]
        for weakness in weaknesses:
            ID = int(weakness.attrib["ID"])
            if ID in self.entities.keys():
                continue
            entity = CWEEntity()
            entity.ID = ID
            entity.Type = "category"
            for relationship in weakness.find("Relationships"):
                nature = relationship.find("Relationship_Nature").text
                targetID = relationship.find("Relationship_Target_ID").text
                if nature not in entity.relationship.keys():
                    entity.relationship[nature] = []
                entity.relationship[nature].append(int(targetID))
            self.entities[ID] = entity


    def parse_compounds(self):
        compounds = self.xml_root.findall("Compound_Elements")[0]
        for compound in compounds:
            ID = int(compound.attrib["ID"])
            if ID in self.entities.keys():
                continue
            entity = CWEEntity()
            entity.ID = ID
            entity.Type = "category"
            for relationship in compound.find("Relationships"):
                nature = relationship.find("Relationship_Nature").text
                targetID = relationship.find("Relationship_Target_ID").text
                if nature not in entity.relationship.keys():
                    entity.relationship[nature] = []
                entity.relationship[nature].append(int(targetID))
            self.entities[ID] = entity


    def parse(self):
        self.parse_views()
        self.parse_categories()
        self.parse_weaknesses()
        self.parse_compounds()
        self.entities[710].relationship["MemberOf"] = [1000]
        self.entities[703].relationship["MemberOf"] = [1000]
        self.entities[664].relationship["MemberOf"] = [1000]
        self.entities[707].relationship["MemberOf"] = [1000]
        self.entities[118].relationship["MemberOf"] = [1000]
        self.entities[682].relationship["MemberOf"] = [1000]
        self.entities[697].relationship["MemberOf"] = [1000]
        self.entities[691].relationship["MemberOf"] = [1000]
        self.entities[435].relationship["MemberOf"] = [1000]
        self.entities[693].relationship["MemberOf"] = [1000]
        self.entities[330].relationship["MemberOf"] = [1000]


if __name__ == "__main__":

    cwe_tree = CWETree("cwe-1000.xml")

    print(cwe_tree.hasRelation(537, 536))