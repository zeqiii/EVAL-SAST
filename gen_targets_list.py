import os, sys

if __name__ == "__main__":
    with open("targets.list", "w") as fp:
        targets = ""
        for one in os.listdir(sys.argv[1]):
            targets = targets + os.path.abspath(os.path.join(sys.argv[1], one)) + "\n"
        targets = targets.strip()
        fp.write(targets)
