import argparse
from varas.com_fm.com_fm import *

op = com_fm("ceph2", "client.vkg")

parser = argparse.ArgumentParser(description="ceph upload download")
parser.add_argument("--c", type=int, required=True, help="0 upload, 1 download")
parser.add_argument("--r", type=str, required=True, help="upload remote path")
parser.add_argument("--l", type=str, required=True, help="download local path")

def upload(local, remote):
	res = op.upload('vkg', local, remote)
	return res

def download(remote, local):
	res = op.download('vkg', remote, local)
	return res

if __name__ == "__main__":
	args = parser.parse_args()
	if args.c == 0:
		upload(args.l, args.r)
	else:
		download(args.r, args.l)
