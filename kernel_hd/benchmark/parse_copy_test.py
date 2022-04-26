import sys
import numpy as np

def format_direction(src, dst):
	cpfile = src.split('/')[-1]
	direction = src + "-" + dst
	if cpfile.startswith("teste") and cpfile.endswith(".dat"):
		cpfile = cpfile[5:-4]
	if src.find("extra_hd") != -1 and dst.find("extra_hd") != -1:
		direction = "virtio to virtio"
	if src.find("extra_hd") == -1 and dst.find("extra_hd") != -1:
		direction = "to virtio"
	if src.find("extra_hd") != -1 and dst.find("extra_hd") == -1:
		direction = "from virtio"

	return direction, cpfile


def parse_file(filename, spdm):
	print ("processing", filename, file=sys.stderr)
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1)

	direction, cpfile = "", ""
	values = []
	for line in f:
		line = line.strip()
		# print("line:", line)
		if not line.isnumeric():
			if cpfile and values:
				average = np.mean(values)
				stdev = np.std(values, ddof=1)
				print(";".join(map(str,(cpfile, spdm, direction, average, stdev))))
				values = []
			_, src, dst = line.strip().split()
			direction, cpfile = format_direction(src, dst)
		else:
			values += [float(line)]
	average = np.mean(values)
	stdev = np.std(values, ddof=1)
	if (values): print(";".join(map(str,(cpfile, spdm, direction, average, stdev))))


def usage():
	print("Usage:", sys.argv[0], "spdm <files with spdm statistics> no_spdm <files with no spdm statistics> ", file=sys.stderr)

if __name__ == "__main__":
	if len(sys.argv) == 1:
		usage()
		exit(-1)

	spdm = ""
	for arg in sys.argv[1:]:
		if arg == "spdm":
			spdm = "spdm"
			print('spdm = "spdm"', file=sys.stderr)
			continue

		if arg == "no_spdm":
			spdm = "no_spdm"
			print('spdm = "no_spdm"', file=sys.stderr)
			continue

		if spdm == "":
			usage()
			exit(-1)

		parse_file(arg, spdm)

