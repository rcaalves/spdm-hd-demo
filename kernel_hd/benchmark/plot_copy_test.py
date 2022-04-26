from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import sys

def format_plot_label(direction, spdm):
	return ("[" + spdm.upper() + "] - ").rjust(12) + direction

def filesizesorter(a):
	a = a.lower()
	suf = {'k':10**3, 'm':10**6, 'g':10**9}
	return int(a[0:-1]) * suf[a[-1]]

if len(sys.argv) == 1:
	print("No input file")
	print("Usage:")
	print("\t python " + sys.argv[0] + " <file output from parse script>")
	exit()

if len(sys.argv) > 2:
	print("Wrong number of parameters")
	print("Usage:")
	print("\t python " + sys.argv[0] + " <file output from parse script>")
	exit()


values = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: (-1, -1))))

spdms = set()
filesizes = set()
directions = set()

f_current = open(sys.argv[1])

# f_current.readline() # skip header
for line in f_current:
	line = line.strip()
	spl = line.split(";")
	(filesize, spdm, direction, avg, desv) = spl
	avg = float(avg)
	desv = float(desv)
	values[spdm][direction][filesize] = (avg, desv)
	spdms.add(spdm)
	directions.add(direction)
	filesizes.add(filesize)
f_current.close()


# colors = ("red", "green", "cyan", "gray", "orange", "pink")
colors = ("#003f5c", "#444e86", "#955196", "#dd5182", "#ff6e54", "#ffa600")
colors = tuple(reversed(colors))
hatches = ('//', '', '\\\\', 'o', '-', '+', 'x', '*', 'O', '.', '/', '\\')
ecolor = ('gray', 'black', )
markers = ('o', 'v', '^', '<', '>', '8', 's', 'p', '*', 'h', 'H', 'D', 'd')
lss = ['solid', 'dashed', 'dashdot', 'dotted', '-', '--', '-.', ':', 'None', ' ', '']
plt.rcParams.update({'font.size': 12, 'legend.fontsize': 10})


fig, ax = plt.subplots()
plt.grid(b=True, which='major', color='gray', linestyle='--', lw=0.5, axis='y')

directions = list(sorted(directions))
filesizes = list(sorted(filesizes, key=filesizesorter))
spdms = list(sorted(spdms))
labels = set()

for direction in directions:
	# print(direction)
	spdmlabelorder = sorted(spdms)
	for filesize in filesizes:
		# print("\t"+filesize)

		spdms = list(sorted(spdms, key = lambda x: -values[x][direction][filesize][0]))

		for spdm in spdms:

			v, e = (values[spdm][direction][filesize][0], values[spdm][direction][filesize][1],)
			width = 0.9 / len(directions)  # the width of the bars
			where = (directions.index(direction) - 1) * width
			x = filesizes.index(filesize)

			colorindex = sorted(spdms).index(spdm)*(len(directions)) + directions.index(direction)

			my_label = format_plot_label(direction, spdm)
			if my_label in labels or spdm != spdmlabelorder[0]:
				my_label = None
			else:
				labels.add(my_label)
				spdmlabelorder = spdmlabelorder [1:]

			myrects = ax.bar(x + where, v, width, color=colors[colorindex],
							linewidth=0.3, edgecolor="black",
							yerr=e, ecolor=ecolor[sorted(spdms).index(spdm)], capsize=5,
							label=my_label, hatch=hatches[sorted(spdms).index(spdm)])  #, alpha=0.5)

ax.set_xticks(np.arange(len(filesizes)))
ax.set_xticklabels(filesizes)

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_xlabel("File size")
ax.set_ylabel("Time [us]")
ax.set_yscale('log')
ax.legend(loc='best', prop={'family': 'monospace'})
savetype = 'png'
plt.savefig('r_copy_test.' + savetype, format=savetype, dpi=300, bbox_inches='tight')