#!/usr/bin/env python3

with open("enum.txt", "r") as fin:
	lines = fin.read().strip().split("\n")

num = 1
for member in lines:
	print("    {} = {}".format(member, num))
	num += 1
