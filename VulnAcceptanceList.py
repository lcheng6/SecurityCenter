import json
import sys
import requests
import pprint
import csv

class VulnAcceptanceList:
	#the list will be a list of mapped fields, in the form of 
	#{Plugin: #####, Plugin Name: XXXXX, Severity, High/Medium/Low, 
	# Total: #, Comments: XXXXX, EnteredInSSC: true/false}
	# Comments is Comments to put into Accept Risk

	f = None;
	filename = "";
	vulnList = [];
	headers = []; 

	def __init__(self):
		self.vulnList  = {}
		self.filename = "";
		self.f = None;
		self.headers = ["Plugin", "PluginName", "Severity", "Total", "Comments", "AcceptRisk"];

	def set_headers(self, headers):
		self.headers = headers

	def read_csv_file (self, filename):
		self.filename = filename;
		self.f = open(filename, 'r');

		reader = csv.reader(self.f);
		headers = reader.next();
		#I have no plans to use headers

		#headers = ["Plugin", "PluginName", "Severity", "Total", "Comments", "AcceptRisk"];

		for row in reader:
			for (k, v) in zip (self.headers, row): 
				mappedRow[k] = v;
			self.vulnList.append(mappedRow);

	def get_row_count(self):
		return len(self.vulnList);

	def get_row_by_index(self, index):
		return self.vulnList[index];
