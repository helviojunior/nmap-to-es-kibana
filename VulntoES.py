# ========================================================================================
# The code below has been adapted and tailored for this project.
# The original version can be found at: https://github.com/ChrisRimondi/VulntoES
# ========================================================================================
from elasticsearch import Elasticsearch
import sys
import re
import json
import time
import getopt
import hashlib
import xml.etree.ElementTree as xml


class NmapES:
	"This class will parse an Nmap XML file and send data to Elasticsearch"

	def __init__(self, input_file,es_ip,es_port,index_name):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.es = Elasticsearch([f'http://{es_ip}:{es_port}'])
		self.index_name = index_name

	def displayInputFileName(self):
		print(self.input_file)

	def __importXML(self):
		# Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toES(self):
		"Returns a list of dictionaries (only for open ports) for each host in the report"
		for h in self.root.iter('host'):
			dict_item = {}
			dict_item['scanner'] = 'nmap'
			if h.tag == 'host':
				if 'endtime' in h.attrib and h.attrib['endtime']:
					dict_item['time'] = time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(float(h.attrib['endtime'])))
			
			for c in h:
				if c.tag == 'address':
					if c.attrib['addr'] and c.attrib['addrtype'] == 'ipv4':
						dict_item['ip'] = c.attrib['addr']
					if c.attrib['addr'] and c.attrib['addrtype'] == 'mac':
						dict_item['mac'] = c.attrib['addr']

				elif c.tag == 'hostnames':
					for names in list(c):
						if names.attrib['name']:
							dict_item['hostname'] = names.attrib['name']

				elif c.tag == 'ports':
					for port in list(c):
						dict_item_ports = {}
						if port.tag == 'port':
							# print(port.tag, port.attrib)
							dict_item_ports['port'] = port.attrib['portid']
							dict_item_ports['protocol'] = port.attrib['protocol']
							for p in list(port):
								if p.tag == 'state':
									dict_item_ports['state'] = p.attrib['state']
								elif p.tag == 'service':
									dict_item_ports['service'] = p.attrib['name']
									if 'product' in p.attrib and p.attrib['product']:
										dict_item_ports['product_name'] = p.attrib['product']
										if 'version' in p.attrib and p.attrib['version']:
											dict_item_ports['product_version'] = p.attrib['version']
									if 'banner' in p.attrib and p.attrib['banner']:
										dict_item_ports['banner'] = p.attrib['banner']
								elif p.tag == 'script':
									if p.attrib['id']:
										if p.attrib['output']:
											if 'scripts' in dict_item_ports:
												dict_item_ports['scripts'][p.attrib['id']] = p.attrib['output']
											else:
												dict_item_ports['scripts'] = dict()
												dict_item_ports['scripts'][p.attrib['id']] = p.attrib['output']
													
							to_upload = merge_two_dicts(dict_item, dict_item_ports)	
							if to_upload['state'] == 'open':
								self.es.index(index=self.index_name, id=calc_id(to_upload), document=json.dumps(to_upload))

def calc_id(item):
	#{'scanner': 'nmap', 'time': '2024/07/26 16:50:12', 'ip': '177.154.191.218', 'hostname': 'br.odin7080.com.br', 'port': '465', 'protocol': 'tcp', 'state': 'open', 'service': 'smtp', 'product_name': 'Exim smtpd', 'product_version': '4.95', 'scripts': {'ssl-cert': 'Subject: commonName=br.odin7080.com.br\nSubject Alternative Name: DNS:br.odin7080.com.br\nIssuer: commonName=cPanel, Inc. Certification Authority/organizationName=cPanel, Inc./stateOrProvinceName=TX/countryName=US\nPublic Key type: rsa\nPublic Key bits: 2048\nSignature Algorithm: sha256WithRSAEncryption\nNot valid before: 2024-07-25T00:00:00\nNot valid after:  2024-10-23T23:59:59\nMD5:   17fb:3443:93bc:46c3:c39e:419d:a06b:9356\nSHA-1: 854c:465b:60a3:f4f2:4577:8f99:bfc4:360e:0b3e:8c16', 'smtp-commands': 'SMTP EHLO br.odin7080.com.br: failed to receive data: failed to receive data', 'ssl-date': 'TLS randomness does not represent time'}}
	sha1sum = hashlib.sha1()
	sha1sum.update(json.dumps({
			k: v
			for k, v in item.items()
			if k in ["ip", "port", "protocol", "state"]
		}).encode("UTF-8"))
	return sha1sum.hexdigest()

def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

def usage():
	print("Usage: VulntoES.py [-i input_file | input_file=input_file] [-e elasticsearch_ip | es_ip=es_ip_address] [-p elasticsearch_port | es_port=es_server_port] [-I index_name] [-r report_type | --report_type=type] [-s name=value] [-h | --help]")

def main():
	letters = 'i:I:e:p:r:s:h' #input_file, index_name es_ip_address, report_type, create_sql, create_xml, help
	keywords = ['input-file=', 'index_name=', 'es_ip=','es_port=','report_type=', 'static=', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError as err:
		print(str(err))
		usage()
		sys.exit()
	
	in_file = ''
	es_ip = ''
	es_port = 9200
	report_type = ''
	index_name = ''
	static_fields = dict()

	for o,p in opts:
		if o in ['-i','--input-file=']:
			in_file = p
		elif o in ['-r', '--report_type=']:
			report_type = p
		elif o in ['-e', '--es_ip=']:
			es_ip=p
		elif o in ['-p', '--es_port=']:
			es_port=p
		elif o in ['-I', '--index_name=']:
			index_name=p
		elif o in ['-s', '--static']:
			name, value = p.split("=", 1)
			static_fields[name] = value
		elif o in ['-h', '--help']:
			usage()
			sys.exit()

	if (len(sys.argv) < 1):
		usage()
		sys.exit()

	try:
		with open(in_file) as f: pass
	except IOError as e:
		print("Input file does not exist. Exiting.")
		sys.exit()

	if report_type.lower() == 'nmap':
		print("Sending Nmap data to Elasticsearch")
		np = NmapES(in_file,es_ip,es_port,index_name)
		np.toES()
	else:
		print("Error: Invalid report type specified. Available options: nmap")
		sys.exit()

if __name__ == "__main__":
	main()
