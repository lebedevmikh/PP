from scapy.all import *


class Iptable():
	"""Класс arp-таблицы """
	def __init__(self,freq):
		self.ip = get_if_addr(conf.iface)
		self.mac = self.get_mac(self.ip)
		self.clients=[]
		self.ticks_to_drop = freq
		self.ticks  = 0
		self.user_count = 0 
		self.add_client(ip=self.ip,mac=self.mac,type=True)


	def add_client(self,ip,mac,type):
		self.clients.append(Client(ip,mac,type))


	def delete_client(self,ip):
		for client in self.clients:
			if client.ip == ip:
				self.clients.remove(client)


	def scan(self):
		arp_request = ARP(pdst=self.ip[:-3]+"1/24")
		broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
		arp_request_broadcast = broadcast/arp_request
		answered_list =  srp(arp_request_broadcast, timeout=3, verbose=False)[0]
		clients_list=[]
		for element in answered_list:
			clients_list.append(element[1].psrc)
		return clients_list


	def get_ip(self):
		return  get_if_addr(conf.iface)


	def get_mac(self,ip):
		arp_request = ARP(pdst=ip)
		broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
		arp_request_broadcast = broadcast/arp_request
		answered_list =  srp(arp_request_broadcast, timeout=1, verbose=False)[0]
		clients_list=[]
		for element in answered_list:
			return element[1].hwsrc


	def check(self,arr):
		old = []
		for obj in self.clients:
			old.append(obj.ip)
		return self.incertion(set(old),set(arr))


	def update(self):
		for new_client in self.check(self.scan()):
			self.add_client(ip=new_client,mac=self.get_mac(new_client),type=False)
		self.ticks =+ 1
		if self.ticks == self.ticks_to_drop:
			self.ticks = 0
			self.drop()
	

	def incertion(self,set_a,set_b):
		return set_b & set_a.union(set_b.difference(set_a))


	def drop(self):
		self.clients = []
		self.user_count = 0
		self.add_client(ip=self.ip,mac=self.mac,type=True) 
		print("refreshed")


class Client():
	def __init__(self,ip,mac,type):
		self.ip = ip
		self.mac = mac
		self.type = type


def main():
	table = Iptable(freq=12)
	while True:
		try:
			table.update()
		except TimeoutError:
			time.sleep(5)
			table.update()
		print(table.clients)
		time.sleep(5)
if __name__ == '__main__':
    main()
