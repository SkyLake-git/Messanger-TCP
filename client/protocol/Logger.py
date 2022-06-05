import crayons
import datetime

class Logger:

	name: str

	def __init__(self, name: str):
		self.name = name

	def send(self, text: str, timestamp: bool = True):
		timest = crayons.cyan(create_timestamp(True), bold=True)
		if (not timestamp):
			timest = ""
		
		print(timest + " " + crayons.black(f"[{self.name}]", bold = True) + " " + text)


def create_timestamp(microseconds=False):
    d = datetime.datetime.now()
    micro=""
    if microseconds:
        micro = f".{str(d.microsecond)[:2]}"
    return f"[{d.month}/{d.day} {d.hour}:{d.minute:02}:{d.second:02}{micro}]"