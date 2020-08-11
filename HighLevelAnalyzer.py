# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta


def fnv1(data):
    h = 0x811c9dc5
    for d in data:
        h = ((h * 0x1000193) & 0xffffffff) ^ d
    return h

def hash(buf, bits):
    if (bits < 1):
        return 0
    h = fnv1(buf)
    if (bits >= 32):
        return h
    else:
        return (h ^ (h >> bits)) & ((1 << bits) - 1)

def idiv(a, b):
    return a // b

def shortDeviceId(devid):
    h = hash(devid, 30)
    return (chr(0x41 + h % 26) +
        chr(0x41 + idiv(h, 26) % 26) +
        chr(0x30 + idiv(h, 26 * 26) % 10) +
        chr(0x30 + idiv(h, 26 * 26 * 10) % 10))

class Hla(HighLevelAnalyzer):
    #my_string_setting = StringSetting(label='My String')
    #my_number_setting = NumberSetting(label='My Number', min_value=0, max_value=100)
    #my_choices_setting = ChoicesSetting(label='My Choice', ['A', 'B'])

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'pkt': {
            'format': '{{data.info}}'
        },
        'ann': {
            'format': '{{data.info}}'
        },
    }

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.bytes = []
        pass

    def flush(self):
        if not self.end_time:
            return
        short_id = shortDeviceId(self.bytes[4:12])
        size = self.bytes[12]
        serv_num = self.bytes[13]
        serv_cmd = self.bytes[14]+self.bytes[15]*256
        info = "%s/%d: " % (short_id, serv_num)
        tp = "pkt"
        if serv_num == 0 and serv_cmd == 0:
            info += "announce %d service(s)" % (size/4)
            tp = "ann"
        else:
            info += "cmd:0x%x sz:%d" % (serv_cmd, size)
        self.res = AnalyzerFrame(tp, self.start_time, self.end_time, {'info':info})
        self.bytes = []
        self.end_time = None
        self.start_time = None

    def decode(self, frame: AnalyzerFrame):
        self.res = None
        if not self.start_time:
            self.start_time = frame.start_time
        if 'error' in frame.data or frame.start_time - self.start_time > GraphTimeDelta(millisecond=2):
            self.flush()
        if 'error' not in frame.data:
            self.bytes.append(ord(frame.data['data']))
            self.end_time = frame.end_time
        return self.res
