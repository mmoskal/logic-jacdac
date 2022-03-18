# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from typing import OrderedDict
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta
import json
import binascii
import os

service_specs = {}


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


def hex(buf):
    return binascii.hexlify(buf).decode()


def u16(buf: bytes, off: int):
    return buf[off] | (buf[off+1] << 8)


def u32(buf: bytes, off: int):
    return buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24)


def crc16(buf: bytes, start: int = 0, end: int = None):
    if end is None:
        end = len(buf)
    crc = 0xffff
    while start < end:
        data = buf[start]
        start += 1
        x = (crc >> 8) ^ data
        x ^= x >> 4
        crc = ((crc << 8) ^ (x << 12) ^ (x << 5) ^ x) & 0xffff
    return crc


class Device:
    def __init__(self, ann) -> None:
        self.device_id = hex(ann[4:12])
        self.short_id = shortDeviceId(ann[4:12])
        self.update(ann)

    def update(self, ann):
        self.announce = ann[16:]

    def num_services(self):
        return len(self.announce) >> 2

    def service_class_at(self, idx):
        if idx == 0:
            return 0
        if idx < self.num_services():
            return u32(self.announce, idx << 2)
        return None

    def service_spec_at(self, idx):
        sclass = str(self.service_class_at(idx))
        if sclass in service_specs:
            return service_specs[sclass]
        return None


def lookup_pkt(spec, id, kinds):
    if spec:
        for pkt in spec['packets']:
            if pkt['identifier'] == id and pkt['kind'] in kinds:
                return pkt
    return None


def get_attrs(devs, pkt: bytes):
    dev_id = hex(pkt[4:12])
    dev: Device = None
    size = pkt[12]
    serv_idx = pkt[13]
    serv_cmd = u16(pkt, 14)
    is_ann = serv_idx == 0 and serv_cmd == 0
    if dev_id in devs:
        dev = devs[dev_id]
        if is_ann:
            dev.update(pkt)
    else:
        ann_pkt = pkt
        if not is_ann:
            ann_pkt = pkt[0:12] + bytes([0, 0, 0, 0])
        dev = Device(ann_pkt)
        devs[dev.device_id] = dev
    spec = dev.service_spec_at(serv_idx)
    is_broadcast = (pkt[3] & 0x04) != 0
    if is_broadcast:
        spec = service_specs[str(u32(pkt, 4))]
    spec_name = spec['camelName'] if spec else "%d" % serv_idx
    info = ""
    needs_ack = (pkt[3] & 0x02) != 0
    is_command = (pkt[3] & 0x01) != 0
    is_report = not is_command
    tp = "err"
    # OrderedDict doesn't work :/
    attrs = dict(
        short_id=dev.short_id,
        service_name=spec_name,
        info='',
        flags='',
        cmd="0x%04x" % serv_cmd,
        service="%d" % serv_idx,
        size="%d" % size,
    )
    if is_broadcast:
        attrs['short_id'] = "*BC*"
    pkt_spec = None
    id = None
    if is_ann:
        for i in range(1, dev.num_services()):
            sp = dev.service_spec_at(i)
            if sp:
                info += "%s, " % sp['camelName']
            else:
                info += "0x%x, " % dev.service_class_at(i)
        tp = "ann"
    elif serv_idx == 0x3f:
        tp = 'ack'
        info = "ack:0x%x" % serv_cmd
    elif serv_idx == 0x3e:
        tp = 'pipe'
        info = "port:%d cnt:%d%s%s" % (
            serv_cmd >> 7,
            serv_cmd & 0x1f,
            " close" if serv_cmd & 0x20 else "",
            " meta" if serv_cmd & 0x40 else ""
        )
    elif serv_idx >= 0x30:
        tp = 'err'
    elif is_report and serv_cmd & 0x8000:
        tp = 'evt'
        id = serv_cmd & 0xff
        pkt_spec = lookup_pkt(spec, id, ["event"])
    elif (serv_cmd >> 12) == 0x1 or (serv_cmd >> 12) == 0x2:
        id = serv_cmd & 0xfff
        pkt_spec = lookup_pkt(spec, id, ["rw", "ro", "const"])
        if (serv_cmd >> 12) == 0x1:
            tp = 'get'
        else:
            tp = 'set'
        if is_report:
            tp += 'v'
    elif (serv_cmd >> 12) == 0x0:
        id = serv_cmd & 0xfff
        if is_command:
            tp = 'cmd'
            pkt_spec = lookup_pkt(spec, id, ["command"])
        else:
            tp = 'rep'
            pkt_spec = lookup_pkt(spec, id, ["report"])
    else:
        tp = 'err'
        info += "cmd:0x%x sz:%d" % (serv_cmd, size)
    if id is not None:
        if pkt_spec:
            attrs['cmd_name'] = pkt_spec['name']
        else:
            attrs['cmd_name'] = "0x%x" % id
    if needs_ack:
        attrs['flags'] = ("[ack:0x%x] " % u16(pkt, 0)) + attrs['flags']
    attrs['info'] = info
    return (tp, attrs)


def split_frame(frame: bytes):
    if frame[2] - frame[12] < 4:
        return [frame]
    else:
        ptr = 12
        res = []
        while ptr < 12 + frame[2]:
            sz = frame[ptr] + 4
            pktbytes = frame[0:12] + frame[ptr:ptr+sz]
            res.append(pktbytes)
            ptr += (sz + 3) & ~3
        return res


fmt = "{{type}} {{data.short_id}}/{{data.service_name}} {{data.cmd_name}} {{data.flags}}{{data.info}}"


class Hla(HighLevelAnalyzer):
    # my_string_setting = StringSetting(label='My String')
    # my_number_setting = NumberSetting(label='My Number', min_value=0, max_value=100)
    # my_choices_setting = ChoicesSetting(label='My Choice', ['A', 'B'])

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'ann': {'format': fmt},
        'ack': {'format': fmt},
        'evt': {'format': fmt},
        'pipe': {'format': fmt},
        'get': {'format': fmt},
        'getv': {'format': fmt},
        'set': {'format': fmt},
        'cmd': {'format': fmt},
        'rep': {'format': fmt},
    }

    def __init__(self):
        f = open(os.path.dirname(__file__) +
                 "/services.json", encoding='utf-8')
        arr = json.load(f)
        f.close()
        self.devices = {}
        for serv in arr:
            service_specs[str(serv['classIdentifier'])] = serv
        self.start_time = None
        self.end_time = None
        self.bytes = []
        pass

    def clear(self):
        self.bytes = []
        self.end_time = None
        self.start_time = None

    def flush(self):
        if not self.end_time:
            return
        if len(self.bytes) < 16:
            self.clear()
            return

        bb = bytes(self.bytes)
        crc = crc16(bb, 2, bb[2] + 12)
        good_crc = crc == u16(bb, 0)
        pkts = split_frame(bb)
        durr = self.end_time - self.start_time
        idx = 0
        lp = len(pkts)
        delta = durr / lp
        for pkt in pkts:
            (tp, attrs) = get_attrs(self.devices, pkt)
            if not good_crc:
                attrs['flags'] = "crc-err " + attrs['flags']
            self.res.append(AnalyzerFrame(
                tp, self.start_time + (delta * idx), self.start_time + (delta * (idx+1)), attrs))
            idx += 1
        self.clear()

    def decode(self, frame: AnalyzerFrame):
        self.res = []
        if not self.start_time:
            self.start_time = frame.start_time
        if 'error' in frame.data or frame.start_time - self.start_time > GraphTimeDelta(millisecond=4):
            self.flush()
        if 'error' not in frame.data:
            self.bytes.append(ord(frame.data['data']))
            self.end_time = frame.end_time
        return self.res
