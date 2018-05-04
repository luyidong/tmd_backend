#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""  
 @desc:  
 @author: Wyz
 @email: w4n9ya@gmail.com  
 @site: https://github.com/w4n9H/WyzBolg/issues 
 """

__author__ = "Wyz"
__version__ = "0.1"


import ctypes.util
from ctypes import *
from socket import *
from sys import platform
from struct import pack, unpack
from collections import namedtuple as _namedtuple


c_uint32_p = POINTER(c_uint32)
c_int_p = POINTER(c_int)
c_ubyte_p = POINTER(c_ubyte)
py_object_p = POINTER(py_object)

PCAP_ERRBUF_SIZE = 256
BIOCIMMEDIATE = -2147204496


class pcap_t(Structure):
    pass


class pcap_stat(Structure):
    if platform == 'nt':
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint),
            ('bs_capt', c_uint)
        ]
    else:
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint)
        ]


pcap_stat_ptr = POINTER(pcap_stat)


class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long)
    ]


class pcap_pkthdr(Structure):
    if platform == 'darwin':
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32),
            ('comments', (c_char * 256))
        ]
    else:
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32)
        ]


pcap_pkthdr_ptr = POINTER(pcap_pkthdr)


class pcap_sf(Structure):
    _fields = [
        ('rfile', c_void_p),
        ('swapped', c_int),
        ('hdrsize', c_int),
        ('version_major', c_int),
        ('version_minor', c_int),
        ('base', c_ubyte_p)
    ]


class pcap_md(Structure):
    if platform.startswith('linux'):
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long),
            ('sock_packet', c_int),
            ('readlen', c_int),
            ('timeout', c_int),
            ('clear_promisc', c_int),
            ('cooked', c_int),
            ('lo_ifindex', c_int),
            ('*device', c_char),
            ('*next', pcap_t),
        ]
    else:
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long)
        ]


class bpf_insn(Structure):
    _fields_ = [
        ('code', c_ushort),
        ('jt', c_ubyte),
        ('jf', c_ubyte),
        ('k', c_int)
    ]


bpf_insn_ptr = POINTER(bpf_insn)


class bpf_program(Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', POINTER(bpf_insn))
    ]


bpf_program_ptr = POINTER(bpf_program)


class sockaddr_in(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sin_len', c_ubyte),
            ('sin_family', c_ubyte),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]
    else:
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]


class sockaddr_in6(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sin6_len', c_ubyte),
            ('sin6_family', c_ubyte),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]
    else:
        _fields_ = [
            ('sin6_family', c_ushort),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]


class sockaddr_sa(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sa_len', c_ubyte),
            ('sa_family', c_ubyte),
            ('sa_data', c_char * 14)
        ]
    else:
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data', c_char * 14)
        ]


class sockaddr_dl(Structure):
    _pack_ = 1
    _fields_ = (
        ('sdl_len', c_ubyte),
        ('sdl_family', c_ubyte),
        ('sdl_index', c_ushort),
        ('sdl_type', c_ubyte),
        ('sdl_nlen', c_ubyte),
        ('sdl_alen', c_ubyte),
        ('sdl_slen', c_ubyte),
        ('sdl_data', (c_ubyte * 12)),
    )


class sockaddr_ll(Structure):
    _pack_ = 1
    _fields_ = (
        ('sll_family', c_ushort),
        ('sll_protocol', c_ushort),
        ('sll_ifindex', c_int),
        ('sll_hatype', c_ushort),
        ('sll_pkttype', c_ubyte),
        ('sll_halen', c_ubyte),
        ('sll_data', (c_ubyte * 8)),
    )


class sockaddr(Union):
    _pack_ = 1
    _fields_ = [
        ('sa', sockaddr_sa),
        ('sin', sockaddr_in),
        ('sin6', sockaddr_in6),
        ('sdl', sockaddr_dl),
        ('sll', sockaddr_ll),
    ]


sockaddr_ptr = POINTER(sockaddr)


class pcap_addr_t(Structure):
    _pack_ = 1


pcap_addr_t_ptr = POINTER(pcap_addr_t)


pcap_addr_t._fields_ = [
    ('next', pcap_addr_t_ptr),
    ('addr', sockaddr_ptr),
    ('netmask', sockaddr_ptr),
    ('broadaddr', sockaddr_ptr),
    ('dstaddr', sockaddr_ptr)
]


class pcap_if_t(Structure):
    _pack_ = 1


pcap_if_t_ptr = POINTER(pcap_if_t)


pcap_if_t._fields_ = [
    ('next', pcap_if_t_ptr),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', pcap_addr_t_ptr),
    ('flags', c_uint)
]


pcap_t._fields_ = [
    ('fd', c_int),
    ('snapshot', c_int),
    ('linktype', c_int),
    ('tzoff', c_int),
    ('offset', c_int),
    ('pcap_sf', pcap_sf),
    ('pcap_md', pcap_md),
    ('bufsize', c_int),
    ('buffer', c_ubyte_p),
    ('bp', c_ubyte_p),
    ('cc', c_int),
    ('pkt', c_char_p),
    ('fcode', bpf_program),
    ('errbuf', (c_char * PCAP_ERRBUF_SIZE))
]


pcap_t_ptr = POINTER(pcap_t)


class pcap_rmtauth(Structure):
    _fields_ = [
        ('type', c_int),
        ('username', c_char_p),
        ('password', c_char_p)
    ]


pcap_rmtauth_ptr = POINTER(pcap_rmtauth)


class pcap_dumper_t(Structure):
    pass


pcap_dumper_t_ptr = POINTER(pcap_dumper_t)


class pcap_stat_ex(Structure):
    _fields_ = [
        ('rx_packets', c_ulong),
        ('tx_packets', c_ulong),
        ('rx_bytes', c_ulong),
        ('tx_bytes', c_ulong),
        ('rx_errors', c_ulong),
        ('tx_errors', c_ulong),
        ('rx_dropped', c_ulong),
        ('tx_dropped', c_ulong),
        ('multicast', c_ulong),
        ('collisions', c_ulong),
        ('rx_length_errors', c_ulong),
        ('rx_over_errors', c_ulong),
        ('rx_crc_errors', c_ulong),
        ('rx_frame_errors', c_ulong),
        ('rx_fifo_errors', c_ulong),
        ('rx_missed_errors', c_ulong),
        ('tx_aborted_errors', c_ulong),
        ('tx_carrier_errors', c_ulong),
        ('tx_fifo_errors', c_ulong),
        ('tx_heartbeat_errors', c_ulong),
        ('tx_window_errors', c_ulong)
    ]


pcap_stat_ex_ptr = POINTER(pcap_stat_ex)
pcap_handler = CFUNCTYPE(None, POINTER(py_object), pcap_pkthdr_ptr, c_ubyte_p)
yield_ = CFUNCTYPE(None)


class FILE(Structure):
    pass


FILE_ptr = POINTER(FILE)


_pcap = None
if platform == 'win32':
    _pcap = ctypes.cdll.LoadLibrary(ctypes.util.find_library('wpcap.dll'))
else:
    _pcap = ctypes.cdll.LoadLibrary(ctypes.util.find_library('pcap'))
print _pcap


pcap_functions = globals()


def load_func(name, restype_=None, argtypes_=()):
    try:
        pcap_functions[name] = getattr(_pcap, name)
        pcap_functions[name].argtypes = argtypes_
        pcap_functions[name].restype = restype_
    except AttributeError:
        def _pcap_unsupported(*args, **kwargs):
            raise NotImplementedError('This version of libpcap does not appear to be compiled with %r support.' % name)
        pcap_functions[name] = _pcap_unsupported


load_func("pcap_lookupdev", c_char_p, [c_char_p])
load_func("pcap_lookupnet", c_int, [c_char_p, c_uint32_p, c_uint32_p, c_char_p])
load_func("pcap_open_live", pcap_t_ptr, [c_char_p, c_int, c_int, c_int, c_char_p])
load_func("pcap_open_dead", pcap_t_ptr, [c_int, c_int])
load_func("pcap_close", argtypes_=[pcap_t_ptr])
load_func("pcap_loop", c_int, [pcap_t_ptr, c_int, pcap_handler, py_object_p])
load_func("pcap_dispatch", c_int, [pcap_t_ptr, c_int, pcap_handler, py_object_p])
load_func("pcap_next", c_ubyte_p, [pcap_t_ptr, pcap_pkthdr_ptr])
load_func("pcap_next_ex", c_int, [pcap_t_ptr, POINTER(pcap_pkthdr_ptr), POINTER(c_ubyte_p)])
load_func("pcap_breakloop", argtypes_=[pcap_t_ptr])
load_func("pcap_lib_version", c_char_p)
load_func("pcap_is_swapped", c_int, [pcap_t_ptr])
load_func("pcap_major_version", c_int, [pcap_t_ptr])
load_func("pcap_minor_version", c_int, [pcap_t_ptr])
load_func("pcap_fileno", c_int, [pcap_t_ptr])
load_func("pcap_geterr", c_char_p, [pcap_t_ptr])
load_func("pcap_compile", c_int, [pcap_t_ptr, bpf_program_ptr, c_char_p, c_int, c_uint32])
load_func("pcap_setfilter", c_int, [pcap_t_ptr, bpf_program_ptr])
load_func("pcap_dump_open", pcap_dumper_t_ptr, [pcap_t_ptr, c_char_p])
load_func("pcap_dump", argtypes_=[pcap_dumper_t_ptr, pcap_pkthdr_ptr, c_char_p])
load_func('pcap_findalldevs', c_int, [POINTER(pcap_if_t_ptr), c_char_p])
load_func('pcap_findalldevs_ex', c_int, [c_char_p, pcap_rmtauth_ptr, POINTER(pcap_if_t_ptr), c_char_p])
load_func('pcap_freealldevs', argtypes_=[pcap_if_t_ptr])


def namedtuple(name, fields):
    cls = _namedtuple(name, fields)
    return type(name,
                (cls,),
                {'__getitem__': lambda s, k: getattr(s, k) if isinstance(k, str) else super(s.__class__, s).__getitem__(k)}
                )


PacketHeader = namedtuple(
        'PacketHeader',
        ('caplen', 'len', 'ts', 'comments') if platform == 'darwin' else ('caplen', 'len', 'ts')
    )
TimeStamp = namedtuple('TimeStamp', ('tv_usec', 'tv_sec'))


def _inet_ntoa(ip):
    return inet_ntop(AF_INET, pack('!L', htonl(ip)))


def _inet6_ntoa(ip):
    return inet_ntop(AF_INET6, ip)


def findalldevs():
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    devs = pcap_if_t_ptr()

    if pcap_findalldevs(pointer(devs), c_char_p((addressof(errbuf)))) == -1:
        raise Exception(str(errbuf.raw))

    return _findalldevs(devs)


def _findalldevs(devs):
    top = devs
    devices = []
    while top:
        top = top.contents
        devices.append({"name": top.name,
                        "description": top.description,
                        "addresses": top.addresses,
                        "flags": top.flags})
        top = top.next
    pcap_freealldevs(devs)
    return devices


def lookup_dev():
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    r = pcap_lookupdev(c_char_p((addressof(errbuf))))
    print r
    if not r:
        raise Exception(str(errbuf.raw))
    return r


def lookup_net(device):
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    netp = c_uint32()
    maskp = c_uint32()

    r = pcap_lookupnet(
        device,
        pointer(netp),
        pointer(maskp),
        c_char_p(addressof(errbuf))
    )
    if r == -1:
        raise Exception(str(errbuf.raw))
    return _inet_ntoa(netp.value), _inet_ntoa(maskp.value)


class TrafficLite(object):
    def __init__(self, device=None, snaplen=1024, promisc=1, to_ms=1000, file_name=None, bpf_expr=None, bpf_opt=1,
                 bpf_netmask='0.0.0.0'):
        self.device = device
        self.snaplen = snaplen
        self.promisc = promisc
        self.to_ms = to_ms

        if not self.device:
            self.device = lookup_dev()

        self._pt = self.open_live()
        print self._pt

        if bpf_expr:
            self.pcap_bpf(bpf_expr, bpf_opt, bpf_netmask)

        if file_name:
            self.dump_file(file_name)

    def open_live(self):
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        _p = pcap_open_live(self.device, self.snaplen, self.promisc, self.to_ms, c_char_p((addressof(errbuf))))
        if not _p:
            raise Exception(errbuf.raw)
        try:
            pass
            # from fcntl import ioctl
            # ioctl(self.fileno(_p), BIOCIMMEDIATE, pack("I", 1))
        except IOError as error:
            print error
        return _p

    def is_swapped(self):
        return pcap_is_swapped(self._pt) == 1

    def minor_version(self):
        return pcap_minor_version(self._pt)

    def major_version(self):
        return pcap_major_version(self._pt)

    def lib_version(self):
        return pcap_lib_version(self._pt)

    def fileno(self, _pt):
        return pcap_fileno(_pt)

    def err(self):
        return pcap_geterr(self._pt)

    def _parse_entry(self, ph, pd):
        if platform == 'darwin':
            return PacketHeader(
                caplen=ph.caplen,
                len=ph.len,
                ts=TimeStamp(tv_usec=ph.ts.tv_usec, tv_sec=ph.ts.tv_sec),
                comments=string_at(ph.comments)
            ), string_at(pd, ph.caplen)

        return PacketHeader(
            caplen=ph.caplen,
            len=ph.len,
            ts=TimeStamp(tv_usec=ph.ts.tv_usec, tv_sec=ph.ts.tv_sec)
        ), string_at(pd, ph.caplen)

    def next_p_ex(self):
        ph = pcap_pkthdr_ptr()
        pd = c_ubyte_p()
        r = pcap_next_ex(self._pt, pointer(ph), pointer(pd))
        if r in [0, -2]:
            return None
        elif r == -1:
            raise Exception(self.err())
        return self._parse_entry(ph.contents, pd)

    def next_p(self):
        ph = pcap_pkthdr()
        pd = pcap_next(self._pt, pointer(ph))
        if not pd:
            return None
        return self._parse_entry(ph, pd)

    def breakloop(self):
        pcap_breakloop(self._pt)

    def _setup_handler(self, looper, cnt, callback, user):
        def _loop_callback(user, ph, pd):
            ph, pd = self._parse_entry(ph.contents, pd)
            callback(user.contents.value, ph, pd)

        r = looper(self._pt, cnt, pcap_handler(_loop_callback), pointer(py_object(user)))
        if r == -1:
            raise Exception(self.err())
        return r

    def loop(self, cnt, callback, user):
        return self._setup_handler(pcap_loop, cnt, callback, user)

    def dispatch(self, cnt, callback, user):
        return self._setup_handler(pcap_dispatch, cnt, callback, user)

    def pcap_bpf(self, expr, opt, netmask):
        _bpf = bpf_program()
        r1 = pcap_compile(self._pt, pointer(_bpf), str(expr), opt, _inet_atoi(str(netmask)))
        if r1 == -1:
            raise Exception(self.err())
        r2 = pcap_setfilter(self._pt, pointer(_bpf))
        if r2 < 0:
            raise Exception(self.err())

    def dump_file(self, file_name):
        def _dump_callback(userarg, pkthdr, packet):
            ph = pcap_pkthdr(timeval(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec), pkthdr.caplen, pkthdr.len)
            pcap_dump(userarg, pointer(ph), packet)
        _pf = pcap_dump_open(self._pt, file_name)
        if not _pf:
            raise Exception(self.err())
        self.loop(-1, _dump_callback, _pf)

    def start_next(self):
        while 1:
            yield self.next_p()

    def start_next_ex(self):
        while 1:
            yield self.next_p_ex()

    def start_loop(self):
        pass


def _inet_atoi(ip):
    return htonl(unpack('!L', inet_aton(ip))[0])


def _inet_to_str(inet):
    # '%d.%d.%d.%d' % tuple(map(ord, list(inet)))
    try:
        return inet_ntop(AF_INET, inet)
    except ValueError:
        return inet_ntop(AF_INET6, inet)


if __name__ == '__main__':
    # for i in findalldevs():
    #     print i
    # \\Device\\NPF_{FF210A19-C0B7-4FDF-BF34-4E1EE3079AEC}
    # \\Device\\NPF_{9395A263-1678-4FBF-ABC6-951B70B5A2EF}
    t = TrafficLite(device='\\Device\\NPF_{28D7B461-0F85-499A-B5D2-D4D06D223826}', promisc=0, snaplen=10000)
    # print t.lib_version()
    t.pcap_bpf(expr='tcp', opt=1, netmask='0.0.0.0')
    for i in t.start_next_ex():
        print i
