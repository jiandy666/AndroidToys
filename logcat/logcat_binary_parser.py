from enum import Enum, unique
from struct import unpack, unpack_from
from typing import BinaryIO




@unique
class LogId(Enum):
    """ typedef enum log_id
        ref: Android source /system/core/include/log/log.h:533
    """
    LOG_ID_MAIN = 0
    LOG_ID_RADIO = 1
    LOG_ID_EVENTS = 2
    LOG_ID_SYSTEM = 3
    LOG_ID_CRASH = 4
    LOG_ID_SECURITY = 5
    LOG_ID_KERNEL = 6


class logger_entry:
    """ref: https://cs.android.com/android/platform/superproject/+/master:system/logging/liblog/include/log/log_read.h;drc=857b1f380d02a7d1dab011850257d472a27370cc;l=39
    
    """

    len: int
    "uint16_t    length of the payload"
    hdr_size: int
    "uint16_t    sizeof(struct logger_entry)"
    pid: int
    "int32_t     generating process's pid"
    tid: int
    "uint32_t    generating process's tid"
    sec: int
    "uint32_t    seconds since Epoch"
    nsec: int
    "uint32_t    nanoseconds"
    lid: int
    "uint32_t    log id of the payload, bottom 4 bits currently"
    uid: int
    "uint32_t    generating process's uid    (since v4)"

    def __init__(self, len_: int, hdr_size: int, pid: int, tid: int, sec: int, nsec: int, lid: int, uid: int) -> None:
        self.len = len_
        self.hdr_size = hdr_size
        self.pid = pid
        self.tid = tid
        self.sec = sec
        self.nsec = nsec
        self.lid = lid
        self.uid = uid




class logger_entry_header:
    pld_size: int
    "uint16_t    length of the payload"
    hdr_size: int
    "uint16_t    sizeof(struct logger_entry)"
    version: int
    "allowed: 1, 3, 4"

    def __init__(self, len_: int, hdr_size: int) -> None:
        self.pld_size = len_
        self.hdr_size = hdr_size
        if hdr_size == 28:
            self.version = 4
        elif hdr_size == 24:
            self.version = 3
        elif hdr_size == 20:
            self.version = 1
        else:
            raise LogcatParserError(
                f"logcat_parser can't recognize this logger_entry (hdr_size={hdr_size})"
            )

    @property
    def size(self) -> int:
        """ total size of log item """
        return self.pld_size + self.hdr_size


class logger_msg:
    def __init__(self, priority: str, tag: bytes, message: bytes) -> None:
        self.priority = priority
        self.tag = tag
        self.message = message


class LogItem:
    def __init__(self, version: int, entry: logger_entry, msg: logger_msg) -> None:
        self.version = version
        self.entry = entry
        self.msg = msg

    def __str__(self) -> str:
        return f"{self.entry.sec}  {self.msg.priority[0].upper()}  {self.msg.tag}  {self.msg.message}"




class LogcatParserError(Exception):
    """ Instantiate this class and raise when errors occured in the process of
        parsing.
    """




class _LogcatMessageParser:
    priority_mapper = [
        'unknown',  # 0x00
        'default',  # 0x01
        'verbose',  # 0x02
        'debug',    # 0x03
        'info',     # 0x04
        'warn',     # 0x05
        'error',    # 0x06
        'fatal',    # 0x07
        'slient'    # 0x08
    ]


    def parseMessage(self, header: logger_entry_header, binary: bytes) -> logger_msg:
        offset, end = header.hdr_size, header.size
        assert end >= len(binary)

        # parse priority
        priority_byte = binary[offset]
        offset += 1
        if priority_byte < 0 or priority_byte >= len(self.priority_mapper):
            raise LogcatParserError(
                "unknown priority bytes " + repr(priority_byte)
                )
        priority = self.priority_mapper[priority_byte]


        # parse tag
        tag_terminatin = self._indexSafe(binary, b'\x00', offset, end)
        if tag_terminatin < 0:
            raise LogcatParserError("invalid message: tag termiation not found")
        tag = binary[offset:tag_terminatin]
        offset = tag_terminatin + 1

        # parse message
        message = binary[offset:end].rstrip(b'\x00')

        return logger_msg(priority, tag, message)


    def _indexSafe(self, binary: bytes, sub: bytes, start: int, end: int) -> int:
        try:
            return binary.index(sub, start, end)
        except ValueError:
            return -1 




PARSE_LOG_BYTES_NOT_ENOUGH = LogItem(-1, None, None)


class LogcatParser:
    def __init__(self) -> None:
        self._messageParser = _LogcatMessageParser()


    def parseHeader(self, binary: bytes) -> logger_entry_header:
        size = len(binary)
        if size < 4:
            return None
        if size > 4:
            binary = binary[:4]

        len_, hdr_size = unpack('HH', binary)
        if hdr_size == 0:
            hdr_size = 20
        return logger_entry_header(len_, hdr_size)


    def parseLogItem(self, binary: bytes) -> LogItem:
        header = self.parseHeader(binary)
        if not header:
            return None
        if len(binary) < header.size:
            return PARSE_LOG_BYTES_NOT_ENOUGH

        if header.version == 4:
            return self._parseLogItem_v4(header, binary)
        elif header.version == 3:
            return self._parseLogItem_v3(header, binary)
        else:
            raise LogcatParserError(
                f"logcat_parser didn't support logger_entry version {header.version}"
            )


    def _parseLogItem_v3(self, header: logger_entry_header, binary: bytes) -> LogItem:
        assert header.version == 3
        assert header.hdr_size == 24
        assert header.size >= len(binary)

        # parse logger_entry
        pid, tid, sec, nsec, lid = \
            unpack_from('iIIII', binary, 4)
        entry = logger_entry(header.pld_size, header.hdr_size, pid, tid, sec, nsec, lid, None)

        # parse logger_msg
        msg = self._messageParser.parseMessage(header, binary)

        return LogItem(header.version, entry, msg)


    def _parseLogItem_v4(self, header: logger_entry_header, binary: bytes) -> LogItem:
        assert header.version == 4
        assert header.hdr_size == 28
        assert header.size >= len(binary)

        # parse logger_entry
        pid, tid, sec, nsec, lid, uid = \
            unpack_from('iIIIII', binary, 4)
        entry = logger_entry(header.pld_size, header.hdr_size, pid, tid, sec, nsec, lid, uid)

        # parse logger_msg
        msg = self._messageParser.parseMessage(header, binary)

        return LogItem(header.version, entry, msg)




class LogcatStream:
    def __init__(self, binary_stream: BinaryIO) -> None:
        self._steam = binary_stream
        self._parser = LogcatParser()


    def __iter__(self) -> LogItem:
        def read(n) -> bytes:
            return self._steam.read(n)

        start = 0
        try:
            while True:
                # read header
                binary = read(4)
                header = self._parser.parseHeader(binary)
                assert header is not None

                # ready entry
                binary += read(header.hdr_size - 4)

                # read message
                first = read(1)
                if first == b'\x00':
                    binary += read(header.pld_size)
                else:
                    binary += first
                    binary += read(header.pld_size - 1)

                item = self._parser.parseLogItem(binary)
                assert item is not None
                assert item != PARSE_LOG_BYTES_NOT_ENOUGH
                yield item

                start += len(binary)
        except:
            print(f'parse failed at: {hex(start)}')
            raise




if __name__ == '__main__':
    def example_binaryLogFile():
        """How to get binary log file
        ```
        $ adb logcat -B > file
        ```
        On Windows: \n
        Because of the binary output of adb.exe had been add another chars, \n
        like '\\x00' after flush stdout, and '\\n' had been replaced to '\\r\\n'. \n
        So you have to get the binary log in adb shell.
        ```
        $ adb shell
        $ logcat -B file
        $ adb pull file
        ```
        """
        file = open('Z:\\tmp\\3.log', 'rb')
        steam = LogcatStream(file)
        for item in steam:
            print(item)

    def example_ADB():
        import platform
        if platform.system().lower() == 'windows':
            raise NotImplementedError('Not working on Windows adb.exe, see the reasons in example_binaryLogFile()')
        from subprocess import Popen, PIPE

        proc = Popen(['adb', 'logcat', '-B'], stdout=PIPE, stderr=PIPE)
        stream = LogcatStream(proc.stdout)
        for item in stream:
            print(item)

    def example_pyadb():
        from ppadb.client import Client as AdbClient

        def dump_logcat(connection):
            stream = LogcatStream(connection)
            for item in stream:
                print(item)
            connection.close()

        # Default is "127.0.0.1" and 5037
        client = AdbClient(host="127.0.0.1", port=5037)
        device = client.devices()[0]
        device.shell("logcat -B", handler=dump_logcat)

    case = 0
    [
        example_binaryLogFile,
        example_ADB,
        example_pyadb
    ][case]()