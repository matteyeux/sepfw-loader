import struct
from binaryninja.binaryview import (
    BinaryView,
    BinaryReader,
)
from binaryninja.enums import Endianness
from binaryninja import mainthread
from binaryninjaui import UIContext
from binaryninja import interaction


class SEPFWView(BinaryView):
    name = "SEPFW"
    long_name = "SEPFW"

    def __init__(self, data):
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.raw = self.data
        self.binary = self.raw.read(0, len(self.raw))
        macho_list = self.get_macho_names(self.data, len(self.raw))

        print(f"Found {len(macho_list)} apps")
        [print(f" - {macho}") for macho in macho_list]

        offset = self.get_header_offset()
        sep_fw_header = self.get_fw_header(offset)
        offset += 0xC8

        choice = interaction.get_choice_input(
            "sep-firmware modules", "choices", macho_list
        )
        if choice is not None:
            print(f"extracting {macho_list[choice]}")
            if choice == 0:
                app = self.extract_sepos_kernel(sep_fw_header)
            elif choice == 1:
                app = self.extract_sepos_root(sep_fw_header)
            else:
                name = macho_list[choice]
                app = self.process_apps(sep_fw_header, offset, name, choice)

            mainthread.execute_on_main_thread_and_wait(
                lambda: UIContext.allContexts()[0].openFilename(app)
            )
        else:
            return False
        return True

    @classmethod
    def is_valid_for_data(self, data):
        if data.read(0x1004, 16) == b"Built by legion2":
            return True
        else:
            return False

    def assert_macho(self, offset):
        assert (
            struct.unpack("<I", self.data[offset : offset + 4])[0]
            == 0xFEEDFACF
        )

    def get_macho_names(self, sep, seplen) -> list:
        """Get the name of all SEP modules (which are mach-o files).
        We look for 'ffff ffff 0000 0000' and right after this pattern
        there is the name of the SEP module.
        """
        name_list = ["kernel", "SEPOS"]
        char = None
        for offset in range(0, seplen, 8):
            flag = sep.read(offset, 8)

            # stop at the first mach-o
            if b"\xcf\xfa\xed\xfe" in flag:
                break

            if flag == b"\xff\xff\xff\xff\x00\x00\x00\x00":
                name = ""
                name_addr = offset + 8
                char = sep.read(0, name_addr)
                while char != b"\x20":
                    char = sep.read(name_addr, 1)
                    name_addr += 1
                    name += char.decode("utf-8")

                name_list.append(name.split(" ")[0])
            offset += 8
        return name_list

    def get_header_offset(self) -> int:
        offset = self.binary.find(b"Built by legion2")
        assert offset > 0
        offset += 0x10
        offset = struct.unpack("<I", self.data[offset : offset + 4])[0]
        return offset

    def get_fw_header(self, offset) -> tuple:
        sep_fw_header_format = "< 16s QQ QQ QQ QQ QQ QQ QQ QQ 16s 16s QQ Q"
        sep_fw_header = struct.unpack(
            sep_fw_header_format, self.data[offset : offset + 0xC8]
        )
        return sep_fw_header

    def extract_sepos_kernel(self, sep_fw_header) -> str:
        kernel_text_offset = sep_fw_header[2]
        self.assert_macho(kernel_text_offset)
        size_offset = self.binary.find(b"__LINKEDIT", kernel_text_offset)
        assert size_offset > 0
        size_offset += 0x20  # segname -> fileoff
        kernel_size = struct.unpack(
            "<Q", self.data[size_offset : size_offset + 8]
        )[0]
        print(
            "{:#08x}-{:#08x} {}".format(
                kernel_text_offset,
                kernel_text_offset + kernel_size,
                "kernel",
            )
        )

        out_file = self.set_output_file('sepos_kernel')
        with open(out_file, "wb") as f:
            f.write(
                self.data[
                    kernel_text_offset : kernel_text_offset + kernel_size
                ]
            )

        return out_file

    def extract_sepos_root(self, sep_fw_header) -> str:
        root_text_offset = sep_fw_header[10]
        self.assert_macho(root_text_offset)
        size_offset = self.binary.find(b"__LINKEDIT", root_text_offset)
        assert size_offset > 0
        size_offset += 0x20  # segname -> fileoff
        root_size = struct.unpack(
            "<Q", self.data[size_offset : size_offset + 8]
        )[0]
        print(
            "{:#08x}-{:#08x} {}".format(
                root_text_offset,
                root_text_offset + root_size,
                "sep_root",
            )
        )
        out_file = self.set_output_file('sepos_root')
        with open(out_file, "wb") as f:
            f.write(self.data[root_text_offset : root_text_offset + root_size])

        return out_file

    def process_apps(self, sep_fw_header, offset, appname, choice) -> str:
        sep_fw_app_format = "< QQ QQ QQ QQ QQ 16s 16s Q"
        app_count = sep_fw_header[21]
        # Process the individual apps.
        for i in range(app_count):
            # Unpack the entry for this app.
            sep_fw_app = struct.unpack(
                sep_fw_app_format, self.data[offset : offset + 0x78]
            )
            text_offset = sep_fw_app[0]
            text_size = sep_fw_app[1]
            data_offset = sep_fw_app[2]
            data_size = sep_fw_app[3]
            name = sep_fw_app[10].decode("ascii").strip()
            self.assert_macho(text_offset)
            print(
                "{:#08x}-{:#08x} {:#08x}-{:#08x} {}".format(
                    text_offset,
                    text_offset + text_size,
                    data_offset,
                    data_offset + data_size,
                    name,
                )
            )
            offset += 0x78
            # Reconstruct the app binary.
            if appname == name:
                out_file = self.set_output_file(name)
                with open(out_file, "wb") as f:
                    f.write(self.data[text_offset : text_offset + text_size])
                    f.write(self.data[data_offset : data_offset + data_size])
                return out_file

    def set_output_file(self, out_name) -> str:
        """Get the path to save file."""
        filename = self.file.original_filename
        out = filename.replace(filename.split('/')[-1], out_name)
        return out
