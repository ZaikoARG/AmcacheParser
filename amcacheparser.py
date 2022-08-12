# (c) Maxim Suhanov


import json
import ctypes
import argparse
import os
from platform import system, version
import sys
from Registry import Registry

__revision__ = 4 # This value will be incremented each time this module is updated.

# Definitions: constants and structures
_TOKEN_ADJUST_PRIVILEGES = 0x20
_SE_PRIVILEGE_ENABLED = 0x2
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_TEMPORARY = 0x100
_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
_FILE_SHARE_READ = 1
_FILE_SHARE_WRITE = 2
_FILE_SHARE_DELETE = 4
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_KEY_READ = 0x20019
_KEY_WOW64_64KEY = 0x100
_STATUS_INVALID_PARAMETER = ctypes.c_int32(0xC000000D).value
_REG_NO_COMPRESSION = 4

_INVALID_SET_FILE_POINTER = 0xFFFFFFFF

_HKEY_USERS = 0x80000003
_HKEY_LOCAL_MACHINE = 0x80000002

class _LUID(ctypes.Structure):
	_fields_ = [ ('LowPart', ctypes.c_uint32), ('HighPart', ctypes.c_int32) ]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [ ('Luid', _LUID), ('Attributes', ctypes.c_uint32) ]


class _TOKEN_PRIVILEGES_5(ctypes.Structure): # This defines 5 array elements.
	_fields_ = [ ('PrivilegeCount', ctypes.c_uint32), ('Privilege0', _LUID_AND_ATTRIBUTES),
		('Privilege1', _LUID_AND_ATTRIBUTES), ('Privilege2', _LUID_AND_ATTRIBUTES),
		('Privilege3', _LUID_AND_ATTRIBUTES), ('Privilege4', _LUID_AND_ATTRIBUTES) ]

# Definitions: functions (API)
ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
ctypes.windll.kernel32.GetCurrentProcess.argtypes = []

ctypes.windll.advapi32.LookupPrivilegeValueW.restype = ctypes.c_int32
ctypes.windll.advapi32.LookupPrivilegeValueW.argtypes = [  ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p ]

ctypes.windll.advapi32.OpenProcessToken.restype = ctypes.c_int32
ctypes.windll.advapi32.OpenProcessToken.argtypes = [ ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.AdjustTokenPrivileges.restype = ctypes.c_int32
ctypes.windll.advapi32.AdjustTokenPrivileges.argtypes = [ ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p ]

ctypes.windll.kernel32.GetLastError.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetLastError.argtypes = []

ctypes.windll.kernel32.CloseHandle.restype = ctypes.c_int32
ctypes.windll.kernel32.CloseHandle.argtypes = [ ctypes.c_void_p ]

ctypes.windll.kernel32.CreateFileW.restype = ctypes.c_void_p
ctypes.windll.kernel32.CreateFileW.argtypes = [ ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.RegOpenKeyExW.restype = ctypes.c_int32
ctypes.windll.advapi32.RegOpenKeyExW.argtypes = [ ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.RegCloseKey.restype = ctypes.c_int32
ctypes.windll.advapi32.RegCloseKey.argtypes = [ ctypes.c_void_p ]

ctypes.windll.advapi32.RegOpenCurrentUser.restype = ctypes.c_int32
ctypes.windll.advapi32.RegOpenCurrentUser.argtypes = [ ctypes.c_uint32, ctypes.c_void_p ]

_APP_HIVES_SUPPORTED = hasattr(ctypes.windll.advapi32, 'RegLoadAppKeyW')
if _APP_HIVES_SUPPORTED:
	ctypes.windll.advapi32.RegLoadAppKeyW.restype = ctypes.c_int32
	ctypes.windll.advapi32.RegLoadAppKeyW.argtypes = [ ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32 ]

ctypes.windll.ntdll.NtSaveKeyEx.restype = ctypes.c_int32
ctypes.windll.ntdll.NtSaveKeyEx.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32 ]

ctypes.windll.kernel32.GetTempFileNameA.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetTempFileNameA.argtypes = [ ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.kernel32.SetFilePointer.restype = ctypes.c_uint32
ctypes.windll.kernel32.SetFilePointer.argtypes = [ ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32 ]

ctypes.windll.kernel32.ReadFile.restype = ctypes.c_int32
ctypes.windll.kernel32.ReadFile.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p ]


class NTFileLikeObject(object):
    # This class implements a read-only file-like object for a given file handle (as returned by the CreateFile() routine).

	def __init__(self, handle):
		self.handle = handle
		self.max_size = self.seek(0, 2)
		self.seek(0, 0)

	def seek(self, offset, whence = 0):
		offset = ctypes.windll.kernel32.SetFilePointer(self.handle, offset, None, whence)
		if offset == _INVALID_SET_FILE_POINTER:
			raise OSError('The SetFilePointer() routine failed')

		return offset

	def tell(self):
		return self.seek(0, 1)

	def read(self, size = None):
		if size is None or size < 0:
			size = self.max_size - self.tell()

		if size <= 0: # Nothing to read.
			return b''

		buffer = ctypes.create_string_buffer(size)
		size_out = ctypes.c_uint32()

		result = ctypes.windll.kernel32.ReadFile(self.handle, ctypes.byref(buffer), size, ctypes.byref(size_out), None)
		if result == 0:
			last_error = ctypes.windll.kernel32.GetLastError()
			raise OSError('The ReadFile() routine failed with this status: {}'.format(last_error))

		return buffer.raw[ : size_out.value]

	def close(self):
		ctypes.windll.kernel32.CloseHandle(self.handle)


class RegistryHivesLive(object):

	def __init__(self):
		self._src_handle = None
		self._dst_handle = None

		self._hkcu_handle = None

		# Acquire the backup privilege.
		self._lookup_process_handle_and_backup_privilege()
		self._acquire_backup_privilege()

	def _lookup_process_handle_and_backup_privilege(self):

		self._proc = ctypes.windll.kernel32.GetCurrentProcess()

		self._backup_luid = _LUID()
		result = ctypes.windll.advapi32.LookupPrivilegeValueW(None, 'SeBackupPrivilege', ctypes.byref(self._backup_luid))
		if result == 0:
			raise OSError('The LookupPrivilegeValueW() routine failed to resolve the \'SeBackupPrivilege\' name')

	def _acquire_backup_privilege(self):

		handle = ctypes.c_void_p()

		result = ctypes.windll.advapi32.OpenProcessToken(self._proc, _TOKEN_ADJUST_PRIVILEGES, ctypes.byref(handle))
		if result == 0:
			raise OSError('The OpenProcessToken() routine failed to provide the TOKEN_ADJUST_PRIVILEGES access')

		tp = _TOKEN_PRIVILEGES_5()
		tp.PrivilegeCount = 1
		tp.Privilege0 = _LUID_AND_ATTRIBUTES()
		tp.Privilege0.Luid = self._backup_luid
		tp.Privilege0.Attributes = _SE_PRIVILEGE_ENABLED

		result_1 = ctypes.windll.advapi32.AdjustTokenPrivileges(handle, False, ctypes.byref(tp), 0, None, None)
		result_2 = ctypes.windll.kernel32.GetLastError()
		if result_1 == 0 or result_2 != 0:
			ctypes.windll.kernel32.CloseHandle(handle)
			raise OSError('The AdjustTokenPrivileges() routine failed to set the backup privilege')

		ctypes.windll.kernel32.CloseHandle(handle)

	def _create_destination_handle(self, FilePath):

		if FilePath is None:
			file_attr = _FILE_ATTRIBUTE_TEMPORARY | _FILE_FLAG_DELETE_ON_CLOSE
			FilePath = self._temp_file()
		else:
			file_attr = _FILE_ATTRIBUTE_NORMAL

		handle = ctypes.windll.kernel32.CreateFileW(FilePath, _GENERIC_READ | _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE, None, _CREATE_ALWAYS, file_attr, None)
		if handle == _INVALID_HANDLE_VALUE:
			raise OSError('The CreateFileW() routine failed to create a file')

		self._dst_handle = handle
		return FilePath

	def _close_destination_handle(self):

		ctypes.windll.kernel32.CloseHandle(self._dst_handle)
		self._dst_handle = None

	def _open_root_key(self, PredefinedKey, KeyPath, WOW64 = False):

		handle = ctypes.c_void_p()

		if not WOW64:
			access_rights = _KEY_READ
		else:
			access_rights = _KEY_READ | _KEY_WOW64_64KEY

		result = ctypes.windll.advapi32.RegOpenKeyExW(PredefinedKey, KeyPath, 0, access_rights, ctypes.byref(handle))
		if result != 0:
			raise OSError('The RegOpenKeyExW() routine failed to open a key')

		self._src_handle = handle

	def _load_application_hive(self, HivePath):

		if not _APP_HIVES_SUPPORTED:
			raise OSError('Application hives are not supported on this system')

		handle = ctypes.c_void_p()
		result = ctypes.windll.advapi32.RegLoadAppKeyW(HivePath, ctypes.byref(handle), _KEY_READ, 0, 0)
		if result != 0:
			raise OSError('The RegLoadAppKeyW() routine failed to load a hive')

		self._src_handle = handle

	def _close_root_key(self):

		ctypes.windll.advapi32.RegCloseKey(self._src_handle)
		self._src_handle = None

	def _do_container_check(self, file_object):

		signature = file_object.read(4)
		if signature != b'regf':
			raise OSError('The exported hive is invalid')

		seq_1 = file_object.read(4)
		seq_2 = file_object.read(4)

		if seq_1 == seq_2 == b'\x01\x00\x00\x00': # This looks like a hive exported from a live container.
			import sys
			print('It seems that you run this script from inside of a container (see the docstring for the RegistryHivesLive class)', file = sys.stderr)

		file_object.seek(0, 0)

	def open_hive_by_key(self, RegistryPath, FilePath = None):

		if self._src_handle is not None:
			self._close_root_key()

		if self._dst_handle is not None:
			self._dst_handle = None

		PredefinedKey, KeyPath = self._resolve_path(RegistryPath)

		FilePath = self._create_destination_handle(FilePath)
		try:
			self._open_root_key(PredefinedKey, KeyPath)
		except Exception:
			self._close_destination_handle()
			raise

		result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)
		if result == _STATUS_INVALID_PARAMETER: # We are running under the Wow64 subsystem.
			self._close_root_key()
			try:
				self._open_root_key(PredefinedKey, KeyPath, True)
			except Exception:
				self._close_destination_handle()
				raise

			result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)

		if result != 0:
			self._close_root_key()
			self._close_destination_handle()
			raise OSError('The NtSaveKeyEx() routine failed with this status: {}'.format(hex(result)))

		self._close_root_key()

		f = NTFileLikeObject(self._dst_handle)
		self._do_container_check(f)
		return f

	def open_apphive_by_file(self, AppHivePath, FilePath = None):

		if self._src_handle is not None:
			self._close_root_key()

		if self._dst_handle is not None:
			self._dst_handle = None

		FilePath = self._create_destination_handle(FilePath)
		try:
			self._load_application_hive(AppHivePath)
		except Exception:
			self._close_destination_handle()
			raise

		result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)
		if result != 0:
			self._close_root_key()
			self._close_destination_handle()
			raise OSError('The NtSaveKeyEx() routine failed with this status: {}'.format(hex(result)))

		self._close_root_key()

		f = NTFileLikeObject(self._dst_handle)
		self._do_container_check(f)
		return f

	def _resolve_predefined_key(self, PredefinedKeyStr):
		"""Convert a predefined key (as a string) to an integer."""

		predef_str = PredefinedKeyStr.upper()

		if predef_str == 'HKU' or predef_str == 'HKEY_USERS':
			return _HKEY_USERS

		if predef_str == 'HKCU' or predef_str == 'HKEY_CURRENT_USER':
			if self._hkcu_handle is None:
				handle = ctypes.c_void_p()
				result = ctypes.windll.advapi32.RegOpenCurrentUser(_KEY_READ, ctypes.byref(handle))
				if result != 0:
					raise OSError('The RegOpenCurrentUser() routine failed to open a root key')

				self._hkcu_handle = handle

			return self._hkcu_handle

		if predef_str == 'HKLM' or predef_str == 'HKEY_LOCAL_MACHINE':
			return _HKEY_LOCAL_MACHINE

		raise ValueError('Cannot resolve this predefined key or it is not supported: {}'.format(PredefinedKeyStr))

	def _resolve_path(self, PathStr):
		"""Resolve a registry path (as a string), return a tuple (predefined_key, key_path)."""

		path_components = PathStr.split('\\')
		if len(path_components) == 0:
			raise ValueError('The registry path specified contains no path components')

		predefined_key = self._resolve_predefined_key(path_components[0])
		key_path = '\\'.join(path_components[1 : ])

		return (predefined_key, key_path)

	def _temp_file(self):
		"""Get and return a path for a temporary file."""

		buffer = ctypes.create_string_buffer(513)
		result = ctypes.windll.kernel32.GetTempFileNameA(b'.', b'hiv', 0, ctypes.byref(buffer))
		if result == 0:
			raise OSError('The GetTempFileNameA() routine failed to create a temporary file')

		tempfile = buffer.value.decode()

		return tempfile


class AmcacheParser:
    def __init__(self, file_path: str):
        # Get Hive Handle
        self.handle = RegistryHivesLive().open_apphive_by_file(file_path)
    
    def parse(self, output_file: str, search_key: str | list=None):
        r = Registry.Registry(self.handle) # Open Hive
        
        root = r.open("Root") # Open Root Key
        
        self.file_dict = {}
        
        with open(output_file, 'w') as jsonfile:
            root_subkeys = root.subkeys()
            
            if (search_key != None and isinstance(search_key, str)
                and not search_key in [subkey.name() for subkey in root_subkeys]):
                
                print("The key specified not exist")
                sys.exit(1)
            
            elif search_key != None and isinstance(search_key, list):
                for key in search_key:
                    if key not in [subkey.name() for subkey in root_subkeys]:
                        print("The key specified not exist")
                        sys.exit(1)
                    continue
                
            for subkey in root_subkeys:
                if search_key != None and isinstance(search_key, str) and subkey.name() != search_key:
                    continue
                elif search_key != None and isinstance(search_key, list) and subkey.name() not in search_key:
                    continue
                self.file_dict[subkey.name()] = {}
                list(map(self.mapper, subkey.subkeys()))
                
            jsonfile.write(json.dumps(self.file_dict, indent=4, sort_keys=True))
    
    def mapper(self, key: Registry.RegistryKey) -> None:
        key_name = key.name()
        
        values_dict = {}
        
        for value in key.values():
            values_dict[value.name()] = str(value.value())
        self.file_dict[list(self.file_dict.keys())[len(self.file_dict) - 1]][key_name] = values_dict
        
        return
        

def isAdmin() -> bool:
	try:
		return os.getuid() == 0
	except AttributeError:
		return ctypes.windll.shell32.IsUserAnAdmin() != 0


def main():
    # Define Description
    msg = "Forensic Windows Tool to parse the Amcache.hve file"
    
    # Define Argument Parser
    parser = argparse.ArgumentParser(description=msg)
    
    group = parser.add_mutually_exclusive_group(required=True)
    
    # Add Arguments
    group.add_argument("-f", 
                        "--file",
                        type=str,
                        help="Path of the Amcache.hve file (or other Hive File)")
    group.add_argument("-l",
                       "--live-amcache",
                       help="Parse the Live Amcache.hve file of your system.",
                       action='store_true')
    parser.add_argument("-o",
                        "--output",
                        type=str,
                        help="Output JSON file path",
                        required=True)
    parser.add_argument("-k",
                        "--key",
                        type=str,
                        help="Return only the content of the specified key (search for multiple keys by separating them with a comma)",
                        required=False)
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    # Parse Args 
    args = parser.parse_args()
    
    # Define Vars
    if args.live:
        if system() == 'Windows' and int(version().split(".")[0]) < 7:
            print("Your system is not compatible with Amcache.hve")
            sys.exit(1)
        filepath = r"C:\Windows\appcompat\Programs\Amcache.hve"
    else:
        filepath = args.file
        
    output = args.output
    if not args.key is None:
        key = args.key.split(",")
    else:
        key = None
        
    # Checks
    if not os.path.exists(filepath):
        print("Input File not exist")
        sys.exit(1)
    
    # Define AmcacheParser Object
    try:
        ap = AmcacheParser(filepath)
    except OSError:
        if isAdmin():
            print("Error loading hive")
            sys.exit(1)
        else:
            print("Error loading hive. Try execute how administrator")
            sys.exit(1)
            
    # Parse Amcache
    ap.parse(output, search_key=key)


if __name__ == '__main__':
    main()