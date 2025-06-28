require 'ext.gc'	-- let luajit setmetatable() also use __gc
local ffi = require 'ffi'

-- using for windows with its missing fields
local safeindex = require 'ext.op'.safeindex

local lib = ffi.C

local has_table_new, new_tab = pcall(require, "table.new")
if not has_table_new or type(new_tab) ~= "function" then
	new_tab = function() return {} end
end


local _M = {
	_VERSION = "0.1",
}

-- Linux:
-- sys/types.h has ssize_t
-- in Windows it's missing, so I wedged it in
require 'ffi.req' 'c.sys.types'

require 'ffi.req' 'c.string'	-- strerror
local errnolib = require 'ffi.req' 'c.errno'

-- Windows and Linux:
-- FILENAME_MAX, SEEK_SET, SEEK_END
-- Windows:
-- _fileno, fseek, ftell
-- ... and fileno alias
-- Linux:
-- fileno
local stdiolib = require 'ffi.req' 'c.stdio'

-- Windows:
-- _getcwd, _wgetcwd, _chdir, _wchdir, _rmdir, _wrmdir, _mkdir, _wmkdir
--require 'ffi.req' 'c.direct'
-- hmm, how come I see the non-_ names here too?  do I not need a lua alias?
-- Linux:
-- getcwd, chdir, rmdir, link, symlink, unlink, syscall, readlink
-- the ffi.c.uinstd file on Windows will instead return ffi.Windows.c.direct
local unistdlib = require 'ffi.req' 'c.unistd'

-- Windows
-- struct stat, _stat64, _wstat64
-- includes a require ffi.Windows.c.direct, which defines mkdir() (not just _mkdir?)
-- Linux:
-- struct stat, stat, lstat, mkdir
local statlib = require 'ffi.req' 'c.sys.stat'

-- sys/syslimits.h
-- https://stackoverflow.com/questions/11025939/maximum-path-constant-for-an-unc-path-on-windows
-- https://superuser.com/questions/14883/what-is-the-longest-file-path-that-windows-can-handle
-- is there no 'maxpath' equiv macro for wide-char functions?
local MAXPATH_UNC = 32767


local DirMetaParent = {}
DirMetaParent.__index = DirMetaParent
function DirMetaParent:close()
	if self.handle then
		self:findclose(self.handle)
	end
	self.handle = nil
	self.closed = true
end
function DirMetaParent:__gc()
	self:close()
end


-- misc
-- Windows-only:
local wchar_t, win_utf8_to_wchar, win_wchar_to_utf8
if ffi.os == "Windows" then
	-- in Windows:
	-- wchar.h -> corecrt_wio.h
	-- mbrtowc, _wfindfirst, _wfindnext, _wfinddata_t, _wfinddata_i64_t
	local wiolib = require 'ffi.req' 'c.wchar'

	-- corecrt_io.h
	-- _findfirst, _findnext, _finddata_t, _finddata_i64_t
	-- _setmode, _locking
	local iolib = require 'ffi.req' 'c.io'

	function wchar_t(s)
		local mbstate = ffi.new('mbstate_t[1]')
		local wcs = ffi.new('wchar_t[?]', #s + 1)
		local i = 0
		local offset = 0
		local len = #s
		while true do
			local processed = wiolib.mbrtowc(
				wcs + i, ffi.cast('const char *', s) + offset, len, mbstate)
			if processed <= 0 then break end
			i = i + 1
			offset = offset + processed
			len = len - processed
		end
		return wcs
	end

	ffi.cdef[[
// https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
// ... says LPTSTR is in WinNT.h
typedef wchar_t* LPTSTR;
// ... says BOOLEAN is in WinNT.h
typedef unsigned char BOOLEAN;
// ... says DWORD is in IntSafe.h
typedef unsigned long DWORD;

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinkw says it is in WinBase.h
BOOLEAN CreateSymbolicLinkW(
	LPTSTR lpSymlinkFileName,
	LPTSTR lpTargetFileName,
	DWORD dwFlags
);

// https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte says it is in stringapiset.h
int WideCharToMultiByte(
	unsigned int	 CodePage,
	DWORD	dwFlags,
	const wchar_t*  lpWideCharStr,
	int	  cchWideChar,
	char*	lpMultiByteStr,
	int	  cbMultiByte,
	const char*   lpDefaultChar,
	int*   lpUsedDefaultChar);

// https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar says it is in stringapiset.h
int MultiByteToWideChar(
	unsigned int	 CodePage,
	DWORD	dwFlags,
	const char*   lpMultiByteStr,
	int	  cbMultiByte,
	wchar_t*   lpWideCharStr,
	int	  cchWideChar);

// https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror says it is in errhandlingapi.h
uint32_t GetLastError();

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagea says it is in winbase.h
uint32_t FormatMessageA(
	uint32_t dwFlags,
	const void* lpSource,
	uint32_t dwMessageId,
	uint32_t dwLanguageId,
	char* lpBuffer,
	uint32_t nSize,
	va_list *Arguments
);
]]
	-- Some helper functions

	-- returns the Windows error message for the specified error
	local function errorMsgWin(lvl)
		local errcode = ffi.C.GetLastError()
		local str = ffi.new("char[?]",1024)
		local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
		local FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
		local numout = ffi.C.FormatMessageA(bit.bor(FORMAT_MESSAGE_FROM_SYSTEM,
			FORMAT_MESSAGE_IGNORE_INSERTS), nil, errcode, 0, str, 1023, nil)
		if numout == 0 then
			error("Windows Error: (Error calling FormatMessage)", lvl)
		else
			error("Windows Error: "..ffi.string(str, numout), lvl)
		end
	end
	local CP_UTF8 = 65001
	local WC_ERR_INVALID_CHARS = 0x00000080
	local MB_ERR_INVALID_CHARS  = 0x00000008

	-- TODO ... unicode_to_wchar ?
	-- returns an array of wchar_t's & size in wchar_t's
	-- upon failure returns nil and error message
	function win_utf8_to_wchar(szUtf8)
		local dwFlags = _M.wchar_errors and MB_ERR_INVALID_CHARS or 0
		local nLenWchar = lib.MultiByteToWideChar(CP_UTF8, dwFlags, szUtf8, -1, nil, 0)
		if nLenWchar == 0 then return nil, errorMsgWin(2) end
		local szUnicode = ffi.new("wchar_t[?]", nLenWchar)
		nLenWchar = lib.MultiByteToWideChar(CP_UTF8, dwFlags, szUtf8, -1, szUnicode, nLenWchar)
		if nLenWchar == 0 then return nil, errorMsgWin(2) end
		return szUnicode, nLenWchar
	end
	_M.win_utf8_to_wchar = win_utf8_to_wchar

	-- returns a Lua string
	-- upon failure returns nil and error message
	function win_wchar_to_utf8(szUnicode)
		local dwFlags = _M.wchar_errors and WC_ERR_INVALID_CHARS or 0
		local nLen = lib.WideCharToMultiByte(CP_UTF8, dwFlags, szUnicode, -1, nil, 0, nil, nil)
		if nLen == 0 then return nil, errorMsgWin(2) end
		local str = ffi.new("char[?]",nLen)
		nLen = lib.WideCharToMultiByte(CP_UTF8, dwFlags, szUnicode, -1, str, nLen, nil, nil)
		if nLen == 0 then return nil, errorMsgWin(2) end
		return ffi.string(str)
	end
	_M.win_wchar_to_utf8 = win_wchar_to_utf8

	local CP_ACP = 0
	-- returns a Lua string
	-- upon failure returns nil and error message
	function _M.win_utf8_to_acp(utf)
		local szUnicode = assert(win_utf8_to_wchar(utf))
		local dwFlags = _M.wchar_errors and WC_ERR_INVALID_CHARS or 0
		local nLen = lib.WideCharToMultiByte(CP_ACP, dwFlags, szUnicode, -1, nil, 0, nil, nil)
		if nLen == 0 then return nil, errorMsgWin(2) end
		local str = ffi.new("char[?]",nLen)
		nLen = lib.WideCharToMultiByte(CP_ACP, dwFlags, szUnicode, -1, str, nLen, nil, nil)
		if nLen == 0 then return nil, errorMsgWin(2) end
		return ffi.string(str)
	end

	function _M.setmode(file, mode)
		if io.type(file) ~= 'file' then
			error("setmode: invalid file")
		end
		if mode ~= nil and (mode ~= 'text' and mode ~= 'binary') then
			error('setmode: invalid mode')
		end
		mode = (mode == 'text') and 0x4000 or 0x8000
		local prev_mode = iolib._setmode(stdiolib.fileno(file), mode)
		if prev_mode == -1 then
			return nil, errnolib.str()
		end
		return true, (prev_mode == 0x4000) and 'text' or 'binary'
	end

	local function check_is_dir(path)
		return _M.attributes(path, 'mode') == 'directory' and 1 or 0
	end

	function _M.link(old, new)
		local is_dir = check_is_dir(old)
		if lib.CreateSymbolicLinkW(
				wchar_t(new),
				wchar_t(old), is_dir) ~= 0 then
			return true
		end
		return nil, errnolib.str()
	end


	-- TODO where do these come from?
	-- msdn says io.h or wchar.h but they weren't generated in my ffi/Windows/c/io.h or wchar.h ...
	local dir_attrs = {
		_A_ARCH = 0x20,
		_A_HIDDEN = 0x02,
		_A_NORMAL = 0x00,
		_A_RDONLY = 0x01,
		_A_SUBDIR = 0x10,
		_A_SYSTEM = 0x04
	}

	local WinDirMetaParent = {}
	for k,v in pairs(DirMetaParent) do WinDirMetaParent[k] = v end
	WinDirMetaParent.__index = WinDirMetaParent
	function WinDirMetaParent:findclose(...)	-- self isn't needed ... you could just use . instead of : and make this a function assignment ...
		return iolib._findclose(...)
	end
	function WinDirMetaParent:size()
		return self.finddata.size
	end
	function WinDirMetaParent:mode()
		return bit.band(self.finddata.attrib, dir_attrs._A_SUBDIR) ~= 0 and "directory" or "file"
	end
	function WinDirMetaParent:attr()
		if type(attr) ~= 'string' then
			return {
				size = self:size(),
				mode = self:mode(),
			}
		elseif attr == 'mode' then
			return self:mode()
		elseif attr == 'size' then
			return self:size()
		else
			-- complain?
		end
	end
	function WinDirMetaParent:next()
		assert(not self.closed, "closed directory")
		if not self.handle then
			self.handle = self:findfirst()
			if self.handle == -1 then
				self.handle = nil
				self.closed = true
				return nil, errnolib.str()
			end
		else
			if self:findnext() ~= 0 then
				self:close()
				return nil
			end
		end
		return self:name(), self
	end


	local WinSDirMeta = {}
	for k,v in pairs(WinDirMetaParent) do WinSDirMeta[k] = v end
	WinSDirMeta.__index = WinSDirMeta
	function WinSDirMeta:new(path)	-- self = mt
		if #path > stdiolib.FILENAME_MAX - 2 then
			error('path too long: ' .. path)
		end
		return setmetatable({
			_pattern = path..'/*',
			finddata = ffi.new'_finddata_t',
		}, self)
	end
	function WinSDirMeta:findfirst()
		return iolib._findfirst(self._pattern, self.finddata)
	end
	function WinSDirMeta:findnext()
		return iolib._findnext(self.handle, self.finddata)
	end
	function WinSDirMeta:name()
		return ffi.string(self.finddata.name)
	end

	function _M.sdir(...)
		local dir_obj = WinSDirMeta:new(...)
		return dir_obj.next, dir_obj
	end


	local WinWDirMeta = {}
	for k,v in pairs(WinDirMetaParent) do WinWDirMeta[k] = v end
	WinWDirMeta.__index = WinWDirMeta
	function WinWDirMeta:new(path)	-- self = mt
		if #path > MAXPATH_UNC then
			error('path too long: ' .. path)
		end
		return setmetatable({
			_pattern = path..'/*',
			finddata = ffi.new'_wfinddata_t',
		}, self)
	end
	function WinWDirMeta:findfirst()
		return wiolib._wfindfirst(assert(win_utf8_to_wchar(self._pattern)), self.finddata)
	end
	function WinWDirMeta:findnext()
		return wiolib._wfindnext(self.handle, self.finddata)
	end
	function WinWDirMeta:name()
		return assert(win_wchar_to_utf8(self.finddata.name))
	end

	function _M.wdir(...)
		local dir_obj = WinWDirMeta:new(...)
		return dir_obj.next, dir_obj
	end


	function _M.dir(path)
		if _M.use_wchar then
			return _M.wdir(path)
		else
			return _M.sdir(path)
		end
	end

	local mode_ltype_map = {
		r = 2, -- LK_NBLCK
		w = 2, -- LK_NBLCK
		u = 0, -- LK_UNLCK
	}

	local function lock(fh, mode, start, len)
		local lkmode = mode_ltype_map[mode]
		if not len or len <= 0 then
			if stdiolib.fseek(fh, 0, stdiolib.SEEK_END) ~= 0 then
				return nil, errnolib.str()
			end
			len = stdiolib.ftell(fh)
		end
		if not start or start <= 0 then
			start = 0
		end
		if stdiolib.fseek(fh, start, stdiolib.SEEK_SET) ~= 0 then
			return nil, errnolib.str()
		end
		local fd = stdiolib.fileno(fh)
		if lib._locking(fd, lkmode, len) == -1 then
			return nil, errnolib.str()
		end
		return true
	end

	function _M.lock(filehandle, mode, start, length)
		if mode ~= 'r' and mode ~= 'w' then
			error("lock: invalid mode")
		end
		if io.type(filehandle) ~= 'file' then
			error("lock: invalid file")
		end
		local ok, err = lock(filehandle, mode, start, length)
		if not ok then
			return nil, err
		end
		return true
	end

	function _M.unlock(filehandle, start, length)
		if io.type(filehandle) ~= 'file' then
			error("unlock: invalid file")
		end
		local ok, err = lock(filehandle, 'u', start, length)
		if not ok then
			return nil, err
		end
		return true
	end
else
	function _M.setmode()
		return true, "binary"
	end

	function _M.link(old, new, symlink)
		local f = symlink and unistdlib.symlink or unistdlib.link
		if f(old, new) == 0 then
			return true
		end
		return nil, errnolib.str()
	end

	-- Linux:
	-- struct dirent, DIR, opendir, readdir, closedir
	require 'ffi.req' 'c.dirent'

	local LinuxDirMeta = {}
	for k,v in pairs(DirMetaParent) do LinuxDirMeta[k] = v end
	LinuxDirMeta.__index = LinuxDirMeta
	function LinuxDirMeta:new(path)	-- self = mt
		return setmetatable({
			handle = lib.opendir(path) or error("cannot open "..path.." : "..errnolib.str()),
		}, self)
	end
	function LinuxDirMeta:findclose()	-- called by :close(), which also clears .handle
		lib.closedir(self.handle)
	end
	function LinuxDirMeta:next()
		assert(not self.closed, "closed directory")
		local dirent = lib.readdir(self.handle)
		if dirent == nil then
			self:close()
			return nil
		end
		return ffi.string(dirent.d_name)	-- , self	-- TODO provide :attr() ?
	end
	-- https://stackoverflow.com/questions/26924757/getting-file-size-using-readdir
	-- seems on POSIX you gotta do a separate call to get mode and size ...

	function _M.dir(...)
		local dir_obj = LinuxDirMeta:new(...)
		return dir_obj.next, dir_obj
	end

	local fcntllib = require 'ffi.req' 'c.fcntl'	-- 'struct flock'
	local mode_ltype_map = {
		r = fcntllib.F_RDLCK,
		w = fcntllib.F_WRLCK,
		u = fcntllib.F_UNLCK,
	}

	local function lock(fd, mode, start, len)
		local flock = ffi.new'struct flock'
		flock.l_type = mode_ltype_map[mode]
		flock.l_whence = stdiolib.SEEK_SET
		flock.l_start = start or 0
		flock.l_len = len or 0
		if fcntllib.fcntl(fd, fcntllib.F_SETLK, flock) == -1 then
			return nil, errnolib.str()
		end
		return true
	end

	function _M.lock(filehandle, mode, start, length)
		if mode ~= 'r' and mode ~= 'w' then
			error("lock: invalid mode")
		end
		if io.type(filehandle) ~= 'file' then
			error("lock: invalid file")
		end
		local fd = stdiolib.fileno(filehandle)
		local ok, err = lock(fd, mode, start, length)
		if not ok then
			return nil, err
		end
		return true
	end

	function _M.unlock(filehandle, start, length)
		if io.type(filehandle) ~= 'file' then
			error("unlock: invalid file")
		end
		local fd = stdiolib.fileno(filehandle)
		local ok, err = lock(fd, 'u', start, length)
		if not ok then
			return nil, err
		end
		return true
	end
end

-- Windows
-- sys/utime.h:
-- _utime64 / _utime32 is in sys/utime.h
-- _wutime is in sys/utime.h or wchar.h
-- struct __utimbuf32, _utime32
-- struct __utimbuf64, _utime64
--
-- Linux, OSX, POSIX:
-- utime.h:
-- struct utimbuf, utime
local utimelib = require 'ffi.req' 'c.utime'
function _M.touch(path, actime, modtime)
	local buf

	if type(actime) == "number" then
		modtime = modtime or actime
		buf = ffi.new(utimelib.struct_utimbuf)
		buf.actime  = actime
		buf.modtime = modtime
	end

	local p = ffi.new("unsigned char[?]", #path + 1)
	ffi.copy(p, path)

	if utimelib.utime(p, buf) == 0 then
		return true
	end
	return nil, errnolib.str()
end

function _M.currentdir()
	if ffi.os == 'Windows' and _M.use_wchar then
		local buf = ffi.new("wchar_t[?]", MAXPATH_UNC)
		if lib._wgetcwd(buf, MAXPATH_UNC) ~= nil then
			return win_wchar_to_utf8(buf)
		end
		return nil, "error in currentdir"
	else
		local size = stdiolib.FILENAME_MAX
		while true do
			local buf = ffi.new("char[?]", size)
			if unistdlib.getcwd(buf, size) ~= nil then
				return ffi.string(buf)
			end
			if ffi.errno() ~= errnolib.ERANGE then
				return nil, errnolib.str()
			end
			size = size * 2
		end
	end
end

function _M.chdir(path)
	assert(type(path) == 'string', 'expected string')
	local res
	if ffi.os == 'Windows' and _M.use_wchar then
		res = lib._wchdir((assert(win_utf8_to_wchar(path))))
	else
		res = unistdlib.chdir(path)
	end
	if res == 0 then return true end
	return nil, errnolib.str()
end

function _M.mkdir(path, mode)
	assert(type(path) == 'string', 'expected string')
	local res
	if ffi.os == 'Windows' then
		if _M.use_wchar then
			res = lib._wmkdir((assert(win_utf8_to_wchar(path))))
		else
			res = lib.mkdir(path)	-- TODO if this is a wrapper on windows then I can pass the mode in here.  no separate case.
		end
	else
		res = statlib.mkdir(path, mode or 509)
	end
	if res == 0 then return true end
	return nil, errnolib.str()
end

function _M.rmdir(path)
	assert(type(path) == 'string', 'expected string')
	local res
	if ffi.os == 'Windows' and _M.use_wchar then
		res = lib._wrmdir((assert(win_utf8_to_wchar(path))))
	else
		res = unistdlib.rmdir(path)
	end
	if res == 0 then return true end
	return nil, errnolib.str()
end


-- lock related
local dir_lock_struct
local create_lockfile
local delete_lockfile

if ffi.os == 'Windows' then
	ffi.cdef[[
typedef const wchar_t* LPCWSTR;
typedef struct _SECURITY_ATTRIBUTES {
	DWORD nLength;
	void *lpSecurityDescriptor;
	int bInheritHandle;
} SECURITY_ATTRIBUTES;
typedef SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew says it's in fileapi.h
void *CreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	void *hTemplateFile
);

// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle says it's in handleapi.h
int CloseHandle(void *hObject);
	]]

	local GENERIC_WRITE = 0x40000000
	local CREATE_NEW = 1
	local FILE_NORMAL_DELETE_ON_CLOSE = 0x04000080

	dir_lock_struct = 'struct {void *lockname;}'

	function create_lockfile(dir_lock, _, lockname)
		lockname = wchar_t(lockname)
		dir_lock.lockname = lib.CreateFileW(lockname, GENERIC_WRITE, 0, nil, CREATE_NEW,
				FILE_NORMAL_DELETE_ON_CLOSE, nil)
		return dir_lock.lockname ~= ffi.cast('void*', -1)
	end

	function delete_lockfile(dir_lock)
		return lib.CloseHandle(dir_lock.lockname)
	end
else
	dir_lock_struct = 'struct {char *lockname;}'
	function create_lockfile(dir_lock, path, lockname)
		dir_lock.lockname = ffi.new('char[?]', #lockname + 1)
		ffi.copy(dir_lock.lockname, lockname)
		return unistdlib.symlink(path, lockname) == 0
	end

	function delete_lockfile(dir_lock)
		return unistdlib.unlink(dir_lock.lockname)
	end
end

local function unlock_dir(dir_lock)
	if dir_lock.lockname ~= nil then
		dir_lock:delete_lockfile()
		dir_lock.lockname = nil
	end
	return true
end

local dir_lock_type = ffi.metatype(dir_lock_struct, {
	__gc = unlock_dir,
	__index = {
		free = unlock_dir,
		create_lockfile = create_lockfile,
		delete_lockfile = delete_lockfile,
	},
})

function _M.lock_dir(path, _)
	-- It's interesting that the lock_dir from vanilla lfs just ignores second paramter.
	-- So, I follow this behavior too :)
	local dir_lock = ffi.new(dir_lock_type)
	local lockname = path .. '/lockfile.lfs'
	if not dir_lock:create_lockfile(path, lockname) then
		return nil, errnolib.str()
	end
	return dir_lock
end

-- stat related
local function stat_func(filepath, buf)
	if ffi.os == 'Windows' and _M.use_wchar then
		return lib._wstat64(assert(win_utf8_to_wchar(filepath)), buf)
	else
		return statlib.stat(filepath, buf)
	end
end

local lstat_func
if ffi.os == 'Windows' then
	lstat_func = stat_func
else	-- Linux, OSX, BSD, etc
	lstat_func = statlib.lstat
end

local ftype_name_map = {}
for k,name in pairs{
-- [[ not in Windows ... will Windows return these bits anyways?  should I define them in Windows anyways?
	S_IFSOCK = 'socket',
	S_IFLNK  = 'link',
	S_IFBLK  = "block device",
	S_IFIFO  = "named pipe",
--]]
	S_IFREG  = 'file',
	S_IFDIR  = 'directory',
	S_IFCHR  = 'char device',
} do
	local v = safeindex(lib, k)
	if v then
		ftype_name_map[v] = name
	end
end

local function mode_to_ftype(mode)
	local ftype = bit.band(mode, lib.S_IFMT)
	return ftype_name_map[ftype] or 'other'
end

local function mode_to_perm(mode)
	local perm_bits = bit.band(mode, 511)	-- 511 == tonumber('777', 8)
	local perm = new_tab(9, 0)
	local i = 9
	while i > 0 do
		local perm_bit = bit.band(perm_bits, 7)
		perm[i] = (bit.band(perm_bit, 1) > 0 and 'x' or '-')
		perm[i-1] = (bit.band(perm_bit, 2) > 0 and 'w' or '-')
		perm[i-2] = (bit.band(perm_bit, 4) > 0 and 'r' or '-')
		i = i - 3
		perm_bits = bit.rshift(perm_bits, 3)
	end
	return table.concat(perm)
end

do
	local function time_or_timespec(time, timespec)
		local t = tonumber(time)
		if not t and timespec then
			t = tonumber(timespec.tv_sec)
		end
		return t
	end

	-- linux __USE_XOPEN2K8 has st_atim st_mtim st_ctim as struct timespec
	-- otherwise it has st_atime st_ctime st_mtime
	local attr_handlers = {
		blksize = function(st) return tonumber((safeindex(st, 'st_blksize'))) end,
		blocks = function(st) return tonumber((safeindex(st, 'st_blocks'))) end,
		dev = function(st) return tonumber(st.st_dev) end,
		gid = function(st) return tonumber(st.st_gid) end,
		ino = function(st) return tonumber(st.st_ino) end,
		mode = function(st) return mode_to_ftype(st.st_mode) end,
		nlink = function(st) return tonumber(st.st_nlink) end,
		permissions = function(st) return mode_to_perm(st.st_mode) end,
		rdev = function(st) return tonumber(st.st_rdev) end,
		size = function(st) return tonumber(st.st_size) end,
		uid = function(st) return tonumber(st.st_uid) end,

		-- timestamps:
		access = function(st) return time_or_timespec(safeindex(st, 'st_atime'), safeindex(st, 'st_atimespec') or safeindex(st, 'st_atim')) end,
		change = function(st) return time_or_timespec(safeindex(st, 'st_ctime'), safeindex(st, 'st_ctimespec') or safeindex(st, 'st_ctim')) end,
		modification = function(st) return time_or_timespec(safeindex(st, 'st_mtime'), safeindex(st, 'st_mtimespec') or safeindex(st, 'st_mtim')) end,
	}

	-- buf used for attributes()
	local buf = ffi.new(statlib.struct_stat)

	-- here I'm breaking/extending lfs convention to support full 64 bit, and nanosecond, time values:
	-- only add these functions if the fields are present ...
	if pcall(function() return buf.st_atim.tv_nsec ~= nil end) then
		-- so how to expose nsec access?
		-- as a second parameter? (maybe lua api compat issues)
		-- as the decimal portion? (compat issues + resolution issues)
		-- as separate functions? (clunky but best) ... and as cdata at that (so we don't lose any of the 64 bits...)
		-- store ns here (all 64 bits)
		-- leave it up to the user to access tv_sec and tv_nsec separately (to be sure they don't get split up / get stored out of sync of one another)
		attr_handlers.access_ns = function(st) return ffi.new('struct timespec', st.st_atim) end
		attr_handlers.change_ns = function(st) return ffi.new('struct timespec', st.st_ctim) end
		attr_handlers.modification_ns = function(st) return ffi.new('struct timespec', st.st_mtim) end
	elseif pcall(function() return buf.st_atimespec.tv_nsec ~= nil end) then
		-- and same but for OSX ...
		attr_handlers.access_ns = function(st) return ffi.new('struct timespec', st.st_atimespec) end
		attr_handlers.change_ns = function(st) return ffi.new('struct timespec', st.st_ctimespec) end
		attr_handlers.modification_ns = function(st) return ffi.new('struct timespec', st.st_mtimespec) end
	end

	-- Add target field for symlinkattributes, which is the absolute path of linked target
	local get_link_target_path
	if ffi.os == 'Windows' then
		get_link_target_path = function()
			return nil, "could not obtain link target: Function not implemented ", errnolib.ENOSYS
		end
	else
		get_link_target_path = function(link_path, statbuf)
			local size = statbuf.st_size
			size = size == 0 and stdiolib.FILENAME_MAX or size
			local buf = ffi.new('char[?]', size + 1)
			local read = unistdlib.readlink(link_path, buf, size)
			if read == -1 then
				return nil, "could not obtain link target: "..errnolib.str(), ffi.errno()
			end
			if read > size then
				return nil, "not enought size for readlink: "..errnolib.str(), ffi.errno()
			end
			buf[size] = 0
			return ffi.string(buf)
		end
	end

	local function safecall(f, ...)
		return f and f(...)
	end

	local function attributes(filepath, attr, follow_symlink)
		local func = follow_symlink and stat_func or lstat_func
		if func(filepath, buf) == -1 then
			return nil, string.format("cannot obtain information from file '%s' : %s", tostring(filepath), errnolib.str()), ffi.errno()
		end

		local atype = type(attr)
		if atype == 'string' then
			local value, err, errn
			if attr == 'target' and not follow_symlink then
				value, err, errn = get_link_target_path(filepath, buf)
				return value, err, errn
			else
				value = safecall(attr_handlers[attr], buf)
			end
			if value == nil then
				error("invalid attribute name '"..attr.."'")
			end
			return value
		else
			local tab = (atype == 'table') and attr or {}
			for k, _ in pairs(attr_handlers) do
				tab[k] = safecall(attr_handlers[k], buf)
			end
			if not follow_symlink then
				tab.target = get_link_target_path(filepath, buf)
			end
			return tab
		end
	end

	function _M.attributes(filepath, attr)
		return attributes(filepath, attr, true)
	end

	function _M.symlinkattributes(filepath, attr)
		return attributes(filepath, attr, false)
	end
end

_M.use_wchar = true
_M.wchar_errors = false
--this would error with _M.wchar_errors = true
--local cad = string.char(0xE0,0x80,0x80)--,0xFD,0xFF)

return _M
