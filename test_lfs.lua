-- luafilesystem/test_lfs.lua
-- Comprehensive Test Suite for lfs_ffi
-- Merged from multiple sources covering: Unicode, Permissions, Locks, Windows Optimizations, Nanoseconds, GC Leaks, Symlinks

-- ============================================================================
-- 0. Bootstrap & Dependencies
-- ============================================================================
local function bootstrap_paths()
    if pcall(require, 'lfs_ffi') then return end
    local function add_path(p)
        if not package.path:find(p, 1, true) then
            package.path = p .. "/?.lua;" .. p .. "/?/init.lua;" .. package.path
        end
    end
    
    -- Combine paths from all inputs
    add_path("vendor/lua-ffi-bindings")
    add_path("../vendor/lua-ffi-bindings")
    add_path(".") 
    
    local function alias_loader(name)
        local alias_map = { ffi = "lua-ffi-bindings" }
        local prefix = name:match("^(%w+)%.")
        if not prefix and alias_map[name] then prefix = name end
        if prefix and alias_map[prefix] then
            local new_name = name:gsub("^" .. prefix, alias_map[prefix])
            -- Try standard loaders
            local loader = (package.searchers or package.loaders)[2]
            local result = loader(new_name)
            if type(result) == "function" then return result end
        end
    end
    table.insert(package.searchers or package.loaders, 2, alias_loader)
end
bootstrap_paths()

local ffi = require('ffi')
local lfs = require('lfs_ffi')

-- LuaUnit loading fallback
local lu_ok, lu = pcall(require, 'luaunit')
if not lu_ok then
    local ok, res = pcall(require, 'vendor.luaunit.luaunit')
    if ok then lu = res else lu = require('luaunit') end
end

-- Fallback for vanilla lfs comparison if available
local has_vanilla, vanilla_lfs = pcall(require, 'lfs')
if not has_vanilla then vanilla_lfs = lfs end

local is_windows = (ffi.os == 'Windows')
local posix = (ffi.os ~= 'Windows')

-- Attribute names for iteration tests
local attr_names = {
    'access', 'change', 'dev', 'gid', 'ino', 'mode', 
    'modification', 'nlink', 'permissions', 'rdev', 'size', 'uid'
}
if posix then
    table.insert(attr_names, 'blksize')
    table.insert(attr_names, 'blocks')
end

-- ============================================================================
-- 1. Attributes & Permissions
-- ============================================================================
TestLfsAttributes = {}

    function TestLfsAttributes:setUp()
        self.fname = "test_attr_file"
        local f = io.open(self.fname, "w")
        f:write("content")
        f:close()
    end

    function TestLfsAttributes:tearDown()
        os.remove(self.fname)
    end

    function TestLfsAttributes:test_basic_fields()
        local info = lfs.attributes(self.fname)
        lu.assertEquals(info.mode, "file")
        lu.assertEquals(info.size, 7)
        lu.assertIsNumber(info.modification)
        lu.assertIsNumber(info.access)
    end

    function TestLfsAttributes:test_permissions_string()
        local info = lfs.attributes(self.fname)
        local perm = info.permissions
        lu.assertIsString(perm)
        lu.assertEquals(#perm, 9)
        lu.assertTrue(perm:match("^[-r][-w][-x][-r][-w][-x][-r][-w][-x]$") ~= nil)
        
        if not is_windows then
            -- On Linux/Posix we usually expect at least user read
            lu.assertEquals(perm:sub(1,1), 'r')
        end
    end

    function TestLfsAttributes:test_nanosecond_precision()
        local info = lfs.attributes(self.fname)
        -- Check for extended fields provided by lfs_ffi
        if info.modification_ns then
            lu.assertEquals(type(info.modification_ns), 'cdata')
            local sec = tonumber(info.modification_ns.tv_sec)
            lu.assertEquals(sec, math.floor(info.modification))
            
            -- Check nsec range
            local nsec = tonumber(info.modification_ns.tv_nsec)
            lu.assertTrue(nsec >= 0 and nsec < 1000000000)
        else
            print(" [INFO] Nanoseconds not supported/detected on this platform")
        end
    end

    function TestLfsAttributes:test_iterate_all_attributes()
        -- Compare with vanilla if available, or just self-consistency
        for i = 1, #attr_names do
            local attr = attr_names[i]
            local val = lfs.attributes(self.fname, attr)
            lu.assertNotNil(val, "Attribute " .. attr .. " is nil")
            
            if has_vanilla and vanilla_lfs ~= lfs then
                local v_val = vanilla_lfs.attributes(self.fname, attr)
                -- On some systems inode/dev might differ slightly between implementations
                -- but logical types should match
                lu.assertEquals(type(val), type(v_val))
            end
        end
    end

    function TestLfsAttributes:test_with_attributes_table()
        local tab = {}
        local info = lfs.attributes(self.fname, tab)
        lu.assertTrue(info == tab)
        lu.assertEquals(info.size, 7)
    end

-- ============================================================================
-- 2. Unicode & Path Handling
-- ============================================================================
TestLfsUnicode = {}

    function TestLfsUnicode:setUp()
        self.dir = "test_unicode_目录"
        self.file = self.dir .. "/测试_🚀.txt"
        self.content = "Data 🌍"
        
        if is_windows then os.execute('rmdir /s /q "' .. self.dir .. '" 2>nul')
        else os.execute('rm -rf "' .. self.dir .. '"') end
    end

    function TestLfsUnicode:tearDown()
        if is_windows then os.execute('rmdir /s /q "' .. self.dir .. '" 2>nul')
        else os.execute('rm -rf "' .. self.dir .. '"') end
    end

    function TestLfsUnicode:test_unicode_workflow()
        -- 1. mkdir
        lu.assertTrue(lfs.mkdir(self.dir))
        
        -- 2. fopen (explicit lfs.fopen or io fallback)
        if lfs.fopen then
            local f = assert(lfs.fopen(self.file, "w"))
            f:write(self.content)
            f:close()
        else
            local f = io.open(self.file, "w")
            if not f and is_windows then 
                print(" [WARN] Skipping write test, standard io.open lacks unicode support")
                return 
            end
            if f then f:write(self.content):close() end
        end

        -- 3. attributes
        local info = lfs.attributes(self.file)
        lu.assertNotNil(info)
        lu.assertEquals(info.size, #self.content)

        -- 4. dir iterator
        local found = false
        for name in lfs.dir(self.dir) do
            if name == "测试_🚀.txt" then found = true end
        end
        lu.assertTrue(found)
        
        -- 5. rename
        local new_file = self.dir .. "/renamed_测试.txt"
        local rename_func = lfs.rename_file or os.rename
        lu.assertTrue(rename_func(self.file, new_file))
        lu.assertNotNil(lfs.attributes(new_file))
    end

-- ============================================================================
-- 3. Directory Iterator & Resource Leaks
-- ============================================================================
TestLfsDirObj = {}

    function TestLfsDirObj:setUp()
        self.root = "test_dirobj"
        lfs.mkdir(self.root)
        self.files = {"a.txt", "b.txt", "c.txt"}
        for _, n in ipairs(self.files) do
            local f = io.open(self.root.."/"..n, "w"); f:write("x"); f:close()
        end
    end

    function TestLfsDirObj:tearDown()
        for _, n in ipairs(self.files) do os.remove(self.root.."/"..n) end
        lfs.rmdir(self.root)
    end

    function TestLfsDirObj:test_iterator_object_optimization()
        local iter, obj = lfs.dir(self.root)
        local count = 0
        for name in iter, obj do
            if name ~= "." and name ~= ".." then
                count = count + 1
                -- Windows Optimization: obj has cached attributes
                if is_windows and obj.size then
                    lu.assertEquals(obj:size(), 1)
                    lu.assertEquals(obj:mode(), "file")
                end
            end
        end
        lu.assertEquals(count, 3)
        
        if obj.close then
            obj:close()
            lu.assertTrue(obj.closed)
        end
    end

    function TestLfsDirObj:test_handle_leak_on_break()
        -- Verify that breaking a loop prematurely releases the handle eventually
        local iter, obj = lfs.dir(self.root)
        iter(obj) -- read one
        -- BREAK LOOP NOW, Handle is still open in 'obj'
        
        iter, obj = nil, nil
        collectgarbage() -- Force GC, __gc should close handle
        
        -- If GC didn't close handle, removing files/dir inside might fail on Windows
        local ok, err = lfs.rmdir(self.root)
        -- We expect failure here because files still exist, but check if error is about "NotEmpty" vs "AccessDenied"
        -- Ideally, we clean files first
        for _, n in ipairs(self.files) do os.remove(self.root.."/"..n) end
        
        local ok_rm, err_rm = lfs.rmdir(self.root)
        lu.assertTrue(ok_rm, "Failed to remove dir, handle likely leaked: " .. tostring(err_rm))
        
        -- Recreate for tearDown
        lfs.mkdir(self.root)
    end

    function TestLfsDirObj:test_chdir()
        local cwd = lfs.currentdir()
        local ok, err = lfs.chdir(self.root)
        lu.assertTrue(ok)
        
        local new_cwd = lfs.currentdir()
        lu.assertTrue(new_cwd:find(self.root, 1, true) ~= nil)
        
        -- Restore
        lfs.chdir(cwd)
    end

-- ============================================================================
-- 4. Concurrency, Locking & Regions
-- ============================================================================
TestLfsLock = {}

    function TestLfsLock:setUp()
        self.fname = "test_lock.dat"
        local f = io.open(self.fname, "w"); f:write("1234567890"); f:close()
    end

    function TestLfsLock:tearDown()
        os.remove(self.fname)
        os.remove("lockfile.lfs") -- Clean up lock_dir artifact
    end

    function TestLfsLock:test_region_locking()
        local f1 = io.open(self.fname, "r+")
        -- Lock bytes 0-2
        local ok, err = lfs.lock(f1, "w", 0, 2)
        lu.assertTrue(ok, err)

        local f2 = io.open(self.fname, "r+")
        -- Lock non-overlapping region (bytes 5-2)
        local ok2, err2 = lfs.lock(f2, "w", 5, 2)
        lu.assertTrue(ok2, "Region locking failed on non-overlapping segment: " .. tostring(err2))

        lfs.unlock(f1, 0, 2)
        lfs.unlock(f2, 5, 2)
        f1:close()
        f2:close()
    end

    function TestLfsLock:test_blocking_lock_child_process()
        -- Spawn child process to try locking same file
        local f = io.open(self.fname, "r+")
        local ok, err = lfs.lock(f, "w") -- Exclusive lock
        lu.assertTrue(ok, err)

        local script = [[
            local lfs = require('lfs_ffi')
            local f = io.open(']]..self.fname:gsub("\\", "/")..[[', 'r+')
            print("CHILD_START")
            -- Attempt lock, should fail or block. 
            -- Assuming non-blocking request or immediate fail behavior for test purpose
            local ok, err = lfs.lock(f, "w", 0, 0) 
            if ok then print("CHILD_LOCKED") else print("CHILD_FAILED") end
            f:close()
        ]]
        
        local script_file = "test_child_lock.lua"
        local fs = io.open(script_file, "w"); fs:write(script); fs:close()
        
        local cmd = string.format('luajit %s', script_file)
        local p = io.popen(cmd)
        local output = p:read("*a") or ""
        p:close()
        
        lfs.unlock(f)
        f:close()
        os.remove(script_file)
        
        lu.assertStrContains(output, "CHILD_FAILED")
    end

    function TestLfsLock:test_lock_dir_lifecycle()
        -- 1. Lock
        local lock_obj, err = lfs.lock_dir(".")
        lu.assertNotNil(lock_obj, err)
        
        -- Verify lockfile existence
        local attr = lfs.attributes("lockfile.lfs")
        lu.assertNotNil(attr)
        
        -- 2. Try Lock Again (Should Fail)
        local lock_obj2, err2 = lfs.lock_dir(".")
        lu.assertNil(lock_obj2)
        
        -- 3. Free/Unlock
        lock_obj:free()
        
        -- Verify lockfile gone
        local attr_gone = lfs.attributes("lockfile.lfs")
        lu.assertNil(attr_gone)
    end

-- ============================================================================
-- 5. Symlinks (Hard vs Soft)
-- ============================================================================
TestLfsSymlink = {}

    function TestLfsSymlink:setUp()
        self.target = "target_file.txt"
        self.link = "link_test"
        local f = io.open(self.target, "w"); f:write("target"); f:close()
    end

    function TestLfsSymlink:tearDown()
        os.remove(self.link)
        os.remove(self.target)
    end

    function TestLfsSymlink:test_hard_link()
        local ok, err = lfs.link(self.target, self.link, false)
        
        if not ok and is_windows then
            print(" [INFO] Hard link failed (perm?): " .. tostring(err))
            return
        end
        lu.assertTrue(ok, err)
        
        local info1 = lfs.attributes(self.target)
        local info2 = lfs.attributes(self.link)
        lu.assertEquals(info1.size, info2.size)
        lu.assertEquals(info2.mode, "file")
    end

    function TestLfsSymlink:test_soft_link()
        local ok, err = lfs.link(self.target, self.link, true)
        
        if not ok and is_windows then
            print(" [INFO] Symlink failed (requires Developer Mode/Admin): " .. tostring(err))
            return
        end
        lu.assertTrue(ok, err)
        
        -- symlinkattributes should show 'link'
        local s_attr = lfs.symlinkattributes(self.link)
        lu.assertEquals(s_attr.mode, "link")
        
        -- attributes should show 'file' (follow link)
        local attr = lfs.attributes(self.link)
        lu.assertEquals(attr.mode, "file")
        
        if s_attr.target then
            lu.assertTrue(s_attr.target:find(self.target) ~= nil)
        end
    end

-- ============================================================================
-- 6. SetMode & Time Touch
-- ============================================================================
TestLfsMisc = {}

    function TestLfsMisc:setUp()
        self.temp = 'temp_misc'
        local f = io.open(self.temp, 'w'); f:write('a'); f:close()
    end

    function TestLfsMisc:tearDown()
        os.remove(self.temp)
    end

    function TestLfsMisc:test_setmode()
        if is_windows then
            local f = io.open(self.temp, 'r')
            local ok, mode = lfs.setmode(f, 'binary')
            lu.assertTrue(ok)
            lu.assertTrue(mode == 'text' or mode == 'binary')
            f:close()
        end
    end

    function TestLfsMisc:test_touch_time_travel()
        -- Test setting time to the past (Birthday of Lua: 1993-07-28)
        local past_time = 743817600
        local ok, err = lfs.touch(self.temp, past_time, past_time)
        lu.assertTrue(ok, err)
        
        local info = lfs.attributes(self.temp)
        lu.assertTrue(math.abs(info.modification - past_time) < 2)
    end

-- ============================================================================
-- 7. Edge Cases & Errors
-- ============================================================================
TestLfsEdge = {}

    function TestLfsEdge:test_rmdir_not_empty()
        local d = "dir_not_empty"
        lfs.mkdir(d)
        local f = io.open(d.."/f", "w"); f:write("x"); f:close()
        
        local ok, err = lfs.rmdir(d)
        lu.assertNil(ok)
        lu.assertNotNil(err)
        
        os.remove(d.."/f")
        lfs.rmdir(d)
    end

    function TestLfsEdge:test_attributes_nonexistent()
        local info, err = lfs.attributes('nonexistent_file_xyz')
        lu.assertNil(info)
        lu.assertStrContains(err, 'No such file')
    end

os.exit(lu.LuaUnit.run())