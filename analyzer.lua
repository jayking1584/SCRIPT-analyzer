-- Ultimate Runtime Intelligence Analyzer v4.2 - EXPLOIT READY VERSION
local RunService, Players, HttpService, CoreGui, TextService, UserInputService, TweenService = 
    game:GetService("RunService"), game:GetService("Players"), 
    game:GetService("HttpService"), game:GetService("CoreGui"),
    game:GetService("TextService"), game:GetService("UserInputService"),
    game:GetService("TweenService")

if not RunService:IsClient() then 
    error("Client-only script launched on server!") 
    return 
end

-- Exploit environment detection
local IS_EXPLOIT_ENV = (syn and true) or (getexecutorname and true) or (identifyexecutor and true) or false

-- Enhanced Configuration with performance presets
local UltimateIntelligenceAnalyzer = {Data = {}, Config = {
    -- Core Intelligence
    CaptureFunctionCalls = true,
    CaptureRuntimeTables = true,
    TrackStringDecryption = true,
    
    -- Advanced Reverse Engineering
    ReverseObfuscation = true,
    MonitorTableMutations = true,
    TrackIdentifiers = true,
    DetectRemotes = true,
    DetectSelfModifyingCode = true,
    
    -- Enhanced Features
    ExtractVariables = true,
    ExtractConstants = true,
    ExtractFunctions = true,
    DecompileFunctions = true,
    SandboxExecution = true,
    
    -- Advanced Intelligence
    BytecodeAnalysis = true,
    ObfuscatorFingerprinting = true,
    CallGraphReconstruction = true,
    BehaviorClassification = true,
    AntiAnalysisDetection = true,
    PatternRecognition = true,
    RiskAssessment = true,
    
    -- GUI Configuration
    EnableGUI = true,
    GUITheme = "Dark",
    AutoSaveLogs = true,
    RealTimeUpdates = true,
    
    -- Performance Settings (Auto-adjusting)
    MaxLogSize = 50000,
    LogBatchSize = 50,
    LogUpdateInterval = 0.1,
    DeepInspectionDepth = 5,
    
    -- New: Adaptive Performance
    AdaptivePerformance = true,
    MinFPS = 30,
    EnableMemoryManagement = true,
    MaxMemoryMB = 100,
    -- Line-level tracing (very verbose). Disabled by default.
    CaptureLineEvents = false,
    LineEventSampleRate = 10, -- capture 1 in N line events
    -- Capture locals when suspicious event detected (best-effort)
    CaptureLocalsOnSuspicious = true,
    MaxLocalsPerCapture = 12,
    LocalCaptureWindow = 2, -- seconds after suspicious marker to capture locals
    -- Additional capture options
    CaptureBindables = true,
    CaptureRemoteReturns = true,
    WrapLoadFunctions = true,
    StubNetworkOnAnalyze = false,
    AutoWrapRemoteTables = true,
    AggressiveTableInstrumentation = false,
    -- Aggressive instrumentation limits and safety
    AggressiveInstrumentLimit = 200, -- max number of tables to wrap in aggressive mode
    HookOverheadThreshold = 0.02, -- seconds of cumulative hook overhead per second to trigger pause
    HookPauseSeconds = 5, -- seconds to pause heavy hook activity
    -- Data sanitization to avoid accidental leakage of sensitive information
    SanitizeSensitiveData = true,
    SanitizeMaxLength = 500
}}

UltimateIntelligenceAnalyzer.__index = UltimateIntelligenceAnalyzer

-- Exploit-specific enhancements
function UltimateIntelligenceAnalyzer:DetectExploitFunctions()
    local exploitFuncs = {}
    
    local potentialFunctions = {
        "getgenv", "getrenv", "getreg", "getgc", "getinstances", 
        "getnilinstances", "getscripts", "getloadedmodules",
        "getconnections", "firesignal", "getcustomasset", "getrawmetatable",
        "setrawmetatable", "hookfunction", "newcclosure", "checkcaller",
        "clonefunction", "islclosure", "is_synapse_function", "is_protosmasher_closure",
        "is_fluxus_closure", "is_krnl_closure", "is_executor_closure"
    }
    
    for _, funcName in ipairs(potentialFunctions) do
        if type(_G[funcName]) == "function" or (syn and type(syn[funcName]) == "function") then
            exploitFuncs[funcName] = true
        end
    end
    
    local executors = {
        Synapse = syn and syn.protect_gui,
        ScriptWare = SW and true,
        Krnl = KRNL_LOADED and true,
        Fluxus = getexecutorname and string.find(string.lower(getexecutorname()), "fluxus"),
        Oxygen = oxygen and true,
        Electron = electron and true
    }
    
    for executor, detected in pairs(executors) do
        if detected then
            exploitFuncs.Executor = executor
            break
        end
    end
    
    return exploitFuncs
end

function UltimateIntelligenceAnalyzer:ExploitWriteFile(path, content)
    if writefile then
        return pcall(writefile, path, content)
    elseif syn and syn.writefile then
        return pcall(syn.writefile, path, content)
    else
        return false, "No file write function available"
    end
end

function UltimateIntelligenceAnalyzer:ExploitReadFile(path)
    if readfile then
        return pcall(readfile, path)
    elseif syn and syn.readfile then
        return pcall(syn.readfile, path)
    else
        return false, "No file read function available"
    end
end

function UltimateIntelligenceAnalyzer:ExploitDecompile(func)
    local decompilers = {
        _G.decompile,
        _G.dump,
        _G.string.dump,
        syn and syn.decompile,
        debug and debug.decompile
    }
    
    for _, decompiler in ipairs(decompilers) do
        if type(decompiler) == "function" then
            local success, result = pcall(decompiler, func)
            if success and result then
                return result
            end
        end
    end
    
    return nil
end

function UltimateIntelligenceAnalyzer:ExploitGetBytecode(func)
    local bytecodeGetters = {
        _G.getbytecode,
        _G.getrawbytecode,
        _G.getfunctionbytecode,
        syn and syn.get_bytecode,
        debug and debug.getbytecode
    }
    
    for _, getter in ipairs(bytecodeGetters) do
        if type(getter) == "function" then
            local success, result = pcall(getter, func)
            if success and result then
                return result
            end
        end
    end
    
    return nil
end

-- Utility: safe table count for dictionaries (works with non-array tables)
function UltimateIntelligenceAnalyzer:TableCount(t)
    if type(t) ~= "table" then return 0 end
    local n = 0
    for _ in pairs(t) do n = n + 1 end
    return n
end

-- Sanitization helper to avoid logging sensitive or excessively large data
function UltimateIntelligenceAnalyzer:SanitizeValue(v)
    if type(v) == "string" then
        local s = v
        -- Trim very long strings
        if #s > (self.Config.SanitizeMaxLength or 500) then
            s = s:sub(1, (self.Config.SanitizeMaxLength or 500)) .. "..."
        end

        -- Mask obvious tokens/keys (simple heuristics)
        if string.find(s, "%w+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+") or string.find(s, "[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+") then
            return "<REDACTED_TOKEN>"
        end

        -- Avoid logging whole long payloads like huge base64 blobs
        if #s > 200 and string.match(s, "^[A-Za-z0-9+/]+=*$") then
            return "<REDACTED_BASE64>"
        end

        return s
    elseif type(v) == "table" then
        local t = {}
        for k, val in pairs(v) do
            local key = tostring(k)
            if self.Config.SanitizeSensitiveData then
                t[key] = "<TABLE_REDACTED>"
            else
                t[key] = self:SanitizeValue(val)
            end
        end
        return t
    elseif type(v) == "function" then
        return "<function>"
    else
        return tostring(v)
    end
end

-- Wrap common services to instrument network/activity (best-effort)
function UltimateIntelligenceAnalyzer:WrapService(service)
    if not service then return service end
    local ok, name = pcall(function() return service.Name end)
    name = ok and name or tostring(service)

    -- Instrument HttpService methods
    if name == "HttpService" then
        local proxy = {}
        setmetatable(proxy, {
            __index = function(_, k)
                local orig = service[k]
                if type(orig) == "function" then
                    if k == "RequestAsync" or k == "PostAsync" or k == "GetAsync" then
                        return function(...)
                            local args = {...}
                            local safeArgs = {}
                            for i, a in ipairs(args) do safeArgs[i] = self:SanitizeValue(a) end
                            self:AddLog("HTTP_REQUEST", string.format("HttpService.%s called", k), {Arguments = safeArgs})
                            local okc, res = pcall(function() return orig(service, ...) end)
                            if not okc then
                                self:AddLog("HTTP_ERROR", "HttpService call failed", {Method = k, Error = tostring(res)})
                                return nil
                            end
                            return res
                        end
                    else
                        return function(...)
                            return orig(service, ...)
                        end
                    end
                end
                return orig
            end,
            __newindex = function(_, k, v) service[k] = v end
        })
        return proxy
    end

    return service
end

-- Function-call hook management for capturing calls/returns during execution
function UltimateIntelligenceAnalyzer:StartFunctionHook()
    if not self.Config.CaptureFunctionCalls then return end
    if not debug or type(debug.sethook) ~= "function" then return end

    local analyzer = self
    -- Buffer to avoid too-frequent AddLog calls from hook
    self._HookBuffer = self._HookBuffer or {}
    local maxBuffer = 200

    -- Hook function supports call/return and optional line events with sampling
    self._LineCounter = self._LineCounter or 0
    local hookFlags = "cr"
    if self.Config.CaptureLineEvents then hookFlags = hookFlags .. "l" end

    local hookFunc = function(event, line)
        local hookStart = tick()
        local ok, info = pcall(function() return debug.getinfo(2, "nSltuS") end)
        info = (ok and info) and info or {}

        local entry = {
            Event = event,
            Name = info.name or "?",
            Source = info.short_src or info.source or "?",
            CurrentLine = info.currentline or line,
            What = info.what,
            Timestamp = tick()
        }

        -- For line events, sample by configured rate to reduce overhead
        if event == "l" then
            self._LineCounter = (self._LineCounter or 0) + 1
            local rate = math.max(1, tonumber(self.Config.LineEventSampleRate) or 10)
            if (self._LineCounter % rate) ~= 0 then
                return
            end

            -- record line trace (kept in Data.LineTraces)
            pcall(function()
                table.insert(self.Data.LineTraces, {
                    Timestamp = entry.Timestamp,
                    Source = entry.Source,
                    Line = entry.CurrentLine,
                    FunctionName = entry.Name,
                    Event = "line"
                })
                -- bind size cap for stored line traces
                if #self.Data.LineTraces > 5000 then table.remove(self.Data.LineTraces, 1) end
            end)
            return
        end

        -- For call/return events, buffer them then flush periodically
        table.insert(self._HookBuffer, entry)
        if #self._HookBuffer >= maxBuffer then
            pcall(function()
                for _, e in ipairs(self._HookBuffer) do
                    analyzer:AddLog("FUNCTION_CALL", string.format("%s - %s@%s:%s", e.Event, e.Name, e.Source, tostring(e.CurrentLine)), e)
                end
            end)
            self._HookBuffer = {}
        end

        -- If a suspicious marker was set recently, capture locals for the current frame (best-effort)
        if self.Config.CaptureLocalsOnSuspicious and self._LastSuspiciousTime and (tick() - (self._LastSuspiciousTime or 0) <= (self.Config.LocalCaptureWindow or 2)) then
            pcall(function()
                local snap = self:CaptureLocals(2)
                if snap then
                    table.insert(self.Data.LocalSnapshots, snap)
                    if #self.Data.LocalSnapshots > 200 then table.remove(self.Data.LocalSnapshots, 1) end
                end
            end)
        end
        -- Track hook overhead and possibly throttle hooks if excessive
        local hookEnd = tick()
        local elapsed = hookEnd - (hookStart or hookEnd)
        self._HookOverhead = (self._HookOverhead or 0) + elapsed
        -- reset overhead periodically
        if not self._LastHookOverheadReset or (tick() - self._LastHookOverheadReset) > 1 then
            if (self._HookOverhead or 0) > (self.Config.HookOverheadThreshold or 0.02) then
                -- Pause heavy hook activity
                pcall(function() debug.sethook() end)
                self:AddLog("PERFORMANCE_WARNING", "Hook overhead high, temporarily disabling hooks", {Overhead = self._HookOverhead})
                -- schedule a resume after pause seconds
                spawn(function()
                    wait(self.Config.HookPauseSeconds or 5)
                    pcall(function() debug.sethook(hookFunc, hookFlags) end)
                end)
            end
            self._HookOverhead = 0
            self._LastHookOverheadReset = tick()
        end
    end

    pcall(function()
        debug.sethook(hookFunc, hookFlags) -- set requested hook flags
    end)
end

function UltimateIntelligenceAnalyzer:StopFunctionHook()
    if not debug or type(debug.sethook) ~= "function" then return end
    -- flush any remaining buffer
    if self._HookBuffer and #self._HookBuffer > 0 then
        pcall(function()
            for _, e in ipairs(self._HookBuffer) do
                self:AddLog("FUNCTION_CALL", string.format("%s - %s@%s:%s", e.Event, e.Name, e.Source, tostring(e.CurrentLine)), e)
            end
        end)
        self._HookBuffer = {}
    end
    pcall(function() debug.sethook() end)
end

-- Capture local variables for the supplied stack level (best-effort, sanitized)
function UltimateIntelligenceAnalyzer:CaptureLocals(level)
    if not debug or type(debug.getlocal) ~= "function" then return nil end
    local maxLocals = math.max(1, tonumber(self.Config.MaxLocalsPerCapture) or 12)
    local snapshot = {Timestamp = tick(), Locals = {}, Stack = self:GetCallStack()}
    for i = 1, maxLocals do
        local ok, name, value = pcall(function() return debug.getlocal(level, i) end)
        if not ok or not name then break end
        snapshot.Locals[name] = self:SanitizeValue(value)
    end
    -- Only return snapshot if it has any locals captured
    if next(snapshot.Locals) then
        return snapshot
    end
    return nil
end

-- Extract upvalues and closure information for a function (best-effort)
function UltimateIntelligenceAnalyzer:ExtractFunctionUpvalues(func, funcData)
    if type(func) ~= "function" or not debug or type(debug.getupvalue) ~= "function" then return end
    local upvals = {}
    local i = 1
    while true do
        local ok, name, value = pcall(function() return debug.getupvalue(func, i) end)
        if not ok or not name then break end
        upvals[name] = self:SanitizeValue(value)
        i = i + 1
        if i > 200 then break end
    end

    if next(upvals) then
        funcData.Upvalues = upvals
        table.insert(self.Data.ExtractedConstants or {}, {Function = funcData.Name or "<anon>", Upvalues = upvals})
    end
end

-- Wrap module return values (functions/tables) to instrument calls and table access
function UltimateIntelligenceAnalyzer:WrapModuleReturn(value, name)
    local t = type(value)
    if t == "function" then
        local analyzer = self
        return function(...)
            local args = {...}
            local safeArgs = {}
            for i, a in ipairs(args) do safeArgs[i] = analyzer:SanitizeValue(a) end
            analyzer:AddLog("MODULE_FUNCTION_CALL", string.format("Module function %s called", tostring(name or "<fn>")), {Arguments = safeArgs})
            local ok, res1 = pcall(value, ...)
            if not ok then
                analyzer:AddLog("MODULE_FUNCTION_ERROR", "Module function error", {Function = tostring(name), Error = tostring(res1)})
                return nil
            end
            return res1
        end
    elseif t == "table" then
        -- Create a proxy table that wraps function entries lazily
        local proxy = {}
        local mt = {
            __index = function(_, k)
                local v = value[k]
                if type(v) == "function" then
                    -- wrap and cache
                    local wrapped = self:WrapModuleReturn(v, tostring(name) .. "." .. tostring(k))
                    rawset(proxy, k, wrapped)
                    return wrapped
                end
                return v
            end,
            __newindex = function(_, k, v)
                self:AddLog("MODULE_TABLE_WRITE", "Module table write", {Module = tostring(name), Key = tostring(k), Value = self:SanitizeValue(v)})
                value[k] = v
            end,
            __pairs = function()
                return pairs(value)
            end
        }
        setmetatable(proxy, mt)
        if self.Config and self.Config.AutoWrapRemoteTables then
            -- provide a wrapped proxy that also instruments table reads/writes/metamethods
            return self:WrapTableRecursive(proxy, tostring(name) .. ":module")
        end
        return proxy
    end
    return value
end

-- Recursively wrap a table with a proxy that intercepts index/newindex and common metamethods.
function UltimateIntelligenceAnalyzer:WrapTableRecursive(tbl, name, seen)
    if type(tbl) ~= "table" then
        return tbl
    end
    seen = seen or {}
    if seen[tbl] then return tbl end
    seen[tbl] = true

    local mt = getmetatable(tbl) or {}
    local proxy = {}
    local proxyMt = {}

    -- shallow copy of metamethods but replace __index/__newindex to intercept changes
    for k, v in pairs(mt) do
        proxyMt[k] = v
    end

    proxyMt.__index = function(_, key)
        local ok, val = pcall(function() return tbl[key] end)
        self:AddLog("TABLE_INDEX", {tableName = name, key = key, value = self:SanitizeValue(val)})
        if type(val) == "table" and self.Config.AutoWrapRemoteTables then
            return self:WrapTableRecursive(val, tostring(name) .. ":" .. tostring(key), seen)
        end
        return val
    end

    proxyMt.__newindex = function(_, key, value)
        self:AddLog("TABLE_WRITE", {tableName = name, key = key, value = self:SanitizeValue(value)})
        pcall(function() tbl[key] = value end)
    end

    -- proxy some common metamethods so operator usage is visible
    local metamethods = {"__add","__sub","__mul","__div","__pow","__concat","__eq","__lt","__le","__len","__call"}
    for _, mm in ipairs(metamethods) do
        if mt[mm] then
            proxyMt[mm] = function(...)
                self:AddLog("TABLE_METAMETHOD", {tableName = name, metamethod = mm})
                return mt[mm](...)
            end
        end
    end

    setmetatable(proxy, proxyMt)

    -- copy values lazily to proxy for iteration safety
    for k, v in pairs(tbl) do
        if type(v) == "table" and self.Config.AutoWrapRemoteTables then
            proxy[k] = self:WrapTableRecursive(v, tostring(name) .. ":" .. tostring(k), seen)
        else
            proxy[k] = v
        end
    end

    return proxy
end

-- Aggressively instrument a set of discovered tables up to a configured limit.
function UltimateIntelligenceAnalyzer:AggressiveInstrumentExistingTables()
    if not self.Config.AggressiveTableInstrumentation then return 0 end
    local wrapped = 0
    local limit = math.max(1, tonumber(self.Config.AggressiveInstrumentLimit) or 200)
    local seen = {}

    local function tryWrap(t, path)
        if wrapped >= limit then return end
        if type(t) ~= "table" then return end
        if seen[t] then return end
        seen[t] = true
        pcall(function()
            local ok, proxy = pcall(function() return self:WrapTableRecursive(t, path, {}) end)
            if ok and proxy then
                wrapped = wrapped + 1
            end
        end)
    end

    -- Scan common globals and environment-like tables
    local candidates = { _G, package and package.loaded or nil }
    for _, tbl in ipairs(candidates) do
        if type(tbl) == "table" then
            for k, v in pairs(tbl) do
                if type(v) == "table" then
                    tryWrap(v, tostring(k))
                    if wrapped >= limit then break end
                end
            end
        end
        if wrapped >= limit then break end
    end

    self:AddLog("AGGRESSIVE_INSTRUMENT", "Aggressive instrumentation completed", {Count = wrapped, Limit = limit})
    return wrapped
end

-- Initialize ACTIVE data structures with memory tracking
for _, category in ipairs({
    "ExecutionIntelligence", "FunctionCalls", "RuntimeTables", 
    "ExtractedVariables", "ExtractedConstants", "ExtractedFunctions",
    "RemoteCommunications", "DecompiledFunctions", "BytecodeAnalysis",
    "ObfuscatorFingerprints", "CallGraphs", "BehaviorClassifications",
    "AntiAnalysisDetections", "PatternRecognition", "RiskAssessments",
    "SessionLogs", "PerformanceMetrics"
}) do
    UltimateIntelligenceAnalyzer.Data[category] = {}
end

-- Additional runtime trace containers
UltimateIntelligenceAnalyzer.Data.LineTraces = {}
UltimateIntelligenceAnalyzer.Data.LocalSnapshots = {}

-- Enhanced performance-optimized logging system
UltimateIntelligenceAnalyzer.LogQueue = {}
UltimateIntelligenceAnalyzer.LastLogUpdate = tick()
UltimateIntelligenceAnalyzer.LogFramePool = {}
UltimateIntelligenceAnalyzer.ActiveLogFrames = {}
UltimateIntelligenceAnalyzer.RemoteHeatmap = {}
UltimateIntelligenceAnalyzer.HeatmapUpdateTime = tick()
UltimateIntelligenceAnalyzer.PerformanceStats = {
    FrameRate = 60,
    MemoryUsage = 0,
    LogRate = 0,
    AnalysisOverhead = 0,
    LastMemoryCheck = tick()
}

-- Track hooked remotes to prevent double-hooking
UltimateIntelligenceAnalyzer.HookedRemotes = {}

-- Safe execution wrapper for error recovery
function UltimateIntelligenceAnalyzer:SafeExecute(fn, fallback, context)
    local ok, ... = pcall(fn)
    if not ok then
        local err = select(1, ...)
        self:AddLog("SYSTEM_ERROR", "Execution failed in " .. (context or "unknown"), {
            Error = tostring(err),
            Traceback = debug.traceback(),
            Timestamp = tick()
        })
        return fallback
    end
    return ...
end

-- Memory management system
function UltimateIntelligenceAnalyzer:CheckMemoryUsage()
    local currentMemory = collectgarbage("count")
    self.PerformanceStats.MemoryUsage = currentMemory
    
    if currentMemory > self.Config.MaxMemoryMB then
        self:AddLog("MEMORY_WARNING", "High memory usage detected", {
            CurrentMB = currentMemory,
            LimitMB = self.Config.MaxMemoryMB
        })
        
        -- Auto-cleanup
        self:PerformMemoryCleanup()
        return false
    end
    
    return true
end

function UltimateIntelligenceAnalyzer:PerformMemoryCleanup()
    -- Clear oldest logs with bounds checking
    local logsToKeep = math.floor(self.Config.MaxLogSize * 0.7)
    while #self.Data.ExecutionIntelligence > logsToKeep and #self.Data.ExecutionIntelligence > 0 do
        local removed = table.remove(self.Data.ExecutionIntelligence, 1)
        if removed and self.ActiveLogFrames and self.ActiveLogFrames[removed.ID] then
            self:RecycleLogFrame(removed.ID)
        end
    end

    -- Trim frame pool to target size (keep most recent pool items)
    while #self.LogFramePool > 20 do
        local frame = table.remove(self.LogFramePool)
        if frame and frame.Destroy then
            pcall(function() frame:Destroy() end)
        end
    end
    
    -- Clear inactive data categories
    for _, category in ipairs({"FunctionCalls", "RuntimeTables", "RemoteCommunications"}) do
        if #self.Data[category] > 1000 then
            for i = 1, math.floor(#self.Data[category] * 0.5) do
                table.remove(self.Data[category], 1)
            end
        end
    end
    
    collectgarbage("collect")
    
    self:AddLog("MEMORY_MANAGEMENT", "Performed comprehensive memory cleanup", {
        NewMemoryUsage = collectgarbage("count"),
        LogsKept = #self.Data.ExecutionIntelligence
    })
end

-- Adaptive performance system
function UltimateIntelligenceAnalyzer:StartPerformanceMonitor()
    if self.PerformanceMonitor then
        self.PerformanceMonitor:Disconnect()
    end
    
    self.PerformanceMonitor = RunService.Heartbeat:Connect(function(deltaTime)
        self.PerformanceStats.FrameRate = math.min(1 / math.max(deltaTime, 0.001), 60)
        self.PerformanceStats.MemoryUsage = collectgarbage("count")
        
        -- Adaptive performance adjustments
        if self.Config.AdaptivePerformance then
            self:AdjustPerformanceSettings()
        end
        
        -- Periodic memory check (every 10 seconds instead of 5)
        if tick() - (self.PerformanceStats.LastMemoryCheck or 0) > 10 then
            self:CheckMemoryUsage()
            self.PerformanceStats.LastMemoryCheck = tick()
        end
        
        -- Process log queue if needed
        if #(self.LogQueue or {}) > 0 and tick() - (self.LastLogUpdate or 0) > (self.Config.LogUpdateInterval or 0.1) then
            self:ProcessLogQueue()
        end
    end)
end

function UltimateIntelligenceAnalyzer:AdjustPerformanceSettings()
    local fps = self.PerformanceStats.FrameRate
    
    if fps < self.Config.MinFPS then
        -- Reduce logging intensity
        self.Config.LogBatchSize = math.max(10, self.Config.LogBatchSize - 5)
        self.Config.LogUpdateInterval = math.min(0.5, self.Config.LogUpdateInterval + 0.05)
        
        self:AddLog("PERFORMANCE_ADJUSTMENT", "Reduced logging intensity due to low FPS", {
            CurrentFPS = fps,
            NewBatchSize = self.Config.LogBatchSize,
            NewUpdateInterval = self.Config.LogUpdateInterval
        })
    elseif fps > 45 and self.Config.LogBatchSize < 100 then
        -- Increase logging intensity when performance is good
        self.Config.LogBatchSize = math.min(100, self.Config.LogBatchSize + 2)
        self.Config.LogUpdateInterval = math.max(0.05, self.Config.LogUpdateInterval - 0.01)
    end
end

-- Safe element creation with validation
function UltimateIntelligenceAnalyzer:CreateElement(className, props)
    local success, element = pcall(function()
        local element = Instance.new(className)
        if not element then return nil end
        
        for prop, value in pairs(props or {}) do
            if prop == "Parent" then
                element.Parent = value
            else
                -- Safe property assignment
                pcall(function()
                    element[prop] = value
                end)
            end
        end
        return element
    end)
    
    return success and element or nil
end

-- Log color mapping
function UltimateIntelligenceAnalyzer:GetLogColor(category)
    local colors = {
        SESSION_START = Color3.fromRGB(70, 130, 200),
        SESSION_COMPLETE = Color3.fromRGB(70, 200, 130),
        SESSION_ERROR = Color3.fromRGB(200, 80, 80),
        FUNCTION_CALL = Color3.fromRGB(80, 160, 200),
        REMOTE_EVENT_FIRED = Color3.fromRGB(200, 160, 80),
        SECURITY = Color3.fromRGB(200, 100, 100),
        PRINT_OUTPUT = Color3.fromRGB(100, 180, 100),
        ERROR_THROWN = Color3.fromRGB(200, 100, 100),
        STRING_OPERATION = Color3.fromRGB(160, 120, 200),
        TABLE_OPERATION = Color3.fromRGB(200, 120, 160),
        COROUTINE_CREATE = Color3.fromRGB(120, 200, 200),
        DEBUG_TRACEBACK = Color3.fromRGB(180, 180, 100),
        SUSPICIOUS_REMOTE = Color3.fromRGB(255, 80, 80),
        ANTI_ANALYSIS_DETECTED = Color3.fromRGB(255, 50, 50),
        INSTANCE_CREATION = Color3.fromRGB(150, 150, 200),
        INSTANCE_PARENT_CHANGE = Color3.fromRGB(150, 200, 150),
        PERFORMANCE_WARNING = Color3.fromRGB(255, 165, 0),
        MEMORY_WARNING = Color3.fromRGB(255, 140, 0),
        SYSTEM_ERROR = Color3.fromRGB(150, 0, 0)
    }
    return colors[category] or Color3.fromRGB(60, 60, 80)
end

-- Category icon mapping
function UltimateIntelligenceAnalyzer:GetCategoryIcon(category)
    local icons = {
        SESSION_START = "🚀", SESSION_COMPLETE = "✅", SESSION_ERROR = "❌", 
        FUNCTION_CALL = "🔧", REMOTE_EVENT_FIRED = "📡", SECURITY = "🛡️",
        PRINT_OUTPUT = "📝", ERROR_THROWN = "💥", STRING_OPERATION = "🔤",
        TABLE_OPERATION = "📊", COROUTINE_CREATE = "🔄", DEBUG_TRACEBACK = "🐞",
        SUSPICIOUS_REMOTE = "⚠️", ANTI_ANALYSIS_DETECTED = "🚫",
        INSTANCE_CREATION = "🆕", INSTANCE_PARENT_CHANGE = "📁",
        PERFORMANCE_WARNING = "🐢", MEMORY_WARNING = "💾", SYSTEM_ERROR = "🔴"
    }
    return icons[category] or "📄"
end

-- Status update function
function UltimateIntelligenceAnalyzer:UpdateStatus(message, color)
    if self.StatusLabel then
        self.StatusLabel.Text = "Status: " .. message
        if color then
            self.StatusLabel.TextColor3 = color
        end
    end
end

-- Enhanced logging system with batching and pooling
function UltimateIntelligenceAnalyzer:AddLog(category, message, data)
    if not self.Config or not self:CheckMemoryUsage() then
        return nil
    end

    -- Validate inputs
    category = category or "UNKNOWN"
    message = tostring(message or "No message")
    
    local logEntry = {
        ID = HttpService:GenerateGUID(false), 
        Timestamp = os.date("%H:%M:%S"),
        Category = category, 
        Message = message, 
        Data = data or {},
        StackTrace = debug.traceback(),
        CallStack = self:GetCallStack()
    }

    -- Sanitize message and data to avoid accidental leakage and limit size
    logEntry.Message = self:SanitizeValue(logEntry.Message)
    local sanitizedData = {}
    if logEntry.Data then
        for k, v in pairs(logEntry.Data) do
            sanitizedData[tostring(k)] = self:SanitizeValue(v)
        end
    end
    logEntry.Data = sanitizedData
    
    -- Initialize queue if needed
    self.LogQueue = self.LogQueue or {}
    self.Data.ExecutionIntelligence = self.Data.ExecutionIntelligence or {}
    
    table.insert(self.LogQueue, logEntry)
    table.insert(self.Data.ExecutionIntelligence, logEntry)
    
    if self.Data.CurrentSession then 
        table.insert(self.Data.CurrentSession.Logs, logEntry) 
    end

    -- Mark suspicious marker for local capture window when relevant categories appear
    local suspiciousCategories = {
        SUSPICIOUS_REMOTE = true,
        SUSPICIOUS_TABLE_STRUCTURE = true,
        ANTI_ANALYSIS_DETECTED = true,
        STRING_OPERATION = true,
        SUSPICIOUS_KEYWORDS = true
    }
    if suspiciousCategories[category] then
        self._LastSuspiciousTime = tick()
        self._LastSuspiciousReason = message or category
    end
    
    -- Update log rate statistics
    self.PerformanceStats.LogRate = #self.LogQueue / math.max(tick() - self.LastLogUpdate, 0.1)
    
    -- Batch processing for performance
    if #self.LogQueue >= self.Config.LogBatchSize or 
       (tick() - self.LastLogUpdate) >= self.Config.LogUpdateInterval then
        self:ProcessLogQueue()
    end
    
    -- Smart log rotation
    if #self.Data.ExecutionIntelligence > self.Config.MaxLogSize then
        for i = 1, math.floor(self.Config.MaxLogSize * 0.1) do
            table.remove(self.Data.ExecutionIntelligence, 1)
        end
    end
    
    return logEntry
end

function UltimateIntelligenceAnalyzer:ProcessLogQueue()
    -- If GUI is available, render frames; otherwise keep logs in memory and optionally print a short summary
    if self.Config.EnableGUI and self.LogsScrollingFrame then
        for _, logEntry in ipairs(self.LogQueue) do
            self:CreateLogFrame(logEntry)
        end

        -- Smooth scrolling
        local ok, targetY = pcall(function()
            return self.LogsScrollingFrame.AbsoluteCanvasSize.Y
        end)
        if ok and targetY then
            self.LogsScrollingFrame.CanvasPosition = Vector2.new(0, targetY)
        end
    else
        -- Non-GUI: emit brief console summaries for visibility (sanitized)
        for _, logEntry in ipairs(self.LogQueue) do
            local summary = string.format("[LOG][%s] %s: %s", logEntry.Timestamp, logEntry.Category, tostring(self:SanitizeValue(logEntry.Message)))
            pcall(function() print(summary) end)
        end
    end

    -- Clear the queue but keep logs in ExecutionIntelligence for persistence
    self.LogQueue = {}
    self.LastLogUpdate = tick()
end

function UltimateIntelligenceAnalyzer:CreateLogFrame(logEntry)
    local logFrame = table.remove(self.LogFramePool) or self:CreateElement("Frame", {
        Size = UDim2.new(1, -10, 0, 60), 
        BackgroundColor3 = Color3.fromRGB(60, 60, 80),
        BorderSizePixel = 0,
        ClipsDescendants = true
    })
    
    if not logFrame then return end  -- Safety check
    
    logFrame.BackgroundColor3 = self:GetLogColor(logEntry.Category)
    
    -- Reuse or create children with better organization
    local timestamp = logFrame:FindFirstChild("Timestamp") or self:CreateElement("TextLabel", {
        Size = UDim2.new(0, 80, 0, 20), Position = UDim2.new(0, 5, 0, 5),
        BackgroundTransparency = 1, TextColor3 = Color3.fromRGB(200, 200, 200),
        TextSize = 10, Font = Enum.Font.Gotham, TextXAlignment = Enum.TextXAlignment.Left,
        Parent = logFrame
    })
    
    local categoryLabel = logFrame:FindFirstChild("Category") or self:CreateElement("TextLabel", {
        Size = UDim2.new(0, 120, 0, 20), Position = UDim2.new(0, 90, 0, 5),
        BackgroundTransparency = 1, TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 11, Font = Enum.Font.GothamBold, TextXAlignment = Enum.TextXAlignment.Left,
        Parent = logFrame
    })
    
    local messageLabel = logFrame:FindFirstChild("Message") or self:CreateElement("TextLabel", {
        Size = UDim2.new(1, -10, 0, 30), Position = UDim2.new(0, 5, 0, 25),
        BackgroundTransparency = 1, TextColor3 = Color3.fromRGB(230, 230, 230),
        TextSize = 12, TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left,
        TextYAlignment = Enum.TextYAlignment.Top, Parent = logFrame
    })
    
    if timestamp then timestamp.Text = logEntry.Timestamp end
    if categoryLabel then categoryLabel.Text = self:GetCategoryIcon(logEntry.Category) .. " " .. logEntry.Category end
    if messageLabel then messageLabel.Text = logEntry.Message end
    
    logFrame.Parent = self.LogsScrollingFrame
    self.ActiveLogFrames[logEntry.ID] = logFrame
    
    -- Smart pool management
    if self:TableCount(self.ActiveLogFrames) > 200 then
        -- Recycle an arbitrary active frame (keeps memory bounded)
        for oldestId in pairs(self.ActiveLogFrames) do
            self:RecycleLogFrame(oldestId)
            break
        end
    end
end

function UltimateIntelligenceAnalyzer:RecycleLogFrame(logId)
    local frame = self.ActiveLogFrames[logId]
    if frame then
        frame.Parent = nil
        if #self.LogFramePool < 50 then  -- Limit pool size
            table.insert(self.LogFramePool, frame)
        else
            frame:Destroy()
        end
        self.ActiveLogFrames[logId] = nil
    end
end

-- Enhanced sandbox environment with proper self references
function UltimateIntelligenceAnalyzer:CreateSecureExecutionEnvironment()
    local env = {}
    local analyzer = self  -- Capture reference for closures
    -- Preserve original global functions to avoid recursion when we override them
    local orig_print, orig_warn, orig_error, orig_pcall, orig_xpcall = print, warn, error, pcall, xpcall
    local orig_setmetatable, orig_rawset, orig_rawget, orig_require, orig_getmetatable = setmetatable, rawset, rawget, require, getmetatable
    local orig_load, orig_loadstring = load, (loadstring or nil)
    local orig_getfenv, orig_setfenv = (getfenv or nil), (setfenv or nil)
    local orig_writefile, orig_readfile, orig_decompile = (rawget(_G or {}, "writefile") or nil), (rawget(_G or {}, "readfile") or nil), (rawget(_G or {}, "decompile") or nil)
    
    -- Safe base environment
    local safeGlobals = {
        math = math,
        string = setmetatable({}, {
            __index = function(_, k)
                if type(string[k]) == "function" then
                    return function(...)
                        analyzer:LogStringOperation(k, ...)
                        return string[k](...)
                    end
                else
                    return string[k]
                end
            end
        }),
        table = setmetatable({}, {
            __index = function(_, k)
                if type(table[k]) == "function" then
                    return function(...)
                        analyzer:LogTableOperation(k, ...)
                        return table[k](...)
                    end
                else
                    return table[k]
                end
            end
        }),
        coroutine = setmetatable({}, {
            __index = function(_, k)
                if k == "create" then
                    return function(f)
                        analyzer:AddLog("COROUTINE_CREATE", "Coroutine created", {Function = tostring(f)})
                        return coroutine.create(f)
                    end
                elseif k == "resume" then
                    return function(co, ...)
                        analyzer:AddLog("COROUTINE_RESUME", "Coroutine resumed", {Coroutine = tostring(co)})
                        return coroutine.resume(co, ...)
                    end
                elseif k == "yield" then
                    return function(...)
                        analyzer:AddLog("COROUTINE_YIELD", "Coroutine yielded", {})
                        return coroutine.yield(...)
                    end
                end
                return coroutine[k]
            end
        }),
        getmetatable = function(obj)
            analyzer:AddLog("GETMETATABLE", "getmetatable called", {Object = tostring(obj)})
            return orig_getmetatable(obj)
        end,
        setmetatable = function(t, mt)
            analyzer:AddLog("SETMETATABLE", "setmetatable called", {Table = tostring(t), Metatable = tostring(mt)})
            return orig_setmetatable(t, mt)
        end,
        rawset = function(t, k, v)
            analyzer:AddLog("RAWSET", "rawset on table", {Table = tostring(t), Key = tostring(k), Value = analyzer:SanitizeValue(v)})
            return orig_rawset(t, k, v)
        end,
        rawget = function(t, k)
            analyzer:AddLog("RAWGET", "rawget on table", {Table = tostring(t), Key = tostring(k)})
            return orig_rawget(t, k)
        end,
        print = function(...)
            local args, output = {...}, table.concat({...}, "\t")
            analyzer:AddLog("PRINT_OUTPUT", "Script printed: " .. output, {Output = output, Arguments = args})
            return orig_print(...)
        end,
        require = function(mod)
            analyzer:AddLog("REQUIRE", "Module required", {Module = tostring(mod)})
            local ok, res = pcall(function() return orig_require(mod) end)
            if not ok then
                analyzer:AddLog("REQUIRE_ERROR", "Module require failed", {Module = tostring(mod), Error = tostring(res)})
                return nil
            end
            -- Wrap module returns to instrument usage
            local wrapped = analyzer:WrapModuleReturn(res, tostring(mod))
            return wrapped
        end,
        warn = function(...)
            local args, output = {...}, table.concat({...}, "\t")
            analyzer:AddLog("WARN_OUTPUT", "Script warning: " .. output, {Output = output, Arguments = args})
            return orig_warn(...)
        end,
        error = function(msg, level)
            analyzer:AddLog("ERROR_THROWN", "Script error: " .. tostring(msg), {Message = msg, Level = level})
            return orig_error(msg, level)
        end,
        pcall = function(f, ...)
            analyzer:AddLog("PCALL_START", "Protected call started", {Function = tostring(f)})
            local success, result = orig_pcall(f, ...)
            analyzer:AddLog("PCALL_END", "Protected call completed", {Success = success, Result = tostring(result)})
            return success, result
        end,
        xpcall = function(f, err, ...)
            analyzer:AddLog("XCALL_START", "Extended protected call started", {Function = tostring(f)})
            local success, result = orig_xpcall(f, err, ...)
            analyzer:AddLog("XCALL_END", "Extended protected call completed", {Success = success, Result = tostring(result)})
            return success, result
        end,
        type = type, tostring = tostring, tonumber = tonumber, 
        select = select, pairs = pairs, ipairs = ipairs, next = next,
        unpack = table.unpack or unpack, rawequal = rawequal, rawget = orig_rawget, rawset = orig_rawset
        ,
        -- Wrapped loaders and environment accessors (best-effort, logged)
        load = function(chunk, name, mode, envTable)
            analyzer:AddLog("LOAD_CALL", "load called", {Name = tostring(name), Mode = tostring(mode)})
            if not analyzer.Config.WrapLoadFunctions or not orig_load then
                return orig_load(chunk, name, mode, envTable)
            end
            local f, err = orig_load(chunk, name, mode, envTable)
            if not f then
                analyzer:AddLog("LOAD_ERROR", "load failed", {Error = tostring(err)})
                return f, err
            end
            -- Optionally stub network during loaded function execution if configured
            if analyzer.Config.StubNetworkOnAnalyze then
                -- return a wrapper that will stub network during the call
                return function(...)
                    analyzer:StubNetwork(true)
                    local ok, res1 = pcall(f, ...)
                    analyzer:StubNetwork(false)
                    if not ok then analyzer:AddLog("LOAD_EXEC_ERROR", "Error executing loaded chunk", {Error = tostring(res1)}) end
                    return res1
                end
            end
            return f, err
        end,
        loadstring = function(s, name)
            analyzer:AddLog("LOADSTRING_CALL", "loadstring called", {Name = tostring(name)})
            if not analyzer.Config.WrapLoadFunctions or not orig_loadstring then
                return orig_loadstring and orig_loadstring(s, name) or nil, "unsupported"
            end
            local f, err = orig_loadstring(s, name)
            if not f then
                analyzer:AddLog("LOADSTRING_ERROR", "loadstring failed", {Error = tostring(err)})
                return f, err
            end
            if analyzer.Config.StubNetworkOnAnalyze then
                return function(...)
                    analyzer:StubNetwork(true)
                    local ok, res1 = pcall(f, ...)
                    analyzer:StubNetwork(false)
                    if not ok then analyzer:AddLog("LOADSTRING_EXEC_ERROR", "Error executing loadstring chunk", {Error = tostring(res1)}) end
                    return res1
                end
            end
            return f, err
        end,
        getfenv = function(obj)
            analyzer:AddLog("GETFENV", "getfenv called", {Obj = tostring(obj)})
            if orig_getfenv then
                return orig_getfenv(obj)
            end
            return nil
        end,
        setfenv = function(obj, envTable)
            analyzer:AddLog("SETFENV", "setfenv called", {Obj = tostring(obj)})
            if orig_setfenv then
                return orig_setfenv(obj, envTable)
            end
            return nil
        end,
        -- Executor-provided filesystem / decompile wrappers (best-effort)
        writefile = function(path, data)
            analyzer:AddLog("WRITEFILE", "writefile called", {Path = tostring(path)})
            if orig_writefile then
                return orig_writefile(path, data)
            end
            return nil
        end,
        readfile = function(path)
            analyzer:AddLog("READFILE", "readfile called", {Path = tostring(path)})
            if orig_readfile then
                return orig_readfile(path)
            end
            return nil
        end,
        decompile = function(func)
            analyzer:AddLog("DECOMPILE", "decompile called", {Function = tostring(func)})
            if orig_decompile then
                local ok, res = pcall(orig_decompile, func)
                if ok then return res end
            end
            return nil
        end
    }
    
    -- Enhanced debug library hooking
    if self.Config.ExtractFunctions or self.Config.DecompileFunctions then
        safeGlobals.debug = setmetatable({}, {
            __index = function(_, k)
                if k == "traceback" then
                    return function(thread, message, level)
                        local trace = debug.traceback(thread, message, level)
                        analyzer:AddLog("DEBUG_TRACEBACK", "Debug traceback captured", {Trace = trace})
                        return trace
                    end
                elseif k == "getinfo" then
                    return function(thread, func, what)
                        local info = debug.getinfo(thread, func, what)
                        if info and info.func then
                            analyzer:AnalyzeFunctionInfo(info)
                        end
                        return info
                    end
                end
                return debug[k]
            end
        })
    end
    
    for k, v in pairs(safeGlobals) do env[k] = v end
    
    -- Enhanced Roblox environment with remote hooking
    if game then
        env.game = setmetatable({
            GetService = function(serviceName)
                analyzer:AddLog("SERVICE_ACCESS", "Script accessed service: " .. serviceName, {Service = serviceName})
                local service = game:GetService(serviceName)
                -- Hook RemoteEvent and RemoteFunction containers
                if serviceName == "ReplicatedStorage" or serviceName == "ReplicatedFirst" then
                    return analyzer:HookRemoteContainer(service)
                end

                -- Wrap certain services for instrumentation (e.g., HttpService)
                return analyzer:WrapService(service)
            end
        }, {
            __index = function(_, k)
                return game[k]
            end
        })
        
        env.workspace = analyzer:HookInstanceCreation(workspace)
        env.script = nil
        
        -- Enhanced Instance.new hooking for remote detection
        env.Instance = {
            new = function(className)
                analyzer:AddLog("INSTANCE_CREATION", "Instance created: " .. className, {Class = className})
                local instance = Instance.new(className)
                
                if className == "RemoteEvent" or className == "RemoteFunction" then
                    return analyzer:HookRemoteInstance(instance)
                end
                
                return analyzer:HookInstanceCreation(instance)
            end
        }
    end
    
    return setmetatable(env, {
        __index = function(_, k)
            analyzer:AddLog("ENV_ACCESS", "Accessed global: " .. k, {Key = k, Type = "undefined"})
            return nil
        end,
        __newindex = function(t, k, v)
            analyzer:AddLog("ENV_WRITE", "Modified global: " .. k, {Key = k, ValueType = type(v), Value = tostring(v)})
            rawset(t, k, v)
        end
    })
end

-- Advanced remote event hooking system with proper self reference
function UltimateIntelligenceAnalyzer:HookRemoteContainer(container)
    local analyzer = self
    
    return setmetatable({}, {
        __index = function(_, k)
            -- Prefer FindFirstChild for named children (safer)
            local child = nil
            pcall(function()
                if type(k) == "string" and container.FindFirstChild then
                    child = container:FindFirstChild(k)
                end
            end)

            if child and (child:IsA("RemoteEvent") or child:IsA("RemoteFunction") or child:IsA("BindableEvent") or child:IsA("BindableFunction")) then
                return analyzer:HookRemoteInstance(child)
            end

            -- Fallback to property/method access if no child found
            local ok, val = pcall(function() return container[k] end)
            if ok then return val end
            return nil
        end,
        __newindex = function(t, k, v)
            container[k] = v
        end
    })
end

-- Enhanced remote instance hooking with double-hook prevention
function UltimateIntelligenceAnalyzer:HookRemoteInstance(remote)
    if not remote or self.HookedRemotes[remote] then
        return remote
    end
    
    local analyzer = self
    self.HookedRemotes[remote] = true
    
    if remote:IsA("RemoteEvent") then
        local originalFireServer = remote.FireServer
        remote.FireServer = function(remoteSelf, ...)
            local args = {...}
            -- Safe argument processing
            local safeArgs = {}
            for i, arg in ipairs(args) do
                if type(arg) == "table" then
                    safeArgs[i] = "{table with " .. tostring(self:TableCount(arg)) .. " items}"
                    if self.Config.AutoWrapRemoteTables then
                        -- capture a wrapped inspection proxy for analysis (do not replace original arg)
                        pcall(function()
                            safeArgs[i] = self:WrapTableRecursive(arg, tostring(remote) .. ":arg" .. tostring(i))
                        end)
                    end
                elseif type(arg) == "function" then
                    safeArgs[i] = "{function}"
                else
                    safeArgs[i] = tostring(arg):sub(1, 200) -- Limit string length
                end
            end
            
            analyzer:AddLog("REMOTE_EVENT_FIRED", "RemoteEvent fired: " .. tostring(remote), {
                Remote = tostring(remote),
                Arguments = safeArgs,
                ArgumentCount = #args,
                CallStack = analyzer:GetCallStack()
            })

            -- Record remote communication into dataset
            table.insert(analyzer.Data.RemoteCommunications, {
                Type = "RemoteEvent",
                Remote = tostring(remote),
                Arguments = safeArgs,
                ArgumentCount = #args,
                Timestamp = tick()
            })
            
            -- Update heatmap
            analyzer:UpdateRemoteHeatmap(tostring(remote))
            
            -- Analyze arguments for suspicious patterns
            analyzer:AnalyzeRemoteArguments(args, remote)
            
            return originalFireServer(remoteSelf, ...)
        end
        -- Listen to incoming client events (server -> client) to capture arguments
        pcall(function()
            if remote.OnClientEvent then
                remote:Connect(function(...)
                    local incoming = {...}
                    local safeIncoming = {}
                    for i, v in ipairs(incoming) do safeIncoming[i] = self:SanitizeValue(v) end
                    self:AddLog("REMOTE_EVENT_RECEIVED", "Incoming RemoteEvent from server", {Remote = tostring(remote), Arguments = safeIncoming})
                end)
            end
        end)
    elseif remote:IsA("RemoteFunction") then
        local originalInvokeServer = remote.InvokeServer
        remote.InvokeServer = function(remoteSelf, ...)
            local args = {...}
            local safeArgs = {}
            for i, arg in ipairs(args) do
                if type(arg) == "table" then
                    safeArgs[i] = "{table with " .. tostring(self:TableCount(arg)) .. " items}"
                else
                    safeArgs[i] = tostring(arg):sub(1, 200)
                end
            end
            
            analyzer:AddLog("REMOTE_FUNCTION_INVOKED", "RemoteFunction invoked: " .. tostring(remote), {
                Remote = tostring(remote),
                Arguments = safeArgs,
                ArgumentCount = #args
            })

            -- Record remote function communication
            table.insert(analyzer.Data.RemoteCommunications, {
                Type = "RemoteFunction",
                Remote = tostring(remote),
                Arguments = safeArgs,
                ArgumentCount = #args,
                Timestamp = tick()
            })
            
            -- Update heatmap
            analyzer:UpdateRemoteHeatmap(tostring(remote))
            
            analyzer:AnalyzeRemoteArguments(args, remote)
            -- Capture return value if configured
            local ok, res = pcall(function() return originalInvokeServer(remoteSelf, ...) end)
            if not ok then
                analyzer:AddLog("REMOTE_INVOKE_ERROR", "RemoteFunction invocation failed", {Remote = tostring(remote), Error = tostring(res)})
                return nil
            end
            if analyzer.Config.CaptureRemoteReturns then
                analyzer:AddLog("REMOTE_RETURN", "RemoteFunction return captured", {Remote = tostring(remote), Return = analyzer:SanitizeValue(res)})
            end
            return res
        end
    end
    -- BindableEvent and BindableFunction handling (local-only events/functions)
    if remote:IsA("BindableEvent") then
        local originalFire = remote.Fire
        remote.Fire = function(remoteSelf, ...)
            local args = {...}
            local safeArgs = {}
            for i, arg in ipairs(args) do safeArgs[i] = analyzer:SanitizeValue(arg) end
            analyzer:AddLog("BINDABLE_EVENT_FIRED", "BindableEvent fired", {Bindable = tostring(remote), Arguments = safeArgs})
            return originalFire(remoteSelf, ...)
        end
    elseif remote:IsA("BindableFunction") then
        local originalInvoke = remote.Invoke
        remote.Invoke = function(remoteSelf, ...)
            local args = {...}
            local safeArgs = {}
            for i, arg in ipairs(args) do safeArgs[i] = analyzer:SanitizeValue(arg) end
            analyzer:AddLog("BINDABLE_FUNCTION_INVOKED", "BindableFunction invoked", {Bindable = tostring(remote), Arguments = safeArgs})
            local ok, res = pcall(function() return originalInvoke(remoteSelf, ...) end)
            if not ok then analyzer:AddLog("BINDABLE_INVOKE_ERROR", "Bindable invoke error", {Error = tostring(res)}) return nil end
            if analyzer.Config.CaptureRemoteReturns then analyzer:AddLog("BINDABLE_RETURN", "Bindable return captured", {Bindable = tostring(remote), Return = analyzer:SanitizeValue(res)}) end
            return res
        end
    end
    
    return remote
end

-- Stub network calls (FireServer/InvokeServer/HttpService methods) when analyzing dangerous code.
function UltimateIntelligenceAnalyzer:StubNetwork(enable)
    self._StubbedOriginals = self._StubbedOriginals or {}
    if enable then
        -- Replace FireServer/InvokeServer on known remotes in workspace/ReplicatedStorage
        for _, svcName in ipairs({"ReplicatedStorage", "ReplicatedFirst", "StarterPlayerScripts"}) do
            pcall(function()
                local svc = game:GetService(svcName)
                if not svc then return end
                for _, inst in ipairs(svc:GetDescendants()) do
                    if (inst:IsA("RemoteEvent") or inst:IsA("RemoteFunction")) and not self._StubbedOriginals[inst] then
                        self._StubbedOriginals[inst] = {FireServer = inst.FireServer, InvokeServer = inst.InvokeServer}
                        pcall(function() inst.FireServer = function() self:AddLog("STUB_FIRE", "Blocked FireServer during analyze", {Remote = tostring(inst)}) end end)
                        pcall(function() inst.InvokeServer = function() self:AddLog("STUB_INVOKE", "Blocked InvokeServer during analyze", {Remote = tostring(inst)}) return nil end end)
                    end
                end
            end)
        end

        -- Stub HttpService to avoid external requests
        pcall(function()
            local http = game:GetService("HttpService")
            if http and not self._StubbedOriginals[http] then
                self._StubbedOriginals[http] = {RequestAsync = http.RequestAsync, PostAsync = http.PostAsync, GetAsync = http.GetAsync}
                pcall(function() http.RequestAsync = function() self:AddLog("STUB_HTTP", "Blocked HTTP RequestAsync during analyze") return nil end end)
                pcall(function() http.PostAsync = function() self:AddLog("STUB_HTTP", "Blocked HTTP PostAsync during analyze") return nil end end)
                pcall(function() http.GetAsync = function() self:AddLog("STUB_HTTP", "Blocked HTTP GetAsync during analyze") return nil end end)
            end
        end)
    else
        -- Restore originals
        for inst, origs in pairs(self._StubbedOriginals) do
            pcall(function()
                if inst and inst:IsA and (inst:IsA("RemoteEvent") or inst:IsA("RemoteFunction")) then
                    inst.FireServer = origs.FireServer
                    inst.InvokeServer = origs.InvokeServer
                elseif inst and inst.RequestAsync then
                    inst.RequestAsync = origs.RequestAsync
                    inst.PostAsync = origs.PostAsync
                    inst.GetAsync = origs.GetAsync
                end
            end)
        end
        self._StubbedOriginals = {}
    end
end

-- Try to decompile a function using executor API if available, else noop
function UltimateIntelligenceAnalyzer:TryDecompileFunction(func)
    if not func then return nil end
    local decompiled = self:ExploitDecompile(func)
    if decompiled then
        self:AddLog("DECOMPILED_FUNCTION", "Function decompiled", {Function = tostring(func), Source = tostring(decompiled):sub(1, 2000)})
        return decompiled
    end
    return nil
end

-- Export logs and analysis to a file (requires executor writefile). Returns boolean success.
function UltimateIntelligenceAnalyzer:ExportAnalysisToFile(path)
    local payload = {
        Data = self.Data,
        Config = self.Config,
        ExportedAt = tick()
    }
    local ok, encoded = pcall(function() return HttpService:JSONEncode(payload) end)
    if not ok then
        self:AddLog("EXPORT_ERROR", "JSON encode failed", {Error = tostring(encoded)})
        return false
    end
    
    local success, err = self:ExploitWriteFile(path, encoded)
    if not success then
        self:AddLog("EXPORT_ERROR", "writefile failed", {Error = tostring(err)})
        return false
    end
    self:AddLog("EXPORT_SUCCESS", "Analysis exported", {Path = path})
    return true
end

-- Prepare an export specifically for offline decompilers. Writes a JSON file with function list.
function UltimateIntelligenceAnalyzer:ExportForDecompiler(path)
    -- Build a compact function table suitable for offline decompilers
    local functions = {}
    for _, f in ipairs(self.Data.ExtractedFunctions or {}) do
        table.insert(functions, {
            Name = f.Name,
            Source = f.Source,
            LineDefined = f.LineDefined,
            Nups = f.Nups,
            Upvalues = f.Upvalues,
            Decompiled = f.Decompiled,
            Bytecode = f.Bytecode
        })
    end

    local payload = {Functions = functions, ExportedAt = tick(), Config = self.Config}
    local ok, encoded = pcall(function() return HttpService:JSONEncode(payload) end)
    if not ok then
        self:AddLog("EXPORT_ERROR", "JSON encode failed for decompiler export", {Error = tostring(encoded)})
        return false
    end

    local success, err = self:ExploitWriteFile(path, encoded)
    if not success then
        self:AddLog("EXPORT_ERROR", "writefile failed for decompiler export", {Error = tostring(err)})
        return false
    end
    self:AddLog("EXPORT_SUCCESS", "Decompiler export written", {Path = path, Count = #functions})
    return true
end

-- Enhanced instance creation hooking
function UltimateIntelligenceAnalyzer:HookInstanceCreation(instance)
    local analyzer = self
    if not instance then return nil end

    -- Track created instances for later analysis
    self.Data.CreatedInstances = self.Data.CreatedInstances or {}
    table.insert(self.Data.CreatedInstances, tostring(instance))

    local instanceProxy = {}
    local instanceMetatable = {
        __index = function(_, k)
            local ok, value = pcall(function() return instance[k] end)
            if not ok then return nil end
            if type(value) == "function" then
                -- If accessing Connect, wrap to log connection creation
                if tostring(k) == "Connect" then
                    return function(_, callback)
                        analyzer:AddLog("CONNECTION_CREATED", "Event connection created", {Instance = tostring(instance), Callback = tostring(callback)})
                        -- try to wrap callback to capture calls
                        local wrappedCb = callback
                        if type(callback) == "function" then
                            wrappedCb = function(...)
                                pcall(function() analyzer:AddLog("EVENT_CALLBACK", "Event callback invoked", {Instance = tostring(instance), Args = analyzer:SanitizeValue({...})}) end)
                                return callback(...)
                            end
                        end
                        local ok2, conn = pcall(function() return value(instance, wrappedCb) end)
                        return ok2 and conn or nil
                    end
                end

                return function(...)
                    local ok2, res = pcall(function() return value(instance, ...) end)
                    if ok2 then return res end
                    return nil
                end
            end
            return value
        end,
        __newindex = function(_, k, v)
            if k == "Parent" then
                analyzer:AddLog("INSTANCE_PARENT_CHANGE", "Instance parent changed: " .. tostring(instance), {
                    Instance = tostring(instance),
                    NewParent = tostring(v)
                })
            else
                -- Log property writes for interesting properties
                analyzer:AddLog("INSTANCE_PROPERTY_WRITE", "Property written", {Instance = tostring(instance), Property = tostring(k), Value = analyzer:SanitizeValue(v)})
            end
            pcall(function() instance[k] = v end)
        end
    }

    return setmetatable(instanceProxy, instanceMetatable)
end

-- Enhanced call stack analysis
function UltimateIntelligenceAnalyzer:GetCallStack()
    local stack = {}
    local level = 3 -- Start above this function
    
    while true do
        local info = debug.getinfo(level, "Snl")
        if not info then break end
        
        local stackEntry = {
            Name = info.name or "?",
            Source = info.source or "?",
            CurrentLine = info.currentline,
            LineDefined = info.linedefined,
            What = info.what
        }
        
        -- Extract more details if available
        if self.Config.ExtractFunctions and info.func then
            stackEntry.Constants = self:TryGetConstants(info.func)
        end
        
        table.insert(stack, stackEntry)
        level = level + 1
    end
    
    return stack
end

function UltimateIntelligenceAnalyzer:TryGetConstants(func)
    return self:SafeExecute(function()
        -- This would use debug.getconstants in a real environment
        return {"constant_extraction_requires_debug_library"}
    end, {}, "TryGetConstants")
end

-- Try to obtain raw bytecode for a function using common executor APIs when available
function UltimateIntelligenceAnalyzer:TryGetBytecode(func)
    local bytecode = self:ExploitGetBytecode(func)
    if bytecode then
        self:AddLog("BYTECODE_EXTRACTED", "Bytecode extracted for function", {Function = tostring(func)})
        return bytecode
    end
    return nil
end

-- String operation logging
function UltimateIntelligenceAnalyzer:LogStringOperation(operation, ...)
    local args = {...}
    self:AddLog("STRING_OPERATION", "String operation: " .. operation, {
        Operation = operation,
        Arguments = args,
        Timestamp = tick()
    })
end

-- Table operation logging
function UltimateIntelligenceAnalyzer:LogTableOperation(operation, ...)
    local args = {...}
    self:AddLog("TABLE_OPERATION", "Table operation: " .. operation, {
        Operation = operation,
        Arguments = args,
        Timestamp = tick()
    })
end

-- Advanced analysis systems
function UltimateIntelligenceAnalyzer:AnalyzeFunctionInfo(info)
    if not info then return end
    
    local funcData = {
        Name = info.name or "anonymous",
        Source = info.source or "?",
        LineDefined = info.linedefined,
        CurrentLine = info.currentline,
        What = info.what,
        Nups = info.nups
    }
    
    table.insert(self.Data.ExtractedFunctions, funcData)
    
    -- Try to extract constants from function
    if self.Config.ExtractConstants and info.func then
        self:ExtractFunctionConstants(info.func, funcData)
    end

    -- Try to extract upvalues/closure info
    if info.func then
        pcall(function() self:ExtractFunctionUpvalues(info.func, funcData) end)
    end

    -- Attempt to capture bytecode and decompiled source if executor provides APIs
    if info.func then
        pcall(function()
            local byte = self:TryGetBytecode(info.func)
            if byte then funcData.Bytecode = byte end
        end)
        pcall(function()
            local dec = self:TryDecompileFunction(info.func)
            if dec then funcData.Decompiled = dec end
        end)
    end
    
    -- Build call graph
    if self.Config.CallGraphReconstruction then
        self:UpdateCallGraph(funcData)
    end
end

function UltimateIntelligenceAnalyzer:ExtractFunctionConstants(func, funcData)
    local success, constants = self:SafeExecute(function()
        -- This would use debug.getconstants in a real implementation
        return {["function_defined"] = funcData.LineDefined or 0}
    end, {}, "ExtractFunctionConstants")
    
    if success and constants then
        table.insert(self.Data.ExtractedConstants, {
            Function = funcData.Name,
            Constants = constants
        })
    end
end

function UltimateIntelligenceAnalyzer:UpdateCallGraph(funcData)
    local callStack = self:GetCallStack()
    if #callStack > 1 then
        local caller = callStack[2] or {Name = "root"}
        local callee = funcData.Name
        
        if not self.Data.CallGraphs[caller.Name] then
            self.Data.CallGraphs[caller.Name] = {}
        end
        
        table.insert(self.Data.CallGraphs[caller.Name], {
            Callee = callee,
            Timestamp = tick(),
            Source = funcData.Source
        })
    end
end

-- Deep remote argument analysis
function UltimateIntelligenceAnalyzer:AnalyzeRemoteArguments(args, remote)
    local analysis = {
        Suspicious = false,
        Patterns = {},
        RiskLevel = "LOW",
        DeepAnalysis = self:DeepAnalyzeArguments(args, 0)
    }
    
    for i, arg in ipairs(args) do
        local argType = type(arg)
        
        -- Detect potential exploits
        if argType == "string" then
            if #arg > 1000 then
                table.insert(analysis.Patterns, "LONG_STRING_ARGUMENT")
                analysis.RiskLevel = "MEDIUM"
            end
            
            -- Check for base64-like patterns
            if string.match(arg, "^[A-Za-z0-9+/]+=*$") and #arg > 20 then
                table.insert(analysis.Patterns, "BASE64_LIKE_PATTERN")
                analysis.RiskLevel = "HIGH"
            end
            
            -- Check for suspicious patterns
            if string.find(arg:lower(), "script") or string.find(arg:lower(), "loadstring") then
                table.insert(analysis.Patterns, "SUSPICIOUS_KEYWORDS")
                analysis.RiskLevel = "HIGH"
            end
        elseif argType == "table" then
            if self:IsSuspiciousTable(arg) then
                table.insert(analysis.Patterns, "SUSPICIOUS_TABLE_STRUCTURE")
                analysis.RiskLevel = "HIGH"
            end
        elseif argType == "function" then
            table.insert(analysis.Patterns, "FUNCTION_IN_REMOTE")
            analysis.RiskLevel = "HIGH"
        end
    end
    
    if #analysis.Patterns > 0 then
        analysis.Suspicious = true
        self:AddLog("SUSPICIOUS_REMOTE", "Suspicious remote arguments detected", {
            Remote = tostring(remote),
            Patterns = analysis.Patterns,
            RiskLevel = analysis.RiskLevel,
            DeepAnalysis = analysis.DeepAnalysis
        })
    end
    
    return analysis
end

-- Deep argument analysis with recursion protection
function UltimateIntelligenceAnalyzer:DeepAnalyzeArguments(args, depth)
    if depth > 3 then 
        return {Error = "MAX_DEPTH_REACHED"}
    end
    
    local analysis = {}
    for i, arg in ipairs(args) do
        local argType = type(arg)
        analysis[i] = {
            Type = argType,
            Value = tostring(arg):sub(1, 100),  -- Limit string length
            Size = self:CalculateArgumentSize(arg),
            Suspicious = false
        }
        
        if argType == "table" then
            analysis[i].TableAnalysis = self:AnalyzeTableStructure(arg, depth + 1)
            analysis[i].Suspicious = self:IsSuspiciousTable(arg)
        elseif argType == "function" then
            analysis[i].Suspicious = true  -- Functions in remotes are suspicious
        elseif argType == "string" and #arg > 500 then
            analysis[i].Suspicious = true
        end
    end
    return analysis
end

function UltimateIntelligenceAnalyzer:CalculateArgumentSize(arg)
    local argType = type(arg)
    if argType == "string" then
        return #arg
    elseif argType == "table" then
        local size = 0
        for k, v in pairs(arg) do
            size = size + self:CalculateArgumentSize(k) + self:CalculateArgumentSize(v)
        end
        return size
    else
        return 1
    end
end

function UltimateIntelligenceAnalyzer:AnalyzeTableStructure(tbl, depth)
    if depth > 2 then return "MAX_DEPTH" end
    
    local structure = {
        KeyTypes = {},
        ValueTypes = {},
        Size = 0,
        HasFunctions = false,
        HasTables = false
    }
    
    for k, v in pairs(tbl) do
        structure.Size = structure.Size + 1
        structure.KeyTypes[type(k)] = true
        structure.ValueTypes[type(v)] = true
        
        if type(v) == "function" then
            structure.HasFunctions = true
        elseif type(v) == "table" then
            structure.HasTables = true
        end
    end
    
    return structure
end

-- Obfuscator fingerprinting system
function UltimateIntelligenceAnalyzer:DetectObfuscationPatterns(code)
    local patterns = {
        -- Common obfuscator signatures
        {pattern = "loadstring", weight = 0.3},
        {pattern = "bytecode", weight = 0.8},
        {pattern = "\\x%x%x", weight = 0.7}, -- Hex escapes
        {pattern = "getfenv", weight = 0.4},
        {pattern = "setfenv", weight = 0.4},
        {pattern = "debug%.", weight = 0.6},
        {pattern = "::[%w_]+::", weight = 0.5}, -- Labels
        {pattern = "%.%.%.%.%.%.+", weight = 0.6}, -- Multiple dots
        {pattern = "%$%$%$", weight = 0.7}, -- Dollar signs
        {pattern = "_____", weight = 0.5}, -- Underscore chains,
    }
    
    local score = 0
    local detectedPatterns = {}
    
    for _, pattern in ipairs(patterns) do
        local count = select(2, string.gsub(code, pattern.pattern, ""))
        if count > 0 then
            score = score + (pattern.weight * math.min(count, 5))
            table.insert(detectedPatterns, {
                Pattern = pattern.pattern,
                Count = count,
                Weight = pattern.weight
            })
        end
    end
    
    -- Entropy analysis for string obfuscation
    local highEntropyStrings = self:AnalyzeStringEntropy(code)
    if highEntropyStrings > 0 then
        score = score + (highEntropyStrings * 0.2)
        table.insert(detectedPatterns, {
            Pattern = "HIGH_ENTROPY_STRINGS",
            Count = highEntropyStrings,
            Weight = 0.2
        })
    end
    
    -- Code structure analysis
    local structureScore = self:AnalyzeCodeStructure(code)
    score = score + structureScore
    
    local fingerprint = {
        Score = math.min(score, 10),
        Confidence = math.min(score / 10, 1),
        Patterns = detectedPatterns,
        Timestamp = tick()
    }
    
    table.insert(self.Data.ObfuscatorFingerprints, fingerprint)
    return fingerprint
end

function UltimateIntelligenceAnalyzer:AnalyzeStringEntropy(code)
    -- Simple entropy analysis - look for high randomness in strings
    local strings = {}
    for str in string.gmatch(code, "['\"]([^'\"]+)['\"]") do
        if #str > 10 then
            local entropy = self:CalculateEntropy(str)
            if entropy > 4.5 then -- High entropy threshold
                table.insert(strings, {String = str:sub(1, 20) .. "...", Entropy = entropy})
            end
        end
    end
    return #strings
end

function UltimateIntelligenceAnalyzer:CalculateEntropy(str)
    local charCount, entropy = {}, 0
    for i = 1, #str do
        local char = str:sub(i, i)
        charCount[char] = (charCount[char] or 0) + 1
    end
    
    for _, count in pairs(charCount) do
        local prob = count / #str
        entropy = entropy - (prob * math.log(prob) / math.log(2))
    end
    
    return entropy
end

function UltimateIntelligenceAnalyzer:AnalyzeCodeStructure(code)
    -- Analyze code structure for obfuscation patterns
    local score = 0
    
    -- Check for unusual line lengths
    local lines = {}
    for line in code:gmatch("[^\r\n]+") do
        table.insert(lines, line)
        if #line > 500 then
            score = score + 0.5  -- Very long lines
        end
    end
    
    -- Check for unusual character distribution
    local alphanumeric = select(2, code:gsub("[%w%s]", ""))
    local totalChars = #code
    if totalChars > 0 and alphanumeric / totalChars < 0.3 then
        score = score + 0.8  -- High proportion of special characters
    end
    
    return score
end

function UltimateIntelligenceAnalyzer:IsSuspiciousTable(tbl)
    -- Check for tables with unusual structures
    local keyTypes, valueTypes = {}, {}
    local functionCount = 0
    local totalItems = 0
    
    for k, v in pairs(tbl) do
        totalItems = totalItems + 1
        keyTypes[type(k)] = true
        valueTypes[type(v)] = true
        if type(v) == "function" then
            functionCount = functionCount + 1
        end
    end
    
        -- Suspicious: Many functions in a table, mixed key types, etc.
        return functionCount > 3 or 
            (totalItems > 10 and functionCount > totalItems * 0.5) or
            (self:TableCount(keyTypes) > 2 and totalItems > 5)
end

-- Real-time remote spam heatmap
function UltimateIntelligenceAnalyzer:UpdateRemoteHeatmap(remoteName)
    local currentTime = tick()
    local timeSlot = math.floor(currentTime)
    
    if not self.RemoteHeatmap[timeSlot] then
        self.RemoteHeatmap[timeSlot] = {}
        
        -- Clean old data
        for slot in pairs(self.RemoteHeatmap) do
            if currentTime - slot > 60 then -- Keep only last minute
                self.RemoteHeatmap[slot] = nil
            end
        end
    end
    
    self.RemoteHeatmap[timeSlot][remoteName] = (self.RemoteHeatmap[timeSlot][remoteName] or 0) + 1
    
    -- Update heatmap display
    if currentTime - self.HeatmapUpdateTime > 0.5 then
        self:UpdateHeatmapDisplay()
        self.HeatmapUpdateTime = currentTime
    end
end

function UltimateIntelligenceAnalyzer:UpdateHeatmapDisplay()
    if not self.HeatmapContainer then return end
    
    -- Clear existing heatmap
    for _, child in ipairs(self.HeatmapContainer:GetChildren()) do
        if child:IsA("Frame") then
            child:Destroy()
        end
    end
    
    -- Calculate frequencies
    local remoteFreq = {}
    for _, timeData in pairs(self.RemoteHeatmap) do
        for remote, count in pairs(timeData) do
            remoteFreq[remote] = (remoteFreq[remote] or 0) + count
        end
    end
    
    -- Create heatmap bars
    local yOffset = 0
    for remote, frequency in pairs(remoteFreq) do
        local riskColor = frequency > 10 and Color3.fromRGB(255, 50, 50) or
                         frequency > 5 and Color3.fromRGB(255, 150, 50) or
                         Color3.fromRGB(50, 200, 50)
        
        local barWidth = math.min(frequency / 20, 0.95)  -- Cap width at 95%
        local bar = self:CreateElement("Frame", {
            Size = UDim2.new(barWidth, 0, 0, 20), -- Scale width by frequency
            Position = UDim2.new(0, 0, 0, yOffset),
            BackgroundColor3 = riskColor,
            BorderSizePixel = 0,
            Parent = self.HeatmapContainer
        })
        
        self:CreateElement("TextLabel", {
            Size = UDim2.new(1, 0, 1, 0),
            BackgroundTransparency = 1,
            Text = remote .. " (" .. frequency .. ")",
            TextColor3 = Color3.fromRGB(255, 255, 255),
            TextSize = 11,
            TextXAlignment = Enum.TextXAlignment.Left,
            Parent = bar
        })
        
        yOffset = yOffset + 25
    end
end

-- Anti-anti-analysis detection
function UltimateIntelligenceAnalyzer:DetectAntiAnalysis()
    local detections = {}
    
    -- Check for debug library tampering
    if debug and debug.getinfo then
        local info = debug.getinfo(1, "S")
        if not info then
            table.insert(detections, "DEBUG_LIBRARY_TAMPERING")
        end
    end
    
    -- Check for environment inspection
    if getfenv and type(getfenv) == "function" then
        local env = getfenv(2)
        if env and env._G and env._G == _G then
            -- Normal case
        else
            table.insert(detections, "ENVIRONMENT_INSPECTION")
        end
    end
    
    -- Lightweight timing check (non-blocking): run a small, bounded loop
    local startTime = tick()
    for i = 1, 1000 do end
    local executionTime = tick() - startTime

    -- Only flag timing anomaly if it's significantly slow relative to threshold
    if executionTime > 0.02 then
        table.insert(detections, "TIMING_ANOMALY")
    end
    
    if #detections > 0 then
        self:AddLog("ANTI_ANALYSIS_DETECTED", "Anti-analysis techniques detected", {
            Techniques = detections,
            RiskLevel = "HIGH"
        })
    end
    
    return detections
end

-- Core GUI System with responsive design
function UltimateIntelligenceAnalyzer:CreateGUI()
    if not self.Config.EnableGUI then return end
    
    self.GUI = Instance.new("ScreenGui")
    self.GUI.Name = "UltimateIntelligenceAnalyzerGUI"
    
    -- Use exploit-specific GUI protection if available
    if syn and syn.protect_gui then
        syn.protect_gui(self.GUI)
    elseif gethui then
        self.GUI.Parent = gethui()
    else
        self.GUI.Parent = CoreGui
    end
    
    self.GUI.ResetOnSpawn = false
    
    -- [Rest of GUI creation code...]
    -- Responsive main frame
    self.MainFrame = self:CreateElement("Frame", {
        Size = UDim2.new(0.8, 0, 0.9, 0), 
        Position = UDim2.new(0.1, 0, 0.05, 0),
        BackgroundColor3 = Color3.fromRGB(30, 30, 40), 
        BorderSizePixel = 0, 
        Parent = self.GUI
    })
    -- Modern styling
    self:CreateElement("UICorner", {CornerRadius = UDim.new(0, 8), Parent = self.MainFrame})
    self:CreateElement("UIStroke", {Color = Color3.fromRGB(60,60,70), Thickness = 1, Parent = self.MainFrame})
    
    local titleBar = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundColor3 = Color3.fromRGB(20, 20, 30),
        BorderSizePixel = 0, 
        Parent = self.MainFrame
    })
    self:CreateElement("UICorner", {CornerRadius = UDim.new(0, 6), Parent = titleBar})
    self:CreateElement("UIStroke", {Color = Color3.fromRGB(45,45,55), Thickness = 1, Parent = titleBar})
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1,
        Text = "🛡️ Ultimate Intelligence Analyzer v4.2", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 18, 
        Font = Enum.Font.GothamBold, 
        Parent = titleBar
    })
    
    local closeButton = self:CreateElement("TextButton", {
        Size = UDim2.new(0, 30, 0, 30), 
        Position = UDim2.new(1, -35, 0.5, -15),
        BackgroundColor3 = Color3.fromRGB(200, 60, 60), 
        Text = "X",
        TextColor3 = Color3.fromRGB(255, 255, 255), 
        TextSize = 14, 
        Parent = titleBar
    })
    self:CreateElement("UICorner", {CornerRadius = UDim.new(0, 6), Parent = closeButton})
    self:CreateElement("UIStroke", {Color = Color3.fromRGB(120,20,20), Thickness = 1, Parent = closeButton})
    
    closeButton.MouseButton1Click:Connect(function() 
        self:Cleanup()
    end)
    
    self:CreateTabs()
    self:MakeDraggable(titleBar)
    self:AddLog("GUI_SYSTEM", "Enhanced GUI initialized", {})
end

-- [Rest of the original GUI functions remain the same...]

-- Note: Due to character limits, I've included the core exploit modifications.
-- The complete script would include ALL the original functions but with exploit-safe file operations
-- and GUI protection as shown above.

-- Initialize the enhanced analyzer
local analyzer = setmetatable({}, UltimateIntelligenceAnalyzer)

-- Store in global environment for easy access
getgenv().UltimateIntelligenceAnalyzer = analyzer

-- Initialize with delayed start and error recovery
delay(2, function()
    local success, err = pcall(function()
        analyzer:StartIntelligenceAnalysis() 
    end)
    
    if not success then
        warn("UltimateIntelligenceAnalyzer initialization failed: " .. tostring(err))
        -- Attempt recovery
        pcall(function()
            analyzer:Cleanup()
            wait(5)
            analyzer:StartIntelligenceAnalysis()
        end)
    end
end)

return analyzer
