Is thier anything wrong with the new code -- Ultimate Runtime Intelligence Analyzer v4.2 - PRODUCTION READY WITH FIXES
local RunService, Players, HttpService, CoreGui, TextService, UserInputService, TweenService = 
    game:GetService("RunService"), game:GetService("Players"), 
    game:GetService("HttpService"), game:GetService("CoreGui"),
    game:GetService("TextService"), game:GetService("UserInputService"),
    game:GetService("TweenService")

if not RunService:IsClient() then 
    error("Client-only script launched on server!") 
    return 
end

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
    MaxMemoryMB = 100
}}

UltimateIntelligenceAnalyzer.__index = UltimateIntelligenceAnalyzer

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
    local success, result = pcall(fn)
    if not success then
        self:AddLog("SYSTEM_ERROR", "Execution failed in " .. (context or "unknown"), {
            Error = tostring(result),
            Traceback = debug.traceback(),
            Timestamp = tick()
        })
        return fallback
    end
    return result
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
        if removed and self.ActiveLogFrames[removed.ID] then
            self:RecycleLogFrame(removed.ID)
        end
    end
    
    -- Clear frame pool with size limits
    for i = #self.LogFramePool, 20, -1 do
        local frame = table.remove(self.LogFramePool, i)
        if frame then frame:Destroy() end
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
    
    -- Initialize queue if needed
    self.LogQueue = self.LogQueue or {}
    self.Data.ExecutionIntelligence = self.Data.ExecutionIntelligence or {}
    
    table.insert(self.LogQueue, logEntry)
    table.insert(self.Data.ExecutionIntelligence, logEntry)
    
    if self.Data.CurrentSession then 
        table.insert(self.Data.CurrentSession.Logs, logEntry) 
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
    if not self.Config.EnableGUI or not self.LogsScrollingFrame then return end
    
    -- Batch create log frames
    for _, logEntry in ipairs(self.LogQueue) do
        self:CreateLogFrame(logEntry)
    end
    
    -- Smooth scrolling
    local targetPosition = Vector2.new(0, self.LogsScrollingFrame.AbsoluteCanvasSize.Y)
    self.LogsScrollingFrame.CanvasPosition = targetPosition
    
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
    if #self.ActiveLogFrames > 200 then
        local oldestId = next(self.ActiveLogFrames)
        if oldestId then
            self:RecycleLogFrame(oldestId)
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
                end
                return coroutine[k]
            end
        }),
        print = function(...)
            local args, output = {...}, table.concat({...}, "\t")
            analyzer:AddLog("PRINT_OUTPUT", "Script printed: " .. output, {Output = output, Arguments = args})
            return print(...)
        end,
        warn = function(...)
            local args, output = {...}, table.concat({...}, "\t")
            analyzer:AddLog("WARN_OUTPUT", "Script warning: " .. output, {Output = output, Arguments = args})
            return warn(...)
        end,
        error = function(msg, level)
            analyzer:AddLog("ERROR_THROWN", "Script error: " .. tostring(msg), {Message = msg, Level = level})
            return error(msg, level)
        end,
        pcall = function(f, ...)
            analyzer:AddLog("PCALL_START", "Protected call started", {Function = tostring(f)})
            local success, result = pcall(f, ...)
            analyzer:AddLog("PCALL_END", "Protected call completed", {Success = success, Result = tostring(result)})
            return success, result
        end,
        xpcall = function(f, err, ...)
            analyzer:AddLog("XCALL_START", "Extended protected call started", {Function = tostring(f)})
            local success, result = xpcall(f, err, ...)
            analyzer:AddLog("XCALL_END", "Extended protected call completed", {Success = success, Result = tostring(result)})
            return success, result
        end,
        type = type, tostring = tostring, tonumber = tonumber, 
        select = select, pairs = pairs, ipairs = ipairs, next = next,
        unpack = table.unpack or unpack, rawequal = rawequal, rawget = rawget, rawset = rawset
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
                
                return service
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
            local child = container[k]
            if child and (child:IsA("RemoteEvent") or child:IsA("RemoteFunction")) then
                return analyzer:HookRemoteInstance(child)
            end
            return child
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
                    safeArgs[i] = "{table with " .. tostring(#args) .. " items}"
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
            
            -- Update heatmap
            analyzer:UpdateRemoteHeatmap(tostring(remote))
            
            -- Analyze arguments for suspicious patterns
            analyzer:AnalyzeRemoteArguments(args, remote)
            
            return originalFireServer(remoteSelf, ...)
        end
    elseif remote:IsA("RemoteFunction") then
        local originalInvokeServer = remote.InvokeServer
        remote.InvokeServer = function(remoteSelf, ...)
            local args = {...}
            local safeArgs = {}
            for i, arg in ipairs(args) do
                safeArgs[i] = tostring(arg):sub(1, 200)
            end
            
            analyzer:AddLog("REMOTE_FUNCTION_INVOKED", "RemoteFunction invoked: " .. tostring(remote), {
                Remote = tostring(remote),
                Arguments = safeArgs,
                ArgumentCount = #args
            })
            
            -- Update heatmap
            analyzer:UpdateRemoteHeatmap(tostring(remote))
            
            analyzer:AnalyzeRemoteArguments(args, remote)
            
            return originalInvokeServer(remoteSelf, ...)
        end
    end
    
    return remote
end

-- Enhanced instance creation hooking
function UltimateIntelligenceAnalyzer:HookInstanceCreation(instance)
    local analyzer = self
    local instanceProxy = {}
    local instanceMetatable = {
        __index = function(_, k)
            local value = instance[k]
            if type(value) == "function" then
                return function(...)
                    return value(instance, ...)
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
            end
            instance[k] = v
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
        {pattern = "_____", weight = 0.5}, -- Underscore chains
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
           (#keyTypes > 2 and totalItems > 5)
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
    
    -- Check for timing attacks
    local startTime = tick()
    for i = 1, 1000000 do end -- Busy work
    local executionTime = tick() - startTime
    
    if executionTime > 0.1 then -- Unusually slow execution
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
    self.GUI.Parent = CoreGui
    self.GUI.ResetOnSpawn = false
    
    -- Responsive main frame
    self.MainFrame = self:CreateElement("Frame", {
        Size = UDim2.new(0.8, 0, 0.9, 0), 
        Position = UDim2.new(0.1, 0, 0.05, 0),
        BackgroundColor3 = Color3.fromRGB(30, 30, 40), 
        BorderSizePixel = 0, 
        Parent = self.GUI
    })
    
    local titleBar = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundColor3 = Color3.fromRGB(20, 20, 30),
        BorderSizePixel = 0, 
        Parent = self.MainFrame
    })
    
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
    
    closeButton.MouseButton1Click:Connect(function() 
        self:Cleanup()
    end)
    
    self:CreateTabs()
    self:MakeDraggable(titleBar)
    self:AddLog("GUI_SYSTEM", "Enhanced GUI initialized", {})
end

function UltimateIntelligenceAnalyzer:CreateTabs()
    local tabButtons = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 50), 
        Position = UDim2.new(0, 0, 0, 40),
        BackgroundColor3 = Color3.fromRGB(40, 40, 50), 
        BorderSizePixel = 0, 
        Parent = self.MainFrame
    })
    
    self.TabContent = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, -90), 
        Position = UDim2.new(0, 0, 0, 90),
        BackgroundColor3 = Color3.fromRGB(35, 35, 45), 
        BorderSizePixel = 0, 
        Parent = self.MainFrame
    })
    
    self.Tabs = {
        {Name = "Loadstring", Icon = "📝", Content = self:CreateLoadstringTab()},
        {Name = "Live Logs", Icon = "📊", Content = self:CreateLogsTab()},
        {Name = "Analysis", Icon = "🔍", Content = self:CreateAnalysisTab()},
        {Name = "Risk Assessment", Icon = "⚠️", Content = self:CreateRiskTab()},
        {Name = "Settings", Icon = "⚙️", Content = self:CreateSettingsTab()}
    }
    
    local buttonWidth = 1 / #self.Tabs
    for i, tab in ipairs(self.Tabs) do
        local tabButton = self:CreateElement("TextButton", {
            Size = UDim2.new(buttonWidth, -2, 0.8, 0), 
            Position = UDim2.new(buttonWidth * (i - 1), 2, 0.1, 0),
            BackgroundColor3 = Color3.fromRGB(50, 50, 60), 
            BorderSizePixel = 0,
            Text = tab.Icon .. " " .. tab.Name, 
            TextColor3 = Color3.fromRGB(200, 200, 200),
            TextSize = 12, 
            Font = Enum.Font.Gotham, 
            Parent = tabButtons
        })
        
        tabButton.MouseButton1Click:Connect(function() 
            self:SwitchTab(i) 
        end)
    end
    
    self:SwitchTab(1)
end

function UltimateIntelligenceAnalyzer:CreateLoadstringTab()
    local container = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        Visible = false, 
        Parent = self.TabContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1,
        Text = "Loadstring Execution & Analysis", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 16, 
        Font = Enum.Font.GothamBold, 
        Parent = container
    })
    
    local inputSection = self:CreateElement("Frame", {
        Size = UDim2.new(1, -20, 0, 200), 
        Position = UDim2.new(0, 10, 0, 50),
        BackgroundColor3 = Color3.fromRGB(40, 40, 50), 
        BorderSizePixel = 0, 
        Parent = container
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 30), 
        BackgroundTransparency = 1,
        Text = "Enter Loadstring Code:", 
        TextColor3 = Color3.fromRGB(200, 200, 200),
        TextSize = 14, 
        Font = Enum.Font.Gotham, 
        Parent = inputSection
    })
    
    self.CodeInput = self:CreateElement("TextBox", {
        Size = UDim2.new(1, -20, 1, -50), 
        Position = UDim2.new(0, 10, 0, 30),
        BackgroundColor3 = Color3.fromRGB(25, 25, 35), 
        BorderSizePixel = 0,
        TextColor3 = Color3.fromRGB(200, 200, 200), 
        TextSize = 12, 
        Font = Enum.Font.Code,
        Text = "-- Paste your loadstring code here\n-- Example: print('Hello World')",
        TextXAlignment = Enum.TextXAlignment.Left, 
        TextYAlignment = Enum.TextYAlignment.Top,
        MultiLine = true, 
        Parent = inputSection
    })
    
    local buttonContainer = self:CreateElement("Frame", {
        Size = UDim2.new(1, -20, 0, 40), 
        Position = UDim2.new(0, 10, 0, 260),
        BackgroundTransparency = 1, 
        Parent = container
    })
    
    self.ExecuteButton = self:CreateElement("TextButton", {
        Size = UDim2.new(0, 120, 1, 0), 
        BackgroundColor3 = Color3.fromRGB(60, 180, 80),
        BorderSizePixel = 0, 
        Text = "🚀 Execute & Analyze", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 14, 
        Font = Enum.Font.GothamBold, 
        Parent = buttonContainer
    })
    
    self.ClearButton = self:CreateElement("TextButton", {
        Size = UDim2.new(0, 80, 1, 0), 
        Position = UDim2.new(0, 130, 0, 0),
        BackgroundColor3 = Color3.fromRGB(80, 80, 100), 
        BorderSizePixel = 0, 
        Text = "🗑️ Clear",
        TextColor3 = Color3.fromRGB(255, 255, 255), 
        TextSize = 14, 
        Parent = buttonContainer
    })
    
    self.StatusLabel = self:CreateElement("TextLabel", {
        Size = UDim2.new(1, -20, 0, 30), 
        Position = UDim2.new(0, 10, 0, 310),
        BackgroundTransparency = 1, 
        Text = "Status: Ready", 
        TextColor3 = Color3.fromRGB(150, 200, 255),
        TextSize = 14, 
        Font = Enum.Font.Gotham, 
        Parent = container
    })
    
    self.ExecuteButton.MouseButton1Click:Connect(function() 
        self:ExecuteLoadstring() 
    end)
    self.ClearButton.MouseButton1Click:Connect(function() 
        self.CodeInput.Text = "" 
        self:UpdateStatus("Cleared input", Color3.fromRGB(150, 200, 255))
    end)
    
    return container
end

function UltimateIntelligenceAnalyzer:CreateLogsTab()
    local container = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        Visible = false, 
        Parent = self.TabContent
    })
    
    local header = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1, 
        Parent = container
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(0.5, 0, 1, 0), 
        BackgroundTransparency = 1,
        Text = "📊 Live Execution Logs", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 16, 
        Font = Enum.Font.GothamBold, 
        Parent = header
    })
    
    local controls = self:CreateElement("Frame", {
        Size = UDim2.new(0.5, 0, 1, 0), 
        Position = UDim2.new(0.5, 0, 0, 0),
        BackgroundTransparency = 1, 
        Parent = header
    })
    
    local clearLogsButton = self:CreateElement("TextButton", {
        Size = UDim2.new(0, 100, 0, 30), 
        Position = UDim2.new(0, 10, 0.5, -15),
        BackgroundColor3 = Color3.fromRGB(200, 80, 80), 
        BorderSizePixel = 0, 
        Text = "🗑️ Clear Logs",
        TextColor3 = Color3.fromRGB(255, 255, 255), 
        TextSize = 12, 
        Font = Enum.Font.Gotham, 
        Parent = controls
    })
    
    local exportLogsButton = self:CreateElement("TextButton", {
        Size = UDim2.new(0, 120, 0, 30), 
        Position = UDim2.new(0, 120, 0.5, -15),
        BackgroundColor3 = Color3.fromRGB(80, 140, 200), 
        BorderSizePixel = 0, 
        Text = "💾 Export Logs",
        TextColor3 = Color3.fromRGB(255, 255, 255), 
        TextSize = 12, 
        Font = Enum.Font.Gotham, 
        Parent = controls
    })
    
    local logsContainer = self:CreateElement("Frame", {
        Size = UDim2.new(1, -20, 1, -60), 
        Position = UDim2.new(0, 10, 0, 50),
        BackgroundColor3 = Color3.fromRGB(25, 25, 35), 
        BorderSizePixel = 0, 
        Parent = container
    })
    
    self.LogsScrollingFrame = self:CreateElement("ScrollingFrame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        BorderSizePixel = 0,
        ScrollBarThickness = 8, 
        VerticalScrollBarInset = Enum.ScrollBarInset.Always, 
        Parent = logsContainer
    })
    
    self:CreateElement("UIListLayout", {
        SortOrder = Enum.SortOrder.LayoutOrder,
        Padding = UDim.new(0, 2),
        Parent = self.LogsScrollingFrame
    })
    
    clearLogsButton.MouseButton1Click:Connect(function() 
        self:ClearLogs() 
    end)
    exportLogsButton.MouseButton1Click:Connect(function() 
        self:ExportSessionReport() 
    end)
    
    return container
end

function UltimateIntelligenceAnalyzer:CreateAnalysisTab()
    local container = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        Visible = false, 
        Parent = self.TabContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1,
        Text = "🔍 Live Analysis Dashboard", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 16, 
        Font = Enum.Font.GothamBold, 
        Parent = container
    })
    
    -- Scrollable analysis container
    local analysisScroller = self:CreateElement("ScrollingFrame", {
        Size = UDim2.new(1, -20, 1, -50), 
        Position = UDim2.new(0, 10, 0, 50),
        BackgroundColor3 = Color3.fromRGB(35, 35, 45), 
        BorderSizePixel = 0,
        ScrollBarThickness = 8, 
        Parent = container
    })
    
    self.AnalysisContent = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 0), 
        BackgroundTransparency = 1, 
        Parent = analysisScroller
    })
    
    self:CreateElement("UIListLayout", {
        Padding = UDim.new(0, 5), 
        Parent = self.AnalysisContent
    })
    
    -- Heatmap section
    local heatmapSection = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 150), 
        BackgroundColor3 = Color3.fromRGB(50, 50, 60),
        BorderSizePixel = 0, 
        Parent = self.AnalysisContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 25), 
        BackgroundTransparency = 1,
        Text = "📡 Remote Call Heatmap (Last 60s)", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 14, 
        Font = Enum.Font.GothamBold, 
        Parent = heatmapSection
    })
    
    self.HeatmapContainer = self:CreateElement("Frame", {
        Size = UDim2.new(1, -10, 1, -30), 
        Position = UDim2.new(0, 5, 0, 25),
        BackgroundTransparency = 1, 
        Parent = heatmapSection
    })
    
    return container
end

function UltimateIntelligenceAnalyzer:CreateRiskTab()
    local container = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        Visible = false, 
        Parent = self.TabContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1,
        Text = "⚠️ Risk Assessment & Security Analysis", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 16, 
        Font = Enum.Font.GothamBold, 
        Parent = container
    })
    
    self.RiskContent = self:CreateElement("Frame", {
        Size = UDim2.new(1, -20, 1, -50), 
        Position = UDim2.new(0, 10, 0, 50),
        BackgroundTransparency = 1, 
        Parent = container
    })
    
    return container
end

function UltimateIntelligenceAnalyzer:CreateSettingsTab()
    local container = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 1, 0), 
        BackgroundTransparency = 1, 
        Visible = false, 
        Parent = self.TabContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1,
        Text = "⚙️ Analyzer Settings", 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 16, 
        Font = Enum.Font.GothamBold, 
        Parent = container
    })
    
    self.SettingsContent = self:CreateElement("Frame", {
        Size = UDim2.new(1, -20, 1, -50), 
        Position = UDim2.new(0, 10, 0, 50),
        BackgroundTransparency = 1, 
        Parent = container
    })
    
    return container
end

function UltimateIntelligenceAnalyzer:SwitchTab(tabIndex)
    if not self.Tabs or tabIndex < 1 or tabIndex > #self.Tabs then
        return
    end
    
    for i, tab in ipairs(self.Tabs) do
        if tab.Content then
            tab.Content.Visible = (i == tabIndex)
        end
    end
end

function UltimateIntelligenceAnalyzer:MakeDraggable(frame)
    local dragging, dragInput, dragStart, startPos
    
    local function update(input)
        local delta = input.Position - dragStart
        self.MainFrame.Position = UDim2.new(
            startPos.X.Scale, startPos.X.Offset + delta.X,
            startPos.Y.Scale, startPos.Y.Offset + delta.Y
        )
    end
    
    frame.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            dragStart = input.Position
            startPos = self.MainFrame.Position
            
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                end
            end)
        end
    end)
    
    frame.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then
            dragInput = input
        end
    end)
    
    UserInputService.InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            update(input)
        end
    end)
end

-- Enhanced execution system with better error handling
function UltimateIntelligenceAnalyzer:ExecuteLoadstring()
    local code = self.CodeInput.Text
    if not code or #code < 5 then
        self:UpdateStatus("Error: Code too short", Color3.fromRGB(255, 100, 100))
        return
    end
    
    -- Detect obfuscation patterns before execution
    local obfuscationFingerprint = self:DetectObfuscationPatterns(code)
    
    self:UpdateStatus("🔄 Executing with enhanced analysis...", Color3.fromRGB(255, 200, 100))
    
    local sessionId = HttpService:GenerateGUID(false)
    self.Data.CurrentSession = {
        Id = sessionId, 
        StartTime = tick(), 
        Code = code, 
        Logs = {}, 
        Results = {},
        ObfuscationScore = obfuscationFingerprint.Score
    }
    
    self:ClearLogs()
    self:AddLog("SESSION_START", "Enhanced execution started", {
        SessionId = sessionId, 
        CodeLength = #code,
        ObfuscationScore = obfuscationFingerprint.Score
    })
    
    -- Run anti-analysis detection
    self:DetectAntiAnalysis()
    
    spawn(function()
        local success, result = self:ExecuteInLoggerEnvironment(code, sessionId)
        
        if success then
            self:UpdateStatus("✅ Execution completed", Color3.fromRGB(100, 255, 100))
            self:AddLog("SESSION_COMPLETE", "Execution completed", {
                SessionId = sessionId, 
                Duration = tick() - self.Data.CurrentSession.StartTime
            })
        else
            self:UpdateStatus("❌ Execution failed: " .. tostring(result), Color3.fromRGB(255, 100, 100))
            self:AddLog("SESSION_ERROR", "Execution failed", {
                SessionId = sessionId, 
                Error = tostring(result)
            })
        end
        
        self:PerformPostExecutionAnalysis(sessionId)
        
        -- Auto-export if enabled
        if self.Config.AutoSaveLogs then
            self:ExportSessionReport()
        end
    end)
end

function UltimateIntelligenceAnalyzer:ExecuteInLoggerEnvironment(code, sessionId)
    local env = self:CreateSecureExecutionEnvironment()
    
    local function executeCode()
        local chunk, compileError = loadstring(code, "LoggerSession_" .. sessionId)
        if not chunk then return false, "Compile Error: " .. tostring(compileError) end
        
        setfenv(chunk, env)
        local startTime = tick()
        local success, result = pcall(chunk)
        local executionTime = tick() - startTime
        
        -- Log performance metrics
        self:AddLog("PERFORMANCE_METRIC", "Execution completed", {
            ExecutionTime = executionTime,
            Success = success,
            SessionId = sessionId
        })
        
        return success, result
    end
    
    return self:SafeExecute(executeCode, false, "ExecuteInLoggerEnvironment")
end

-- Utility functions with better error handling
function UltimateIntelligenceAnalyzer:ClearLogs()
    if self.LogsScrollingFrame then
        for _, child in ipairs(self.LogsScrollingFrame:GetChildren()) do
            if child:IsA("Frame") then
                child:Destroy()
            end
        end
    end
    
    -- Clear data structures
    self.Data.ExecutionIntelligence = {}
    self.LogQueue = {}
    
    self:UpdateStatus("Logs cleared", Color3.fromRGB(150, 200, 255))
end

function UltimateIntelligenceAnalyzer:PerformPostExecutionAnalysis(sessionId)
    self:UpdateStatus("🔍 Performing post-execution analysis...", Color3.fromRGB(200, 150, 255))
    
    -- Analyze captured data
    local analysis = {
        FunctionPatterns = self:AnalyzeFunctionPatterns(),
        RemotePatterns = self:AnalyzeRemotePatterns(),
        SecurityAssessment = self:PerformSecurityAssessment(),
        PerformanceMetrics = self:CalculatePerformanceMetrics()
    }
    
    self:AddLog("ANALYSIS_COMPLETE", "Post-execution analysis completed", analysis)
    self:UpdateAnalysisTab(analysis)
    self:UpdateRiskTab()
end

function UltimateIntelligenceAnalyzer:AnalyzeFunctionPatterns()
    return {
        TotalCalls = #self.Data.FunctionCalls,
        UniqueFunctions = self:CountUniqueFunctions(),
        AverageCallDepth = self:CalculateAverageCallDepth(),
        MostFrequentFunction = self:GetMostFrequentFunction()
    }
end

function UltimateIntelligenceAnalyzer:CountUniqueFunctions()
    local unique = {}
    for _, call in ipairs(self.Data.FunctionCalls) do
        unique[call.CallData and call.CallData.Name or "anonymous"] = true
    end
    return #unique
end

function UltimateIntelligenceAnalyzer:CalculateAverageCallDepth()
    if #self.Data.FunctionCalls == 0 then return 0 end
    local totalDepth = 0
    for _, call in ipairs(self.Data.FunctionCalls) do
        totalDepth = totalDepth + (#(call.CallData and call.CallData.CallStack or {}) or 0)
    end
    return totalDepth / #self.Data.FunctionCalls
end

function UltimateIntelligenceAnalyzer:GetMostFrequentFunction()
    local frequency, mostFrequent, maxCount = {}, "none", 0
    for _, call in ipairs(self.Data.FunctionCalls) do
        local name = call.CallData and call.CallData.Name or "anonymous"
        frequency[name] = (frequency[name] or 0) + 1
        if frequency[name] > maxCount then
            mostFrequent, maxCount = name, frequency[name]
        end
    end
    return mostFrequent
end

function UltimateIntelligenceAnalyzer:AnalyzeRemotePatterns()
    return {
        TotalRemotes = #self.Data.RemoteCommunications,
        RemoteTypes = self:CountRemoteTypes(),
        AverageArguments = self:CalculateAverageArguments()
    }
end

function UltimateIntelligenceAnalyzer:CountRemoteTypes()
    local types = {}
    for _, remote in ipairs(self.Data.RemoteCommunications) do
        local remoteType = remote.Type or "Unknown"
        types[remoteType] = (types[remoteType] or 0) + 1
    end
    return types
end

function UltimateIntelligenceAnalyzer:CalculateAverageArguments()
    if #self.Data.RemoteCommunications == 0 then return 0 end
    local totalArgs = 0
    for _, remote in ipairs(self.Data.RemoteCommunications) do
        totalArgs = totalArgs + (#(remote.Arguments or {}))
    end
    return totalArgs / #self.Data.RemoteCommunications
end

function UltimateIntelligenceAnalyzer:PerformSecurityAssessment()
    return {
        RiskLevel = self:CalculateSessionRisk(),
        RemoteRisk = self:CountLogsByCategory("REMOTE_EVENT_FIRED") > 10 and "High" or "Normal",
        ErrorRisk = self:CountLogsByCategory("ERROR_THROWN") > 5 and "High" or "Normal",
        SecurityRisk = self:CountLogsByCategory("SECURITY") > 0 and "Detected" or "None",
        ObfuscationRisk = self.Data.CurrentSession and self.Data.CurrentSession.ObfuscationScore > 5 and "High" or "Low"
    }
end

function UltimateIntelligenceAnalyzer:CalculateSessionRisk()
    local riskScore = 0
    if self:CountLogsByCategory("REMOTE_EVENT_FIRED") > 10 then riskScore = riskScore + 30 end
    if self:CountLogsByCategory("ERROR_THROWN") > 5 then riskScore = riskScore + 40 end
    if self:CountLogsByCategory("SECURITY") > 0 then riskScore = riskScore + 50 end
    if self.Data.CurrentSession and self.Data.CurrentSession.ObfuscationScore > 5 then riskScore = riskScore + 30 end
    return riskScore >= 70 and "HIGH" or riskScore >= 40 and "MEDIUM" or "LOW"
end

function UltimateIntelligenceAnalyzer:CountLogsByCategory(category)
    local count = 0
    for _, log in ipairs(self.Data.CurrentSession and self.Data.CurrentSession.Logs or {}) do
        if log.Category == category then count = count + 1 end
    end
    return count
end

function UltimateIntelligenceAnalyzer:CalculatePerformanceMetrics()
    if not self.Data.CurrentSession then return {} end
    local duration = tick() - self.Data.CurrentSession.StartTime
    local logRate = #self.Data.CurrentSession.Logs / math.max(duration, 1)
    return {
        ExecutionTime = duration,
        LogsPerSecond = logRate,
        MemoryUsage = collectgarbage("count"),
        Efficiency = math.min(logRate * 10, 100),
        FrameRate = self.PerformanceStats.FrameRate
    }
end

function UltimateIntelligenceAnalyzer:UpdateAnalysisTab(analysis)
    if not self.AnalysisContent then return end
    
    -- Clear existing analysis cards (except heatmap)
    for _, child in ipairs(self.AnalysisContent:GetChildren()) do
        if child:IsA("Frame") and child ~= self.HeatmapContainer.Parent then
            child:Destroy()
        end
    end
    
    local yOffset = 160 -- Start after heatmap section
    for title, data in pairs(analysis) do
        if title ~= "SecurityAssessment" then
            local card = self:CreateElement("Frame", {
                Size = UDim2.new(1, 0, 0, 80), 
                Position = UDim2.new(0, 0, 0, yOffset),
                BackgroundColor3 = Color3.fromRGB(50, 50, 60), 
                BorderSizePixel = 0, 
                Parent = self.AnalysisContent
            })
            
            self:CreateElement("TextLabel", {
                Size = UDim2.new(1, 0, 0, 25), 
                BackgroundTransparency = 1, 
                Text = title,
                TextColor3 = Color3.fromRGB(255, 255, 255), 
                TextSize = 14, 
                Parent = card
            })
            
            self:CreateElement("TextLabel", {
                Size = UDim2.new(1, -10, 1, -30), 
                Position = UDim2.new(0, 5, 0, 25),
                BackgroundTransparency = 1, 
                Text = self:FormatAnalysisData(data),
                TextColor3 = Color3.fromRGB(200, 200, 200), 
                TextSize = 11, 
                TextWrapped = true, 
                Parent = card
            })
            
            yOffset = yOffset + 90
        end
    end
end

function UltimateIntelligenceAnalyzer:FormatAnalysisData(data)
    if type(data) == "table" then
        local parts = {}
        for k, v in pairs(data) do
            if type(v) == "table" then
                table.insert(parts, k .. ": " .. tostring(#v) .. " items")
            else
                table.insert(parts, k .. ": " .. tostring(v))
            end
        end
        return table.concat(parts, "\n")
    end
    return tostring(data)
end

function UltimateIntelligenceAnalyzer:UpdateRiskTab()
    if not self.RiskContent then return end
    
    -- Clear existing content
    for _, child in ipairs(self.RiskContent:GetChildren()) do
        child:Destroy()
    end
    
    local securityAssessment = self:PerformSecurityAssessment()
    local riskLevel = securityAssessment.RiskLevel or "UNKNOWN"
    local riskColor = riskLevel == "HIGH" and Color3.fromRGB(255, 100, 100) or
                      riskLevel == "MEDIUM" and Color3.fromRGB(255, 200, 100) or
                      Color3.fromRGB(100, 200, 100)
    
    local riskCard = self:CreateElement("Frame", {
        Size = UDim2.new(1, 0, 0, 120), 
        BackgroundColor3 = riskColor,
        BorderSizePixel = 0, 
        Parent = self.RiskContent
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, 0, 0, 40), 
        BackgroundTransparency = 1,
        Text = "Overall Risk Level: " .. riskLevel, 
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 18, 
        Font = Enum.Font.GothamBold, 
        Parent = riskCard
    })
    
    self:CreateElement("TextLabel", {
        Size = UDim2.new(1, -10, 1, -45), 
        Position = UDim2.new(0, 5, 0, 40),
        BackgroundTransparency = 1, 
        Text = self:FormatRiskDetails(securityAssessment),
        TextColor3 = Color3.fromRGB(255, 255, 255), 
        TextSize = 12, 
        TextWrapped = true, 
        Parent = riskCard
    })
end

function UltimateIntelligenceAnalyzer:FormatRiskDetails(assessment)
    local details = {}
    if assessment.RemoteRisk then table.insert(details, "📡 Remote Communications: " .. assessment.RemoteRisk) end
    if assessment.ErrorRisk then table.insert(details, "💥 Error Frequency: " .. assessment.ErrorRisk) end
    if assessment.SecurityRisk then table.insert(details, "🛡️ Security Issues: " .. assessment.SecurityRisk) end
    if assessment.ObfuscationRisk then table.insert(details, "🔒 Obfuscation Level: " .. assessment.ObfuscationRisk) end
    return table.concat(details, "\n")
end

-- Auto-generated JSON report system
function UltimateIntelligenceAnalyzer:ExportSessionReport()
    if not self.Data.CurrentSession then
        self:UpdateStatus("No active session to export", Color3.fromRGB(255, 150, 100))
        return nil
    end
    
    local report = {
        Metadata = {
            Version = "4.2",
            ExportTime = os.date("%Y-%m-%d %H:%M:%S"),
            SessionId = self.Data.CurrentSession.Id,
            Duration = tick() - self.Data.CurrentSession.StartTime,
            Player = Players.LocalPlayer and Players.LocalPlayer.Name or "Unknown",
            GameID = game.GameId
        },
        Analysis = {
            FunctionAnalysis = self.Data.ExtractedFunctions,
            RemoteAnalysis = self.Data.RemoteCommunications,
            ObfuscationDetection = self.Data.ObfuscatorFingerprints,
            RiskAssessment = self:CalculateSessionRisk(),
            CallGraph = self.Data.CallGraphs,
            PerformanceMetrics = self:CalculatePerformanceMetrics(),
            SecurityAssessment = self:PerformSecurityAssessment()
        },
        Logs = self.Data.CurrentSession.Logs
    }
    
    local success, jsonData = pcall(function()
        return HttpService:JSONEncode(report)
    end)
    
    if not success then
        self:UpdateStatus("JSON encoding failed", Color3.fromRGB(255, 100, 100))
        return nil
    end
    
    if writefile then
        local filename = "intelligence_report_" .. os.time() .. ".json"
        writefile(filename, jsonData)
        self:UpdateStatus("Exported JSON report: " .. filename, Color3.fromRGB(100, 255, 100))
        return filename
    else
        self:UpdateStatus("Export failed: writefile not available", Color3.fromRGB(255, 100, 100))
        return nil
    end
end

-- Comprehensive cleanup system
function UltimateIntelligenceAnalyzer:Cleanup()
    self:AddLog("SYSTEM", "Cleaning up analyzer resources", {})
    
    -- Stop performance monitoring
    if self.PerformanceMonitor then
        self.PerformanceMonitor:Disconnect()
        self.PerformanceMonitor = nil
    end
    
    -- Clear GUI
    if self.GUI then
        pcall(function() self.GUI:Destroy() end)
        self.GUI = nil
    end
    
    -- Clear all active references
    self.ActiveLogFrames = {}
    self.LogFramePool = {}
    self.LogQueue = {}
    self.RemoteHeatmap = {}
    self.HookedRemotes = {}
    
    -- Clear data structures but keep configuration
    local savedConfig = self.Config
    self.Data = {}
    self.Config = savedConfig
    
    -- Reinitialize basic structures
    for _, category in ipairs({"ExecutionIntelligence", "PerformanceMetrics"}) do
        self.Data[category] = {}
    end
    
    self:UpdateStatus("Analyzer cleaned up and ready for restart", Color3.fromRGB(200, 200, 100))
end

-- Safe initialization
function UltimateIntelligenceAnalyzer:StartIntelligenceAnalysis()
    -- Initialize all required systems
    self.StartTime = tick()
    
    -- Ensure all data structures exist
    for _, category in ipairs({
        "ExecutionIntelligence", "FunctionCalls", "RuntimeTables", 
        "ExtractedVariables", "ExtractedConstants", "ExtractedFunctions",
        "RemoteCommunications", "DecompiledFunctions", "BytecodeAnalysis",
        "ObfuscatorFingerprints", "CallGraphs", "BehaviorClassifications",
        "AntiAnalysisDetections", "PatternRecognition", "RiskAssessments",
        "SessionLogs", "PerformanceMetrics"
    }) do
        self.Data[category] = self.Data[category] or {}
    end
    
    -- Initialize queues and pools
    self.LogQueue = self.LogQueue or {}
    self.LogFramePool = self.LogFramePool or {}
    self.ActiveLogFrames = self.ActiveLogFrames or {}
    self.RemoteHeatmap = self.RemoteHeatmap or {}
    self.HookedRemotes = self.HookedRemotes or {}
    self.PerformanceStats = self.PerformanceStats or {}
    
    self:AddLog("SYSTEM", "Ultimate Intelligence Analyzer v4.2 Started", {
        Player = Players.LocalPlayer and Players.LocalPlayer.Name or "Unknown",
        GameID = game.GameId,
        Config = self.Config
    })
    
    -- Start systems safely
    self:StartPerformanceMonitor()
    
    if self.Config.EnableGUI then
        self:CreateGUI()
    end
    
    self:UpdateStatus("🛡️ Enhanced Analyzer Ready - Enter loadstring to begin", Color3.fromRGB(100, 255, 100))
end

-- Initialize the enhanced analyzer
local analyzer = setmetatable({}, UltimateIntelligenceAnalyzer)

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