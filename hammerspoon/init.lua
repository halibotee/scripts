--------------------------------------------------------------------------------
-- GEMINI-Prime 核心守护进程 (v4.5.6) - 中文系统深度适配版 (完美适配前台调度)
-- 修订：窗口排列时，使用 CoreGraphics 真实显示尺寸剔除台前调度左侧缩略图窗口
-- 修订：WindowManager 改为三档开关 (0 关闭 / 1 仅排列 / 2 排列 + 再次长按恢复)
-- 修订：开关面板沿用原单行格式，并在行尾注释中补充各参数值（0 / 1 / 2）的说明
--------------------------------------------------------------------------------

local logger = hs.logger.new('CoreDaemon', 'info')

-- =============================================================================
-- [全局功能开关面板 Feature Toggles] (0: 关闭, 1: 开启, 部分模块另有 2 档，见各行说明)
-- =============================================================================
local FeatureSwitches = {
    AutoQuit      = 0,  -- 模块 1：自动退出应用 (0 关闭；1 开启：应用最后一个窗口关闭后自动退出，有未保存文档或在排除名单内的除外)
    FinderTools   = 1,  -- 模块 2：Command+E 访达静默新建文本 (0 关闭；1 开启)
    KeyRemapper   = 1,  -- 模块 3：右 Command 映射 Delete (0xE7 -> 0x4C) (0 关闭并恢复系统默认键位；1 开启)
    ServerMode    = 0,  -- 模块 4：服务器模式 合盖插电不眠+拔电后15s休眠 (0 关闭；1 开启)
    WindowManager = 1   -- 模块 5：左 Cmd 长按一键排列 + 鼠标边缘吸附分屏 (0 关闭；1 开启，长按仅排列；2 开启，再次长按左 Cmd 恢复原有布局)
}

-- =============================================================================
-- [系统级紧急逃生舱] 
-- =============================================================================
hs.hotkey.bind({"cmd", "ctrl", "alt", "shift"}, "K", function()
    hs.alert.show("🚨 紧急重载 Hammerspoon 🚨", 2)
    hs.reload()
end)

-- =============================================================================
-- 模块 1：AutoQuit
-- =============================================================================
if FeatureSwitches.AutoQuit == 1 then
    do
        local Config = {
            delay = 0.5,
            ExcludeList = {
                ["Finder"] = true, ["访达"] = true, ["Hammerspoon"] = true, ["Dock"] = true,
                ["WeChat"] = true, ["微信"] = true, ["Music"] = true, ["音乐"] = true,
                ["IINA"] = true, ["Google Chrome"] = true, ["iMovie"] = true,
                ["Microsoft Word"] = true, ["Microsoft Excel"] = true,
                ["Microsoft PowerPoint"] = true, ["Battery Toolkit"] = true,
                ["MakLock"] = true, ["Code"] = true, ["iTerm2"] = true,
            }
        }

        local function hasUnsavedDocument(app)
            for _, win in ipairs(app:allWindows()) do
                if win.isDocumentEdited and win:isDocumentEdited() then return true end
                local title = win:title()
                if title and (string.find(title, "^●") or string.find(title, "— 已编辑") or string.find(title, "— Edited") or string.find(title, "%*")) then
                    return true
                end
            end
            return false
        end

        local function processApp(app)
            if not app or not app:isRunning() or app:kind() ~= 1 then return end
            if Config.ExcludeList[app:name()] then return end
            local visibleWindows = 0
            for _, win in ipairs(app:allWindows()) do
                if win:isStandard() then visibleWindows = visibleWindows + 1 end
            end
            if visibleWindows == 0 and not hasUnsavedDocument(app) then app:kill() end
        end

        local quitWatcher = hs.window.filter.default
        quitWatcher:subscribe(hs.window.filter.windowDestroyed, function(win)
            local app = win:application()
            if not app or app:kind() ~= 1 then return end
            hs.timer.doAfter(Config.delay, function() processApp(app) end)
        end)
    end
end

-- =============================================================================
-- 模块 2：Finder 生产力增强
-- =============================================================================
if FeatureSwitches.FinderTools == 1 then
    do
        hs.hotkey.bind({"cmd"}, "E", function()
            local success, result, _ = hs.osascript.applescript([[
                tell application "Finder"
                    try
                        set currentPath to (insertion location as alias)
                        return POSIX path of currentPath
                    on error
                        return POSIX path of (desktop as alias)
                    end try
                end tell
            ]])
            if not success or type(result) ~= "string" then return end
            local basePath = result:gsub("\n", "")
            local fileName, extension = "untitled", ".MD"
            local finalPath = basePath .. fileName .. extension
            if hs.fs.attributes(finalPath) then
                local i = 1
                while true do
                    finalPath = basePath .. fileName .. " " .. i .. extension
                    if not hs.fs.attributes(finalPath) then break end
                    i = i + 1
                end
            end
            os.execute('touch "' .. finalPath .. '"')
            hs.alert.show("已新建: " .. finalPath:match("^.+/(.+)$"), 0.5) 
        end)
    end
end

-- =============================================================================
-- 模块 3：内核级硬件劫持 (物理右 Command -> Delete)
-- =============================================================================
do
    local mapCmd = [[hidutil property --set '{"UserKeyMapping":[{"HIDKeyboardModifierMappingSrc":0x7000000E7,"HIDKeyboardModifierMappingDst":0x70000004C}]}' > /dev/null 2>&1]]
    local resetCmd = [[hidutil property --set '{"UserKeyMapping":[]}' > /dev/null 2>&1]]
    
    if FeatureSwitches.KeyRemapper == 1 then 
        os.execute(mapCmd) 
    else 
        os.execute(resetCmd) 
    end
end

-- =============================================================================
-- 模块 4：ServerMode
-- =============================================================================
if FeatureSwitches.ServerMode == 1 then
    _G.ServerModeObjects = _G.ServerModeObjects or {}
    
    do
        local SLEEP_DELAY = 15 
        local serverDelayTimer = nil
        local heartbeatTimer = nil

        local function isReallyPowered()
            local ps = hs.battery.powerSource()
            local charging = hs.battery.isCharging()
            return (ps ~= "Battery Power") or charging
        end

        local function enforceAssertions()
            if isReallyPowered() then
                hs.caffeinate.set("system", true, false)
                hs.caffeinate.set("systemIdle", true, false)
            end
        end

        local function updateServerStatus()
            local isPlugged = isReallyPowered()
            
            if isPlugged then
                enforceAssertions()
                if not heartbeatTimer then
                    heartbeatTimer = hs.timer.doEvery(60, enforceAssertions)
                end
                if serverDelayTimer then
                    serverDelayTimer:stop()
                    serverDelayTimer = nil
                end
            else
                if not serverDelayTimer then
                    serverDelayTimer = hs.timer.doAfter(SLEEP_DELAY, function()
                        if not isReallyPowered() then
                            hs.caffeinate.set("system", false)
                            hs.caffeinate.set("systemIdle", false)
                            if heartbeatTimer then 
                                heartbeatTimer:stop() 
                                heartbeatTimer = nil 
                            end
                        end
                        serverDelayTimer = nil
                    end)
                end
            end
        end

        if _G.ServerModeObjects.batteryWatcher then _G.ServerModeObjects.batteryWatcher:stop() end
        _G.ServerModeObjects.batteryWatcher = hs.battery.watcher.new(updateServerStatus):start()

        if _G.ServerModeObjects.sleepWatcher then _G.ServerModeObjects.sleepWatcher:stop() end
        _G.ServerModeObjects.sleepWatcher = hs.caffeinate.watcher.new(function(eventType)
            if eventType == hs.caffeinate.watcher.systemWillSleep then
                if isReallyPowered() then
                    hs.caffeinate.lockScreen()
                    hs.timer.doAfter(0.5, enforceAssertions)
                end
            elseif eventType == hs.caffeinate.watcher.systemDidWake then
                updateServerStatus()
            end
        end):start()

        updateServerStatus()
    end
end

-- =============================================================================
-- 模块 5：WindowManager (左 Cmd 长按一键排列/恢复 + 鼠标边缘吸附分屏)
-- =============================================================================
if FeatureSwitches.WindowManager >= 1 then
    _G.WindowManagerObjects = _G.WindowManagerObjects or {}

    do
        hs.window.animationDuration = 0

        local LEFT_CMD_KEYCODE = 55     -- 物理左侧 Command 硬件键码
        local HOLD_THRESHOLD   = 0.4    -- 长按触发阈值（秒）
        local EDGE_THRESHOLD   = 15     -- 鼠标拖拽至屏幕边缘的吸附像素阈值
        local THUMB_RATIO      = 0.85   -- 屏幕实际显示尺寸 / 窗口真实尺寸 低于此值，判定为台前调度缩略图
        local DEBUG_WINDOWS    = false  -- 设为 true：长按排列时在 Hammerspoon 控制台输出每个窗口的判定详情

        local holdTimer  = nil
        local isArranged = false
        local savedFrames = {}

        -- 通过 CoreGraphics 读取"当前真正显示在屏幕上"的窗口及其实际显示尺寸。
        -- 台前调度左侧缩略图：辅助功能接口(AX)返回的仍是窗口的原始大小，
        -- 但 CoreGraphics 返回的是被缩小后的真实显示尺寸，据此即可准确区分。
        -- 返回 { [窗口ID字符串] = {x=, y=, w=, h=} }；失败时返回 nil。
        local function getOnScreenBounds()
            local ok, result = hs.osascript.javascript([[
                ObjC.import('CoreGraphics');
                var opts = $.kCGWindowListOptionOnScreenOnly | $.kCGWindowListExcludeDesktopElements;
                var raw = $.CGWindowListCopyWindowInfo(opts, $.kCGNullWindowID);
                var list = ObjC.deepUnwrap(ObjC.castRefToObject(raw));
                var out = {};
                list.forEach(function(w) {
                    if (w.kCGWindowLayer === 0 && w.kCGWindowBounds) {
                        out[String(w.kCGWindowNumber)] = {
                            x: w.kCGWindowBounds.X,
                            y: w.kCGWindowBounds.Y,
                            w: w.kCGWindowBounds.Width,
                            h: w.kCGWindowBounds.Height
                        };
                    }
                });
                JSON.stringify(out);
            ]])
            if not ok then return nil end
            if type(result) == "string" then
                local decoded = hs.json.decode(result)
                if type(decoded) == "table" then return decoded end
                return nil
            end
            if type(result) == "table" then return result end
            return nil
        end

        -- 判断窗口是否为当前舞台的"真实大窗口"
        local function isRealStageWindow(win, bounds, screenFrame)
            local f = win:frame()
            local id = tostring(win:id())

            if bounds then
                local b = bounds[id]
                -- 不在屏幕显示列表里（其他舞台被隐藏等）→ 排除
                if not b then
                    if DEBUG_WINDOWS then
                        print(string.format("[排除-不在屏幕] %s (%s)", win:title() or "", id))
                    end
                    return false
                end
                -- 实际显示尺寸明显小于真实尺寸 → 左侧缩略图 → 排除
                local isThumb = (b.w < f.w * THUMB_RATIO) or (b.h < f.h * THUMB_RATIO)
                if DEBUG_WINDOWS then
                    print(string.format("[%s] %s | AX %dx%d | CG %dx%d @ (%d,%d)",
                        isThumb and "排除-缩略图" or "保留", win:title() or "", f.w, f.h, b.w, b.h, b.x, b.y))
                end
                return not isThumb
            end

            -- 兜底：CoreGraphics 查询失败时，退回坐标范围判断
            if f.x < screenFrame.x - 20 or f.x > screenFrame.x + screenFrame.w then
                return false
            end
            return true
        end

        -- 一键网格自动排列当前屏幕的活动窗口（完美适配前台调度，过滤左侧边栏缩略图）
        local function arrangeWindows()
            local screen = hs.screen.mainScreen()
            local screenFrame = screen:frame()
            local bounds = getOnScreenBounds()

            -- 使用 window.filter 获取当前 Space 的标准窗口
            local wf = hs.window.filter.defaultCurrentSpace
            local windows = hs.fnutils.filter(wf:getWindows(), function(win)
                if not win:isStandard() or win:screen() ~= screen then return false end
                return isRealStageWindow(win, bounds, screenFrame)
            end)

            local count = #windows
            if count == 0 then
                hs.alert.show("当前无可排列的活动窗口", 0.8)
                return 
            end

            savedFrames = {}
            for _, win in ipairs(windows) do
                savedFrames[win:id()] = win:frame()
            end

            local cols = math.ceil(math.sqrt(count))
            local rows = math.ceil(count / cols)
            local cellHeight = screenFrame.h / rows

            for i, win in ipairs(windows) do
                local index = i - 1
                local col = index % cols
                local row = math.floor(index / cols)
                local currentCols = (row == rows - 1) and (count - row * cols) or cols
                local actualWidth = screenFrame.w / currentCols

                win:setFrame({
                    x = screenFrame.x + col * actualWidth,
                    y = screenFrame.y + row * cellHeight,
                    w = actualWidth,
                    h = cellHeight
                })
            end
            isArranged = true
            hs.alert.show("已自动排列 (" .. count .. " 个窗口)", 0.8)
        end

        -- 恢复原有的窗口位置与尺寸
        local function restoreWindows()
            for winId, oldFrame in pairs(savedFrames) do
                local win = hs.window.get(winId)
                if win and win:isStandard() then
                    win:setFrame(oldFrame)
                end
            end
            isArranged = false
            savedFrames = {}
            hs.alert.show("已恢复原有窗口布局", 0.8)
        end

        local function toggleWindowArrangement()
            -- 档位 2：已排列状态下再次长按 → 恢复原有布局
            -- 档位 1：每次长按都只执行排列，不恢复
            if FeatureSwitches.WindowManager >= 2 and isArranged then
                restoreWindows()
            else
                arrangeWindows()
            end
        end

        -- 清理旧监听器防止重载重复挂载
        if _G.WindowManagerObjects.cmdHoldTap then _G.WindowManagerObjects.cmdHoldTap:stop() end
        if _G.WindowManagerObjects.dragSnapTap then _G.WindowManagerObjects.dragSnapTap:stop() end

        -- 1. 监听左侧 Command 单独长按
        _G.WindowManagerObjects.cmdHoldTap = hs.eventtap.new({
            hs.eventtap.event.types.flagsChanged,
            hs.eventtap.event.types.keyDown,
            hs.eventtap.event.types.leftMouseDown
        }, function(event)
            local eventType = event:getType()
            if eventType == hs.eventtap.event.types.keyDown or eventType == hs.eventtap.event.types.leftMouseDown then
                if holdTimer then
                    holdTimer:stop()
                    holdTimer = nil
                end
                return false
            end
            local keyCode = event:getKeyCode()
            local flags = event:getFlags()
            if keyCode == LEFT_CMD_KEYCODE then
                local onlyCmd = flags.cmd and not (flags.shift or flags.ctrl or flags.alt or flags.fn)
                if onlyCmd then
                    if not holdTimer then
                        holdTimer = hs.timer.doAfter(HOLD_THRESHOLD, function()
                            holdTimer = nil
                            toggleWindowArrangement()
                        end)
                    end
                else
                    if holdTimer then
                        holdTimer:stop()
                        holdTimer = nil
                    end
                end
            else
                if holdTimer then
                    holdTimer:stop()
                    holdTimer = nil
                end
            end
            return false
        end):start()

        -- 2. 监听鼠标拖拽窗口到屏幕边缘松手自动吸附
        _G.WindowManagerObjects.dragSnapTap = hs.eventtap.new({
            hs.eventtap.event.types.leftMouseUp
        }, function(event)
            local win = hs.window.focusedWindow()
            if not win or not win:isStandard() then return false end
            local mousePos = hs.mouse.absolutePosition()
            local screen = hs.mouse.getCurrentScreen()
            local max = screen:frame()
            local full = screen:fullFrame()
            if mousePos.x <= full.x + EDGE_THRESHOLD then
                win:setFrame({x = max.x, y = max.y, w = max.w / 2, h = max.h})
                isArranged = false
            elseif mousePos.x >= full.x + full.w - EDGE_THRESHOLD then
                win:setFrame({x = max.x + max.w / 2, y = max.y, w = max.w / 2, h = max.h})
                isArranged = false
            elseif mousePos.y <= full.y + EDGE_THRESHOLD then
                win:setFrame(max)
                isArranged = false
            end
            return false
        end):start()
    end
end

-- =============================================================================
-- [启动诊断报告]
-- =============================================================================
local statusMsg = "Hammerspoon v4.5.6\n"
local keys = {}
for k in pairs(FeatureSwitches) do table.insert(keys, k) end
table.sort(keys)
for _, moduleName in ipairs(keys) do
    local status = FeatureSwitches[moduleName]
    local stateStr = "❌ OFF"
    if status == 1 then
        stateStr = "✅ ON"
    elseif status >= 2 then
        stateStr = "✅ ON (Lv" .. status .. ")"
    end
    statusMsg = statusMsg .. string.format("%s: %s\n", moduleName, stateStr)
end
hs.alert.show(statusMsg, 3)
