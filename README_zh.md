# DLLHijacking-Patcher

基于 [TitanEngine](https://github.com/HelloYmf/TitanEngine) 的 Windows DLL 动态追踪与补丁工具。

本工具追踪目标 DLL 中执行的每一条指令，识别初始化阶段，发现初始化后的调用点（**points**），计算 `.text` 段中最大的空白区域，并通过将 `CALL` 指令重定向到该区域来验证每个调用点——确认该区域可安全到达且可写入 shellcode。

支持 **x86** 和 **x64** 目标程序。

---

## 工作原理

```
┌─────────────┐   InitDebugW    ┌──────────────────┐
│ dll_tracer  │ ─────────────►  │  Target Process  │
│  (debugger) │                 │  (EXE + DLL)     │
│             │ ◄── MemBPX ───  │                  │
│  ┌────────┐ │   (on 1st DLL   │                  │
│  │ Tracer │ │    execution)   │                  │
│  └────────┘ │                 │                  │
│  ┌────────┐ │ ── StepInto ──► │                  │
│  │  DB    │ │ ◄─ callback ──  │  (every instr)   │
│  └────────┘ │                 └──────────────────┘
└─────────────┘
       │
       ▼
  SQLite .db  ──►  Validation  ──►  outputs/<callerRva>_<foa>_<size>/
```

### 核心算法

| 阶段 | 描述 |
| --- | --- |
| **初始化检测** | 从 DLL 加载开始追踪，直到第一个导出函数被调用。此前执行的所有指令属于"初始化区域"，标记为不可覆写。 |
| **调用点发现** | 在 POST_INIT 阶段，记录每个目标地址落在初始化区域外的 `CALL` 指令作为调用点（`caller_rva` → `rva`）。 |
| **空间计算** | 合并整个追踪过程中所有已执行的 RVA 区间，找出 `.text` 段中最大的连续未执行区域。起始地址 **16 字节对齐**（满足 x64 ABI 及 SSE/AVX 要求）。 |
| **验证** | 对于每个 `E8 rel32` 形式的 CALL 调用点：将 CALL 目标重定向到空白区域，将空白区域清零，启动补丁后的调试会话，在 `caller_rva` 和空白区域起始处各设置一个断点。两个断点必须按顺序触发才判定为 `YES`。 |
| **输出保存** | 判定为 `YES` 时：将 EXE 和补丁后的 DLL（CALL 已重定向，空白区域保留**原始字节**）保存到 `outputs/<callerRva>_<foa>_<size>/`。可选择通过 `--shellcode` 参数将 shellcode 写入空白区域。 |

---

## 环境要求

| 依赖项 | 版本 | 说明 |
| --- | --- | --- |
| Windows | 10 / 11 (x64 主机) | Win32 调试 API 需要 |
| Visual Studio | 2019+ (MSVC) | 需安装"使用 C++ 的桌面开发"工作负载 |
| CMake | ≥ 3.15 | VS 自带或从 cmake.org 下载 |
| 网络连接 | 仅首次配置时需要 | FetchContent 下载 SQLite 3.45.3 合并版 |

> **TitanEngine** 的 x86 和 x64 预编译二进制文件已包含在 `deps/` 目录中，无需额外构建。

---

## 构建

### 快速构建（推荐）

```bat
build.bat              :: 所有架构 (x86 + x64)，Debug
build.bat x64 Release  :: 仅 x64 Release
build.bat x86          :: 仅 x86 Debug
build.bat all Release  :: x86 + x64，Release
build.bat all all      :: 所有组合
```

输出位于 `build_x86\<Config>\` 和 `build_x64\<Config>\`。

### 手动 CMake

```bat
:: x64
cmake -B build_x64 -A x64
cmake --build build_x64 --config Debug

:: x86
cmake -B build_x86 -A Win32
cmake --build build_x86 --config Debug
```

`TitanEngine.dll` 会自动复制到生成的可执行文件旁边。

---

## 使用方法

```
dll_tracer.exe --sam <sample_dir> [options]
```

| 选项 | 必需 | 描述 |
| --- | --- | --- |
| `--sam <dir>` | 是 | 样本目录——必须包含 1 个 `.exe` 和目标 `.dll` |
| `--dll <name>` | 否 | 当目录包含多个 DLL 时指定目标 DLL 文件名 |
| `--max-points <N>` | 否 | 记录 N 个调用点后停止（0 = 无限制，默认） |
| `--validate-timeout <sec>` | 否 | 每个调用点的验证超时时间，单位秒（默认：5） |
| `--shellcode <hex\|file>` | 否 | shellcode，可以是十六进制字符串（`9090CC`）或二进制文件路径。当 `size ≤ blank_size` 时写入输出 DLL 的空白区域。 |

### 示例

```bat
:: 追踪所有调用点，x64 目标
dll_tracer.exe --sam D:\samples\defender --dll MpClient.dll

:: 快速测试：仅第一个调用点，x86 目标
dll_tracer.exe --sam D:\samples\edge --dll msedgeupdate.dll --max-points 1

:: 带 shellcode 注入的验证
dll_tracer.exe --sam D:\samples\edge --max-points 1 --shellcode 909090C3

:: 从二进制文件加载 shellcode
dll_tracer.exe --sam D:\samples\target --shellcode D:\payloads\calc.bin
```

---

## 输出数据库

文件名：`{exe_stem}_{dll_stem}_{YYYYMMDD_HHMMSS}.db`
格式：SQLite 3

| 表名 | 描述 |
| --- | --- |
| `dll_instructions` | DLL 内执行的每条指令：`rva`、`execution_order`、`instr_size`、`is_init_end`、`in_init_region` |
| `points` | 发现的调用点：`rva`、`caller_rva`、`execution_order`、`blank_foa`、`blank_rva`、`blank_size`、`validated`（1=YES，0=TIMEOUT，-1=NO） |
| `exports` | 追踪时的 DLL 导出表快照 |
| `analysis_meta` | 键值对元数据：exe/dll 名称、时间戳、操作系统信息、指令计数 |

---

## 验证详情

### 前置条件（每个调用点）

- `caller_rva` 处的 `CALL` 必须是 **`E8 rel32`** 形式（5 字节，操作码 `0xE8`）。
- 其他形式（`FF 15`、`FF D0` 等）将被跳过，标记为 `validated=-1 (NO)`。

### 验证流程

对于每个符合条件的调用点，验证器执行以下步骤：

1. 创建 `<sam_dir>/tmp/{HHmmss}_{callerRva}/` 目录，复制 EXE 和 DLL
2. **重定向** `E8 rel32` CALL 到 `blank_rva`（仅修改 4 字节的 rel32 字段，保留 `0xE8`）
3. **清零** DLL 副本中的空白区域（严格测试：无代码可执行）
4. 启动补丁副本的新调试会话
5. 设置 **两个一次性断点**：一个在 `caller_rva`，一个在 `blank_rva`
6. 启动看门狗线程，按配置的超时时间监控

| 结果 | 含义 | `validated` 值 |
| --- | --- | --- |
| `YES` | **两个**断点按顺序触发——调用点到达且重定向成功 | `1` |
| `TIMEOUT` | 进程运行超时，两个断点未全部触发 | `0` |
| `NO` | 进程在到达调用点前崩溃（或非 E8 CALL 被跳过） | `-1` |

### `YES` 时的输出

保存到 `<sam_dir>/outputs/<callerRva8>_<blankFoa8>_<blankSize8>/`：

| 文件 | 内容 |
| --- | --- |
| `*.dll` | 原始 DLL，仅 CALL 重定向被修补——**空白区域保留原始字节** |
| `*.exe` | 宿主 EXE 的未修改副本（便于重新测试） |

如果提供了 `--shellcode` 且其大小不超过 `blank_size`，shellcode 也会被写入输出 DLL 的空白区域。

> shellcode 以普通函数调用方式执行（`E8 CALL`），因此栈处于标准函数入口状态。在 shellcode 末尾使用简单的 `RET` 即可返回原始调用流程。

### 地址对齐

空白区域起始地址（`blank_rva` 和 `blank_foa`）始终 **16 字节对齐**：

- 无论 ASLR 如何，都能保证 VA 对齐（Windows ImageBase 始终 ≥ 页对齐 = 16 的倍数）。
- 满足 x64 ABI 函数入口要求及 SSE/AVX 数据对齐。

判定为 `YES` 时，临时目录会被删除。判定为 `TIMEOUT`/`NO` 时，临时目录保留以供检查。

---

## 许可证

本项目基于 MIT 许可证发布。
