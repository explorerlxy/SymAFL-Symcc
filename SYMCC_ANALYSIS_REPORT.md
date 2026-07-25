# SymCC 工作原理与 SymAFL 扩展分析报告

## 一、SymCC 项目概述

SymCC 是一个**基于编译器的符号执行引擎**（compiler-based concolic executor），由法国 EURECOM S3 实验室开发，论文发表于 USENIX Security 2020。其核心思想是：**在编译期将符号执行能力嵌入目标程序，而非在运行时通过解释器进行符号执行**。这避免了传统符号执行中"解释执行"带来的巨大性能开销。

SymCC 采用 **concolic execution（混合执行）** 模式：程序按照具体的输入值正常执行（具体路径），同时编译器注入的代码在后台追踪每个值的符号表达式。每当遇到分支指令时，SymCC 将分支条件推入路径约束集合，并调用 SMT 求解器（Z3）尝试生成能走另一条分支的新输入。

### 项目仓库结构

```
symcc/
├── compiler/           # LLVM 编译器 Pass（核心）
│   ├── Pass.cpp/h      # 插桩入口 + AFL 覆盖率插桩（你扩展的）
│   ├── Symbolizer.cpp/h # 指令访问者，插入符号追踪代码
│   ├── Runtime.cpp/h   # 运行时库函数映射
│   ├── Main.cpp        # Pass 注册
│   └── symcc.in        # 编译器包装脚本模板
├── runtime/            # 运行时支持库（子模块 symcc-rt）
│   ├── include/
│   │   ├── Config.h    # 配置系统（环境变量）
│   │   ├── Shadow.h    # 影子内存管理（按页粒度）
│   │   ├── RuntimeCommon.h # 运行时 API 接口定义
│   │   └── LibcWrappers.h  # Libc 函数包装
│   ├── src/
│   │   ├── Config.cpp
│   │   ├── LibcWrappers.cpp
│   │   └── backends/
│   │       ├── qsym/Runtime.cpp   # QSYM 后端（你扩展的）
│   │       └── simple/Runtime.cpp # Simple 后端（你扩展的）
└── util/
    └── symcc_fuzzing_helper/  # AFL 混合模糊测试协调器
```

---

## 二、原始 SymCC 工作原理

### 2.1 整体架构

```
┌─────────────────────────────────────────────────┐
│                  编译阶段                         │
│  C/C++ 源码 ──→ clang + SymCC LLVM Pass ──→ 二进制 │
│                     │                            │
│              注入 _sym_build_* 调用               │
│              注入 _sym_push_path_constraint       │
│              注入 _sym_read/write_memory          │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                  运行阶段                         │
│  二进制执行 ──→ 具体路径计算 + 符号表达式构建       │
│     │                                            │
│     ├── 每个 SSA 值 → 对应的符号表达式 (SymExpr)   │
│     ├── 每个分支点 → 推入路径约束 + 求解新输入      │
│     └── 内存操作   → 影子内存读写                  │
└─────────────────────────────────────────────────┘
```

### 2.2 编译器 Pass 详解

#### 2.2.1 Pass 注册 (`compiler/Main.cpp`)
- 同时支持 Legacy Pass Manager（LLVM ≤15）和 New Pass Manager（LLVM ≥13）
- 注册在 `VectorizerStart` 和 `PipelineStart` 阶段
- 前置 Pass：`ScalarizerPass`（标量化）、`LowerAtomicPass`（原子操作降级）

#### 2.2.2 模块级插桩 (`compiler/Pass.cpp :: instrumentModule`)
1. **声明外部全局变量**：`__afl_area_ptr`、`__afl_prev_loc`（AFL 覆盖率位图和前一个位置）
2. **重命名拦截函数**：遇到 `malloc`、`read`、`memcpy` 等被拦截的库函数时，将其重命名为 `*_symbolized`，使得调用被重定向到运行时包装器
3. **注入构造函数**：
   - `_sym_initialize`：初始化符号执行运行时
   - `__afl_auto_init`：初始化 AFL fork server（**你添加的**）

#### 2.2.3 函数级插桩 (`compiler/Pass.cpp :: instrumentFunction`)
这是核心的插桩流程：

```
对每个函数 F:
  1. 收集所有指令到列表
  2. 预处理：展开无法处理的 Intrinsic 和内联汇编
  3. 创建 Symbolizer 实例
  4. 对每个函数参数：调用 _sym_get_parameter_expression 获取表达式
  5. 对每个基本块：插入 _sym_notify_basic_block
  6. 对每条指令：调用 symbolizer.visit(I) → 插入符号追踪代码
  7. 最终化 PHI 节点
  8. 插入 short-circuit 代码（纯具体数据跳过符号计算）
  9. [你添加的] 在每个基本块插入 AFL 覆盖率更新代码
```

#### 2.2.4 Symbolizer 指令处理 (`compiler/Symbolizer.cpp`)

`Symbolizer` 继承自 `llvm::InstVisitor`，对每种 LLVM IR 指令类型执行相应的符号化处理：

| 指令类型 | 处理方式 |
|---------|---------|
| `BinaryOperator` (add/sub/mul/div...) | 调用 `_sym_build_add` 等运行时函数 |
| `UnaryOperator` (fneg) | 调用 `_sym_build_fp_neg` |
| `CmpInst` (icmp/fcmp) | 调用 `_sym_build_equal` 等比较函数 |
| `BranchInst` (条件跳转) | 调用 `_sym_push_path_constraint`，这是求解新输入的核心 |
| `SelectInst` (三元运算符) | 推入路径约束 + 选择对应表达式 |
| `LoadInst` | 调用 `_sym_read_memory` 从影子内存读取 |
| `StoreInst` | 调用 `_sym_write_memory` 写入影子内存 |
| `CallInst` | 调用 `_sym_notify_call`，传递参数表达式 |
| `ReturnInst` | 调用 `_sym_set_return_expression` |
| `PHINode` | 创建符号 PHI 节点（延迟处理） |
| `SwitchInst` | 为每个 case 推入路径约束 |
| `GetElementPtrInst` | 对地址计算进行符号化 |
| `CastInst` (sext/zext/trunc...) | 调用对应的类型转换运行时函数 |
| 浮点转换 (sitofp/fptosi...) | 调用对应的浮点转换运行时函数 |

#### 2.2.5 Short-Circuit 优化 (`Symbolizer::shortCircuitExpressionUses`)

这是一个重要的性能优化。大部分程序值在运行时都是具体的（非符号化的），没必要为它们构建 Z3 表达式。Short-circuit 机制通过基本块分裂实现：

```
原始代码:                    优化后:
res_expr = call _sym_compute   start:
                              ├─ 检查是否有符号输入
                              ├─ 全部具体 → 跳过，res_expr=null
                              └─ 有符号输入 → slow_path:
                                  ├─ 为具体参数创建表达式
                                  └─ 执行符号计算
```

### 2.3 运行时库详解

#### 2.3.1 配置系统 (`Config.h / Config.cpp`)

通过环境变量配置，使用 `std::variant` 支持多种输入模式：

```cpp
using InputConfig = std::variant<NoInput, StdinInput, MemoryInput, FileInput>;
```

| 环境变量 | 作用 |
|---------|------|
| `SYMCC_OUTPUT_DIR` | 新测试用例输出目录（默认 `/tmp/output`）|
| `SYMCC_NO_SYMBOLIC_INPUT` | 设为1则完全具体执行 |
| `SYMCC_INPUT_FILE` | 从指定文件读取符号化输入 |
| `SYMCC_MEMORY_INPUT` | 通过 API 调用提供符号化输入 |
| `SYMCC_LOG_FILE` | 后端日志文件 |
| `SYMCC_ENABLE_LINEARIZATION` | QSYM 路径剪枝优化 |
| `SYMCC_AFL_COVERAGE_MAP` | AFL 覆盖率位图文件 |

#### 2.3.2 影子内存 (`Shadow.h`)

影子内存是符号执行的核心数据结构，用于追踪哪些内存区域包含符号化值：

- **页面粒度管理**：每 4096 字节一页，按需分配影子页
- **三种迭代器**：
  - `ReadShadowIterator`：只读遍历（无影子→返回 null）
  - `NonNullReadShadowIterator`：读遍历（无影子→返回具体值表达式）
  - `WriteShadowIterator`：写遍历（无影子→自动创建）
- **`isConcrete()`**：快速检查内存区域是否完全具体化

#### 2.3.3 Libc 函数包装 (`LibcWrappers.cpp`)

对常见的 Libc 函数进行符号感知包装，确保符号化数据在库函数调用中不被丢失：

- **I/O 函数**：`read`、`fread`、`fgets`、`getc` 等 → 标记读取的数据为符号化
- **内存函数**：`memcpy`、`memset`、`memmove`、`bcopy` 等 → 传播影子内存
- **字符串函数**：`strncpy`、`strchr` → 传播符号化数据
- **网络函数**：`ntohl` → 保持符号化
- **内存分配**：`malloc`、`calloc`、`mmap` → 重置影子内存

#### 2.3.4 两个后端

**Simple Backend**：基于 Z3 C++ API 的薄封装，直接构建和求解表达式，无优化剪枝。

**QSYM Backend**：集成 QSYM（一个高性能混合执行引擎），具有：
- 基本块剪枝（`SYMCC_ENABLE_LINEARIZATION`）
- 调用栈感知的优化
- AFL 覆盖率位图集成
- 路径爆炸抑制

---

## 三、你的 SymAFL 扩展详解

你提交的 commit `e449f3e` ("symAFL260327") 对 SymCC 进行了大规模改造，将其从一个独立的符号执行工具转变为一个**深度集成 AFL fuzzer 的混合模糊测试系统**。这些修改分布在编译器和运行时两个层面。

### 3.1 编译器层修改

#### 3.1.1 AFL 覆盖率插桩 (`compiler/Pass.cpp`)

在原始 `instrumentFunction()` 末尾添加了完整的 AFL 风格覆盖率追踪代码：

```cpp
// 在每个基本块起始处插入:
unsigned int cur_loc = AFL_R(MAP_SIZE);  // 随机基本块ID [0, 65536)
LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
Value *MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));
// 更新位图: MapPtr[prev_loc ^ cur_loc] += 1
// 更新 prev_loc = cur_loc >> 1
```

这是 **AFL 经典的边覆盖率算法**：通过 `prev_loc XOR cur_loc` 来唯一标识程序边（edge），然后将计数器增加1。这个改动使得 SymCC 编译出的程序可以直接与 AFL 共享覆盖率位图。

#### 3.1.2 构造函数链 (`compiler/Pass.cpp :: instrumentModule`)

同时注册两个全局构造函数：
```cpp
appendToGlobalCtors(M, ctor1, 0);  // _sym_initialize    - 符号执行初始化
appendToGlobalCtors(M, ctor2, 0);  // __afl_auto_init    - AFL fork server 初始化
```

#### 3.1.3 头文件宏定义 (`compiler/Pass.h`)

```cpp
#define AFL_R(x) (random() % (x))
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)  // = 65536
```

### 3.2 运行时层修改（核心扩展）

runtime 子模块的 diff 显示 7 个文件被修改，共增加 692 行代码。以下按功能模块分析：

#### 3.2.1 AFL Fork Server 集成

在 **QSYM 和 Simple 两个后端** 都实现了完整的 AFL fork server（`__afl_start_forkserver`）：

```
母进程                   子进程
  │                        │
  ├─ write(FORKSRV_FD+1)   │   (握手，告知 AFL 已就绪)
  │                        │
  ├─ read(FORKSRV_FD) ◄────│   (等待 AFL 发送执行信号)
  │                        │
  ├─ reset_gconfig()       │   (根据共享内存切换符号输入模式)
  ├─ fork() ───────────────┤
  │                        │
  ├─ write(子PID)          │   执行目标程序（符号执行）
  ├─ waitpid()             │
  ├─ write(status)         │
  │                        │
  └─ 循环 ◄────────────────┘   程序退出
```

**设计要点**：
- 使用固定文件描述符 `FORKSRV_FD=198` 与 AFL 通信
- 母进程（fork server）在 `while(1)` 循环中等待 AFL 发送新任务
- 每次 fork 前调用 `reset_gconfig()` 动态切换执行模式
- 支持 `__AFL_DEFER_FORKSRV` 环境变量延迟初始化

#### 3.2.2 五路共享内存通道

通过环境变量传递共享内存 ID，建立 5 条与外部协调器（AFL/symcc_fuzzing_helper）的通信通道：

| 环境变量 | 对应全局变量 | 类型 | 作用 |
|---------|-------------|------|------|
| `__AFL_SHM_ID` | `__afl_area_ptr` | `u8[65536]` | AFL 覆盖率位图 |
| `__AFL_SHM_OUTDIR_ENV_ID` | `__out_dir` | `u8*` (字符串) | 输出目录路径 |
| `__AFL_SHM_SYMBOLIC_ENV_ID` | `__symbolic` | `s32*` / `u8*` | 符号/具体模式切换标志 |
| `__AFL_SHM_QUEUE_ENTRY_ID` | `__queue_entry_id` | `u32*` | 当前队列条目编号 |
| `__AFL_SHM_INSERT_DEPTH__ID` | `__insert_depth` | `u32*` | 路径约束插入起始深度 |

**`__symbolic` 模式编码**：
- `0` → `NoInput`（纯具体执行，等同于普通 fuzzer）
- `1` → `StdinInput`（从标准输入读取符号化数据）
- `2` → `MemoryInput`（通过 API 提供符号化数据，仅 Simple 后端）
- `3` → `FileInput`（从文件读取符号化数据，仅 Simple 后端）

这使得外部协调器可以在**不重启进程**的情况下，动态切换每次执行的符号模式。

#### 3.2.3 求解器状态持久化（路径约束保存）

`save_solver_to_file()` 是这次扩展的**核心创新**之一：

```cpp
void save_solver_to_file() {
    if(__symbolic == NULL || *__symbolic == 0)
      return;  // 纯具体执行模式，无需保存

    // 生成文件名: <out_dir>/queue/.pct-<6位队列编号>
    std::string filename = string((char *)__out_dir) +
                           "/queue/.pct-" + oss.str();

    // 获取求解器中的所有约束断言
    z3::expr_vector asserts = g_solver->getSolver().assertions();

    // 只保存 __insert_depth 之后新增的约束
    for(uint32_t i = *__insert_depth; i < asserts.size(); i++) {
        smt2_str << "(assert " << asserts[i].to_string() << ")\n";
    }

    // 写入文件
    std::ofstream file(filename);
    file << smt2_str.str();
}
```

**设计意图分析**：

1. **路径约束增量保存**：通过 `__insert_depth` 实现增量保存——只保存本次执行新添加的约束断言，避免重复保存已有约束。这在 fork server 多轮执行场景中至关重要。

2. **崩溃现场保留**：通过 `std::atexit` 和信号处理器注册，确保程序崩溃时也能保存当前的路径约束。这对于 crash triage（崩溃分类和根因分析）非常有价值——可以回放导致崩溃的路径约束，复现崩溃。

3. **文件命名约定**：`.pct-XXXXXX`（pct = path constraint）文件保存在 AFL queue 子目录下，可以与 AFL 的队列条目一一对应。

#### 3.2.4 信号处理与崩溃时约束保存

```cpp
void register_signals() {
    const int signals[] = {SIGABRT, SIGFPE, SIGILL, SIGSEGV, SIGTERM};
    for(int sig : signals) {
        struct sigaction sa;
        sa.sa_handler = signal_handler;  // 先保存约束，再恢复默认处理
        sigfillset(&sa.sa_mask);
        sigaction(sig, &sa, nullptr);
    }
}
```

捕获 5 种终止信号，在程序异常退出前自动保存路径约束。结合 `atexit(save_solver_to_file)`，形成了**双重保障**。

#### 3.2.5 其他修改

| 文件 | 修改 | 目的 |
|-----|------|------|
| `CMakeLists.txt` | 添加 `-g` 编译标志 | 启用调试符号，便于问题定位 |
| `CMakeLists.txt`（qsym） | 移除 Z3 4.5 最低版本限制 | 兼容更新版本的 Z3 |
| `CMakeLists.txt`（qsym） | 添加 `-fno-rtti` 条件编译 | 与 LLVM 的 RTTI 设置保持一致 |
| `Config.cpp` | 默认 `g_config.input = StdinInput{}` | 确保默认从标准输入读取符号化数据 |
| `Config.cpp` | 输入模式检查逻辑微调 | 改进条件判断 |
| `LibcWrappers.cpp` | `inputFileDescriptor` 移到命名空间外 | 使其可被后端 Runtime.cpp 通过 `extern` 引用 |
| `Runtime.cpp`（qsym） | 注释掉输出目录存在性检查 | 不再强制要求预先创建输出目录 |

---

## 四、SymAFL 系统架构总览

你的扩展将 SymCC 从独立工具转变为**AFL 驱动的混合模糊测试系统**：

```
┌──────────────────────────────────────────────────────────┐
│                     AFL (afl-fuzz)                        │
│  - 维护种子队列                                            │
│  - 变异生成新输入                                          │
│  - 管理覆盖率位图                                          │
│  - 通过共享内存与 SymCC 通信                               │
└────────────┬─────────────────────────────────────────────┘
             │  fork server 协议
             │  共享内存 (5通道)
             ▼
┌──────────────────────────────────────────────────────────┐
│           SymCC 编译的目标程序 (fork server 子进程)         │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │  编译器注入的符号追踪代码                           │    │
│  │  - 具体路径执行 + 符号表达式构建                    │    │
│  │  - AFL 覆盖率位图更新 (你添加)                     │    │
│  │  - 路径约束推入 Z3 求解器                          │    │
│  └──────────────────────────────────────────────────┘    │
│                         │                                │
│                         ▼                                │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Z3 求解器                                        │    │
│  │  - 尝试对每个分支点求解新输入                       │    │
│  │  - 生成的新输入 → 写入输出目录 → AFL 导入           │    │
│  └──────────────────────────────────────────────────┘    │
│                         │                                │
│                         ▼                                │
│  ┌──────────────────────────────────────────────────┐    │
│  │  路径约束持久化 (你添加)                            │    │
│  │  - atexit/signal → save_solver_to_file()          │    │
│  │  - SMT-LIB 格式保存到 .pct-XXXXXX                 │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### 4.1 工作流程

1. **启动阶段**：AFL 启动 fork server（SymCC 编译的目标程序）
2. **每轮执行**：
   - AFL 通过管道唤醒 fork server
   - fork server 通过共享内存读取 `__symbolic` 模式标志
   - 根据模式决定是否启用符号执行
   - fork 子进程执行具体路径 + 构建符号表达式
   - 子进程在关键位置更新 AFL 覆盖率位图
   - 在每个分支点推入路径约束，尝试求解新输入
   - 子进程退出时保存路径约束到 `.pct-XXXXXX` 文件
3. **结果反馈**：新生成的测试用例被 AFL 导入种子队列

### 4.2 关键创新点

1. **双模式无缝切换**：同一进程可在"纯 fuzzing"和"concolic execution"之间动态切换（通过 `__symbolic` 共享内存标志），无需重新编译或重启。

2. **增量路径约束保存**：通过 `__insert_depth` 实现约束的增量保存，避免在多轮 fork server 执行中重复保存基线约束。

3. **崩溃时约束保全**：通过信号处理器 + atexit 双重机制，确保程序异常退出时也能保留完整的路径约束，为崩溃分析提供完整的符号上下文。

4. **AFL 深度耦合**：不是简单的"通过 helper 交换种子"（那是原始 symcc_fuzzing_helper 的做法），而是将 AFL 的运行时机制（fork server、覆盖率位图、共享内存）直接嵌入 SymCC 运行时，实现真正的深度融合。

---

## 五、技术评价与潜在问题

### 5.1 优势

- **性能提升显著**：fork server 模式避免了每次执行都重新初始化求解器（Z3 context 创建开销很大）
- **崩溃可追溯**：路径约束保存使得每个崩溃都能回溯到触发的符号条件
- **灵活的混合策略**：可以根据需要动态调整符号执行的比例（通过 `__symbolic` 标志）

### 5.2 潜在问题

1. **线程安全**：`inputFileDescriptor` 全局变量和 `reset_gconfig()` 中的配置切换在 fork 场景下是安全的，但若有线程使用则存在竞争条件。

2. **solve_solver_to_file 在 simple 后端被禁用**：代码被注释掉，意味着 Simple 后端目前不支持路径约束保存。这个特性仅在 QSYM 后端生效。

3. **MAP_SIZE 硬编码**：`MAP_SIZE=65536` 是 classic AFL 的大小，与 AFL++ 的扩展位图可能不兼容。

4. **错误处理**：共享内存连接失败时调用 `_exit(1)` 直接退出，缺少更友好的错误提示。

5. **内存泄漏风险**：`__afl_area_initial[MAP_SIZE]` 作为初始缓冲区在 `__afl_map_shm()` 后被替换，但原始缓冲区不会被释放（影响微小，因为仅 64KB）。

---

## 六、总结

SymCC 是一个创新的编译器驱动符号执行框架，通过 LLVM Pass 在编译时注入符号追踪代码，避免了传统解释型符号执行的巨大性能开销。其核心架构分为**编译器 Pass**（处理 LLVM IR 指令，注入运行时库调用）和**运行时库**（通过 Z3 构建和求解符号表达式，管理影子内存）。

你的 SymAFL 扩展在此基础上实现了三个层次的关键改进：

1. **编译器层**：在 LLVM IR 级别直接插入 AFL 覆盖率插桩代码
2. **运行时层**：在两个后端（QSYM 和 Simple）中都实现了 AFL fork server 集成、五路共享内存通信
3. **持久化层**：实现了求解器状态的增量保存和崩溃现场保留机制

这使得 SymCC 从独立的 concolic executor 进化为与 AFL 深度融合的混合模糊测试系统，可以在纯 fuzzing 和符号执行之间灵活切换，并能在崩溃时保留完整的符号执行上下文。这些扩展特别适合需要精确 crash triage 和复杂路径探索的安全测试场景。
