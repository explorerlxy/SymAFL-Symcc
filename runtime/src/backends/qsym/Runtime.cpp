// This file is part of the SymCC runtime.
//
// The SymCC runtime is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// The SymCC runtime is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with SymCC. If not, see <https://www.gnu.org/licenses/>.

//
// Definitions that we need for the QSYM backend
//

#include "Runtime.h"
#include "GarbageCollection.h"

// C++
#if __has_include(<filesystem>)
#define HAVE_FILESYSTEM 1
#elif __has_include(<experimental/filesystem>)
#define HAVE_FILESYSTEM 0
#else
#error "We need either <filesystem> or the older <experimental/filesystem>."
#endif

#include <atomic>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <unordered_set>
#include <variant>

#if HAVE_FILESYSTEM
#include <filesystem>
#else
#include <experimental/filesystem>
#endif

#ifdef DEBUG_RUNTIME
#include <chrono>
#endif

// C
#include <cstdint>
#include <cstdio>
#include <csignal>

// QSYM
#include <afl_trace_map.h>
#include <call_stack_manager.h>
#include <expr_builder.h>
#include <solver.h>

// LLVM
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/ArrayRef.h>

// Runtime
#include <Config.h>
#include <LibcWrappers.h>
#include <Shadow.h>

extern int inputFileDescriptor;

extern "C" {
  #include <stdio.h>
  #include <stdlib.h>
  #include <signal.h>
  #include <unistd.h>
  #include <string.h>
  #include <assert.h>
  #include <stdint.h>
  #include <stdbool.h>

  #include <sys/mman.h>
  #include <sys/shm.h>
  #include <sys/wait.h>
  #include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */


#define FORKSRV_FD          198
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"
#define SHM_SYMBOLIC_ENV_VAR                         "__AFL_SHM_SYMBOLIC_ENV_ID"
#define SHM_OUT_DIR_ENV_VAR                         "__AFL_SHM_OUTDIR_ENV_ID"
#define SHM_QUEUE_ENTRY_ID_ENV_VAR                  "__AFL_SHM_QUEUE_ENTRY_ID"
#define SHM_INSERT_DEPTH_ENV_VAR                    "__AFL_SHM_INSERT_DEPTH__ID"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

// __afl_area_initial的长度必须为MAP_SIZE，因为插桩代码的基本块ID是[0, MAP_SIZE），否则可能会导致越届崩溃。
u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;
u8* __out_dir = __afl_area_initial;

u32* __queue_entry_id = NULL;
u32* __insert_depth = NULL;
s32* __symbolic = NULL;

__thread u32 __afl_prev_loc = 0;

// Definition of Global Variables for Edge-BranCond Mapping.
// __thread bool __cond_jmp = false;
// __thread u8* __bran_cond = NULL;


/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = (u8*)shmat(shm_id, NULL, 0);

    if (__afl_area_ptr == (void *)-1) _exit(1);

    __afl_area_ptr[0] = 1;

  }
  // else{
  //   printf("No __afl_area_ptr provided.\n");
  //   _exit(1);
  // }
}

static void __afl_out_dir_shm(void) {

  char *id_str = getenv(SHM_OUT_DIR_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __out_dir = (u8*)shmat(shm_id, NULL, 0);

    if (__out_dir == (void *)-1) _exit(1);

  }
  // else{
  //   printf("No __out_dir provided.\n");
  //   _exit(1);
  // }
}

static void __afl_symbolic_id_shm(void) {

  char *id_str = getenv(SHM_SYMBOLIC_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __symbolic = (s32*)shmat(shm_id, NULL, 0);

    if (__symbolic == (void *)-1) _exit(1);

  }
  // else{
  //   printf("No __symbolic provided.\n");
  //   _exit(1);
  // }
}
static void __afl_queue_entry_id_shm(void) {

  char *id_str = getenv(SHM_QUEUE_ENTRY_ID_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __queue_entry_id = (u32*)shmat(shm_id, NULL, 0);

    if (__queue_entry_id == (void *)-1) _exit(1);

  }
  // else{
  //   printf("No __queue_entry_id provided.\n");
  //   _exit(1);
  // }
}

static void __afl_insert_depth_shm(void) {

  char *id_str = getenv(SHM_INSERT_DEPTH_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __insert_depth = (u32*)shmat(shm_id, NULL, 0);

    if (__insert_depth == (void *)-1) _exit(1);

  }
  // else{
  //   printf("No __insert_depth provided.\n");
  //   _exit(1);
  // }
}

static void reset_gconfig(void) {

  char *id_str = getenv(SHM_SYMBOLIC_ENV_VAR);

  if (id_str)
    switch(*__symbolic) {
      case 0:
        g_config.input = NoInput{};
        inputFileDescriptor = -1;
        break;
      case 1:
        g_config.input = StdinInput{};
        inputFileDescriptor = 0;
        break;
      default:
        // printf("Invalid input type.\n");
        // _exit(1);
        return;
    }
}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;


  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);



      /* Once woken up, create a clone of our process. */
    reset_gconfig();
    child_pid = fork();
    if (child_pid < 0) _exit(1);

    /* In child process: close fds, resume execution. */

    if (!child_pid) {

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      return;

    }


    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, 0) < 0)
      _exit(1);


    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_queue_entry_id_shm();
    __afl_symbolic_id_shm();
    __afl_insert_depth_shm();
    __afl_out_dir_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */
void __afl_auto_init(void) {

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

}
namespace qsym {

ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

} // namespace qsym

namespace {

/// Indicate whether the runtime has been initialized.
std::atomic_flag g_initialized = ATOMIC_FLAG_INIT;

/// A mapping of all expressions that we have ever received from QSYM to the
/// corresponding shared pointers on the heap.
///
/// We can't expect C clients to handle std::shared_ptr, so we maintain a single
/// copy per expression in order to keep the expression alive. The garbage
/// collector decides when to release our shared pointer.
///
/// std::map seems to perform slightly better than std::unordered_map on our
/// workload.
std::map<SymExpr, qsym::ExprRef> allocatedExpressions;

SymExpr registerExpression(const qsym::ExprRef &expr) {
  SymExpr rawExpr = expr.get();

  if (allocatedExpressions.count(rawExpr) == 0) {
    // We don't know this expression yet. Create a copy of the shared pointer to
    // keep the expression alive.
    allocatedExpressions[rawExpr] = expr;
  }

  return rawExpr;
}

/// The user-provided test case handler, if any.
///
/// If the user doesn't register a handler, we use QSYM's default behavior of
/// writing the test case to a file in the output directory.
TestCaseHandler g_test_case_handler = nullptr;

/// A QSYM solver that doesn't require the entire input on initialization.
class EnhancedQsymSolver : public qsym::Solver {
  // Warning!
  //
  // Before we can override methods of qsym::Solver, we need to declare them
  // virtual because the QSYM code refers to the solver with a pointer of type
  // qsym::Solver*; for non-virtual methods, it will always choose the
  // implementation of the base class. Beware that making a method virtual adds
  // a small performance overhead and requires us to change QSYM code.
  //
  // Subclassing the QSYM solver is ugly but helps us to avoid making too many
  // changes in the QSYM codebase.

public:
  EnhancedQsymSolver()
      : qsym::Solver("/dev/null", g_config.outputDir, g_config.aflCoverageMap) {
  }

  void pushInputByte(size_t offset, uint8_t value) {
    if (inputs_.size() <= offset)
      inputs_.resize(offset + 1);

    inputs_[offset] = value;
  }

  void saveValues(const std::string &suffix) override {
    if (auto handler = g_test_case_handler) {
      auto values = getConcreteValues();
      // The test-case handler may be instrumented, so let's call it with
      // argument expressions to meet instrumented code's expectations.
      // Otherwise, we might end up erroneously using whatever expression was
      // last registered for a function parameter.
      _sym_set_parameter_expression(0, nullptr);
      _sym_set_parameter_expression(1, nullptr);
      handler(values.data(), values.size());
    } else {
      Solver::saveValues(suffix);
    }
  }
};

EnhancedQsymSolver *g_enhanced_solver;

} // namespace

using namespace qsym;

#if HAVE_FILESYSTEM
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif


void save_solver_to_file() {
    // std::string fn = "./shm_var";
    // std::ofstream f(fn);
    // if (f.is_open()) {
    //     f << __afl_area_ptr<<endl;
    //     f << *__symbolic << endl;
    //     // f << __out_dir<<endl;
    //     f << *__queue_entry_id<<endl;
    //     f.close();
    //     std::cout << "Solver state saved to " << fn << std::endl;
    // } else {
    //     std::cerr << "Unable to open file " << fn << std::endl;
    // }
    if(__symbolic == NULL || *__symbolic == 0)
      return;

    std::ostringstream oss, smt2_str;
    oss << std::setw(6) << std::setfill('0') << *__queue_entry_id;
    std::string filename = string((char *)__out_dir) + "/queue/.pct-" + oss.str();
    // Convert the solver state to an SMT-LIB formatted string
    // std::string smt2_str = qsym::g_solver->getSolver().to_smt2();
    z3::expr_vector asserts = qsym::g_solver->getSolver().assertions();
    for(uint32_t i = *__insert_depth; i < asserts.size(); i++){
      smt2_str << "(assert " << asserts[i].to_string() <<  ")\n";
    } 

    // Write the SMT-LIB string to a file
    std::ofstream file(filename);
    if (file.is_open()) {
        file << smt2_str.str();
        file.close();
        std::cout << "Solver state saved to " << filename << std::endl;
    } else {
        std::cerr << "Unable to open file " << filename << std::endl;
    }
}


void signal_handler(int sig) {
    save_solver_to_file();
    signal(sig, SIG_DFL);
    raise(sig);
}

void register_signals() {
    const int signals[] = {SIGABRT, SIGFPE, SIGILL, SIGSEGV, SIGTERM};
    for(int sig : signals) {
        struct sigaction sa;
        sa.sa_handler = signal_handler;
        sigfillset(&sa.sa_mask);
        sigaction(sig, &sa, nullptr);
    }
}

void _sym_initialize(void) {
  if (g_initialized.test_and_set())
    return;

  loadConfig();
  initLibcWrappers();
  std::cerr << "This is SymCC running with the QSYM backend" << std::endl;
  if (std::holds_alternative<NoInput>(g_config.input)) {
    std::cerr
        << "Performing fully concrete execution (i.e., without symbolic input)"
        << std::endl;
    return;
  }

  // // Check the output directory
  // if (!fs::exists(g_config.outputDir) ||
  //     !fs::is_directory(g_config.outputDir)) {
  //   std::cerr << "Error: the output directory " << g_config.outputDir
  //             << " (configurable via SYMCC_OUTPUT_DIR) does not exist."
  //             << std::endl;
  //   exit(-1);
  // }

  std::atexit(save_solver_to_file);
  register_signals();
  g_z3_context = new z3::context{};
  g_enhanced_solver = new EnhancedQsymSolver{};
  g_solver = g_enhanced_solver; // for QSYM-internal use
  g_expr_builder = g_config.pruning ? PruneExprBuilder::create()
                                    : SymbolicExprBuilder::create();
}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits) {
  // std::cerr << "Calling _sym_build_integer and g_expr_builder is " << g_expr_builder << std::endl;
  // QSYM's API takes uintptr_t, so we need to be careful when compiling for
  // 32-bit systems: the compiler would helpfully truncate our uint64_t to fit
  // into 32 bits.
  if constexpr (sizeof(uint64_t) == sizeof(uintptr_t)) {
    // 64-bit case: all good.
    return registerExpression(g_expr_builder->createConstant(value, bits));
  } else {
    // 32-bit case: use the regular API if possible, otherwise create an
    // llvm::APInt.
    if (uintptr_t value32 = value; value32 == value)
      return registerExpression(g_expr_builder->createConstant(value32, bits));

    return registerExpression(
        g_expr_builder->createConstant({64, value}, bits));
  }
}

SymExpr _sym_build_integer128(uint64_t high, uint64_t low) {
  std::array<uint64_t, 2> words = {low, high};
  return registerExpression(g_expr_builder->createConstant({128, words}, 128));
}

SymExpr _sym_build_integer_from_buffer(void *buffer, unsigned num_bits) {
  assert(num_bits % 64 == 0);
  return registerExpression(g_expr_builder->createConstant(
      {num_bits, num_bits / 64, (uint64_t *)buffer}, num_bits));
}

SymExpr _sym_build_null_pointer() {
  return registerExpression(
      g_expr_builder->createConstant(0, sizeof(uintptr_t) * 8));
}

SymExpr _sym_build_true() {
  return registerExpression(g_expr_builder->createTrue());
}

SymExpr _sym_build_false() {
  return registerExpression(g_expr_builder->createFalse());
}

SymExpr _sym_build_bool(bool value) {
  return registerExpression(g_expr_builder->createBool(value));
}

#define DEF_BINARY_EXPR_BUILDER(name, qsymName)                                \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) {                            \
    return registerExpression(g_expr_builder->create##qsymName(                \
        allocatedExpressions.at(a), allocatedExpressions.at(b)));              \
  }

DEF_BINARY_EXPR_BUILDER(add, Add)
DEF_BINARY_EXPR_BUILDER(sub, Sub)
DEF_BINARY_EXPR_BUILDER(mul, Mul)
DEF_BINARY_EXPR_BUILDER(unsigned_div, UDiv)
DEF_BINARY_EXPR_BUILDER(signed_div, SDiv)
DEF_BINARY_EXPR_BUILDER(unsigned_rem, URem)
DEF_BINARY_EXPR_BUILDER(signed_rem, SRem)

DEF_BINARY_EXPR_BUILDER(shift_left, Shl)
DEF_BINARY_EXPR_BUILDER(logical_shift_right, LShr)
DEF_BINARY_EXPR_BUILDER(arithmetic_shift_right, AShr)

DEF_BINARY_EXPR_BUILDER(signed_less_than, Slt)
DEF_BINARY_EXPR_BUILDER(signed_less_equal, Sle)
DEF_BINARY_EXPR_BUILDER(signed_greater_than, Sgt)
DEF_BINARY_EXPR_BUILDER(signed_greater_equal, Sge)
DEF_BINARY_EXPR_BUILDER(unsigned_less_than, Ult)
DEF_BINARY_EXPR_BUILDER(unsigned_less_equal, Ule)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_than, Ugt)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_equal, Uge)
DEF_BINARY_EXPR_BUILDER(equal, Equal)
DEF_BINARY_EXPR_BUILDER(not_equal, Distinct)

DEF_BINARY_EXPR_BUILDER(bool_and, LAnd)
DEF_BINARY_EXPR_BUILDER(and, And)
DEF_BINARY_EXPR_BUILDER(bool_or, LOr)
DEF_BINARY_EXPR_BUILDER(or, Or)
DEF_BINARY_EXPR_BUILDER(bool_xor, Distinct)
DEF_BINARY_EXPR_BUILDER(xor, Xor)

#undef DEF_BINARY_EXPR_BUILDER

SymExpr _sym_build_neg(SymExpr expr) {
  return registerExpression(
      g_expr_builder->createNeg(allocatedExpressions.at(expr)));
}

SymExpr _sym_build_not(SymExpr expr) {
  return registerExpression(
      g_expr_builder->createNot(allocatedExpressions.at(expr)));
}

SymExpr _sym_build_ite(SymExpr cond, SymExpr a, SymExpr b) {
  return registerExpression(g_expr_builder->createIte(
      allocatedExpressions.at(cond), allocatedExpressions.at(a),
      allocatedExpressions.at(b)));
}

SymExpr _sym_build_sext(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(g_expr_builder->createSExt(
      allocatedExpressions.at(expr), bits + expr->bits()));
}

SymExpr _sym_build_zext(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(g_expr_builder->createZExt(
      allocatedExpressions.at(expr), bits + expr->bits()));
}

SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->createTrunc(allocatedExpressions.at(expr), bits));
}

void _sym_push_path_constraint(SymExpr constraint, int taken,
                               uintptr_t site_id) {
  if (constraint == nullptr)
    return;

  g_solver->addJcc(allocatedExpressions.at(constraint), taken != 0, site_id);
}

SymExpr _sym_get_input_byte(size_t offset, uint8_t value) {
  g_enhanced_solver->pushInputByte(offset, value);
  return registerExpression(g_expr_builder->createRead(offset));
}

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) {
  return registerExpression(g_expr_builder->createConcat(
      allocatedExpressions.at(a), allocatedExpressions.at(b)));
}

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) {
  return registerExpression(g_expr_builder->createExtract(
      allocatedExpressions.at(expr), last_bit, first_bit - last_bit + 1));
}

size_t _sym_bits_helper(SymExpr expr) { return expr->bits(); }

SymExpr _sym_build_bool_to_bit(SymExpr expr) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->boolToBit(allocatedExpressions.at(expr), 1));
}

//
// Floating-point operations (unsupported in QSYM)
//

// Even if we don't generally support operations on floats in this backend, we
// need dummy implementations of a few functions to help the parts of the
// instrumentation that deal with structures; if structs contain floats, the
// instrumentation expects to be able to create bit-vector expressions for
// them.

SymExpr _sym_build_float(double, int is_double) {
  // We create an all-zeros bit vector, mainly to capture the length of the
  // value. This is compatible with our dummy implementation of
  // _sym_build_float_to_bits.
  return registerExpression(
      g_expr_builder->createConstant(0, is_double ? 64 : 32));
}

SymExpr _sym_build_float_to_bits(SymExpr expr) { return expr; }

#define UNSUPPORTED(prototype)                                                 \
  prototype { return nullptr; }

UNSUPPORTED(SymExpr _sym_build_fp_add(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_sub(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_mul(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_div(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_rem(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_abs(SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_neg(SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_less_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_less_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_not_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_less_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_less_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_not_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_int_to_float(SymExpr, int, int))
UNSUPPORTED(SymExpr _sym_build_float_to_float(SymExpr, int))
UNSUPPORTED(SymExpr _sym_build_bits_to_float(SymExpr, int))
UNSUPPORTED(SymExpr _sym_build_float_to_signed_integer(SymExpr, uint8_t))
UNSUPPORTED(SymExpr _sym_build_float_to_unsigned_integer(SymExpr, uint8_t))

#undef UNSUPPORTED
#undef H

//
// Call-stack tracing
//

void _sym_notify_call(uintptr_t site_id) {
  g_call_stack_manager.visitCall(site_id);
}

void _sym_notify_ret(uintptr_t site_id) {
  g_call_stack_manager.visitRet(site_id);
}

void _sym_notify_basic_block(uintptr_t site_id) {
  g_call_stack_manager.visitBasicBlock(site_id);
}

//
// Debugging
//

const char *_sym_expr_to_string(SymExpr expr) {
  static char buffer[4096];

  auto expr_string = expr->toString();
  auto copied = expr_string.copy(
      buffer, std::min(expr_string.length(), sizeof(buffer) - 1));
  buffer[copied] = '\0';

  return buffer;
}

bool _sym_feasible(SymExpr expr) {
  expr->simplify();

  g_solver->push();
  g_solver->add(expr->toZ3Expr());
  bool feasible = (g_solver->check() == z3::sat);
  g_solver->pop();

  return feasible;
}

//
// Garbage collection
//

void _sym_collect_garbage() {
  if (allocatedExpressions.size() < g_config.garbageCollectionThreshold)
    return;

#ifdef DEBUG_RUNTIME
  auto start = std::chrono::high_resolution_clock::now();
#endif

  auto reachableExpressions = collectReachableExpressions();
  for (auto expr_it = allocatedExpressions.begin();
       expr_it != allocatedExpressions.end();) {
    if (reachableExpressions.count(expr_it->first) == 0) {
      expr_it = allocatedExpressions.erase(expr_it);
    } else {
      ++expr_it;
    }
  }

#ifdef DEBUG_RUNTIME
  auto end = std::chrono::high_resolution_clock::now();

  std::cerr << "After garbage collection: " << allocatedExpressions.size()
            << " expressions remain" << std::endl
            << "\t(collection took "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " milliseconds)" << std::endl;
#endif
}

//
// Test-case handling
//

void symcc_set_test_case_handler(TestCaseHandler handler) {
  g_test_case_handler = handler;
}
