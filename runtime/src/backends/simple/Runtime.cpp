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
// along with the SymCC runtime. If not, see <https://www.gnu.org/licenses/>.

#include <Runtime.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <set>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <z3++.h>
#include <csignal>

#ifndef NDEBUG
#include <chrono>
#endif

#include "Config.h"
#include "GarbageCollection.h"
#include "LibcWrappers.h"
#include "Shadow.h"

#ifndef NDEBUG
// Helper to print pointers properly.
#define P(ptr) reinterpret_cast<void *>(ptr)
#endif

#define FSORT(is_double)                                                       \
  ((is_double) ? Z3_mk_fpa_sort_double(g_context)                              \
               : Z3_mk_fpa_sort_single(g_context))

/* TODO Eventually we'll want to inline as much of this as possible. I'm keeping
   it in C for now because that makes it easier to experiment with new features,
   but I expect that a lot of the functions will stay so simple that we can
   generate the corresponding bitcode directly in the compiler pass. */

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
u8* __symbolic = __afl_area_initial;

u32* __queue_entry_id = NULL;
u32* __insert_depth = NULL;

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
  else{
    printf("No __afl_area_ptr provided.\n");
    _exit(1);
  }
}

static void __afl_out_dir_shm(void) {

  char *id_str = getenv(SHM_OUT_DIR_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __out_dir = (u8*)shmat(shm_id, NULL, 0);

    if (__out_dir == (void *)-1) _exit(1);

  }
  else{
    printf("No __out_dir provided.\n");
    _exit(1);
  }
}

static void __afl_symbolic_id_shm(void) {

  char *id_str = getenv(SHM_SYMBOLIC_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __symbolic = (u8*)shmat(shm_id, NULL, 0);

    if (__symbolic == (void *)-1) _exit(1);

  }
  else{
    printf("No __symbolic provided.\n");
    _exit(1);
  }
}
static void __afl_queue_entry_id_shm(void) {

  char *id_str = getenv(SHM_QUEUE_ENTRY_ID_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __queue_entry_id = (u32*)shmat(shm_id, NULL, 0);

    if (__queue_entry_id == (void *)-1) _exit(1);

  }
  else{
    printf("No __queue_entry_id provided.\n");
    _exit(1);
  }
}

static void __afl_insert_depth_shm(void) {

  char *id_str = getenv(SHM_INSERT_DEPTH_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __insert_depth = (u32*)shmat(shm_id, NULL, 0);

    if (__insert_depth == (void *)-1) _exit(1);

  }
  else{
    printf("No __insert_depth provided.\n");
    _exit(1);
  }
}

static void reset_gconfig(void) {

  switch(*__symbolic) {
    case 0:
      g_config.input = NoInput{};
      break;
    case 1:
      g_config.input = StdinInput{};
      break;
    case 2:
      g_config.input = MemoryInput{};
      break;
    case 3:
      g_config.input = FileInput{};
      break;
    default:
      printf("Invalid input type.\n");
      _exit(1);
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

namespace {

/// Indicate whether the runtime has been initialized.
std::atomic_flag g_initialized = ATOMIC_FLAG_INIT;

/// The global Z3 context.
Z3_context g_context;

/// The global floating-point rounding mode.
Z3_ast g_rounding_mode;

/// The global Z3 solver.
Z3_solver g_solver; // TODO make thread-local

// Some global constants for efficiency.
Z3_ast g_null_pointer, g_true, g_false;

FILE *g_log = stderr;

#ifndef NDEBUG
[[maybe_unused]] void dump_known_regions() {
  std::cerr << "Known regions:" << std::endl;
  for (const auto &[page, shadow] : g_shadow_pages) {
    std::cerr << "  " << P(page) << " shadowed by " << P(shadow) << std::endl;
  }
}

void handle_z3_error(Z3_context c [[maybe_unused]], Z3_error_code e) {
  assert(c == g_context && "Z3 error in unknown context");
  std::cerr << Z3_get_error_msg(g_context, e) << std::endl;
  assert(!"Z3 error");
}
#endif

SymExpr build_variable(const char *name, uint8_t bits) {
  Z3_symbol sym = Z3_mk_string_symbol(g_context, name);
  auto *sort = Z3_mk_bv_sort(g_context, bits);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  Z3_ast result = Z3_mk_const(g_context, sym, sort);
  Z3_inc_ref(g_context, result);
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

/// The set of all expressions we have ever passed to client code.
std::set<SymExpr> allocatedExpressions;

SymExpr registerExpression(SymExpr expr) {
  if (allocatedExpressions.count(expr) == 0) {
    // We don't know this expression yet. Record it and increase the reference
    // counter.
    allocatedExpressions.insert(expr);
    Z3_inc_ref(g_context, expr);
  }

  return expr;
}

} // namespace

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
    // if(*__symbolic == 0)
    //   return;

    // std::ostringstream oss, smt2_str;
    // oss << std::setw(6) << std::setfill('0') << *__queue_entry_id;
    // std::string filename = std::string((char *)__out_dir) + "/queue/.pct-" + oss.str();
    // // Convert the solver state to an SMT-LIB formatted string
    // // std::string smt2_str = qsym::g_solver->getSolver().to_smt2();
    // z3::expr_vector asserts = g_solver.assertions();
    // for(uint32_t i = *__insert_depth; i < asserts.size(); i++){
    //   smt2_str << "(assert " << asserts[i].to_string() <<  ")\n";
    // } 

    // // Write the SMT-LIB string to a file
    // std::ofstream file(filename);
    // if (file.is_open()) {
    //     file << smt2_str.str();
    //     file.close();
    //     std::cout << "Solver state saved to " << filename << std::endl;
    // } else {
    //     std::cerr << "Unable to open file " << filename << std::endl;
    // }
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

#ifndef NDEBUG
  std::cerr << "Initializing symbolic runtime" << std::endl;
#endif

  std::atexit(save_solver_to_file);
  register_signals();
  loadConfig();
  initLibcWrappers();
  std::cerr << "This is SymCC running with the simple backend" << std::endl
            << "For anything but debugging SymCC itself, you will want to use "
               "the QSYM backend instead (see README.md for build instructions)"
            << std::endl;

  Z3_config cfg;

  cfg = Z3_mk_config();
  Z3_set_param_value(cfg, "model", "true");
  Z3_set_param_value(cfg, "timeout", "10000"); // milliseconds
  g_context = Z3_mk_context_rc(cfg);
  Z3_del_config(cfg);

#ifndef NDEBUG
  Z3_set_error_handler(g_context, handle_z3_error);
#endif

  g_rounding_mode = Z3_mk_fpa_round_nearest_ties_to_even(g_context);
  Z3_inc_ref(g_context, g_rounding_mode);

  g_solver = Z3_mk_solver(g_context);
  Z3_solver_inc_ref(g_context, g_solver);

  auto *pointerSort = Z3_mk_bv_sort(g_context, 8 * sizeof(void *));
  Z3_inc_ref(g_context, (Z3_ast)pointerSort);
  g_null_pointer = Z3_mk_int(g_context, 0, pointerSort);
  Z3_inc_ref(g_context, g_null_pointer);
  Z3_dec_ref(g_context, (Z3_ast)pointerSort);
  g_true = Z3_mk_true(g_context);
  Z3_inc_ref(g_context, g_true);
  g_false = Z3_mk_false(g_context);
  Z3_inc_ref(g_context, g_false);

  if (g_config.logFile.empty()) {
    g_log = stderr;
  } else {
    g_log = fopen(g_config.logFile.c_str(), "w");
  }
}

Z3_ast _sym_build_integer(uint64_t value, uint8_t bits) {
  auto *sort = Z3_mk_bv_sort(g_context, bits);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto *result =
      registerExpression(Z3_mk_unsigned_int64(g_context, value, sort));
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

Z3_ast _sym_build_integer128(uint64_t high, uint64_t low) {
  return registerExpression(Z3_mk_concat(
      g_context, _sym_build_integer(high, 64), _sym_build_integer(low, 64)));
}

Z3_ast _sym_build_float(double value, int is_double) {
  auto *sort = FSORT(is_double);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto *result =
      registerExpression(Z3_mk_fpa_numeral_double(g_context, value, sort));
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

Z3_ast _sym_get_input_byte(size_t offset, uint8_t) {
  static std::vector<SymExpr> stdinBytes;

  if (offset < stdinBytes.size())
    return stdinBytes[offset];

  auto varName = "stdin" + std::to_string(stdinBytes.size());
  auto *var = build_variable(varName.c_str(), 8);

  stdinBytes.resize(offset);
  stdinBytes.push_back(var);

  return var;
}

Z3_ast _sym_build_null_pointer(void) { return g_null_pointer; }
Z3_ast _sym_build_true(void) { return g_true; }
Z3_ast _sym_build_false(void) { return g_false; }
Z3_ast _sym_build_bool(bool value) { return value ? g_true : g_false; }

Z3_ast _sym_build_neg(Z3_ast expr) {
  return registerExpression(Z3_mk_bvneg(g_context, expr));
}

#define DEF_BINARY_EXPR_BUILDER(name, z3_name)                                 \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) {                            \
    return registerExpression(Z3_mk_##z3_name(g_context, a, b));               \
  }

DEF_BINARY_EXPR_BUILDER(add, bvadd)
DEF_BINARY_EXPR_BUILDER(sub, bvsub)
DEF_BINARY_EXPR_BUILDER(mul, bvmul)
DEF_BINARY_EXPR_BUILDER(unsigned_div, bvudiv)
DEF_BINARY_EXPR_BUILDER(signed_div, bvsdiv)
DEF_BINARY_EXPR_BUILDER(unsigned_rem, bvurem)
DEF_BINARY_EXPR_BUILDER(signed_rem, bvsrem)
DEF_BINARY_EXPR_BUILDER(shift_left, bvshl)
DEF_BINARY_EXPR_BUILDER(logical_shift_right, bvlshr)
DEF_BINARY_EXPR_BUILDER(arithmetic_shift_right, bvashr)

DEF_BINARY_EXPR_BUILDER(signed_less_than, bvslt)
DEF_BINARY_EXPR_BUILDER(signed_less_equal, bvsle)
DEF_BINARY_EXPR_BUILDER(signed_greater_than, bvsgt)
DEF_BINARY_EXPR_BUILDER(signed_greater_equal, bvsge)
DEF_BINARY_EXPR_BUILDER(unsigned_less_than, bvult)
DEF_BINARY_EXPR_BUILDER(unsigned_less_equal, bvule)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_than, bvugt)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_equal, bvuge)
DEF_BINARY_EXPR_BUILDER(equal, eq)

DEF_BINARY_EXPR_BUILDER(and, bvand)
DEF_BINARY_EXPR_BUILDER(or, bvor)
DEF_BINARY_EXPR_BUILDER(bool_xor, xor)
DEF_BINARY_EXPR_BUILDER(xor, bvxor)

DEF_BINARY_EXPR_BUILDER(float_ordered_greater_than, fpa_gt)
DEF_BINARY_EXPR_BUILDER(float_ordered_greater_equal, fpa_geq)
DEF_BINARY_EXPR_BUILDER(float_ordered_less_than, fpa_lt)
DEF_BINARY_EXPR_BUILDER(float_ordered_less_equal, fpa_leq)
DEF_BINARY_EXPR_BUILDER(float_ordered_equal, fpa_eq)

#undef DEF_BINARY_EXPR_BUILDER

Z3_ast _sym_build_ite(Z3_ast cond, Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_ite(g_context, cond, a, b));
}

Z3_ast _sym_build_fp_add(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_fpa_add(g_context, g_rounding_mode, a, b));
}

Z3_ast _sym_build_fp_sub(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_fpa_sub(g_context, g_rounding_mode, a, b));
}

Z3_ast _sym_build_fp_mul(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_fpa_mul(g_context, g_rounding_mode, a, b));
}

Z3_ast _sym_build_fp_div(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_fpa_div(g_context, g_rounding_mode, a, b));
}

Z3_ast _sym_build_fp_rem(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_fpa_rem(g_context, a, b));
}

Z3_ast _sym_build_fp_abs(Z3_ast a) {
  return registerExpression(Z3_mk_fpa_abs(g_context, a));
}

Z3_ast _sym_build_fp_neg(Z3_ast a) {
  return registerExpression(Z3_mk_fpa_neg(g_context, a));
}

Z3_ast _sym_build_not(Z3_ast expr) {
  return registerExpression(Z3_mk_bvnot(g_context, expr));
}

Z3_ast _sym_build_not_equal(Z3_ast a, Z3_ast b) {
  return registerExpression(Z3_mk_not(g_context, Z3_mk_eq(g_context, a, b)));
}

Z3_ast _sym_build_bool_and(Z3_ast a, Z3_ast b) {
  Z3_ast operands[] = {a, b};
  return registerExpression(Z3_mk_and(g_context, 2, operands));
}

Z3_ast _sym_build_bool_or(Z3_ast a, Z3_ast b) {
  Z3_ast operands[] = {a, b};
  return registerExpression(Z3_mk_or(g_context, 2, operands));
}

Z3_ast _sym_build_float_ordered_not_equal(Z3_ast a, Z3_ast b) {
  return registerExpression(
      Z3_mk_not(g_context, _sym_build_float_ordered_equal(a, b)));
}

Z3_ast _sym_build_float_ordered(Z3_ast a, Z3_ast b) {
  return registerExpression(
      Z3_mk_not(g_context, _sym_build_float_unordered(a, b)));
}

Z3_ast _sym_build_float_unordered(Z3_ast a, Z3_ast b) {
  Z3_ast checks[2];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_greater_than(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_greater_than(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_greater_equal(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_greater_equal(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_less_than(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_less_than(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_less_equal(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_less_equal(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_equal(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_equal(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_float_unordered_not_equal(Z3_ast a, Z3_ast b) {
  Z3_ast checks[3];
  checks[0] = Z3_mk_fpa_is_nan(g_context, a);
  checks[1] = Z3_mk_fpa_is_nan(g_context, b);
  checks[2] = _sym_build_float_ordered_not_equal(a, b);
  return registerExpression(Z3_mk_or(g_context, 2, checks));
}

Z3_ast _sym_build_sext(Z3_ast expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;
  return registerExpression(Z3_mk_sign_ext(g_context, bits, expr));
}

Z3_ast _sym_build_zext(Z3_ast expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;
  return registerExpression(Z3_mk_zero_ext(g_context, bits, expr));
}

Z3_ast _sym_build_trunc(Z3_ast expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(Z3_mk_extract(g_context, bits - 1, 0, expr));
}

Z3_ast _sym_build_int_to_float(Z3_ast value, int is_double, int is_signed) {
  auto *sort = FSORT(is_double);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto *result = registerExpression(
      is_signed
          ? Z3_mk_fpa_to_fp_signed(g_context, g_rounding_mode, value, sort)
          : Z3_mk_fpa_to_fp_unsigned(g_context, g_rounding_mode, value, sort));
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

Z3_ast _sym_build_float_to_float(Z3_ast expr, int to_double) {
  auto *sort = FSORT(to_double);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto *result = registerExpression(
      Z3_mk_fpa_to_fp_float(g_context, g_rounding_mode, expr, sort));
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

Z3_ast _sym_build_bits_to_float(Z3_ast expr, int to_double) {
  if (expr == nullptr)
    return nullptr;

  auto *sort = FSORT(to_double);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto *result = registerExpression(Z3_mk_fpa_to_fp_bv(g_context, expr, sort));
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

Z3_ast _sym_build_float_to_bits(Z3_ast expr) {
  if (expr == nullptr)
    return nullptr;
  return registerExpression(Z3_mk_fpa_to_ieee_bv(g_context, expr));
}

Z3_ast _sym_build_float_to_signed_integer(Z3_ast expr, uint8_t bits) {
  return registerExpression(Z3_mk_fpa_to_sbv(
      g_context, Z3_mk_fpa_round_toward_zero(g_context), expr, bits));
}

Z3_ast _sym_build_float_to_unsigned_integer(Z3_ast expr, uint8_t bits) {
  return registerExpression(Z3_mk_fpa_to_ubv(
      g_context, Z3_mk_fpa_round_toward_zero(g_context), expr, bits));
}

Z3_ast _sym_build_bool_to_bit(Z3_ast expr) {
  if (expr == nullptr)
    return nullptr;
  return _sym_build_ite(expr, _sym_build_integer(1, 1),
                        _sym_build_integer(0, 1));
}

void _sym_push_path_constraint(Z3_ast constraint, int taken,
                               uintptr_t site_id [[maybe_unused]]) {
  if (constraint == nullptr)
    return;

  constraint = Z3_simplify(g_context, constraint);
  Z3_inc_ref(g_context, constraint);

  /* Check the easy cases first: if simplification reduced the constraint to
     "true" or "false", there is no point in trying to solve the negation or *
     pushing the constraint to the solver... */

  if (Z3_is_eq_ast(g_context, constraint, g_true)) {
    assert(taken && "We have taken an impossible branch");
    Z3_dec_ref(g_context, constraint);
    return;
  }

  if (Z3_is_eq_ast(g_context, constraint, g_false)) {
    assert(!taken && "We have taken an impossible branch");
    Z3_dec_ref(g_context, constraint);
    return;
  }

  /* Generate a solution for the alternative */
  Z3_ast not_constraint =
      Z3_simplify(g_context, Z3_mk_not(g_context, constraint));
  Z3_inc_ref(g_context, not_constraint);

  Z3_solver_push(g_context, g_solver);
  Z3_solver_assert(g_context, g_solver, taken ? not_constraint : constraint);
  fprintf(g_log, "Trying to solve:\n%s\n",
          Z3_solver_to_string(g_context, g_solver));

  Z3_lbool feasible = Z3_solver_check(g_context, g_solver);
  if (feasible == Z3_L_TRUE) {
    Z3_model model = Z3_solver_get_model(g_context, g_solver);
    Z3_model_inc_ref(g_context, model);
    fprintf(g_log, "Found diverging input:\n%s\n",
            Z3_model_to_string(g_context, model));
    Z3_model_dec_ref(g_context, model);
  } else {
    fprintf(g_log, "Can't find a diverging input at this point\n");
  }
  fflush(g_log);

  Z3_solver_pop(g_context, g_solver, 1);

  /* Assert the actual path constraint */
  Z3_ast newConstraint = (taken ? constraint : not_constraint);
  Z3_inc_ref(g_context, newConstraint);
  Z3_solver_assert(g_context, g_solver, newConstraint);
  assert((Z3_solver_check(g_context, g_solver) == Z3_L_TRUE) &&
         "Asserting infeasible path constraint");
  Z3_dec_ref(g_context, constraint);
  Z3_dec_ref(g_context, not_constraint);
}

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) {
  return registerExpression(Z3_mk_concat(g_context, a, b));
}

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) {
  return registerExpression(
      Z3_mk_extract(g_context, first_bit, last_bit, expr));
}

size_t _sym_bits_helper(SymExpr expr) {
  auto *sort = Z3_get_sort(g_context, expr);
  Z3_inc_ref(g_context, (Z3_ast)sort);
  auto result = Z3_get_bv_sort_size(g_context, sort);
  Z3_dec_ref(g_context, (Z3_ast)sort);
  return result;
}

/* No call-stack tracing */
void _sym_notify_call(uintptr_t) {}
void _sym_notify_ret(uintptr_t) {}
void _sym_notify_basic_block(uintptr_t) {}

/* Debugging */
const char *_sym_expr_to_string(SymExpr expr) {
  return Z3_ast_to_string(g_context, expr);
}

bool _sym_feasible(SymExpr expr) {
  expr = Z3_simplify(g_context, expr);
  Z3_inc_ref(g_context, expr);

  Z3_solver_push(g_context, g_solver);
  Z3_solver_assert(g_context, g_solver, expr);
  Z3_lbool feasible = Z3_solver_check(g_context, g_solver);
  Z3_solver_pop(g_context, g_solver, 1);

  Z3_dec_ref(g_context, expr);
  return (feasible == Z3_L_TRUE);
}

/* Garbage collection */
void _sym_collect_garbage() {
  if (allocatedExpressions.size() < g_config.garbageCollectionThreshold)
    return;

#ifndef NDEBUG
  auto start = std::chrono::high_resolution_clock::now();
  auto startSize = allocatedExpressions.size();
#endif

  auto reachableExpressions = collectReachableExpressions();
  for (auto expr_it = allocatedExpressions.begin();
       expr_it != allocatedExpressions.end();) {
    if (reachableExpressions.count(*expr_it) == 0) {
      expr_it = allocatedExpressions.erase(expr_it);
    } else {
      ++expr_it;
    }
  }

#ifndef NDEBUG
  auto end = std::chrono::high_resolution_clock::now();
  auto endSize = allocatedExpressions.size();

  std::cerr << "After garbage collection: " << endSize
            << " expressions remain (before: " << startSize << ")" << std::endl
            << "\t(collection took "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " milliseconds)" << std::endl;
#endif
}

/* Test-case handling */
void symcc_set_test_case_handler(TestCaseHandler) {
  // The simple backend doesn't support test-case handlers. However, let's not
  // make this a fatal error; otherwise, users would have to change their
  // programs to make them work with the simple backend.
  fprintf(
      g_log,
      "Warning: test-case handlers aren't supported in the simple backend\n");
}
