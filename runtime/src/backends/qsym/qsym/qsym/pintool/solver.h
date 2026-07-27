#ifndef QSYM_SOLVER_H_
#define QSYM_SOLVER_H_

#include <unordered_set>
#include <z3++.h>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pin.H"

#include "afl_trace_map.h"
#include "expr.h"
// #include "thread_context.h"
#include "expr_builder.h"
#include "dependency.h"

namespace qsym {

extern z3::context *g_z3_context;
typedef std::unordered_set<ExprRef, ExprRefHash, ExprRefEqual> ExprRefSetTy;

class Solver {
public:
  ExprRefSetTy updated_exprs_;
  ExprRefSetTy added_exprs_;
  
  Solver(
      const std::string input_file,
      const std::string out_dir,
      const std::string bitmap);
  virtual ~Solver() = default;

  z3::solver& getSolver();
  z3::context& getContext();
  void addIfUnique(z3::expr e);

  // P3: lazily record branch constraints without any Z3 interaction. The
  // vector holds unique constraints in first-occurrence order, preserving
  // the index semantics that *__insert_depth relies on. Materialization to
  // Z3 and SMT-LIB serialization only happen at trace-dump time (see
  // save_solver_to_file() in the qsym backend Runtime.cpp), and the dump
  // itself is gated by AFL via the __AFL_SHM_DUMP_TRACE_ID channel, so
  // screening executions that turn out not to gain coverage never touch Z3.
  void traceConstraint(const ExprRef &e);
  const std::vector<ExprRef> &getTracedConstraints() const {
    return traced_constraints_;
  }

  void push();
  void reset();
  void pop();
  void add(z3::expr expr);
  z3::check_result check();

  bool checkAndSave(const std::string& postfix="");
  void addJcc(ExprRef, bool, ADDRINT);
  void addAddr(ExprRef, ADDRINT);
  void addAddr(ExprRef, llvm::APInt);
  void addValue(ExprRef, ADDRINT);
  void addValue(ExprRef, llvm::APInt);
  void solveAll(ExprRef, llvm::APInt);
  UINT8 getInput(ADDRINT index);

  ADDRINT last_pc() { return last_pc_; }

protected:
  std::string           input_file_;
  std::vector<UINT8>    inputs_;
  std::string           out_dir_;
  z3::context&          context_;
  z3::solver            solver_;
  z3::solver            solver;
  std::string           session_;
  INT32                 num_generated_;
  AflTraceMap           trace_;
  bool                  last_interested_;
  bool                  syncing_;
  uint64_t              start_time_;
  uint64_t              solving_time_;
  ADDRINT               last_pc_;
  DependencyForest<Expr> dep_forest_;
  std::unordered_set<unsigned>   constraint_set;  // P1: Z3 AST ids (hash-consed), was SMT-LIB strings
  // P3: lazy trace state. Dedup uses the memoized structural XXH32 of each
  // Expr; a 32-bit collision can drop one unique constraint (acceptable for
  // a fuzzing heuristic; exact dedup happens again via Z3 AST ids at dump).
  std::vector<ExprRef>        traced_constraints_;
  std::unordered_set<uint32_t> traced_hash_set_;

  void checkOutDir();
  void readInput();

  std::vector<UINT8> getConcreteValues();
  virtual void saveValues(const std::string& postfix);
  void printValues(const std::vector<UINT8>& values);

  z3::expr getPossibleValue(z3::expr& z3_expr);
  z3::expr getMinValue(z3::expr& z3_expr);
  z3::expr getMaxValue(z3::expr& z3_expr);

  void addToSolver(ExprRef e, bool taken);
  void syncConstraints(ExprRef e);

  void addConstraint(ExprRef e, bool taken, bool is_interesting);
  void addConstraint(ExprRef e);
  bool addRangeConstraint(ExprRef, bool);
  void addNormalConstraint(ExprRef, bool);

  ExprRef getRangeConstraint(ExprRef e, bool is_unsigned);

  bool isInterestingJcc(ExprRef, bool, ADDRINT);
  void negatePath(ExprRef, bool);
  void solveOne(z3::expr);

  void checkFeasible();
};

extern Solver* g_solver;

} // namespace qsym

#endif // QSYM_SOLVER_H_
