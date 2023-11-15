/*
 * Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#ifndef SHARE_OPTO_VECTORIZATION_HPP
#define SHARE_OPTO_VECTORIZATION_HPP

#include "utilities/pair.hpp"
#include "opto/node.hpp"
#include "opto/loopnode.hpp"

class VLoopAnalyzer;

// Code in this file and the vectorization.cpp contains shared logics and
// utilities for C2's loop auto-vectorization.

// A vectorization pointer (VPointer) has information about an address for
// dependence checking and vector alignment. It's usually bound to a memory
// operation in a counted loop for vectorizable analysis.
class VPointer : public ArenaObj {
 protected:
  MemNode*        _mem;      // My memory reference node
  PhaseIdealLoop* _phase;    // PhaseIdealLoop handle
  IdealLoopTree*  _lpt;      // Current IdealLoopTree
  PhiNode*        _iv;       // The loop induction variable

  Node* _base;               // null if unsafe nonheap reference
  Node* _adr;                // address pointer
  int   _scale;              // multiplier for iv (in bytes), 0 if no loop iv
  int   _offset;             // constant offset (in bytes)

  Node* _invar;              // invariant offset (in bytes), null if none
#ifdef ASSERT
  Node* _debug_invar;
  bool  _debug_negate_invar; // if true then use: (0 - _invar)
  Node* _debug_invar_scale;  // multiplier for invariant
#endif

  Node_Stack* _nstack;       // stack used to record a vpointer trace of variants
  bool        _analyze_only; // Used in loop unrolling only for vpointer trace
  uint        _stack_idx;    // Used in loop unrolling only for vpointer trace

  PhaseIdealLoop* phase() const { return _phase; }
  IdealLoopTree*  lpt() const   { return _lpt; }
  PhiNode*        iv() const    { return _iv; }

  bool is_loop_member(Node* n) const;
  bool invariant(Node* n) const;

  // Match: k*iv + offset
  bool scaled_iv_plus_offset(Node* n);
  // Match: k*iv where k is a constant that's not zero
  bool scaled_iv(Node* n);
  // Match: offset is (k [+/- invariant])
  bool offset_plus_k(Node* n, bool negate = false);

 public:
  enum CMP {
    Less          = 1,
    Greater       = 2,
    Equal         = 4,
    NotEqual      = (Less | Greater),
    NotComparable = (Less | Greater | Equal)
  };

  VPointer(MemNode* mem, PhaseIdealLoop* phase, IdealLoopTree* lpt,
            Node_Stack* nstack, bool analyze_only);
  // Following is used to create a temporary object during
  // the pattern match of an address expression.
  VPointer(VPointer* p);

  bool valid()  { return _adr != nullptr; }
  bool has_iv() { return _scale != 0; }

  Node* base()             { return _base; }
  Node* adr()              { return _adr; }
  MemNode* mem()           { return _mem; }
  int   scale_in_bytes()   { return _scale; }
  Node* invar()            { return _invar; }
  int   offset_in_bytes()  { return _offset; }
  int   memory_size()      { return _mem->memory_size(); }
  Node_Stack* node_stack() { return _nstack; }

  // Comparable?
  bool invar_equals(VPointer& q) {
    assert(_debug_invar == NodeSentinel || q._debug_invar == NodeSentinel ||
           (_invar == q._invar) == (_debug_invar == q._debug_invar &&
                                    _debug_invar_scale == q._debug_invar_scale &&
                                    _debug_negate_invar == q._debug_negate_invar), "");
    return _invar == q._invar;
  }

  int cmp(VPointer& q) {
    if (valid() && q.valid() &&
        (_adr == q._adr || (_base == _adr && q._base == q._adr)) &&
        _scale == q._scale   && invar_equals(q)) {
      bool overlap = q._offset <   _offset +   memory_size() &&
                       _offset < q._offset + q.memory_size();
      return overlap ? Equal : (_offset < q._offset ? Less : Greater);
    } else {
      return NotComparable;
    }
  }

  bool overlap_possible_with_any_in(Node_List* p) {
    for (uint k = 0; k < p->size(); k++) {
      MemNode* mem = p->at(k)->as_Mem();
      VPointer p_mem(mem, phase(), lpt(), nullptr, false);
      // Only if we know that we have Less or Greater can we
      // be sure that there can never be an overlap between
      // the two memory regions.
      if (!not_equal(p_mem)) {
        return true;
      }
    }
    return false;
  }

  bool not_equal(VPointer& q)     { return not_equal(cmp(q)); }
  bool equal(VPointer& q)         { return equal(cmp(q)); }
  bool comparable(VPointer& q)    { return comparable(cmp(q)); }
  static bool not_equal(int cmp)  { return cmp <= NotEqual; }
  static bool equal(int cmp)      { return cmp == Equal; }
  static bool comparable(int cmp) { return cmp < NotComparable; }

  void print();

#ifndef PRODUCT
  class Tracer {
    friend class VPointer;
    bool _is_trace_alignment;
    static int _depth;
    int _depth_save;
    void print_depth() const;
    int  depth() const    { return _depth; }
    void set_depth(int d) { _depth = d; }
    void inc_depth()      { _depth++; }
    void dec_depth()      { if (_depth > 0) _depth--; }
    void store_depth()    { _depth_save = _depth; }
    void restore_depth()  { _depth = _depth_save; }

    class Depth {
      friend class VPointer;
      Depth()      { ++_depth; }
      Depth(int x) { _depth = 0; }
      ~Depth()     { if (_depth > 0) --_depth; }
    };
    Tracer(bool is_trace_alignment) : _is_trace_alignment(is_trace_alignment) {}

    // tracing functions
    void ctor_1(Node* mem);
    void ctor_2(Node* adr);
    void ctor_3(Node* adr, int i);
    void ctor_4(Node* adr, int i);
    void ctor_5(Node* adr, Node* base,  int i);
    void ctor_6(Node* mem);

    void scaled_iv_plus_offset_1(Node* n);
    void scaled_iv_plus_offset_2(Node* n);
    void scaled_iv_plus_offset_3(Node* n);
    void scaled_iv_plus_offset_4(Node* n);
    void scaled_iv_plus_offset_5(Node* n);
    void scaled_iv_plus_offset_6(Node* n);
    void scaled_iv_plus_offset_7(Node* n);
    void scaled_iv_plus_offset_8(Node* n);

    void scaled_iv_1(Node* n);
    void scaled_iv_2(Node* n, int scale);
    void scaled_iv_3(Node* n, int scale);
    void scaled_iv_4(Node* n, int scale);
    void scaled_iv_5(Node* n, int scale);
    void scaled_iv_6(Node* n, int scale);
    void scaled_iv_7(Node* n);
    void scaled_iv_8(Node* n, VPointer* tmp);
    void scaled_iv_9(Node* n, int _scale, int _offset, Node* _invar);
    void scaled_iv_10(Node* n);

    void offset_plus_k_1(Node* n);
    void offset_plus_k_2(Node* n, int _offset);
    void offset_plus_k_3(Node* n, int _offset);
    void offset_plus_k_4(Node* n);
    void offset_plus_k_5(Node* n, Node* _invar);
    void offset_plus_k_6(Node* n, Node* _invar, bool _negate_invar, int _offset);
    void offset_plus_k_7(Node* n, Node* _invar, bool _negate_invar, int _offset);
    void offset_plus_k_8(Node* n, Node* _invar, bool _negate_invar, int _offset);
    void offset_plus_k_9(Node* n, Node* _invar, bool _negate_invar, int _offset);
    void offset_plus_k_10(Node* n, Node* _invar, bool _negate_invar, int _offset);
    void offset_plus_k_11(Node* n);
  } _tracer; // Tracer
#endif

  Node* maybe_negate_invar(bool negate, Node* invar);

  void maybe_add_to_invar(Node* new_invar, bool negate);

  Node* register_if_new(Node* n) const;
};


// Vector element size statistics for loop vectorization with vector masks
class VectorElementSizeStats {
 private:
  static const int NO_SIZE = -1;
  static const int MIXED_SIZE = -2;
  int* _stats;

 public:
  VectorElementSizeStats(Arena* a) : _stats(NEW_ARENA_ARRAY(a, int, 4)) {
    clear();
  }

  void clear() { memset(_stats, 0, sizeof(int) * 4); }

  void record_size(int size) {
    assert(1 <= size && size <= 8 && is_power_of_2(size), "Illegal size");
    _stats[exact_log2(size)]++;
  }

  int count_size(int size) {
    assert(1 <= size && size <= 8 && is_power_of_2(size), "Illegal size");
    return _stats[exact_log2(size)];
  }

  int smallest_size() {
    for (int i = 0; i <= 3; i++) {
      if (_stats[i] > 0) return (1 << i);
    }
    return NO_SIZE;
  }

  int largest_size() {
    for (int i = 3; i >= 0; i--) {
      if (_stats[i] > 0) return (1 << i);
    }
    return NO_SIZE;
  }

  int unique_size() {
    int small = smallest_size();
    int large = largest_size();
    return (small == large) ? small : MIXED_SIZE;
  }
};


class VLoop : public StackObj {
protected:
  PhaseIdealLoop* _phase = nullptr;
  Arena* _arena = nullptr;
  IdealLoopTree* _lpt = nullptr;
  CountedLoopNode* _cl = nullptr;
  Node* _cl_exit = nullptr;
  PhiNode* _iv = nullptr;
  bool _allow_cfg = false;

  static constexpr char const* SUCCESS                    = "success";
  static constexpr char const* FAILURE_ALREADY_VECTORIZED = "loop already vectorized";
  static constexpr char const* FAILURE_UNROLL_ONLY        = "loop only wants to be unrolled";
  static constexpr char const* FAILURE_VECTOR_WIDTH       = "vector_width must be power of 2";
  static constexpr char const* FAILURE_VALID_COUNTED_LOOP = "must be valid counted loop (int)";
  static constexpr char const* FAILURE_CONTROL_FLOW       = "control flow in loop not allowed";
  static constexpr char const* FAILURE_BACKEDGE           = "nodes on backedge not allowed";
  static constexpr char const* FAILURE_PRE_LOOP_LIMIT     = "main-loop must be able to adjust pre-loop-limit (not found)";

public:
  VLoop(PhaseIdealLoop* phase) : _phase(phase),
                                 _arena(phase->C->comp_arena()) {}
  NONCOPYABLE(VLoop);

protected:
  virtual void reset(IdealLoopTree* lpt, bool allow_cfg) {
    assert(_phase == lpt->_phase, "must be the same phase");
    _lpt       = lpt;
    _cl        = nullptr;
    _cl_exit   = nullptr;
    _iv        = nullptr;
    _allow_cfg = allow_cfg;
  }

public:
  Arena* arena()          const { return _arena; }
  IdealLoopTree* lpt()    const { assert(_lpt     != nullptr, ""); return _lpt; };
  PhaseIdealLoop* phase() const { assert(_phase   != nullptr, ""); return _phase; }
  CountedLoopNode* cl()   const { assert(_cl      != nullptr, ""); return _cl; };
  Node* cl_exit()         const { assert(_cl_exit != nullptr, ""); return _cl_exit; };
  PhiNode* iv()           const { assert(_iv      != nullptr, ""); return _iv; };
  bool is_allow_cfg()     const { return _allow_cfg; }

  bool in_loopbody(const Node* n) const {
    // TODO refactor to allow cfg. See counter example with
    // nodes on backedge but backedge has no additional outputs
    const Node* ctrl = _phase->has_ctrl(n) ? _phase->get_ctrl(n) : n;
    return n != nullptr && n->outcnt() > 0 && ctrl == _cl;
    // if (n == nullptr || n->outcnt() == 0) { return false; }
    // const Node* ctrl = _phase->has_ctrl(n) ? _phase->get_ctrl(n) : n;
    // assert((ctrl == _cl) == (_phase->get_loop((Node*)ctrl) == _lpt), "WIP");
    // return _phase->get_loop((Node*)ctrl) == _lpt;
  }

  // Check if the loop passes some basic preconditions for vectorization.
  // Overwrite previous data.Return indicates if analysis succeeded.
  bool check_preconditions(IdealLoopTree* lpt, bool allow_cfg);

protected:
  const char* check_preconditions_helper();
};

class VLoopReductions : public StackObj {
private:
  typedef const Pair<const Node*, int> PathEnd;

  VLoop* _vloop;
  VectorSet _loop_reductions;

public:
  VLoopReductions(VLoop* vloop) : _vloop(vloop),
                                  _loop_reductions(_vloop->arena()){};
  NONCOPYABLE(VLoopReductions);
  void reset() {
    _loop_reductions.clear();
  }

private:
  // Search for a path P = (n_1, n_2, ..., n_k) such that:
  // - original_input(n_i, input) = n_i+1 for all 1 <= i < k,
  // - path(n) for all n in P,
  // - k <= max, and
  // - there exists a node e such that original_input(n_k, input) = e and end(e).
  // Return <e, k>, if P is found, or <nullptr, -1> otherwise.
  // Note that original_input(n, i) has the same behavior as n->in(i) except
  // that it commutes the inputs of binary nodes whose edges have been swapped.
  template <typename NodePredicate1, typename NodePredicate2>
  static PathEnd find_in_path(const Node* n1, uint input, int max,
                              NodePredicate1 path, NodePredicate2 end) {
    const PathEnd no_path(nullptr, -1);
    const Node* current = n1;
    int k = 0;
    for (int i = 0; i <= max; i++) {
      if (current == nullptr) {
        return no_path;
      }
      if (end(current)) {
        return PathEnd(current, k);
      }
      if (!path(current)) {
        return no_path;
      }
      current = original_input(current, input);
      k++;
    }
    return no_path;
  }

public:
  // Whether n is a reduction operator and part of a reduction cycle.
  // This function can be used for individual queries outside auto-vectorization,
  // e.g. to inform matching in target-specific code. Otherwise, the
  // almost-equivalent but faster mark_reductions() is preferable.
  static bool is_reduction(const Node* n);
  // Whether n is marked as a reduction node.
  bool is_marked_reduction(const Node* n) const { return _loop_reductions.test(n->_idx); }
  bool is_marked_reduction_loop() { return !_loop_reductions.is_empty(); }
private:
  // Whether n is a standard reduction operator.
  static bool is_reduction_operator(const Node* n);
  // Whether n is part of a reduction cycle via the 'input' edge index. To bound
  // the search, constrain the size of reduction cycles to LoopMaxUnroll.
  static bool in_reduction_cycle(const Node* n, uint input);
  // Reference to the i'th input node of n, commuting the inputs of binary nodes
  // whose edges have been swapped. Assumes n is a commutative operation.
public:
  static Node* original_input(const Node* n, uint i);
  // Find and mark reductions in a loop. Running mark_reductions() is similar to
  // querying is_reduction(n) for every node in the loop, but stricter in
  // that it assumes counted loops and requires that reduction nodes are not
  // used within the loop except by their reduction cycle predecessors.
  void mark_reductions();
};

class VLoopMemorySlices : public StackObj {
private:
  VLoop* _vloop;

  GrowableArray<PhiNode*> _heads;
  GrowableArray<MemNode*> _tails;

public:
  VLoopMemorySlices(VLoop* vloop) :
    _vloop(vloop),
    _heads(_vloop->arena(), 8,  0, nullptr),
    _tails(_vloop->arena(), 8,  0, nullptr) {};

  NONCOPYABLE(VLoopMemorySlices);

  void reset() {
    _heads.clear();
    _tails.clear();
  }

  void analyze();

  const GrowableArray<PhiNode*> &heads() const { return _heads; }
  const GrowableArray<MemNode*> &tails() const { return _tails; }

  // Get all memory nodes of a slice, in reverse order
  void get_slice(Node* head, Node* tail, GrowableArray<Node*> &slice) const;

  DEBUG_ONLY(void print() const;)
};


class VLoopBody : public StackObj {
private:
  VLoop* _vloop;

  GrowableArray<Node*> _body;
  GrowableArray<int> _body_idx;

  static constexpr char const* FAILURE_NODE_NOT_ALLOWED  = "encontered unhandled node";

public:
  VLoopBody(VLoop* vloop) :
    _vloop(vloop),
    _body(_vloop->arena(), 8, 0, nullptr),
    _body_idx(_vloop->arena(), (int)(1.10 * _vloop->phase()->C->unique()), 0, 0) {}

  NONCOPYABLE(VLoopBody);

  void reset() {
    _body.clear();
    _body_idx.clear();
  }

  const char* construct();
  DEBUG_ONLY(void print() const;)

  int body_idx(const Node* n) const {
    assert(_vloop->in_loopbody(n), "must be in loop_body");
    return _body_idx.at(n->_idx);
  }

  const GrowableArray<Node*>& body() const { return _body; }

private:
  void set_body_idx(Node* n, int i) {
    assert(_vloop->in_loopbody(n), "must be in loop_body");
    _body_idx.at_put_grow(n->_idx, i);
  }
};

// ========================= Dependence Graph =====================

class DepMem;

//------------------------------DepEdge---------------------------
// An edge in the dependence graph.  The edges incident to a dependence
// node are threaded through _next_in for incoming edges and _next_out
// for outgoing edges.
class DepEdge : public ArenaObj {
 protected:
  DepMem* _pred;
  DepMem* _succ;
  DepEdge* _next_in;   // list of in edges, null terminated
  DepEdge* _next_out;  // list of out edges, null terminated

 public:
  DepEdge(DepMem* pred, DepMem* succ, DepEdge* next_in, DepEdge* next_out) :
    _pred(pred), _succ(succ), _next_in(next_in), _next_out(next_out) {}

  DepEdge* next_in()  { return _next_in; }
  DepEdge* next_out() { return _next_out; }
  DepMem*  pred()     { return _pred; }
  DepMem*  succ()     { return _succ; }

  void print();
};

//------------------------------DepMem---------------------------
// A node in the dependence graph.  _in_head starts the threaded list of
// incoming edges, and _out_head starts the list of outgoing edges.
class DepMem : public ArenaObj {
 protected:
  Node*    _node;     // Corresponding ideal node
  DepEdge* _in_head;  // Head of list of in edges, null terminated
  DepEdge* _out_head; // Head of list of out edges, null terminated

 public:
  DepMem(Node* node) : _node(node), _in_head(nullptr), _out_head(nullptr) {}

  Node*    node()                { return _node;     }
  DepEdge* in_head()             { return _in_head;  }
  DepEdge* out_head()            { return _out_head; }
  void set_in_head(DepEdge* hd)  { _in_head = hd;    }
  void set_out_head(DepEdge* hd) { _out_head = hd;   }

  int in_cnt();  // Incoming edge count
  int out_cnt(); // Outgoing edge count

  void print();
};

//------------------------------DepGraph---------------------------
class DepGraph {
 protected:
  Arena* _arena;
  GrowableArray<DepMem*> _map;
  DepMem* _root;
  DepMem* _tail;

 public:
  DepGraph(Arena* a) : _arena(a), _map(a, 8,  0, nullptr) {
    _root = new (_arena) DepMem(nullptr);
    _tail = new (_arena) DepMem(nullptr);
  }

  DepMem* root() { return _root; }
  DepMem* tail() { return _tail; }

  // Return dependence node corresponding to an ideal node
  DepMem* dep(Node* node) const { return _map.at(node->_idx); }

  // Make a new dependence graph node for an ideal node.
  DepMem* make_node(Node* node);

  // Make a new dependence graph edge dprec->dsucc
  DepEdge* make_edge(DepMem* dpred, DepMem* dsucc);

  DepEdge* make_edge(Node* pred,   Node* succ)   { return make_edge(dep(pred), dep(succ)); }
  DepEdge* make_edge(DepMem* pred, Node* succ)   { return make_edge(pred,      dep(succ)); }
  DepEdge* make_edge(Node* pred,   DepMem* succ) { return make_edge(dep(pred), succ);      }

  void init() { _map.clear(); } // initialize

  void print(Node* n)   { dep(n)->print(); }
  void print(DepMem* d) { d->print(); }
};

//------------------------------DepPreds---------------------------
// Iterator over predecessors in the dependence graph and
// non-memory-graph inputs of ideal nodes.
class DepPreds : public StackObj {
private:
  Node*    _n;
  int      _next_idx, _end_idx;
  DepEdge* _dep_next;
  Node*    _current;
  bool     _done;

public:
  DepPreds(Node* n, const DepGraph& dg);
  Node* current() { return _current; }
  bool  done()    { return _done; }
  void  next();
};

//------------------------------DepSuccs---------------------------
// Iterator over successors in the dependence graph and
// non-memory-graph outputs of ideal nodes.
class DepSuccs : public StackObj {
private:
  Node*    _n;
  int      _next_idx, _end_idx;
  DepEdge* _dep_next;
  Node*    _current;
  bool     _done;

public:
  DepSuccs(Node* n, DepGraph& dg);
  Node* current() { return _current; }
  bool  done()    { return _done; }
  void  next();
};

class VLoopDependenceGraph : public StackObj {
public:
  class DependenceEdge;
  class DependenceNode;
private:
  VLoop* _vloop;
  const VLoopMemorySlices& _memory_slices;
  const VLoopBody& _body;

  GrowableArray<DependenceNode*> _map;
  DependenceNode* _root;
  DependenceNode* _sink;

public:
  VLoopDependenceGraph(VLoop* vloop,
                       const VLoopMemorySlices& memory_slices,
                       const VLoopBody& body) :
    _vloop(vloop),
    _memory_slices(memory_slices),
    _body(body),
    _map(vloop->arena(), 8,  0, nullptr),
    _root(nullptr),
    _sink(nullptr) {}

  NONCOPYABLE(VLoopDependenceGraph);

  void reset() {
    _map.clear();
    _root = new (_vloop->arena()) DependenceNode(nullptr);
    _sink = new (_vloop->arena()) DependenceNode(nullptr);
  }

  void build();

  DependenceNode* root() const { return _root; }
  DependenceNode* sink() const { return _sink; }

  // Return dependence node corresponding to an ideal node
  DependenceNode* get_node(Node* node) const {
    assert(node != nullptr, "must not be nullptr");
    DependenceNode* d = _map.at(node->_idx);
    assert(d != nullptr, "must find dependence node");
    return d;
  }

  // Make a new dependence graph node for an ideal node.
  DependenceNode* make_node(Node* node);

  // Make a new dependence graph edge dprec->dsucc
  DependenceEdge* make_edge(DependenceNode* dpred, DependenceNode* dsucc);


  // TODO more functionality!

  void print() const;

  // An edge in the dependence graph.  The edges incident to a dependence
  // node are threaded through _next_in for incoming edges and _next_out
  // for outgoing edges.
  class DependenceEdge : public ArenaObj {
  protected:
    DependenceNode* _pred;
    DependenceNode* _succ;
    DependenceEdge* _next_in;  // list of in edges, null terminated
    DependenceEdge* _next_out; // list of out edges, null terminated

  public:
    DependenceEdge(DependenceNode* pred,
                   DependenceNode* succ,
                   DependenceEdge* next_in,
                   DependenceEdge* next_out) :
      _pred(pred), _succ(succ), _next_in(next_in), _next_out(next_out) {}

    DependenceEdge* next_in()  { return _next_in; }
    DependenceEdge* next_out() { return _next_out; }
    DependenceNode* pred()     { return _pred; }
    DependenceNode* succ()     { return _succ; }

    // TODO
    //void print();
  };

  // A node in the dependence graph.  _in_head starts the threaded list of
  // incoming edges, and _out_head starts the list of outgoing edges.
  class DependenceNode : public ArenaObj {
  protected:
    Node*           _node;     // Corresponding ideal node
    DependenceEdge* _in_head;  // Head of list of in edges, null terminated
    DependenceEdge* _out_head; // Head of list of out edges, null terminated

  public:
    DependenceNode(Node* node) :
      _node(node),
      _in_head(nullptr),
      _out_head(nullptr)
    {
      assert(node == nullptr ||
             node->is_Mem() ||
             node->is_memory_phi(),
             "only memory graph nodes expected");
    }

    Node*           node()                { return _node;     }
    DependenceEdge* in_head()             { return _in_head;  }
    DependenceEdge* out_head()            { return _out_head; }
    void set_in_head(DependenceEdge* hd)  { _in_head = hd;    }
    void set_out_head(DependenceEdge* hd) { _out_head = hd;   }

    int in_cnt();  // Incoming edge count
    int out_cnt(); // Outgoing edge count

    void print() const;
  };
};

class VLoopAnalyzer : public VLoop {
protected:
  static constexpr char const* FAILURE_NO_MAX_UNROLL = "slp max unroll analysis required";
  static constexpr char const* FAILURE_NO_REDUCTION_OR_STORE = "no reduction and no store in loop";

  // Submodules that analyze different aspects of the loop
  VLoopReductions      _reductions;
  VLoopMemorySlices    _memory_slices;
  VLoopBody            _body;
  VLoopDependenceGraph _dependence_graph;

public:
  VLoopAnalyzer(PhaseIdealLoop* phase) :
    VLoop(phase),
    // TODO pass this in by const reference!
    _reductions(this),
    _memory_slices(this),
    _body(this),
    _dependence_graph(this, _memory_slices, _body) {};
  NONCOPYABLE(VLoopAnalyzer);

  // Analyze the loop in preparation for vectorization.
  // Overwrite previous data.Return indicates if analysis succeeded.
  bool analyze(IdealLoopTree* lpt,
               bool allow_cfg);

  // Read-only accessors for submodules
  const VLoopReductions& reductions() const            { return _reductions; }
  const VLoopMemorySlices& memory_slices() const       { return _memory_slices; }
  const VLoopBody& body() const                        { return _body; }
  const VLoopDependenceGraph& dependence_graph() const { return _dependence_graph; }

private:
  virtual void reset(IdealLoopTree* lpt, bool allow_cfg) override {
    VLoop::reset(lpt, allow_cfg);
    _reductions.reset();
    _memory_slices.reset();
    _body.reset();
    _dependence_graph.reset();
  }
  const char* analyze_helper();
};

#endif // SHARE_OPTO_VECTORIZATION_HPP
