/** Stateful taint flow shared by the original TaintP2X rule set. */
import javascript
import TaintP2XModels

module TaintP2XFlowConfig implements DataFlow::StateConfigSig {
  class FlowState = TaintP2XModels::FlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof TaintP2XModels::TaintP2XSource and
    state = TaintP2XModels::FlowState::normal()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof TaintP2XModels::TaintP2XSink and
    state = sink.(TaintP2XModels::TaintP2XSink).getRequiredState()
  }

  predicate isBarrier(DataFlow::Node node) { none() }

  predicate isBarrier(DataFlow::Node node, FlowState state) { none() }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    TaintP2XModels::isFileOperationStep(node1, node2) and
    state1 = TaintP2XModels::FlowState::normal() and
    state2 = TaintP2XModels::FlowState::fileOperation()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module TaintP2XFlow = TaintTracking::GlobalWithState<TaintP2XFlowConfig>;
