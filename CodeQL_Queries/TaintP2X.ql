/**
 * Generic TaintP2X query.
 *
 * The query is fixed. Language/API-specific Source, Sink and Sanitizer
 * definitions are loaded from the generated TaintP2XModels module, which is
 * produced from CodeQL_Models/taintp2x_models.json.
 *
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id taintp2x/dataflow
 * @tags security external/cwe/cwe-094
 */
import javascript
import TaintP2XModels

module TaintP2XConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof TaintP2XModels::TaintP2XSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof TaintP2XModels::TaintP2XSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof TaintP2XModels::TaintP2XSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode call |
      TaintP2XModels::isFileOperationCall(call) and
      node1 = call.getAnArgument() and
      node2 = call
    )
  }
}

module TaintP2XFlow = TaintTracking::Global<TaintP2XConfig>;
import TaintP2XFlow::PathGraph

from TaintP2XFlow::PathNode source, TaintP2XFlow::PathNode sink
where TaintP2XFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TaintP2X data from " + source.getNode().(TaintP2XModels::TaintP2XSource).getKind() +
    " reaches " + sink.getNode().(TaintP2XModels::TaintP2XSink).getCategory()
