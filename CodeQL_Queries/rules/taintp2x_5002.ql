/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name Possible ExecImportSink:
 * @kind path-problem
 * @problem.severity warning
 * @id taintp2x/5002
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlowQuery
import TaintP2XFlow::PathGraph

from TaintP2XFlow::PathNode source, TaintP2XFlow::PathNode sink
where
  TaintP2XFlow::flowPath(source, sink) and
  source.getNode() instanceof TaintP2XModels::LLMControlledSource and
  (sink.getNode() instanceof TaintP2XModels::ExecImportSink)
select sink.getNode(), source, sink, "User specified data may reach a code execution sink"
