/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User controlled data to email send to users
 * @kind path-problem
 * @problem.severity warning
 * @id taintp2x/6007
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlowQuery
import TaintP2XFlow::PathGraph

from TaintP2XFlow::PathNode source, TaintP2XFlow::PathNode sink
where
  TaintP2XFlow::flowPath(source, sink) and
  source.getNode() instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink.getNode() instanceof TaintP2XModels::EmailSendSink)
select sink.getNode(), source, sink, "User controlled data is in emails being sent from server."
