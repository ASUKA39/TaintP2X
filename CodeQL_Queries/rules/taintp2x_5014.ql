/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User controlled response headers
 * @kind path-problem
 * @problem.severity warning
 * @id taintp2x/5014
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
  (sink.getNode() instanceof TaintP2XModels::ResponseHeaderValueSink or sink.getNode() instanceof TaintP2XModels::ResponseHeaderNameSink)
select sink.getNode(), source, sink, "User controlled data is used to set headers on a response"
