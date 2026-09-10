/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User Controlled file returned to user
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6013
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::ReturnedToUserSink)
select sink, "User Controlled file returned to user"
