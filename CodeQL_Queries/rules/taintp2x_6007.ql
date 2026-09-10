/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name User controlled data to email send to users
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6007
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::EmailSendSink)
select sink, "User controlled data is in emails being sent from server."
