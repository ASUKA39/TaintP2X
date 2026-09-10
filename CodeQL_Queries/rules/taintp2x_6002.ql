/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name Possible ExecImportSink:
 * @kind problem
 * @problem.severity warning
 * @id taintp2x/6002
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlow

from DataFlow::Node source, DataFlow::Node sink
where
  TaintP2XFlow::flow(source, sink) and
  source instanceof TaintP2XModels::FromUrlLLMControlledSource and
  (sink instanceof TaintP2XModels::ExecImportSink)
select sink, "User specified data may reach a code execution sink"
